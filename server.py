#!/usr/bin/env python3
"""VisualClaude — web frontend for Claude Code sessions kept alive in tmux.

Each session is a tmux session named vc-<name> running `claude`. The browser
talks to this server over HTTP/WebSocket; the server bridges a PTY running
`tmux attach` to the WebSocket. Closing the browser detaches, never kills.
"""
import asyncio
import fcntl
import hmac
import json
import os
import hashlib
import secrets
import shlex
import shutil
import signal
import ssl
import struct
import base64
import subprocess
import termios
import time
from pathlib import Path

from aiohttp import web, WSMsgType
from webauthn import (
    generate_authentication_options, generate_registration_options,
    options_to_json, verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

BASE = Path(__file__).resolve().parent
HOST = os.environ.get("VC_HOST", "127.0.0.1")
PORT = int(os.environ.get("VC_PORT", "7788"))
PREFIX = "vc-"
SECRET_FILE = BASE / ".secret"
CERT_FILE = BASE / "certs" / "cert.pem"
KEY_FILE = BASE / "certs" / "key.pem"
COOKIE = "vc_token"
COOKIE_PRE = "vc_pre"

if SECRET_FILE.exists():
    TOKEN = SECRET_FILE.read_text().strip()
else:
    TOKEN = secrets.token_urlsafe(24)
    SECRET_FILE.write_text(TOKEN + "\n")
    SECRET_FILE.chmod(0o600)


# --------------------------------------------------------------- user accounts
USERS_FILE = BASE / "users.json"
SESSION_DAYS = 90


def load_users() -> dict:
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    return {}


def save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2))
    USERS_FILE.chmod(0o600)


INVITES_FILE = BASE / "invites.json"


def load_invites() -> dict:
    if INVITES_FILE.exists():
        return json.loads(INVITES_FILE.read_text())
    return {}


def save_invites(invites: dict):
    INVITES_FILE.write_text(json.dumps(invites, indent=2))
    INVITES_FILE.chmod(0o600)


def is_admin(user: str) -> bool:
    return bool(load_users().get(user, {}).get("admin"))


MODELS = ("sonnet", "opus", "haiku")
SANDBOX_IMAGE = "visualclaude-sandbox"
SANDBOX_ROOT = Path("/srv/visualclaude")
HOST_CREDS = Path.home() / ".claude" / ".credentials.json"


def user_prefs(users: dict, user: str) -> dict:
    rec = users.get(user, {})
    return {
        "model": rec.get("model") or None,          # pin sessions to a model
        "allow_args": bool(rec.get("admin")) or bool(rec.get("allow_args")),
        "sandbox": bool(rec.get("sandbox")),        # run in docker
    }


def sandbox_setup(user: str, model) -> Path:
    """Prepare per-user sandbox dirs; returns the user's sandbox root."""
    root = SANDBOX_ROOT / user
    (root / "work").mkdir(parents=True, exist_ok=True)
    cfg = root / "claude-config"
    cfg.mkdir(exist_ok=True)
    root.chmod(0o700)
    # refresh OAuth credentials from the host account on every session start
    if HOST_CREDS.exists():
        dst = cfg / ".credentials.json"
        dst.write_bytes(HOST_CREDS.read_bytes())
        dst.chmod(0o600)
    # ~/.claude.json holds onboarding state; persist it across --rm containers
    cj = root / "claude.json"
    if not cj.exists():
        cj.write_text(json.dumps({"hasCompletedOnboarding": True}))
    # hard-pin the model via managed settings inside the container:
    # highest-precedence tier, not overridable by --model or /model
    managed = ({"model": model, "availableModels": [model],
                "enforceAvailableModels": True}
               if model else {})
    (root / "managed-settings.json").write_text(json.dumps(managed))
    return root


def hash_pw(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt,
                          n=16384, r=8, p=1, dklen=32).hex()


def check_pw(users: dict, username: str, password: str) -> bool:
    rec = users.get(username)
    if not rec:
        hash_pw(password, b"x" * 16)  # constant-time-ish: still do the work
        return False
    return hmac.compare_digest(hash_pw(password, bytes.fromhex(rec["salt"])),
                               rec["hash"])


def sign_session(user: str, exp: int) -> str:
    return hmac.new(TOKEN.encode(), f"{user}:{exp}".encode(),
                    hashlib.sha256).hexdigest()


def make_session_cookie(user: str) -> str:
    exp = int(time.time()) + SESSION_DAYS * 86400
    return f"{user}:{exp}:{sign_session(user, exp)}"


def request_user(request: web.Request):
    """Username from the signed session cookie, or None."""
    parts = request.cookies.get(COOKIE, "").split(":")
    if len(parts) != 3:
        return None
    user, exp, sig = parts
    if not valid_name(user) or not exp.isdigit() or int(exp) < time.time():
        return None
    if not hmac.compare_digest(sig, sign_session(user, int(exp))):
        return None
    return user


def user_target(user: str, name: str) -> str:
    return f"{PREFIX}{user}--{name}"


# ------------------------------------------------------------- session metadata
SESSIONS_META = BASE / "sessions.json"


def load_meta() -> dict:
    if SESSIONS_META.exists():
        return json.loads(SESSIONS_META.read_text())
    return {}


def save_meta(meta: dict):
    SESSIONS_META.write_text(json.dumps(meta, indent=2))


def claude_history_dir(info: dict) -> Path:
    """Claude Code stores transcripts under <config>/projects/<munged cwd>."""
    if info.get("sandbox"):
        user = info.get("user", "")
        munged = info.get("container_cwd", "/work").replace("/", "-")
        return SANDBOX_ROOT / user / "claude-config" / "projects" / munged
    munged = info.get("cwd", "").replace("/", "-").replace(".", "-")
    return Path.home() / ".claude" / "projects" / munged


def cleanup_session(target: str) -> bool:
    """Reap container, and for dirs we created: delete files + claude history.

    Returns True if the working directory was deleted. Directories that
    existed before the session are never touched.
    """
    subprocess.run(["docker", "rm", "-f", target], capture_output=True)
    meta = load_meta()
    info = meta.pop(target, None)
    save_meta(meta)
    if not info or not info.get("delete_dir"):
        return False
    path = Path(info.get("cwd", ""))
    # paranoia: only delete deep, existing paths no other session still uses
    if (len(path.parts) < 3 or not path.is_dir()
            or any(m.get("cwd") == info["cwd"] for m in meta.values())):
        return False
    shutil.rmtree(path, ignore_errors=True)
    shutil.rmtree(claude_history_dir(info), ignore_errors=True)
    return True


# ------------------------------------------------------------------ 2FA: TOTP
def hotp(key: bytes, counter: int) -> str:
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0xF
    code = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    try:
        key = base64.b32decode(secret_b32)
    except Exception:
        return False
    step = int(time.time()) // 30
    code = code.strip().replace(" ", "")
    return any(hmac.compare_digest(hotp(key, step + i), code)
               for i in range(-window, window + 1))


# -------------------------------------------------------------- 2FA: WebAuthn
RP_ID = os.environ.get("VC_RP_ID", "host.example.ts.net")
RP_ORIGIN = f"https://{RP_ID}"
RP_NAME = "VisualClaude"
_challenges: dict = {}  # (kind, user) -> (challenge_bytes, expires_at)


def stash_challenge(kind: str, user: str, challenge: bytes):
    now = time.time()
    for k in [k for k, (_, exp) in _challenges.items() if exp < now]:
        del _challenges[k]
    _challenges[(kind, user)] = (challenge, now + 300)


def pop_challenge(kind: str, user: str):
    item = _challenges.pop((kind, user), None)
    if item and item[1] > time.time():
        return item[0]
    return None


def user_keys(rec: dict) -> list:
    return rec.get("webauthn") or []


def has_second_factor(rec: dict) -> bool:
    return bool(rec.get("totp")) or bool(user_keys(rec))


def tmux(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["tmux", *args], capture_output=True, text=True)


def valid_name(name: str) -> bool:
    return bool(name) and len(name) <= 40 and all(
        c.isalnum() or c in "-_" for c in name
    )


# ---------------------------------------------------------------- middleware
@web.middleware
async def auth_middleware(request, handler):
    path = request.path
    if path in ("/login", "/register", "/logout", "/favicon.ico") \
            or path.startswith("/login/") or path.startswith("/vendor/"):
        return await handler(request)
    user = request_user(request)
    if user is None:
        if path.startswith("/api/") or path.startswith("/ws/"):
            raise web.HTTPUnauthorized(text="unauthorized")
        raise web.HTTPFound("/login")
    request["user"] = user
    return await handler(request)


# ---------------------------------------------------------------- auth pages
LOGIN_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VisualClaude — login</title><style>
body{margin:0;display:flex;align-items:center;justify-content:center;height:100vh;
background:#1a1915;color:#e8e2d5;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
main{display:flex;flex-direction:column;gap:12px;width:min(340px,90vw)}
form{display:flex;flex-direction:column;gap:12px}
h1{font-size:18px;font-weight:600;margin:0 0 4px}h1 span{color:#d97757}
input{background:#26241e;border:1px solid #3d3a30;border-radius:8px;padding:10px 12px;
color:#e8e2d5;font:inherit;font-size:14px}input:focus{outline:none;border-color:#d97757}
button{background:#d97757;border:none;border-radius:8px;padding:10px;color:#1a1915;
font:inherit;font-weight:600;cursor:pointer}button:hover{background:#e08b6e}
p.err{color:#e0655a;font-size:13px;margin:0;min-height:1em}
details{border-top:1px solid #3d3a30;padding-top:12px}
summary{color:#8a8578;cursor:pointer;font-size:13px;margin-bottom:10px}
details button{background:#26241e;color:#e8e2d5;border:1px solid #3d3a30}
</style></head><body><main>
<form method=post action=/login>
<h1><span>*</span> VisualClaude</h1>
<input name=user placeholder="username" autofocus autocomplete=username>
<input name=password type=password placeholder="password" autocomplete=current-password>
<button>Sign in</button><p class=err>__ERR__</p></form>
<details __OPEN__><summary>Create account</summary>
<form method=post action=/register>
<input name=invite type=password placeholder="invite code" autocomplete=off>
<input name=user placeholder="username (a-z 0-9 - _)" autocomplete=username>
<input name=password type=password placeholder="password (min 8 chars)" autocomplete=new-password>
<button>Register</button><p class=err>__RERR__</p></form></details>
</main></body></html>"""


def login_page(err="", rerr="", status=200):
    html = (LOGIN_HTML.replace("__ERR__", err).replace("__RERR__", rerr)
            .replace("__OPEN__", "open" if rerr else ""))
    return web.Response(text=html, content_type="text/html", status=status)


def session_response(user: str) -> web.Response:
    resp = web.HTTPFound("/")
    resp.set_cookie(COOKIE, make_session_cookie(user),
                    max_age=SESSION_DAYS * 86400,
                    httponly=True, samesite="Strict", secure=True)
    return resp


async def login_get(request):
    return login_page()


def sign_pre(user: str, exp: int) -> str:
    return hmac.new(TOKEN.encode(), f"pre:{user}:{exp}".encode(),
                    hashlib.sha256).hexdigest()


def pre_user(request: web.Request):
    """Username from the short-lived pre-auth (password ok, 2FA pending)."""
    parts = request.cookies.get(COOKIE_PRE, "").split(":")
    if len(parts) != 3:
        return None
    user, exp, sig = parts
    if not valid_name(user) or not exp.isdigit() or int(exp) < time.time():
        return None
    if not hmac.compare_digest(sig, sign_pre(user, int(exp))):
        return None
    return user


TFA_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VisualClaude — verify</title><style>
body{margin:0;display:flex;align-items:center;justify-content:center;height:100vh;
background:#1a1915;color:#e8e2d5;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
main{display:flex;flex-direction:column;gap:14px;width:min(340px,90vw)}
h1{font-size:18px;font-weight:600;margin:0}h1 span{color:#d97757}
input{background:#26241e;border:1px solid #3d3a30;border-radius:8px;padding:10px 12px;
color:#e8e2d5;font:inherit;font-size:16px;text-align:center;letter-spacing:.3em;width:100%;box-sizing:border-box}
input:focus{outline:none;border-color:#d97757}
button{background:#d97757;border:none;border-radius:8px;padding:10px;color:#1a1915;
font:inherit;font-weight:600;cursor:pointer;width:100%}
button.alt{background:#26241e;color:#e8e2d5;border:1px solid #3d3a30}
p.err{color:#e0655a;font-size:13px;margin:0;min-height:1em}
form{display:flex;flex-direction:column;gap:10px;margin:0}</style></head><body><main>
<h1><span>*</span> Two-factor verification</h1>
__TOTP__
__KEY__
<p class=err id=err>__ERR__</p>
<script>
const err = m => document.getElementById('err').textContent = m;
async function useKey(){
  try{
    const opts = await (await fetch('/login/webauthn/start',{method:'POST'})).json();
    const cred = await navigator.credentials.get(
      {publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(opts)});
    const r = await fetch('/login/webauthn/finish',{method:'POST',
      headers:{'content-type':'application/json'}, body: JSON.stringify(cred.toJSON())});
    if(r.ok) location.href='/'; else err(await r.text());
  }catch(e){ err(e.message || 'security key failed'); }
}
</script></main></body></html>"""


def tfa_page(rec: dict, err: str = "", status: int = 200):
    totp_form = ("""<form method=post action=/login/2fa>
<input name=code inputmode=numeric autocomplete=one-time-code
 placeholder="123456" maxlength=6 autofocus>
<button>Verify code</button></form>""" if rec.get("totp") else "")
    key_btn = ('<button class=alt onclick="useKey()">Use security key</button>'
               if user_keys(rec) else "")
    html = (TFA_HTML.replace("__TOTP__", totp_form)
            .replace("__KEY__", key_btn).replace("__ERR__", err))
    return web.Response(text=html, content_type="text/html", status=status)


async def login_post(request):
    form = await request.post()
    user = str(form.get("user", "")).strip().lower()
    password = str(form.get("password", ""))
    await asyncio.sleep(0.4)  # blunt brute-force brake
    users = load_users()
    if not (valid_name(user) and check_pw(users, user, password)):
        return login_page(err="wrong username or password", status=401)
    rec = users[user]
    if not has_second_factor(rec):
        return session_response(user)
    exp = int(time.time()) + 300
    resp = tfa_page(rec)
    resp.set_cookie(COOKIE_PRE, f"{user}:{exp}:{sign_pre(user, exp)}",
                    max_age=300, httponly=True, samesite="Strict", secure=True)
    return resp


async def tfa_post(request):
    user = pre_user(request)
    if user is None:
        raise web.HTTPFound("/login")
    form = await request.post()
    code = str(form.get("code", ""))
    users = load_users()
    rec = users.get(user) or {}
    await asyncio.sleep(0.4)
    if rec.get("totp") and totp_verify(rec["totp"], code):
        resp = session_response(user)
        resp.del_cookie(COOKIE_PRE)
        return resp
    return tfa_page(rec, err="wrong code", status=401)


async def login_webauthn_start(request):
    user = pre_user(request)
    if user is None:
        raise web.HTTPUnauthorized(text="expired, log in again")
    keys = user_keys(load_users().get(user) or {})
    if not keys:
        raise web.HTTPBadRequest(text="no security keys registered")
    opts = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(k["id"]))
            for k in keys],
    )
    stash_challenge("login", user, opts.challenge)
    return web.json_response(json.loads(options_to_json(opts)))


async def login_webauthn_finish(request):
    user = pre_user(request)
    if user is None:
        raise web.HTTPUnauthorized(text="expired, log in again")
    challenge = pop_challenge("login", user)
    if challenge is None:
        raise web.HTTPBadRequest(text="no pending challenge")
    body = await request.text()
    users = load_users()
    rec = users.get(user) or {}
    cred_id = json.loads(body).get("id", "")
    key = next((k for k in user_keys(rec) if k["id"] == cred_id), None)
    if key is None:
        raise web.HTTPBadRequest(text="unknown credential")
    try:
        result = verify_authentication_response(
            credential=body, expected_challenge=challenge,
            expected_rp_id=RP_ID, expected_origin=RP_ORIGIN,
            credential_public_key=base64url_to_bytes(key["public_key"]),
            credential_current_sign_count=int(key.get("sign_count", 0)),
        )
    except Exception as e:
        raise web.HTTPBadRequest(text=f"verification failed: {e}")
    key["sign_count"] = result.new_sign_count
    save_users(users)
    resp = web.json_response({"ok": True})
    resp.set_cookie(COOKIE, make_session_cookie(user),
                    max_age=SESSION_DAYS * 86400,
                    httponly=True, samesite="Strict", secure=True)
    resp.del_cookie(COOKIE_PRE)
    return resp


def create_user(users: dict, user: str, password: str, admin: bool = False):
    """Validate and add a user to the dict. Returns an error string or None."""
    if not valid_name(user):
        return "username: a-z, 0-9, - and _ only (max 40)"
    if len(password) < 8:
        return "password must be at least 8 characters"
    if user in users:
        return "username already taken"
    salt = secrets.token_bytes(16)
    users[user] = {"salt": salt.hex(), "hash": hash_pw(password, salt),
                   "created": int(time.time()), "admin": admin}
    save_users(users)
    return None


async def register_post(request):
    form = await request.post()
    invite = str(form.get("invite", ""))
    user = str(form.get("user", "")).strip().lower()
    password = str(form.get("password", ""))
    await asyncio.sleep(0.4)
    users = load_users()
    if not users:
        # bootstrap: the master token creates the first account, as admin
        if not hmac.compare_digest(invite, TOKEN):
            return login_page(rerr="wrong invite token", status=403)
        admin = True
    else:
        invites = load_invites()
        matched = next((c for c in invites
                        if hmac.compare_digest(invite, c)), None)
        if matched is None:
            return login_page(rerr="invalid invite code", status=403)
        admin = False
    err = create_user(users, user, password, admin=admin)
    if err:
        return login_page(rerr=err, status=400)
    if users and not admin:
        del invites[matched]  # consume only after successful registration
        save_invites(invites)
    return session_response(user)


async def logout_post(request):
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE)
    return resp


# ---------------------------------------------------------------- session api
async def me(request):
    users = load_users()
    prefs = user_prefs(users, request["user"])
    return web.json_response({"user": request["user"],
                              "admin": is_admin(request["user"]),
                              "allow_args": prefs["allow_args"],
                              "sandbox": prefs["sandbox"]})


# ------------------------------------------------------------- 2fa self-service
async def tfa_status(request):
    rec = load_users().get(request["user"]) or {}
    return web.json_response({
        "totp": bool(rec.get("totp")),
        "keys": [{"id": k["id"], "name": k.get("name", "key"),
                  "created": k.get("created", 0)} for k in user_keys(rec)],
    })


async def totp_start(request):
    user = request["user"]
    users = load_users()
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    users[user]["totp_pending"] = secret
    save_users(users)
    uri = (f"otpauth://totp/VisualClaude:{user}?secret={secret}"
           f"&issuer=VisualClaude&digits=6&period=30")
    return web.json_response({"secret": secret, "uri": uri})


async def totp_confirm(request):
    user = request["user"]
    body = await request.json()
    users = load_users()
    pending = users[user].get("totp_pending")
    if not pending:
        raise web.HTTPBadRequest(text="no pending TOTP setup")
    if not totp_verify(pending, str(body.get("code", ""))):
        raise web.HTTPBadRequest(text="wrong code, try again")
    users[user]["totp"] = pending
    users[user].pop("totp_pending", None)
    save_users(users)
    return web.json_response({"ok": True})


async def totp_disable(request):
    user = request["user"]
    body = await request.json()
    users = load_users()
    current = users[user].get("totp")
    if not current:
        raise web.HTTPBadRequest(text="TOTP is not enabled")
    if not totp_verify(current, str(body.get("code", ""))):
        raise web.HTTPBadRequest(text="wrong code")
    users[user].pop("totp", None)
    save_users(users)
    return web.json_response({"ok": True})


async def webauthn_reg_start(request):
    user = request["user"]
    rec = load_users().get(user) or {}
    opts = generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME,
        user_id=user.encode(), user_name=user,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(k["id"]))
            for k in user_keys(rec)],
    )
    stash_challenge("reg", user, opts.challenge)
    return web.json_response(json.loads(options_to_json(opts)))


async def webauthn_reg_finish(request):
    user = request["user"]
    challenge = pop_challenge("reg", user)
    if challenge is None:
        raise web.HTTPBadRequest(text="no pending challenge")
    body = await request.json()
    name = str(body.get("name", "")).strip()[:40] or "security key"
    try:
        result = verify_registration_response(
            credential=json.dumps(body.get("credential")),
            expected_challenge=challenge,
            expected_rp_id=RP_ID, expected_origin=RP_ORIGIN,
        )
    except Exception as e:
        raise web.HTTPBadRequest(text=f"registration failed: {e}")
    users = load_users()
    users[user].setdefault("webauthn", []).append({
        "id": bytes_to_base64url(result.credential_id),
        "public_key": bytes_to_base64url(result.credential_public_key),
        "sign_count": result.sign_count,
        "name": name, "created": int(time.time()),
    })
    save_users(users)
    return web.json_response({"ok": True}, status=201)


async def webauthn_delete(request):
    user = request["user"]
    cred_id = request.match_info["id"]
    users = load_users()
    keys = user_keys(users.get(user) or {})
    remaining = [k for k in keys if k["id"] != cred_id]
    if len(remaining) == len(keys):
        raise web.HTTPNotFound(text="no such key")
    users[user]["webauthn"] = remaining
    save_users(users)
    return web.json_response({"ok": True})


# ---------------------------------------------------------------- admin api
def require_admin(request):
    if not is_admin(request["user"]):
        raise web.HTTPForbidden(text="admin only")


async def admin_list_users(request):
    require_admin(request)
    users = load_users()
    return web.json_response([
        {"name": u, "created": rec.get("created", 0),
         "admin": bool(rec.get("admin")),
         "model": rec.get("model") or "",
         "allow_args": bool(rec.get("allow_args")),
         "sandbox": bool(rec.get("sandbox"))}
        for u, rec in sorted(users.items())
    ])


async def admin_update_user(request):
    require_admin(request)
    name = request.match_info["name"]
    users = load_users()
    if name not in users:
        raise web.HTTPNotFound(text="no such user")
    body = await request.json()
    if "model" in body:
        model = str(body["model"] or "")
        if model and model not in MODELS:
            raise web.HTTPBadRequest(
                text=f"model must be one of {', '.join(MODELS)} or empty")
        users[name]["model"] = model or None
    if "allow_args" in body:
        users[name]["allow_args"] = bool(body["allow_args"])
    if "sandbox" in body:
        users[name]["sandbox"] = bool(body["sandbox"])
    if body.get("reset_2fa"):  # lockout recovery
        for k in ("totp", "totp_pending", "webauthn"):
            users[name].pop(k, None)
    save_users(users)
    return web.json_response({"ok": True})


async def admin_create_user(request):
    require_admin(request)
    body = await request.json()
    users = load_users()
    err = create_user(users, str(body.get("name", "")).strip().lower(),
                      str(body.get("password", "")),
                      admin=bool(body.get("admin")))
    if err:
        raise web.HTTPBadRequest(text=err)
    return web.json_response({"ok": True}, status=201)


async def admin_delete_user(request):
    require_admin(request)
    name = request.match_info["name"]
    if name == request["user"]:
        raise web.HTTPBadRequest(text="cannot delete yourself")
    users = load_users()
    if name not in users:
        raise web.HTTPNotFound(text="no such user")
    del users[name]
    save_users(users)
    # kill their tmux sessions too
    out = tmux("list-sessions", "-F", "#{session_name}")
    for sess in out.stdout.splitlines():
        if sess.startswith(f"{PREFIX}{name}--"):
            tmux("kill-session", "-t", "=" + sess)
            cleanup_session(sess)
    return web.json_response({"ok": True})


async def admin_list_invites(request):
    require_admin(request)
    return web.json_response([
        {"code": c, "created": rec.get("created", 0)}
        for c, rec in sorted(load_invites().items(),
                             key=lambda kv: -kv[1].get("created", 0))
    ])


async def admin_create_invite(request):
    require_admin(request)
    invites = load_invites()
    code = secrets.token_urlsafe(9)
    invites[code] = {"created": int(time.time()), "by": request["user"]}
    save_invites(invites)
    return web.json_response({"code": code}, status=201)


async def admin_delete_invite(request):
    require_admin(request)
    invites = load_invites()
    code = request.match_info["code"]
    if code not in invites:
        raise web.HTTPNotFound(text="no such invite")
    del invites[code]
    save_invites(invites)
    return web.json_response({"ok": True})


async def list_sessions(request):
    mine = request["user"] + "--"
    meta = load_meta()
    out = tmux(
        "list-sessions", "-F",
        "#{session_name}\t#{session_created}\t#{session_attached}\t#{session_path}",
    )
    sessions = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[0].startswith(PREFIX):
            continue
        rest = parts[0][len(PREFIX):]
        if not rest.startswith(mine):
            continue
        sessions.append({
            "name": rest[len(mine):],
            "created": int(parts[1] or 0),
            "attached": parts[2] not in ("0", ""),
            "path": parts[3],
            "ephemeral": bool(meta.get(parts[0], {}).get("delete_dir")),
        })
    sessions.sort(key=lambda s: -s["created"])
    return web.json_response(sessions)


async def create_session(request):
    user = request["user"]
    body = await request.json()
    name = str(body.get("name", "")).strip()
    cwd = str(body.get("cwd", "")).strip()
    extra = str(body.get("args", "")).strip()  # e.g. --continue
    if not valid_name(name):
        raise web.HTTPBadRequest(text="name must be alphanumeric/-/_ (max 40)")
    prefs = user_prefs(load_users(), user)
    if extra and not prefs["allow_args"]:
        raise web.HTTPForbidden(text="claude args are not allowed for your account")

    claude_cmd = "claude"
    if prefs["model"]:
        claude_cmd += f" --model {shlex.quote(prefs['model'])}"
    if extra:
        claude_cmd += " " + " ".join(shlex.quote(a) for a in shlex.split(extra))
    # If claude exits, drop to a shell instead of killing the session.
    claude_cmd += " ; exec bash"

    target = user_target(user, name)
    if tmux("has-session", "-t", "=" + target).returncode == 0:
        raise web.HTTPConflict(text="session already exists")

    if prefs["sandbox"]:
        # workspace confined to /work inside the container
        root = sandbox_setup(user, prefs["model"])
        sub = Path("/work").joinpath(cwd.lstrip("/")).resolve()
        if not str(sub).startswith("/work"):
            raise web.HTTPBadRequest(text="directory must be inside /work")
        host_dir = root / "work" / str(sub)[len("/work"):].lstrip("/")
        if host_dir.exists() and not host_dir.is_dir():
            raise web.HTTPBadRequest(text=f"not a directory: {sub}")
        dir_existed = host_dir.exists()
        host_dir.mkdir(parents=True, exist_ok=True)
        session_info = {"user": user, "cwd": str(host_dir),
                        "container_cwd": str(sub), "sandbox": True,
                        "delete_dir": not dir_existed}
        # reap a stale container left over from a killed tmux session
        subprocess.run(["docker", "rm", "-f", target], capture_output=True)
        docker = [
            "docker", "run", "--rm", "-it", "--name", target,
            "--hostname", name, "--memory", "2g", "--cpus", "2",
            "--pids-limit", "512",
            "-v", f"{root / 'work'}:/work",
            "-v", f"{root / 'claude-config'}:/root/.claude",
            "-v", f"{root / 'claude.json'}:/root/.claude.json",
            "-v", f"{root / 'managed-settings.json'}"
                  ":/etc/claude-code/managed-settings.json:ro",
            "-w", str(sub), SANDBOX_IMAGE,
            "bash", "-c", claude_cmd,
        ]
        cmd = " ".join(shlex.quote(a) for a in docker)
        cwd = str(sub)  # shown in the session list
        r = tmux("new-session", "-d", "-s", target,
                 "-x", "200", "-y", "50", cmd)
    else:
        path = Path(cwd or "~").expanduser()
        if not path.is_absolute():
            path = Path.home() / path
        if path.exists() and not path.is_dir():
            raise web.HTTPBadRequest(text=f"not a directory: {path}")
        dir_existed = path.exists()
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise web.HTTPBadRequest(text=f"cannot create directory: {e}")
        cwd = str(path)
        session_info = {"user": user, "cwd": cwd, "sandbox": False,
                        "delete_dir": not dir_existed}
        r = tmux("new-session", "-d", "-s", target, "-c", cwd,
                 "-x", "200", "-y", "50", claude_cmd)
    if r.returncode != 0:
        raise web.HTTPInternalServerError(text=r.stderr.strip() or "tmux failed")
    meta = load_meta()
    meta[target] = session_info
    save_meta(meta)
    tmux("set-option", "-t", target, "status", "off")
    tmux("set-option", "-t", target, "window-size", "latest")
    tmux("set-option", "-t", target, "history-limit", "10000")
    return web.json_response({"name": name}, status=201)


async def kill_session(request):
    name = request.match_info["name"]
    if not valid_name(name):
        raise web.HTTPBadRequest(text="bad name")
    target = user_target(request["user"], name)
    r = tmux("kill-session", "-t", "=" + target)
    if r.returncode != 0:
        raise web.HTTPNotFound(text=r.stderr.strip() or "no such session")
    files_deleted = cleanup_session(target)
    return web.json_response({"ok": True, "files_deleted": files_deleted})


# ---------------------------------------------------------------- ws bridge
async def ws_terminal(request):
    name = request.match_info["name"]
    if not valid_name(name):
        raise web.HTTPBadRequest(text="bad name")
    target = user_target(request["user"], name)
    if tmux("has-session", "-t", "=" + target).returncode != 0:
        raise web.HTTPNotFound(text="no such session")

    ws = web.WebSocketResponse(heartbeat=30, max_msg_size=1 << 20)
    await ws.prepare(request)

    loop = asyncio.get_running_loop()
    master, slave = os.openpty()
    env = dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8")
    proc = await asyncio.create_subprocess_exec(
        "tmux", "attach-session", "-t", "=" + target,
        stdin=slave, stdout=slave, stderr=slave,
        env=env, preexec_fn=os.setsid,
    )
    os.close(slave)
    os.set_blocking(master, False)

    out_queue: asyncio.Queue = asyncio.Queue(maxsize=512)

    def on_readable():
        try:
            data = os.read(master, 65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if data:
            try:
                out_queue.put_nowait(data)
            except asyncio.QueueFull:
                pass  # drop under extreme backpressure; tmux will redraw
        else:
            loop.remove_reader(master)
            out_queue.put_nowait(None)

    loop.add_reader(master, on_readable)

    def resize(cols: int, rows: int):
        cols = max(20, min(500, cols))
        rows = max(5, min(300, rows))
        fcntl.ioctl(master, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0))
        try:
            os.killpg(proc.pid, signal.SIGWINCH)
        except ProcessLookupError:
            pass

    async def pump_out():
        while True:
            data = await out_queue.get()
            if data is None:
                break
            # coalesce whatever queued up to cut frame count
            while not out_queue.empty():
                more = out_queue.get_nowait()
                if more is None:
                    await ws.send_bytes(data)
                    return
                data += more
            await ws.send_bytes(data)
        if not ws.closed:
            await ws.close()

    pump = asyncio.create_task(pump_out())
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    ev = json.loads(msg.data)
                except ValueError:
                    continue
                if ev.get("type") == "input":
                    os.write(master, str(ev.get("data", "")).encode())
                elif ev.get("type") == "resize":
                    resize(int(ev.get("cols", 80)), int(ev.get("rows", 24)))
            elif msg.type == WSMsgType.BINARY:
                os.write(master, msg.data)
    finally:
        pump.cancel()
        try:
            loop.remove_reader(master)
        except Exception:
            pass
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGHUP)  # detach client only
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), 3)
            except asyncio.TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            os.close(master)
        except OSError:
            pass
    return ws


# ---------------------------------------------------------------- static
async def index(request):
    return web.FileResponse(BASE / "public" / "index.html")


def main():
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get("/", index)
    app.router.add_get("/login", login_get)
    app.router.add_post("/login", login_post)
    app.router.add_post("/register", register_post)
    app.router.add_post("/logout", logout_post)
    app.router.add_post("/login/2fa", tfa_post)
    app.router.add_post("/login/webauthn/start", login_webauthn_start)
    app.router.add_post("/login/webauthn/finish", login_webauthn_finish)
    app.router.add_get("/api/2fa", tfa_status)
    app.router.add_post("/api/2fa/totp/start", totp_start)
    app.router.add_post("/api/2fa/totp/confirm", totp_confirm)
    app.router.add_post("/api/2fa/totp/disable", totp_disable)
    app.router.add_post("/api/2fa/webauthn/start", webauthn_reg_start)
    app.router.add_post("/api/2fa/webauthn/finish", webauthn_reg_finish)
    app.router.add_delete("/api/2fa/webauthn/{id}", webauthn_delete)
    app.router.add_get("/api/me", me)
    app.router.add_get("/api/users", admin_list_users)
    app.router.add_post("/api/users", admin_create_user)
    app.router.add_patch("/api/users/{name}", admin_update_user)
    app.router.add_delete("/api/users/{name}", admin_delete_user)
    app.router.add_get("/api/invites", admin_list_invites)
    app.router.add_post("/api/invites", admin_create_invite)
    app.router.add_delete("/api/invites/{code}", admin_delete_invite)
    app.router.add_get("/api/sessions", list_sessions)
    app.router.add_post("/api/sessions", create_session)
    app.router.add_delete("/api/sessions/{name}", kill_session)
    app.router.add_get("/ws/{name}", ws_terminal)
    app.router.add_static("/vendor/", BASE / "public" / "vendor")
    ssl_ctx = None
    scheme = "http"
    if os.environ.get("VC_TLS", "1") != "0":
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        scheme = "https"
    print(f"VisualClaude on {scheme}://{HOST}:{PORT}  (token in {SECRET_FILE})")
    web.run_app(app, host=HOST, port=PORT, ssl_context=ssl_ctx, print=None)


if __name__ == "__main__":
    main()
