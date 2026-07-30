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
import signal
import ssl
import struct
import subprocess
import termios
import time
from pathlib import Path

from aiohttp import web, WSMsgType

BASE = Path(__file__).resolve().parent
HOST = os.environ.get("VC_HOST", "127.0.0.1")
PORT = int(os.environ.get("VC_PORT", "7788"))
PREFIX = "vc-"
SECRET_FILE = BASE / ".secret"
CERT_FILE = BASE / "certs" / "cert.pem"
KEY_FILE = BASE / "certs" / "key.pem"
COOKIE = "vc_token"

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
            or path.startswith("/vendor/"):
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
<input name=invite type=password placeholder="invite token" autocomplete=off>
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


async def login_post(request):
    form = await request.post()
    user = str(form.get("user", "")).strip().lower()
    password = str(form.get("password", ""))
    await asyncio.sleep(0.4)  # blunt brute-force brake
    if valid_name(user) and check_pw(load_users(), user, password):
        return session_response(user)
    return login_page(err="wrong username or password", status=401)


async def register_post(request):
    form = await request.post()
    invite = str(form.get("invite", ""))
    user = str(form.get("user", "")).strip().lower()
    password = str(form.get("password", ""))
    await asyncio.sleep(0.4)
    if not hmac.compare_digest(invite, TOKEN):
        return login_page(rerr="wrong invite token", status=403)
    if not valid_name(user):
        return login_page(rerr="username: a-z, 0-9, - and _ only (max 40)",
                          status=400)
    if len(password) < 8:
        return login_page(rerr="password must be at least 8 characters",
                          status=400)
    users = load_users()
    if user in users:
        return login_page(rerr="username already taken", status=409)
    salt = secrets.token_bytes(16)
    users[user] = {"salt": salt.hex(), "hash": hash_pw(password, salt),
                   "created": int(time.time())}
    save_users(users)
    return session_response(user)


async def logout_post(request):
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE)
    return resp


# ---------------------------------------------------------------- session api
async def me(request):
    return web.json_response({"user": request["user"]})


async def list_sessions(request):
    mine = request["user"] + "--"
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
        })
    sessions.sort(key=lambda s: -s["created"])
    return web.json_response(sessions)


async def create_session(request):
    body = await request.json()
    name = str(body.get("name", "")).strip()
    cwd = str(body.get("cwd", "")).strip() or str(Path.home())
    extra = str(body.get("args", "")).strip()  # e.g. --continue
    if not valid_name(name):
        raise web.HTTPBadRequest(text="name must be alphanumeric/-/_ (max 40)")
    path = Path(cwd).expanduser()
    if not path.is_absolute():
        path = Path.home() / path
    if path.exists() and not path.is_dir():
        raise web.HTTPBadRequest(text=f"not a directory: {path}")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise web.HTTPBadRequest(text=f"cannot create directory: {e}")
    cwd = str(path)
    target = user_target(request["user"], name)
    if tmux("has-session", "-t", "=" + target).returncode == 0:
        raise web.HTTPConflict(text="session already exists")
    # If claude exits, drop to a shell instead of killing the session.
    cmd = "claude"
    if extra:
        cmd += " " + " ".join(shlex.quote(a) for a in shlex.split(extra))
    cmd += " ; exec bash"
    r = tmux("new-session", "-d", "-s", target, "-c", cwd,
             "-x", "200", "-y", "50", cmd)
    if r.returncode != 0:
        raise web.HTTPInternalServerError(text=r.stderr.strip() or "tmux failed")
    tmux("set-option", "-t", target, "status", "off")
    tmux("set-option", "-t", target, "window-size", "latest")
    tmux("set-option", "-t", target, "history-limit", "10000")
    return web.json_response({"name": name}, status=201)


async def kill_session(request):
    name = request.match_info["name"]
    if not valid_name(name):
        raise web.HTTPBadRequest(text="bad name")
    r = tmux("kill-session", "-t", "=" + user_target(request["user"], name))
    if r.returncode != 0:
        raise web.HTTPNotFound(text=r.stderr.strip() or "no such session")
    return web.json_response({"ok": True})


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
    app.router.add_get("/api/me", me)
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
