# VisualClaudeCode

Web client for running Claude Code on this machine. Every session is a tmux
session (named `vc-<name>`) running `claude`, so conversations stay alive when
you close the browser; the web UI is just a live view (PTY → WebSocket →
xterm.js) that attaches/detaches.

## Access

- URL: **https://vcc.example.com** — published via a Cloudflare Tunnel
  (outbound-only; no inbound port on the server) and gated by **Cloudflare
  Access (Zero Trust)**. Login is your Cloudflare Access identity (Google
  SSO); only emails allowed by the Access policy get in. See
  [docs/cloudflare.md](docs/cloudflare.md).
- The app independently validates the Access JWT (signature via team JWKS,
  audience, issuer, expiry) on every request; user records auto-provision
  keyed to the Access identity.

### Admin control (SENSITIVE)

Admin is **not** granted to whoever signs in first. In cloudflare mode it is
determined solely by `VCC_ADMIN_EMAILS` in `.env`, re-evaluated from that list
on every request. Being *allowed* by the Access policy only lets someone reach
the app as a normal user; admin is a separate, explicit whitelist.

Treat this list as root-equivalent: an admin can create users, **turn off a
user's sandbox** (which gives that account a root shell on this host), raise
session limits, and delete users and their files. Only put fully-trusted
identities in it. Changes apply on the user's next request after
`systemctl restart visualclaude`. To add an admin: append the email
(comma-separated) and restart.

### First-run deployment

Filling `.env` alone does **not** provision Cloudflare. After copying
`.env.example` to `.env` and filling in the token, zone, hostname and admin
email, run once:

```
.venv/bin/python scripts/deploy.py
```

That creates/updates the tunnel, DNS, Access app + allow policy, and login
method; writes the discovered `VCC_ACCESS_TEAM_DOMAIN`/`VCC_ACCESS_AUD` back
into `.env`; installs the `cloudflared` service; and restarts the app. It is
idempotent — safe to re-run after changing allowed emails or the hostname.
The app service itself auto-starts on boot; only the one-time Cloudflare
provisioning needs this script.
- Legacy standalone mode (`VCC_AUTH=local`): username/password accounts with
  optional TOTP/WebAuthn 2FA, invite codes, and self-served TLS — still in
  the codebase for deployments without Cloudflare.

## Per-user restrictions (admin panel)

- **Model pin**: sessions launch with `--model X`. For sandboxed users this is
  hard-enforced inside the container via a managed-settings.json mount
  (`model` + `availableModels` + `enforceAvailableModels`) — `/model` cannot
  escape it. For non-sandboxed users it's launch-time only (they have host
  shell access anyway).
- **args**: whether the "claude args" field on session create is honored
  (admins always may).
- **sandbox**: the user's sessions run inside the `visualclaude-sandbox`
  docker image (built from `sandbox/Dockerfile`) with 2G RAM / 2 CPUs / 512
  pids. They see only `/srv/visualclaude/<user>/work` (mounted at `/work`),
  their own Claude config volume, and OAuth credentials seeded from the host
  account at session start. No host filesystem, no systemd, no docker socket.
  tmux still lives on the host, so sessions survive service restarts
  (`KillMode=process`).
- TLS is terminated by Cloudflare; the app listens on 127.0.0.1:7788 plain
  HTTP and is reachable only through the tunnel. A self-signed cert in
  `certs/` plus `VC_TLS=1` / `VC_HOST=<addr>` in `.env` is a legacy
  standalone-HTTPS fallback for non-Cloudflare deployments.

## Usage

- **New session**: pick a name, optionally a working directory (default `~`) and
  extra `claude` args (e.g. `--continue` to resume the last conversation in
  that directory).
- Green dot = someone is attached. Closing the tab only detaches — the session
  keeps running. `✕` kills the tmux session (the conversation itself remains
  resumable with `claude --continue` in that directory).
- If `claude` exits inside a session you get a plain bash shell in the same
  tmux session, so you can restart it.
- Quick-key bar at the bottom (Esc, Shift-Tab, ^C, arrows, Paste) — mainly for
  phones/tablets.
- Sessions are normal tmux sessions: `tmux attach -t vc-<name>` from SSH works
  too, and both views stay in sync.

## Reboot persistence

tmux sessions die with the host, so the server snapshots the list of live
sessions (`resurrect.json`) on a schedule and on every create/kill/shutdown.
On startup, any session from the last snapshot that no longer exists is
recreated with its original launch command plus `--continue`, so the Claude
Code conversation resumes where it left off (Claude Code keeps transcripts on
disk per directory). Sandboxed sessions are restored the same way, including
their docker wrapper. A brief "✓ sessions saved" appears in the menu bar each
time a snapshot lands.

The interval is set in the admin panel (**Session persistence**, default 5
min, 0 = off) and stored in `settings.json`. Terminal scrollback is not
restored — only the session, its directory, and its conversation.

## Service

Runs as systemd unit `visualclaude.service` (enabled at boot):

```
systemctl status visualclaude
journalctl -u visualclaude -f
```

Server: `server.py` (aiohttp, venv in `.venv/`). Frontend: `public/index.html`
with vendored xterm.js in `public/vendor/`. Host/port overridable via
`VC_HOST` / `VC_PORT` env vars in the unit file.

## Security notes

- The app binds 127.0.0.1 only; the sole way in is the Cloudflare Tunnel,
  which is outbound-only — there is no public inbound port on the host.
  Cloudflare Access (Zero Trust) gates every request at the edge, and the app
  re-validates the Access JWT itself.
- In cloudflare mode identity comes from Access; the app's own accounts
  auto-provision keyed to the verified email. In legacy `local` mode: scrypt
  password hashes, HMAC-signed cookies (HttpOnly + Secure), constant-time
  comparisons, optional TOTP/WebAuthn 2FA. `users.json` and `.secret` are 0600
  and gitignored.
- A session gives shell access as the host user (Claude sessions drop to bash
  on exit) unless the user is sandboxed — so admin (`VCC_ADMIN_EMAILS`) and
  the Access allow-list are the security boundary; guard both.

## Security review (2026-08-10)

Findings from a read of `server.py`, `scripts/deploy.py`, `public/index.html`
and the sandbox image against the deployed configuration. Cloudflare Access
gates everything, so none of these are reachable pre-auth — they are
post-authentication or host-local. **None are fixed yet**; this is the
hardening backlog, not a description of the current defences.

### Fix first

- **`.env` backups are not gitignored.** `.gitignore` covers `.env` but not
  `.env.bak*`, so a stray backup holding `CLOUDFLARE_API_TOKEN` gets picked up
  by `git add -A`. Ignore `.env*` (with `!.env.example`) and delete any
  backup. Nothing secret is in the history today.
- **No `Origin` check on the WebSocket, and no CSRF defence** (`ws_terminal`).
  `/ws/<name>` accepts an upgrade from any origin and authorises purely on the
  `CF_Authorization` cookie; WebSockets are not covered by CORS, so a page the
  signed-in user visits can attach to a live session and both read and write
  the terminal. The only thing in the way is the cookie's SameSite attribute,
  and `scripts/deploy.py` sets `http_only_cookie_attribute` but never
  `same_site_cookie_attribute` — so it rests on each browser's Lax-by-default.
  `POST /api/sessions` is reachable the same way (a `text/plain` body skips
  the preflight). Reject requests whose `Origin` is not
  `https://$VCC_HOSTNAME`, and set `same_site_cookie_attribute: "strict"` when
  provisioning the Access app.
- **Sandboxed users get the host's Anthropic OAuth credentials.**
  `sandbox_setup` copies `~/.claude/.credentials.json` into every user's
  config volume, mounted at `/root/.claude` in a container that drops to a
  root shell and has unrestricted egress, so a sandboxed user can read and
  exfiltrate the account's access + refresh token. The sandbox protects the
  host filesystem, **not** the Claude account — until per-user credentials
  exist, a sandboxed user is someone you trust with the account.
- **Auto-provisioned users default to non-sandboxed, i.e. root on the host.**
  `ensure_cf_user` writes no `sandbox` key, so `user_prefs` yields `False`:
  the moment an email is added to the Access policy that person gets a root
  shell and can read `.env`, `.secret`, `users.json`, `~/.ssh` and every repo
  on the box. Default new records to `sandbox: true` and let an admin turn it
  off deliberately.
- **`CLOUDFLARE_API_TOKEN` reaches every session's environment.**
  `_load_env()` pushes all of `.env` into `os.environ` and the tmux server
  inherits it, so `tmux show-environment -g` returns the token and every
  `claude` process on the host can read it from `/proc/self/environ` — a
  prompt-injected session included. It does not cross into docker sandboxes.
  `server.py` never uses the variable (it is deploy-only), so popping it right
  after `_load_env()` costs nothing.

### Minor

- Sandbox sessions are created without `-c`, so tmux reports the server's own
  working directory and `/api/sessions` hands the install path to a user who
  should only ever know `/work`. Return the stored `container_cwd` instead.
- Raw `OSError`, `tmux` and `docker` stderr and WebAuthn exception text are
  returned to the client, carrying host paths. Only reachable by users who
  already have host access, but generic text plus a server-side log is the
  better default.
- `sessions.json`, `settings.json` and `resurrect.json` are `0644` while
  `.env`, `.secret` and `users.json` are correctly `0600`. `sessions.json`
  holds usernames, host paths and full restore commands.
- `GET /api/persist` is the one route missing its `require_admin` — any
  authenticated user learns the snapshot interval and last-save time.
- Sandbox containers use default bridge networking, so they can reach the
  docker gateway, the host's Tailscale address (and thus its `sshd`) and the
  open internet. The app itself is loopback-only, as is `cloudflared`.

### Verified sound

Recorded so a later change does not quietly undo them: the Access JWT check
pins RS256 and requires `exp`/`iat`/`aud`/`iss`, with no cookie fallback in
cloudflare mode; `email_slug` binds the readable prefix to a SHA-256 of the
exact address and `ensure_cf_user` refuses on mismatch; banning `--` in names
keeps session-ownership parsing unambiguous, so no user can address another's
sessions; `safe_join`, `rmtree_confined` and the `O_NOFOLLOW|O_EXCL`
credential write defeat symlinks planted from inside the sandbox; the frontend
uses `textContent` for every server-supplied string; static serving is limited
to `/vendor/`; and no secret has ever been committed.

## License

MIT — see [LICENSE](LICENSE). Vendored frontend libraries (xterm.js,
qrcodejs) are MIT-licensed by their respective authors.
