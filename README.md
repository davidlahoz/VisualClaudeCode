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

## License

MIT — see [LICENSE](LICENSE). Vendored frontend libraries (xterm.js,
qrcodejs) are MIT-licensed by their respective authors.
