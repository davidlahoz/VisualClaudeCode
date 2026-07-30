# VisualClaudeCode

Web client for running Claude Code on this machine. Every session is a tmux
session (named `vc-<name>`) running `claude`, so conversations stay alive when
you close the browser; the web UI is just a live view (PTY → WebSocket →
xterm.js) that attaches/detaches.

## Access

- URL: **https://host.example.ts.net** (tailnet only — Tailscale is
  purely the network layer, it knows nothing about app users)
- **App accounts**: sign in with username + password (scrypt-hashed in
  `users.json`); the signed session cookie keeps you logged in for 90 days.
  The very first account is bootstrapped by registering with the master token
  from `/root/VisualClaudeCode/.secret` and becomes **admin**; after that the
  master token no longer registers accounts.
- **Admin panel** (button in the header for admins): list/create/delete users
  and mint one-time invite codes that let someone register themselves.
  Deleting a user also kills all their tmux sessions. Codes are single-use and
  revocable; consumed only on successful registration.
- Each user only sees their own sessions — tmux sessions are namespaced
  `vc-<user>--<name>` and one user cannot list, attach, or kill another's.
- **2FA** (optional, per user, via the "security" button): authenticator-app
  TOTP codes (QR enrollment) and/or WebAuthn hardware keys / passkeys. With
  any factor enrolled, login becomes password → second step (code or key).
  Admins can strip a locked-out user's factors with "reset 2FA", and can
  check "2FA" on a user to make enrollment mandatory: until that user adds a
  factor, the API serves them nothing but the security endpoints and the UI
  pins them in the enrollment panel.

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
- TLS is terminated by `tailscale serve` with a real Let's Encrypt certificate
  for the tailnet name — browsers show it as fully secure, and Tailscale
  auto-renews it. The app itself listens on 127.0.0.1:7788 plain HTTP only.
- Fallback: a self-signed cert lives in `certs/`; setting `VC_TLS=1` and
  `VC_HOST=127.0.0.1` in the systemd unit serves HTTPS directly again.

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

- The app binds 127.0.0.1 only; the sole way in is `tailscale serve` (tailnet
  only — this is NOT Funnel, nothing is public). `tailscale serve status` to
  inspect, `tailscale serve --https=443 off` to tear down.
- Auth: scrypt password hashes, HMAC-signed session cookies (HttpOnly +
  Secure), constant-time comparisons, 0.4s delay on failed login/register.
  The invite token gates account creation. `users.json` and `.secret` are 0600
  and gitignored. To reset a password, delete the user's entry from
  `users.json` and re-register.
- Anyone with the token effectively has shell access as root (Claude sessions
  drop to bash on exit) — treat the token like an SSH key.

## License

MIT — see [LICENSE](LICENSE). Vendored frontend libraries (xterm.js,
qrcodejs) are MIT-licensed by their respective authors.
