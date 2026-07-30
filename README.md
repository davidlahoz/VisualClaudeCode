# VisualClaude

Web client for running Claude Code on this machine. Every session is a tmux
session (named `vc-<name>`) running `claude`, so conversations stay alive when
you close the browser; the web UI is just a live view (PTY → WebSocket →
xterm.js) that attaches/detaches.

## Access

- URL: **https://host.example.ts.net** (tailnet only)
- **No login needed from the tailnet**: `tailscale serve` injects the verified
  `Tailscale-User-Login` identity header (and strips spoofed ones), so you land
  straight in the app, identified by your tailnet account. Each user gets their
  own session list — tmux sessions are namespaced `vc-<user>--<name>` and one
  user cannot see or touch another's.
- Token fallback: `/root/VisualClaude/.secret` still works via the login page
  or a `vc_token` cookie (used for scripts / direct localhost access); it maps
  to the user in `VC_DEFAULT_USER` (systemd unit).
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
- Token auth on every route (constant-time compare, HttpOnly + Secure cookie).
- Anyone with the token effectively has shell access as root (Claude sessions
  drop to bash on exit) — treat the token like an SSH key.
