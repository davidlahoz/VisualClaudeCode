# Cloudflare setup

VisualClaudeCode is published through a **Cloudflare Tunnel** (outbound-only —
the server has no open inbound port) and gated by **Cloudflare Access (Zero
Trust)**. User identity comes from the Access JWT, which the app verifies
itself (signature against the team JWKS, audience, issuer, expiry) on every
request — the tunnel being fronted by Access is not blindly trusted.

## Components

- Tunnel `vcc` (remotely managed) → ingress `vcc.example.com` →
  `http://127.0.0.1:7788`; runs as the `cloudflared` systemd service.
- DNS: proxied CNAME `vcc` → `<tunnel-id>.cfargotunnel.com`.
- Access application `VisualClaudeCode` on `vcc.example.com` with an allow
  policy for specific emails; 24h session; HttpOnly cookie.
- App `.env`: `VCC_AUTH=cloudflare`, `VCC_ACCESS_TEAM_DOMAIN`,
  `VCC_ACCESS_AUD`, `VCC_ADMIN_EMAILS`.

## API token

`CLOUDFLARE_API_TOKEN` in `.env` is used **only** for provisioning and
management tasks (nothing in the running app calls the Cloudflare API). It can
therefore be scoped tightly. Everything this project ever does needs at most:

| Scope | Permission | Level | Used for |
|---|---|---|---|
| Account | Cloudflare Tunnel | Edit | create/configure the tunnel, fetch its run token |
| Account | Access: Apps and Policies | Edit | Access app + allow policy (add/remove users) |
| Account | Access: Organizations, Identity Providers, and Groups | Edit | team domain + login method — **one-time**, drop after setup |
| Zone (example.com) | DNS | Edit | the `vcc` CNAME |
| Zone (example.com) | Zone Settings | Edit | min TLS version, Always Use HTTPS — **one-time** |
| Zone (example.com) | Zone WAF | Edit | rate-limiting/WAF rules — **one-time** |

Recommended steady-state token (day-to-day user management only):
**Access: Apps and Policies (Edit)** + **Cloudflare Tunnel (Read)**. Everything
else can be re-granted temporarily when infrastructure changes.

Additional token hardening (set when creating/editing the token):

- **Client IP Address Filtering**: allow only this server's egress IP.
- **TTL**: give the token an expiry and rotate.
- Never commit it; `.env` is gitignored and chmod 600.

## Managing users

Who can reach the app = the Access policy (Zero Trust dashboard → Access →
Applications → VisualClaudeCode, or via API). The app auto-provisions its
per-user record (model pin, sandbox, session limits) on first visit, keyed by
the Access identity. Admins are the emails in `VCC_ADMIN_EMAILS`.

## Edge hardening applied

- Access allow-list policy (default-deny for everyone else).
- Rate limiting rule on `vcc.example.com` at the edge.
- Minimum TLS 1.2 and Always Use HTTPS on the zone.
- Origin bound to loopback; TLS terminated by Cloudflare; tunnel is
  outbound-only.
