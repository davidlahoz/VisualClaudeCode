#!/usr/bin/env python3
"""One-command Cloudflare deployment for VisualClaudeCode.

Reads configuration from ../.env and provisions everything needed to serve
the app at VCC_HOSTNAME behind Cloudflare Access: the named tunnel, its DNS
record, ingress, the Access application + allow policy, and a Zero Trust
identity provider if none exists. Idempotent — safe to re-run. On success it
writes the discovered VCC_ACCESS_TEAM_DOMAIN / VCC_ACCESS_AUD back into .env,
installs the cloudflared service, and flips VCC_AUTH to cloudflare.

Requires in .env:
  CLOUDFLARE_API_TOKEN   scoped token (see docs/cloudflare.md)
  VCC_ZONE               apex domain, e.g. example.com
  VCC_HOSTNAME           public hostname, e.g. vcc.example.com
  VCC_TUNNEL_NAME        tunnel name, e.g. vcc
  VCC_ADMIN_EMAILS       comma list; also the default Access allow-list
Optional:
  VCC_ALLOWED_EMAILS     Access allow-list (defaults to VCC_ADMIN_EMAILS)
  VC_PORT                local app port (default 7788)
"""
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
ENV = BASE / ".env"

# The provisioning token may be IP-pinned to this host's IPv4; some hosts
# default to IPv6 egress which the pin rejects. Force IPv4 for the API.
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda *a, **k: [ai for ai in _gai(*a, **k)
                                      if ai[0] == socket.AF_INET]

API = "https://api.cloudflare.com/client/v4"


def load_env() -> dict:
    env = {}
    for line in ENV.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def write_env(updates: dict):
    lines = ENV.read_text().splitlines()
    keys = set(updates)
    out = []
    for line in lines:
        k = line.split("=", 1)[0].strip() if "=" in line else None
        if k in keys:
            out.append(f"{k}={updates.pop(k)}")
        else:
            out.append(line)
    for k, v in updates.items():
        out.append(f"{k}={v}")
    ENV.write_text("\n".join(out) + "\n")
    ENV.chmod(0o600)


def main():
    env = load_env()
    token = env.get("CLOUDFLARE_API_TOKEN")
    if not token:
        sys.exit("CLOUDFLARE_API_TOKEN missing from .env")
    zone_name = env.get("VCC_ZONE") or sys.exit("VCC_ZONE missing from .env")
    hostname = env.get("VCC_HOSTNAME") or sys.exit("VCC_HOSTNAME missing from .env")
    tunnel_name = env.get("VCC_TUNNEL_NAME", "vcc")
    port = env.get("VC_PORT", "7788")
    allowed = [e.strip() for e in
               (env.get("VCC_ALLOWED_EMAILS")
                or env.get("VCC_ADMIN_EMAILS", "")).split(",") if e.strip()]
    if not allowed:
        sys.exit("VCC_ADMIN_EMAILS (or VCC_ALLOWED_EMAILS) must list at least "
                 "one email — it becomes the Access allow-list and the admin.")

    def cf(method, path, body=None):
        req = urllib.request.Request(
            API + path, method=method,
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req) as r:
                out = json.load(r)
        except urllib.error.HTTPError as e:
            out = json.load(e)
        if not out.get("success"):
            sys.exit(f"Cloudflare API error {method} {path}: {out.get('errors')}")
        return out["result"]

    cf("GET", "/user/tokens/verify")
    print("✓ API token valid")

    zones = cf("GET", f"/zones?name={zone_name}")
    if not zones:
        sys.exit(f"zone {zone_name} not visible to this token")
    zid, acc = zones[0]["id"], zones[0]["account"]["id"]
    subdomain = hostname.split("." + zone_name)[0]

    org = cf("GET", f"/accounts/{acc}/access/organizations")
    if not org or not org.get("auth_domain"):
        sys.exit("No Zero Trust organization; create one in the dashboard "
                 "(Zero Trust → Settings) then re-run.")
    team = org["auth_domain"]
    print(f"✓ team domain {team}")

    if not cf("GET", f"/accounts/{acc}/access/identity_providers"):
        cf("POST", f"/accounts/{acc}/access/identity_providers",
           {"name": "One-time PIN", "type": "onetimepin", "config": {}})
        print("✓ created One-time PIN login method")

    tuns = cf("GET",
              f"/accounts/{acc}/cfd_tunnel?name={tunnel_name}&is_deleted=false")
    tun = tuns[0] if tuns else cf(
        "POST", f"/accounts/{acc}/cfd_tunnel",
        {"name": tunnel_name, "config_src": "cloudflare"})
    tid = tun["id"]
    ttoken = cf("GET", f"/accounts/{acc}/cfd_tunnel/{tid}/token")
    cf("PUT", f"/accounts/{acc}/cfd_tunnel/{tid}/configurations",
       {"config": {"ingress": [
           {"hostname": hostname, "service": f"http://127.0.0.1:{port}"},
           {"service": "http_status:404"}]}})
    print(f"✓ tunnel {tunnel_name} ({tid}) configured")

    recs = cf("GET", f"/zones/{zid}/dns_records?name={hostname}")
    dns = {"type": "CNAME", "name": subdomain,
           "content": f"{tid}.cfargotunnel.com", "proxied": True}
    if recs:
        cf("PUT", f"/zones/{zid}/dns_records/{recs[0]['id']}", dns)
    else:
        cf("POST", f"/zones/{zid}/dns_records", dns)
    print(f"✓ DNS {hostname} → tunnel")

    apps = cf("GET", f"/accounts/{acc}/access/apps")
    app = next((a for a in apps if a.get("domain") == hostname), None)
    app_body = {"name": "VisualClaudeCode", "type": "self_hosted",
                "domain": hostname, "session_duration": "24h",
                "http_only_cookie_attribute": True,
                "auto_redirect_to_identity": True}
    app = (cf("PUT", f"/accounts/{acc}/access/apps/{app['id']}", app_body)
           if app else
           cf("POST", f"/accounts/{acc}/access/apps", app_body))
    pols = cf("GET", f"/accounts/{acc}/access/apps/{app['id']}/policies")
    pol = {"name": "allowed users", "decision": "allow", "precedence": 1,
           "include": [{"email": {"email": e}} for e in allowed]}
    if pols:
        cf("PUT", f"/accounts/{acc}/access/apps/{app['id']}/policies/"
           f"{pols[0]['id']}", pol)
    else:
        cf("POST", f"/accounts/{acc}/access/apps/{app['id']}/policies", pol)
    print(f"✓ Access app + allow policy ({', '.join(allowed)})")

    # hardening (best-effort; needs Zone Settings perms)
    for k, v in (("min_tls_version", "1.2"), ("always_use_https", "on")):
        try:
            cf("PATCH", f"/zones/{zid}/settings/{k}", {"value": v})
        except SystemExit:
            print(f"  (skipped zone setting {k}: token lacks Zone Settings)")

    write_env({"VCC_AUTH": "cloudflare",
               "VCC_ACCESS_TEAM_DOMAIN": team,
               "VCC_ACCESS_AUD": app["aud"]})
    print("✓ wrote VCC_ACCESS_* into .env, VCC_AUTH=cloudflare")

    if Path("/etc/systemd/system/cloudflared.service").exists():
        subprocess.run(["systemctl", "restart", "cloudflared"], check=False)
        print("✓ cloudflared already installed — restarted")
    else:
        subprocess.run(["cloudflared", "service", "install", ttoken],
                       check=False)
        subprocess.run(["systemctl", "enable", "--now", "cloudflared"],
                       check=False)
        print("✓ cloudflared service installed")
    subprocess.run(["systemctl", "restart", "visualclaude"], check=False)
    print(f"\n✓ Deployed. Open https://{hostname}")


if __name__ == "__main__":
    main()
