#!/bin/bash
# Refuse to start until the HOST tmux server's socket is present.
#
# tmux clients silently autostart a server when the socket is missing. In this
# container that would put the tmux server -- and therefore every session
# process -- inside the container, where the host's claude binary and the
# user's working directories do not exist. Failing loudly here is far better:
# restart: unless-stopped will retry, and tmux-server.service arrives shortly
# after docker.service on boot.
set -euo pipefail

SOCKET=/tmp/tmux-0/default
DEADLINE=$((SECONDS + 60))

# Probe LIVENESS, not mere existence. A tmux server that dies leaves its socket
# file behind, and a bare `[ -S "$SOCKET" ]` happily accepts that corpse -- then
# the first client autostarts a replacement server inside the container, which
# is precisely the outcome this guard exists to prevent. `show-options -g` is
# the right probe: it round-trips to the server, it succeeds against a server
# with zero sessions (unlike has-session), and it is not a server-starting
# command, so it can never create the thing it is checking for.
server_alive() {
    [ -S "$SOCKET" ] && tmux -S "$SOCKET" show-options -g exit-empty >/dev/null 2>&1
}

while ! server_alive; do
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        if [ -S "$SOCKET" ]; then
            echo "FATAL: socket $SOCKET exists but no tmux server answers on it (stale)." >&2
        else
            echo "FATAL: host tmux socket $SOCKET absent after 60s." >&2
        fi
        echo "Is tmux-server.service running on the host? (systemctl status tmux-server)" >&2
        exit 1
    fi
    echo "waiting for a live host tmux server on $SOCKET ..." >&2
    sleep 2
done

echo "host tmux socket present; starting VisualClaude" >&2
exec "$@"
