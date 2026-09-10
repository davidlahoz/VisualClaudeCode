# ubuntu:24.04 is deliberate, not incidental: it is the host's own release.
# The tmux client in here attaches to the HOST tmux server over a mounted
# socket, and tmux refuses to talk across protocol versions -- so this must
# stay pinned to whatever `tmux -V` reports on the host (3.4). It also gives
# Python 3.12.3, matching the venv this image replaces.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# docker-ce-cli comes from Docker's own repo; Ubuntu's docker.io package would
# drag in a daemon we must never run (the host daemon is the only one, reached
# through the mounted socket).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv tmux ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get purge -y curl gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# PEP 668 marks the system Python externally-managed, so the dependencies that
# used to live in ./.venv on the host go here instead.
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# server.py resolves every state file from Path(__file__).parent, and reads
# ~/.claude/.credentials.json from HOME. The application code itself is
# bind-mounted at this same path at run time (see compose.yaml) rather than
# COPYed, so state written at runtime persists on the host.
# PATH here is the HOST's PATH, deliberately. `tmux new-session` copies the
# CLIENT's environment into the new session, and the session's processes are
# forked by the host tmux server -- so this PATH is resolved against the host
# filesystem, and it is what decides whether `claude` (/root/.local/bin/claude)
# is findable. The container's own venv is therefore invoked by absolute path in
# CMD rather than being put on PATH, so that nothing container-specific leaks
# into the sessions users get.
ENV PATH=/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

ENV HOME=/root
WORKDIR /opt/razorlabs.dev/VisualClaudeCode

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/opt/venv/bin/python", "server.py"]
