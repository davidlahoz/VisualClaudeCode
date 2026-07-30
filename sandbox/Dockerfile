FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git ripgrep procps less nano bash \
    && rm -rf /var/lib/apt/lists/*

# Claude Code native binary
RUN curl -fsSL https://claude.ai/install.sh | bash \
    && ln -s /root/.local/bin/claude /usr/local/bin/claude

ENV TERM=xterm-256color LANG=C.UTF-8
WORKDIR /work
CMD ["bash"]
