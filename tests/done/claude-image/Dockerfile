# The Claude Code worker seat's image (route A): the pinned CLI plus the tracer the launcher
# needs inside the container (strace 6.6 or later, setpriv, /bin/sh) and python for the tasks.
FROM node:22-trixie-slim@sha256:154ba2f4d6fec323d28e4f4bb86bba4677f1223391a1979cf521304e03a98dfa
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 python-is-python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code@2.1.302 \
    && npm cache clean --force
