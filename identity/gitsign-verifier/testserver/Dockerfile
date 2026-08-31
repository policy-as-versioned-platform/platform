# Serves THIS repo's own real gitsign-signed tags over smart HTTP, so
# verify-source-verification.sh's live tail (section 10) makes gitsign-verifier
# fetch and verify a real signature, not a stand-in. Same minimal pattern as
# driftwood/tuppence/ludlow's git-server (git-http-backend via lighttpd on
# Debian; Alpine does not ship git-http-backend). deploy.sh prepares
# platform.git as a bare clone of this checkout, offline, before the build.
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git lighttpd ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY platform.git /srv/git/platform.git
COPY lighttpd.conf /etc/lighttpd/lighttpd.conf
RUN useradd -u 10001 git && git config --system --add safe.directory '*'
USER 10001
EXPOSE 8080
ENTRYPOINT ["lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
