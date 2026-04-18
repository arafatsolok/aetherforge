# =============================================================================
# Tool container — Metasploit Framework (msfrpcd)
# Long-running daemon: exposes RPC on :55553 consumed by pymetasploit3.
# This container is profile-gated and does NOT run ephemerally.
# =============================================================================
FROM metasploitframework/metasploit-framework:latest

ARG APP_UID=10103
ARG APP_GID=10103

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tini \
      ca-certificates \
      curl \
      netcat-openbsd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid ${APP_GID} msfrpc \
 && useradd  --system --uid ${APP_UID} --gid ${APP_GID} \
             --home-dir /home/msfrpc --create-home --shell /bin/bash msfrpc

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && chown -R msfrpc:msfrpc /home/msfrpc

# msfrpcd needs root to load some modules reliably but the outer bootstrap
# script will drop capabilities inside the container for network isolation.
USER root

EXPOSE 55553

HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=5 \
  CMD nc -z 127.0.0.1 55553 || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["/usr/local/bin/entrypoint.sh"]
