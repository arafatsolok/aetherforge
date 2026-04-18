#!/usr/bin/env bash
# =============================================================================
# Orchestrator entrypoint
#
# Runs as root only long enough to:
#   1. Match the host docker socket's GID so `aetherforge` can use it
#      without exposing the socket to non-aetherforge users.
#   2. Chown the bind-mounted artefact dir to uid 10001 (named volume
#      created root-owned by Docker on first boot).
# Then drops privileges via `gosu` and execs the real CMD.
#
# Replaces the temporary docker-compose.override.yml that was running
# the orchestrator as root in Phases 5-7.
# =============================================================================
set -euo pipefail

APP_UID=${APP_UID:-10001}
APP_GID=${APP_GID:-10001}
ARTIFACTS_DIR=${ARTIFACTS_DIR:-/opt/aetherforge/data/artifacts}
DOCKER_SOCK=${DOCKER_SOCK:-/var/run/docker.sock}

if [ "$(id -u)" -eq 0 ]; then
  # 1. Align aetherforge's docker group with the host socket's GID.
  if [ -S "${DOCKER_SOCK}" ]; then
    SOCK_GID="$(stat -c '%g' "${DOCKER_SOCK}")"
    if [ "${SOCK_GID}" != "0" ]; then
      if ! getent group docker_host >/dev/null 2>&1; then
        groupadd -g "${SOCK_GID}" docker_host 2>/dev/null \
          || groupmod -g "${SOCK_GID}" docker 2>/dev/null \
          || true
      fi
      usermod -aG "${SOCK_GID}" aetherforge 2>/dev/null || true
    else
      # Socket is root:root → only root can use it. Add aetherforge to
      # root group as a last resort. Operators should chown the socket.
      usermod -aG 0 aetherforge 2>/dev/null || true
    fi
  fi

  # 2. Make sure the bind-mounted artefact dir is writable.
  mkdir -p "${ARTIFACTS_DIR}"
  chown -R "${APP_UID}:${APP_GID}" "${ARTIFACTS_DIR}" 2>/dev/null || true

  # 3. Drop privileges. ``gosu`` preserves env + signals.
  if command -v gosu >/dev/null 2>&1; then
    exec gosu aetherforge "$@"
  else
    # Fallback if gosu isn't installed; su -s /bin/sh keeps signals usable.
    exec su -s /bin/sh -c "$(printf '%q ' "$@")" aetherforge
  fi
fi

# Already non-root (e.g. user= in compose set explicitly) — just exec.
exec "$@"
