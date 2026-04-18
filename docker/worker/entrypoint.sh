#!/usr/bin/env bash
# Worker entrypoint — see docker/orchestrator/entrypoint.sh for the full
# rationale. Same shape with worker-specific UID 10002.
set -euo pipefail

APP_UID=${APP_UID:-10002}
APP_GID=${APP_GID:-10002}
ARTIFACTS_DIR=${ARTIFACTS_DIR:-/opt/aetherforge/data/artifacts}
DOCKER_SOCK=${DOCKER_SOCK:-/var/run/docker.sock}

if [ "$(id -u)" -eq 0 ]; then
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
      usermod -aG 0 aetherforge 2>/dev/null || true
    fi
  fi

  mkdir -p "${ARTIFACTS_DIR}"
  chown -R "${APP_UID}:${APP_GID}" "${ARTIFACTS_DIR}" 2>/dev/null || true

  if command -v gosu >/dev/null 2>&1; then
    exec gosu aetherforge "$@"
  else
    exec su -s /bin/sh -c "$(printf '%q ' "$@")" aetherforge
  fi
fi

exec "$@"
