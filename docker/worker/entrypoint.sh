#!/usr/bin/env bash
# Worker entrypoint — see docker/orchestrator/entrypoint.sh for the full
# rationale. UID/GID derived from the in-container `aetherforge` user so
# the chown stays correct even if the Dockerfile bumps the baseline
# (we previously had a 10001-vs-10002 mismatch with the orchestrator,
# which made the worker EACCES on the shared artefacts volume).
set -euo pipefail

APP_UID=${APP_UID:-$(id -u aetherforge 2>/dev/null || echo 10001)}
APP_GID=${APP_GID:-$(id -g aetherforge 2>/dev/null || echo 10001)}
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
