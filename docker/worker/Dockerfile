# syntax=docker/dockerfile:1.7
# =============================================================================
# Worker image — Temporal worker + RQ consumer
# Separate image from orchestrator so it doesn't pull in weasyprint/fonts.
# =============================================================================
ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      libffi-dev \
      libssl-dev \
      libpq-dev \
      libxml2-dev \
      libxslt1-dev \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /build
COPY pyproject.toml requirements.txt ./
RUN pip install --upgrade pip wheel setuptools \
 && pip install -r requirements.txt


FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

# MUST match the orchestrator's UID/GID — both containers share the
# `artifacts` named volume and write per-execution sub-directories. A
# UID mismatch makes the worker's mkdir() return EACCES on a dir the
# orchestrator created (or vice-versa). 10001 is the orchestrator's
# baseline.
ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aetherforge \
    AETHERFORGE_HOME=/opt/aetherforge \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      tini \
      libpq5 \
      libxml2 \
      libxslt1.1 \
      docker.io \
      gosu \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get clean

RUN groupadd --system --gid ${APP_GID} aetherforge \
 && useradd  --system --uid ${APP_UID} --gid ${APP_GID} \
             --home-dir ${AETHERFORGE_HOME} --shell /bin/bash aetherforge \
 && usermod -aG docker aetherforge

COPY --from=builder /opt/venv /opt/venv

WORKDIR ${AETHERFORGE_HOME}
RUN mkdir -p app rules configs data/artifacts data/logs \
 && chown -R aetherforge:aetherforge ${AETHERFORGE_HOME}

COPY --chown=aetherforge:aetherforge app     ./app
COPY --chown=aetherforge:aetherforge rules   ./rules
COPY --chown=aetherforge:aetherforge configs ./configs
COPY --chown=aetherforge:aetherforge scripts ./scripts

# Pre-create + chown artefact dir so named-volume first-mount inherits.
RUN mkdir -p ${AETHERFORGE_HOME}/data/artifacts \
 && chown -R aetherforge:aetherforge ${AETHERFORGE_HOME}/data

COPY docker/worker/entrypoint.sh /usr/local/bin/aetherforge-entrypoint
RUN chmod +x /usr/local/bin/aetherforge-entrypoint

# Container starts as ROOT only long enough for the entrypoint to align
# the docker-socket GID + chown artefacts; ``gosu aetherforge`` then drops privs.
USER root

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
  CMD su -s /bin/sh -c 'python -m scripts.healthcheck --role worker' aetherforge || exit 1

ENTRYPOINT ["tini", "--", "/usr/local/bin/aetherforge-entrypoint"]
CMD ["python", "-m", "app.workflows.worker"]
