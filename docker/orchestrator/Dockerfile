# syntax=docker/dockerfile:1.7
# =============================================================================
# Orchestrator image — FastAPI + HTMX dashboard
# =============================================================================
ARG PYTHON_VERSION=3.12

# -----------------------------------------------------------------------------
# Stage 1 — builder: install all Python deps into a venv
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Build deps for WeasyPrint (Cairo/Pango), lxml, asyncpg, cryptography.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      curl \
      git \
      libffi-dev \
      libssl-dev \
      libxml2-dev \
      libxslt1-dev \
      libpq-dev \
      libcairo2 \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libgdk-pixbuf-2.0-0 \
      libjpeg-dev \
      zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Create an isolated venv we can copy to the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /build
COPY pyproject.toml requirements.txt ./
RUN pip install --upgrade pip wheel setuptools \
 && pip install -r requirements.txt


# -----------------------------------------------------------------------------
# Stage 2 — runtime: minimal image with only what is needed at run time
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/opt/aetherforge \
    AETHERFORGE_HOME=/opt/aetherforge \
    PATH="/opt/venv/bin:${PATH}"

# Runtime libs for WeasyPrint + Postgres + lxml. Plus the `docker` CLI so
# the orchestrator can fall back to shell-out invocations if ever needed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
      tini \
      libpq5 \
      libxml2 \
      libxslt1.1 \
      libcairo2 \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libgdk-pixbuf-2.0-0 \
      libjpeg62-turbo \
      libffi8 \
      fonts-dejavu-core \
      docker.io \
      gosu \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get clean

# Non-root user
RUN groupadd --system --gid ${APP_GID} aetherforge \
 && useradd  --system --uid ${APP_UID} --gid ${APP_GID} \
             --home-dir ${AETHERFORGE_HOME} --shell /bin/bash aetherforge \
 # Add to docker group so the orchestrator can use docker.sock (bind-mounted).
 # The docker group ID is set at runtime via entrypoint; keep default for now.
 && usermod -aG docker aetherforge

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv

# App layout
WORKDIR ${AETHERFORGE_HOME}
RUN mkdir -p app templates static rules configs migrations data/artifacts data/reports data/logs \
 && chown -R aetherforge:aetherforge ${AETHERFORGE_HOME}

COPY --chown=aetherforge:aetherforge app        ./app
COPY --chown=aetherforge:aetherforge templates  ./templates
COPY --chown=aetherforge:aetherforge static     ./static
COPY --chown=aetherforge:aetherforge rules      ./rules
COPY --chown=aetherforge:aetherforge configs    ./configs
COPY --chown=aetherforge:aetherforge migrations ./migrations
COPY --chown=aetherforge:aetherforge scripts    ./scripts

# Pre-create + chown the artefact dir so the named volume's first-mount
# permission inherits correctly. Entrypoint also chowns at boot for the
# bind-mount + UID-changed cases.
RUN mkdir -p ${AETHERFORGE_HOME}/data/artifacts \
 && chown -R aetherforge:aetherforge ${AETHERFORGE_HOME}/data

# Hardening entrypoint (root-aligns docker GID + chowns artefacts + drops privs).
COPY docker/orchestrator/entrypoint.sh /usr/local/bin/aetherforge-entrypoint
RUN chmod +x /usr/local/bin/aetherforge-entrypoint

# IMPORTANT: container starts as ROOT only long enough for the entrypoint
# to align GIDs + chown artefacts; ``gosu aetherforge`` then drops privs.
USER root

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=5 \
  CMD curl --fail --silent --show-error http://127.0.0.1:8000/health || exit 1

ENTRYPOINT ["tini", "--", "/usr/local/bin/aetherforge-entrypoint"]

# Use gunicorn+uvicorn for prod, uvicorn reload for dev (controlled by env).
CMD ["sh", "-c", "\
  if [ \"${API_RELOAD:-false}\" = \"true\" ]; then \
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload; \
  else \
    exec gunicorn app.main:app \
      --workers ${API_WORKERS:-2} \
      --worker-class uvicorn.workers.UvicornWorker \
      --bind 0.0.0.0:8000 \
      --access-logfile - \
      --error-logfile - \
      --timeout 120 \
      --graceful-timeout 30; \
  fi"]
