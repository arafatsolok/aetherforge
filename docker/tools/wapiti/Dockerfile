# =============================================================================
# Tool container — Wapiti
# =============================================================================
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# wapiti3 imports `pkg_resources`, which:
#   * python:3.12-slim does NOT ship by default,
#   * setuptools >= 80 REMOVED (deprecation completed, upstream dropped
#     the module in favour of `importlib.metadata`).
# Pin setuptools to a version that still provides pkg_resources. Without
# this every wapiti invocation dies with
#   ModuleNotFoundError: No module named 'pkg_resources'
# which is silent from the orchestrator's POV.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --upgrade pip \
 && pip install 'setuptools<80' \
 && pip install wapiti3==3.2.1

RUN groupadd --system --gid 10106 scanner \
 && useradd  --system --uid 10106 --gid scanner \
             --home-dir /home/scanner --create-home --shell /bin/bash scanner \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "wapiti"]
CMD ["--help"]
