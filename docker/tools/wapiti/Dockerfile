# =============================================================================
# Tool container — Wapiti
# =============================================================================
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --upgrade pip \
 && pip install wapiti3==3.2.1

RUN groupadd --system --gid 10106 scanner \
 && useradd  --system --uid 10106 --gid scanner \
             --home-dir /home/scanner --create-home --shell /bin/bash scanner \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "wapiti"]
CMD ["--help"]
