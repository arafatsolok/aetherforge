# =============================================================================
# Tool container — sqlmap
# =============================================================================
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG SQLMAP_REF=1.8.12

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --depth=1 --branch ${SQLMAP_REF} \
      https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

RUN groupadd --system --gid 10104 scanner \
 && useradd  --system --uid 10104 --gid scanner \
             --home-dir /home/scanner --create-home --shell /bin/bash scanner \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "python", "/opt/sqlmap/sqlmap.py"]
CMD ["--version"]
