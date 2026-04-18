# =============================================================================
# Tool container — OWASP Nettacker
# Full install of OWASP's automated pentest framework.
# =============================================================================
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git \
      ca-certificates \
      tini \
      curl \
      nmap \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Clone a pinned tag — upgrade cadence controlled by the orchestrator repo.
ARG NETTACKER_REF=0.4.0
RUN git clone --depth=1 --branch ${NETTACKER_REF} \
      https://github.com/OWASP/Nettacker.git /opt/Nettacker \
 && cd /opt/Nettacker \
 && pip install --upgrade pip \
 && pip install -r requirements.txt

RUN groupadd --system --gid 10102 scanner \
 && useradd  --system --uid 10102 --gid scanner \
             --home-dir /home/scanner --create-home --shell /bin/bash scanner \
 && mkdir -p /output /opt/Nettacker/.data \
 && chown -R scanner:scanner /output /opt/Nettacker/.data /home/scanner

USER scanner
WORKDIR /opt/Nettacker

ENTRYPOINT ["tini", "--", "python", "/opt/Nettacker/nettacker.py"]
CMD ["--help"]
