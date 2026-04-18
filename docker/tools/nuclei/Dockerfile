# =============================================================================
# Tool container — ProjectDiscovery / Nuclei
# Upstream pd-nuclei image runs as root; we add tini, create an isolated
# `scanner` user, and pre-fetch the template set as that user.
# =============================================================================
ARG NUCLEI_VERSION=v3.3.5

FROM projectdiscovery/nuclei:${NUCLEI_VERSION}

USER root
RUN apk add --no-cache tini ca-certificates \
 && addgroup -g 10112 -S scanner \
 && adduser  -u 10112 -G scanner -S -h /home/scanner scanner \
 && mkdir -p /home/scanner /output \
 && chown -R scanner:scanner /home/scanner /output

USER scanner
WORKDIR /home/scanner

# Pre-fetch template set so each run skips the sync. Templates are
# baked into the image; refresh by rebuilding.
RUN nuclei -update-templates -silent || true

ENTRYPOINT ["tini", "--", "nuclei"]
CMD ["-version"]
