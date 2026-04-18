# =============================================================================
# Tool container — nmap
# Ephemeral: spawned once per scan by the Docker executor and removed on exit.
# Hardened: non-root, read-only FS, no caps, no network until attached.
# =============================================================================
FROM alpine:3.20

ARG NMAP_VERSION=7.95

RUN apk add --no-cache \
      nmap=${NMAP_VERSION}-r0 \
      nmap-scripts=${NMAP_VERSION}-r0 \
      nmap-nselibs=${NMAP_VERSION}-r0 \
      ca-certificates \
      tini \
      libcap

# Run as non-root but keep CAP_NET_RAW so -sS/-O still work.
# The executor starts the container with --cap-drop=ALL --cap-add=NET_RAW.
RUN addgroup -g 10100 -S scanner \
 && adduser  -u 10100 -G scanner -S -h /home/scanner scanner \
 && mkdir -p /output \
 && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "/usr/bin/nmap"]
CMD ["--version"]
