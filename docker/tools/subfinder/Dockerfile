# =============================================================================
# Tool container — ProjectDiscovery / subfinder
# =============================================================================
FROM projectdiscovery/subfinder:latest

USER root
RUN apk add --no-cache tini

RUN addgroup -g 10107 -S scanner 2>/dev/null || true \
 && adduser  -u 10107 -G scanner -S -h /home/scanner scanner 2>/dev/null || true

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "subfinder"]
CMD ["-version"]
