# =============================================================================
# Tool container — ProjectDiscovery / httpx
# =============================================================================
FROM projectdiscovery/httpx:latest

USER root
RUN apk add --no-cache tini

RUN addgroup -g 10109 -S scanner 2>/dev/null || true \
 && adduser  -u 10109 -G scanner -S -h /home/scanner scanner 2>/dev/null || true

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "httpx"]
CMD ["-version"]
