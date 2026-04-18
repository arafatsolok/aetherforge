# =============================================================================
# Tool container — ProjectDiscovery / subfinder
# =============================================================================
FROM projectdiscovery/subfinder:latest

USER root
RUN apk add --no-cache tini

RUN addgroup -g 10107 -S scanner 2>/dev/null || true \
 && adduser  -u 10107 -G scanner -S -h /home/scanner scanner 2>/dev/null || true

# Subfinder requires its config FILES to exist on disk, even if empty.
# Without paid API keys it simply skips those sources and falls back
# to free ones (crt.sh, hackertarget, alienvault, anubis, wayback).
RUN mkdir -p /home/scanner/.config/subfinder \
 && printf 'resolvers:\n  - 1.1.1.1\n  - 8.8.8.8\nsources:\n  - crtsh\n  - hackertarget\n  - alienvault\n  - anubis\n  - waybackarchive\n' \
    > /home/scanner/.config/subfinder/provider-config.yaml \
 && printf 'resolvers:\n  - 1.1.1.1\n  - 8.8.8.8\n' \
    > /home/scanner/.config/subfinder/config.yaml \
 && chown -R scanner:scanner /home/scanner/.config

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "subfinder"]
CMD ["-version"]
