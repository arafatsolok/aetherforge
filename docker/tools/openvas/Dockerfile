# =============================================================================
# Tool container — OpenVAS / Greenbone
# Note: the heavy image comes from docker-compose directly (immauss/openvas).
# This Dockerfile exists for compose to reference a local build context if
# the operator wants to pin / customize. By default it's a no-op passthrough.
# =============================================================================
FROM immauss/openvas:22.4.41

# Upstream image already provides the full stack (gvmd, ospd-openvas, gsad,
# postgres, redis). Keep as-is — overlay config via /etc/gvm at runtime via
# compose volume mount.

LABEL org.aetherforge.role="vuln-scanner"
