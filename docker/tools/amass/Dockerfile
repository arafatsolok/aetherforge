# =============================================================================
# Tool container — OWASP Amass
# =============================================================================
FROM caffix/amass:latest

USER root

RUN apk add --no-cache tini ca-certificates

RUN addgroup -g 10108 -S scanner 2>/dev/null || true \
 && adduser  -u 10108 -G scanner -S -h /home/scanner scanner 2>/dev/null || true \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "amass"]
CMD ["--help"]
