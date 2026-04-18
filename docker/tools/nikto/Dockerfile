# =============================================================================
# Tool container — nikto
# =============================================================================
FROM alpine:3.20

RUN apk add --no-cache perl perl-net-ssleay git ca-certificates tini \
 && git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto

RUN addgroup -g 10105 -S scanner \
 && adduser  -u 10105 -G scanner -S -h /home/scanner scanner \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "perl", "/opt/nikto/program/nikto.pl"]
CMD ["-Version"]
