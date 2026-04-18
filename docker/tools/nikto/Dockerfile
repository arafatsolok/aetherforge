# =============================================================================
# Tool container — nikto
# =============================================================================
FROM alpine:3.20

# Alpine's `perl` package is a stripped-down distribution. Nikto needs
# a pile of CPAN modules (JSON output, XML reports, HTTPS, cookie jar,
# …). Without them every run dies instantly with:
#   ERROR: Required module not found: JSON
#   ERROR: Required module not found: XML::Writer
# which is SILENT from the orchestrator's POV (0 stdout, 0 stderr) and
# leaves zero findings in the DB.
RUN apk add --no-cache \
      perl perl-net-ssleay perl-json perl-json-xs \
      perl-xml-writer perl-xml-parser \
      perl-libwww perl-lwp-protocol-https perl-http-cookies \
      perl-net-dns \
      git ca-certificates tini \
 && git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto

RUN addgroup -g 10105 -S scanner \
 && adduser  -u 10105 -G scanner -S -h /home/scanner scanner \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "perl", "/opt/nikto/program/nikto.pl"]
CMD ["-Version"]
