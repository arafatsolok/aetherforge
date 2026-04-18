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
# WORKDIR = /tmp because the sandbox mounts /tmp as tmpfs (rw) while
# the rest of the rootfs is read-only. Nikto with `-Format json`
# auto-names an output file in CWD; without a writable CWD it aborts
# with "Unable to open 'nikto_<host>_<ts>.json' for write" AND
# still-useful text output on stdout is silently lost.
WORKDIR /tmp

ENTRYPOINT ["tini", "--", "perl", "/opt/nikto/program/nikto.pl"]
CMD ["-Version"]
