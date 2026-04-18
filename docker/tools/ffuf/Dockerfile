# =============================================================================
# Tool container — ffuf (fast web fuzzer)
# =============================================================================
FROM golang:1.22-alpine AS builder

ARG FFUF_VERSION=v2.1.0

RUN apk add --no-cache git \
 && go install github.com/ffuf/ffuf/v2@${FFUF_VERSION}


FROM alpine:3.20

RUN apk add --no-cache ca-certificates tini curl

COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

# ffuf needs a wordlist. Ship the SecLists curated set so every rule
# that invokes ffuf has a known path (/wordlists/*.txt). We fetch only
# the three most common lists (common, quickhits, raft-medium) to keep
# the image <40 MB — the full SecLists tree is ~2 GB.
RUN mkdir -p /wordlists \
 && curl -fsSL -o /wordlists/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
 && curl -fsSL -o /wordlists/raft-medium-directories.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt \
 && curl -fsSL -o /wordlists/quickhits.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt

RUN addgroup -g 10110 -S scanner \
 && adduser  -u 10110 -G scanner -S -h /home/scanner scanner \
 && mkdir -p /output && chown scanner:scanner /output /wordlists

# ffuf 2.x touches $HOME/.config/ffuf/scraper on startup — on a
# read-only rootfs that crashes the process with
# "open /home/scanner/.config/ffuf/scraper: no such file or directory".
# Pre-create the directory so the file exists (empty is fine — ffuf
# falls back silently). Also use /tmp as the output dir (rule passes
# -o /output/... currently; /output is no longer writable, so any
# -o target must land under /tmp).
USER root
RUN mkdir -p /home/scanner/.config/ffuf \
 && chown -R scanner:scanner /home/scanner/.config

USER scanner
WORKDIR /tmp

ENTRYPOINT ["tini", "--", "/usr/local/bin/ffuf"]
CMD ["-V"]
