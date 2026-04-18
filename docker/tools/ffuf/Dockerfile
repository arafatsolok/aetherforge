# =============================================================================
# Tool container — ffuf (fast web fuzzer)
# =============================================================================
FROM golang:1.22-alpine AS builder

ARG FFUF_VERSION=v2.1.0

RUN apk add --no-cache git \
 && go install github.com/ffuf/ffuf/v2@${FFUF_VERSION}


FROM alpine:3.20

RUN apk add --no-cache ca-certificates tini

COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

RUN addgroup -g 10110 -S scanner \
 && adduser  -u 10110 -G scanner -S -h /home/scanner scanner \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "/usr/local/bin/ffuf"]
CMD ["-V"]
