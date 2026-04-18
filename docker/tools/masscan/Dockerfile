# =============================================================================
# Tool container — masscan
# Fast async port scanner. Requires CAP_NET_RAW + CAP_NET_ADMIN.
# =============================================================================
FROM alpine:3.20 AS builder

RUN apk add --no-cache build-base git libpcap-dev

RUN git clone --depth=1 https://github.com/robertdavidgraham/masscan.git /src \
 && cd /src && make -j$(nproc)


FROM alpine:3.20

RUN apk add --no-cache libpcap ca-certificates tini

COPY --from=builder /src/bin/masscan /usr/local/bin/masscan

RUN addgroup -g 10101 -S scanner \
 && adduser  -u 10101 -G scanner -S -h /home/scanner scanner \
 && mkdir -p /output && chown scanner:scanner /output

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["tini", "--", "/usr/local/bin/masscan"]
CMD ["--version"]
