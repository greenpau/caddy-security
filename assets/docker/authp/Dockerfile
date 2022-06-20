FROM caddy:builder AS builder

LABEL org.opencontainers.image.title=authp
LABEL org.opencontainers.image.description="Authentication Portal"
LABEL org.opencontainers.image.url=https://github.com/greenpau/caddy-security
LABEL org.opencontainers.image.source=https://github.com/greenpau/caddy-security
LABEL org.opencontainers.image.version=1.0.1
LABEL maintainer="greenpau"

RUN xcaddy build \
    --with github.com/greenpau/caddy-security@v1.1.14 \
    --with github.com/greenpau/caddy-trace \
    --with github.com/caddy-dns/cloudflare

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
