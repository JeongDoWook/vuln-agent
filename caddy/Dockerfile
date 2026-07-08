# DuckDNS DNS-01 플러그인이 포함된 Caddy 를 빌드한다(공식 caddy 이미지엔 없음).
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/caddy-dns/duckdns

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
COPY entrypoint.sh /usr/local/bin/vg-entrypoint.sh
RUN chmod +x /usr/local/bin/vg-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/vg-entrypoint.sh"]
