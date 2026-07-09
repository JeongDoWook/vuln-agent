#!/bin/sh
# docker secret 으로 마운트된 DuckDNS 토큰을 환경변수로 노출한 뒤 Caddy 실행.
#   (Caddyfile 의 {env.DUCKDNS_TOKEN} 가 이 값을 참조)
set -e

if [ -f /run/secrets/duckdns_token ]; then
	DUCKDNS_TOKEN="$(tr -d '\r\n' < /run/secrets/duckdns_token)"
	export DUCKDNS_TOKEN
fi

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
