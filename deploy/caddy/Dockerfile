# 공식 Caddy 이미지 + 우리 Caddyfile 만. 플러그인은 넣지 않는다.
#   2026-08-09 이전엔 xcaddy 로 DuckDNS DNS-01 플러그인을 넣어 빌드했지만, 정식 인증서 전환을
#   하지 않기로 확정해(자체서명 `tls internal` 유지) 플러그인·토큰 주입 진입점이 전부 죽었다.
#   기본 CMD(`caddy run --config /etc/caddy/Caddyfile --adapter caddyfile`)를 그대로 쓴다.
FROM caddy:2
COPY Caddyfile /etc/caddy/Caddyfile
