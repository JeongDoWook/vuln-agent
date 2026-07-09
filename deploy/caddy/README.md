# Caddy — HTTPS 리버스 프록시 (운영 전용)

vuln-agent 웹을 **HTTPS**로 감싸는 앞단 프록시. Let's Encrypt 인증서를
**DuckDNS DNS-01** 챌린지로 발급하므로 **인바운드 80/443 포트 개방이 필요 없다**
(방화벽에 새 포트를 뚫지 않아도 됨). 기존 8080 포워딩을 그대로 재사용한다.

```
브라우저 ──https──▶ [포워딩 8080] ──▶ caddy:443 (TLS 종료) ──http──▶ web:80 (Apache/PHP)
```

접속 주소: **https://ost-server.duckdns.org:8080**

## 구성 파일
- `Dockerfile` — DuckDNS 플러그인을 넣어 Caddy 를 빌드(공식 이미지엔 없음)
- `Caddyfile` — 도메인 1개, `tls { dns duckdns }`, `reverse_proxy web:80`
- `entrypoint.sh` — docker secret 의 토큰을 `DUCKDNS_TOKEN` env 로 노출 후 Caddy 실행

## 배포 (서버에서)
1. **DuckDNS 토큰 입력** (랜덤 아님, 본인 DuckDNS 계정 토큰) — `deploy/` 에서 실행:
   ```bash
   printf %s 'DuckDNS-토큰' > ../secrets/duckdns_token.txt
   ```
   토큰은 https://www.duckdns.org 로그인 후 상단 "token" 값.
2. 기동/갱신 (`deploy/` 에서):
   ```bash
   ./compose_runner.sh prod up -d --build
   ```
3. 첫 인증서 발급 로그 확인(수십 초):
   ```bash
   docker compose -p vulnagent logs -f caddy
   #  "certificate obtained successfully" 뜨면 성공
   ```
4. 브라우저에서 **https://ost-server.duckdns.org:8080** — 자물쇠 확인.

인증서는 `caddy_data` 볼륨에 영속화되어 재시작해도 재발급하지 않으며, 만료 전 자동 갱신된다.

## 롤백 (HTTPS 끄고 평문 8080 으로 복귀)
`compose.prod.yml` 에서 caddy 서비스를 지우고 web 에 `ports: ["${WEB_PORT:-8080}:80"]` 를
되살린 뒤 `prod up -d` 하면 이전 상태로 돌아간다.

## 참고
- 뒷단 web 은 호스트로 노출되지 않는다(내부 `web:80`). 외부는 오직 caddy(TLS)만 통과.
- DNS-01 이라 80 을 쓰지 않는다. 나중에 `:8080` 없는 깔끔한 주소(443)를 원하면
  네트워크팀에 443 포워딩을 요청하고 `published` 를 443 으로 바꾸면 된다.
- 토큰이 틀리면 인증서 발급이 실패하고 사이트가 안 뜬다 → 로그로 확인 후 토큰 교정.
