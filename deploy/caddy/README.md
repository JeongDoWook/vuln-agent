# Caddy — HTTPS 리버스 프록시 (운영 전용)

vuln-agent 웹을 **HTTPS**로 감싸는 앞단 프록시. Let's Encrypt 인증서를
**DuckDNS DNS-01** 챌린지로 발급하므로 **인증서 발급에는 인바운드 80 이 필요 없다**
(HTTP-01 챌린지를 쓰지 않는다).

다만 **접속 경로로는 80·443 을 연다** — 포트 없는 깔끔한 주소(443)를 쓰고, 평문 80 으로
들어온 요청을 https 로 리다이렉트하기 위해서다. 기존 8080 포워딩도 하위호환으로 유지한다.
(호스트에 포트가 실제로 뚫려 있어야 하는 건 물론이고, 앞단 네트워크 방화벽에도 80·443
인바운드 포워딩이 있어야 밖에서 닿는다.)

```
브라우저 ──https──▶ [포워딩 443]  ──▶ caddy:443 (TLS 종료) ──http──▶ web:80 (Apache/PHP)
브라우저 ──http ──▶ [포워딩 80]   ──▶ caddy:80  ──308──▶ https://ost-server.duckdns.org/…
에이전트 ──https──▶ [포워딩 8080] ──▶ caddy:443 (TLS 종료) ──http──▶ web:80   ← 하위호환
```

접속 주소: **https://ost-server.duckdns.org**
평문 `http://ost-server.duckdns.org` 로 들어와도 https 로 자동 리다이렉트(308)된다.
기존 **https://ost-server.duckdns.org:8080** 도 그대로 동작한다 — 설치된 에이전트들이
그 주소로 등록돼 있어 하위호환으로 계속 열어 둔다(`compose.prod.yml` 의 caddy `ports` 참고).

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
4. 브라우저에서 **https://ost-server.duckdns.org** — 자물쇠 확인.
5. 리다이렉트·하위호환 확인 (80·443 은 앞단 네트워크 방화벽 포워딩이 열린 뒤에 밖에서 닿는다):
   ```bash
   curl -sI http://ost-server.duckdns.org/findings.php   # → 308 + Location: https://…/findings.php
   curl -skI https://ost-server.duckdns.org:8080/findings.php  # → 302 (미로그인 리다이렉트 = TLS 정상)
   ```

인증서는 `caddy_data` 볼륨에 영속화되어 재시작해도 재발급하지 않으며, 만료 전 자동 갱신된다.

## 롤백 (HTTPS 끄고 평문 8080 으로 복귀)
`compose.prod.yml` 에서 caddy 서비스를 지우고 web 에 `ports: ["${WEB_PORT:-8080}:80"]` 를
되살린 뒤 `prod up -d` 하면 이전 상태로 돌아간다.

## 참고
- 뒷단 web 은 호스트로 노출되지 않는다(내부 `web:80`). 외부는 오직 caddy(TLS)만 통과.
- **`:8080` 없는 깔끔한 주소(443)는 실현됐다.** `compose.prod.yml` 의 caddy `ports` 가
  8080→443 외에 80→80, 443→443 을 함께 published 한다. 80 리다이렉트 리스너는 Caddyfile
  사이트 블록에 포트를 적지 않아 Caddy 가 자동으로 만든 것이라 Caddyfile 수정은 필요 없었다.
- 인증서 발급(DNS-01)에는 여전히 80 을 쓰지 않는다 — 80 은 오직 리다이렉트 진입점이다.
- `:8080` 은 지우지 않는다. 설치된 에이전트들이 그 주소로 등록돼 있다.
- 토큰이 틀리면 인증서 발급이 실패하고 사이트가 안 뜬다 → 로그로 확인 후 토큰 교정.
