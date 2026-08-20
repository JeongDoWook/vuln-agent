# 지난 변경 — 운영 서버에서 1회 조치가 필요했던 것

> `deploy/README.md` 에 있던 같은 제목의 절을 그대로 옮긴 기록이다(2026-08-20).
> 현행 배포 절차가 아니라 **그 시점에 이미 돌고 있던 서버**를 업데이트할 때만 필요했던 1회 조치다.

새로 배포하는 서버엔 **해당 없다**(템플릿에서 만든 `.env.prod` 는 처음부터 갖춰져 있다).
**이미 돌고 있는 서버를 업데이트할 때만** 아래를 날짜 순으로 훑고, 아직 안 한 게 있으면
`update.sh` **전에** 처리한다. 앞으로 같은 성격의 공지도 여기에 날짜별로 쌓는다.

| 날짜 | 무엇 | 서버에서 할 일 |
|---|---|---|
| 2026-07-27 | `.env.prod` 에 `PROD_DOMAIN` 추가 | **있다** — 이 줄이 없으면 caddy 가 못 뜬다(= HTTPS 중단) |
| 2026-08-08 | 보안 응답 헤더 추가(HSTS 제외) | 없음 — `update.sh` 가 caddy 를 재기동하면 적용된다 |

## 2026-07-27 — `.env.prod` 에 `PROD_DOMAIN` 추가

Caddy 사이트 주소를 저장소에 박아 두지 않고 **환경변수 `PROD_DOMAIN`** 으로 뺐다
(`deploy/caddy/Caddyfile` 의 `{$PROD_DOMAIN}`). **이 변경 이전부터 돌던 서버의 `.env.prod` 에는
이 줄이 없다** — 그대로 `update.sh` 를 돌리면 caddy 가 못 뜬다(= HTTPS 중단).

```bash
cd /apps/vulnagent/app/deploy
grep -q '^PROD_DOMAIN=' .env.prod || echo 'PROD_DOMAIN=실제운영도메인' >> .env.prod
./compose_runner.sh doctor        # "✓ .env.prod: PROD_DOMAIN" 확인
bash update.sh                    # 그 다음에 갱신
```

값은 **지금 접속하는 도메인과 정확히 같아야 한다** — TLS 인증서가 이 이름으로 발급/서빙된다.
빠뜨리면 조용히 넘어가지 않고 시끄럽게 실패한다(의도적):
compose 가 `${PROD_DOMAIN:?…}` 로 거부하고, 뚫려도 Caddy 가 빈 주소를 전역 옵션 블록으로
파싱해 기동에 실패한다(2026-08-08 이후 메시지: `server block without any key is global
configuration, and if used, it must be first`. 그 전엔 `unrecognized global option: encode`
였다 — 죽는다는 사실은 같다).

## 2026-08-08 — 보안 응답 헤더 추가 (HSTS 는 제외)

`deploy/caddy/Caddyfile` 에 `(security_headers)` snippet 을 넣어 모든 응답에 아래를 붙인다.
**서버에서 할 조치는 없다** — `update.sh`(또는 `prod up -d --build`)로 caddy 가 재기동되면 적용된다.

| 헤더 | 값 |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | `default-src 'self'` 기준(자세한 값은 Caddyfile) |
| `Server` / `X-Powered-By` | **제거** |
| `Strict-Transport-Security` | **붙이지 않는다** — 아래 참조 |

**평문 80 진입도 같은 헤더를 받는다.** 예전엔 Caddy 가 자동 생성한 리다이렉트가 우리 사이트
블록 밖이라 `import security_headers` 가 안 걸렸고, 그 경로의 응답만 헤더가 하나도 없이
`Server: Caddy` 가 그대로 나갔다(실측). 전역 블록의 `auto_https disable_redirects` 로 암묵적
리다이렉트를 끄고, 평문 전부를 `http://:80` 한 블록이 명시적으로 처리한다 — 동작은 그대로
308 이고(301 이 아니다. POST 의 메서드·본문을 보존한다) 헤더만 붙는다.

확인:

```bash
curl -skI https://$PROD_DOMAIN/login.php   # 위 헤더가 보이고 Server 가 없어야 한다
curl -sI  -H "Host: $PROD_DOMAIN" http://127.0.0.1:80/login.php   # 평문 진입: 308 + 같은 헤더
```

### HSTS 를 붙이지 않는 이유

TLS 는 `tls internal`(Caddy 내부 CA 자체서명)이고, **이건 확정된 결정이다**(2026-08-09, 이슈 #518 —
정식 인증서 전환은 하지 않는다). 자체서명이라 브라우저는 `ERR_CERT_AUTHORITY_INVALID` 를 낸다.
이 상태에서 HSTS 를 보내면 브라우저가 그 호스트를 HSTS 목록에 올리고,
**HSTS 호스트에서는 인증서 예외("고급 → 계속 진행")가 아예 허용되지 않는다.** 즉 접속 수단이
사라지고, `max-age` 가 만료되기 전엔 사용자가 브라우저 내부 설정에서 HSTS 항목을 손으로 지우는 것
말고는 되돌릴 방법이 없다. 그래서 붙이지 않는다.

자체서명을 쓰는 이유와 그 대가(에이전트 루트 CA 배포)는
[`../../../deploy/caddy/README.md`](../../../deploy/caddy/README.md) **"자체서명을 쓰는 이유"** 한 곳에 둔다.
