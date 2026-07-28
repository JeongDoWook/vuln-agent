# deploy — 배포 인프라

중앙 서버(대시보드 + 수집 API)를 컨테이너로 띄우는 곳이다. compose 파일·러너·Caddy(HTTPS
리버스 프록시)·마이그레이션 러너가 모두 여기 있다. **모든 명령은 `cd deploy` 후 실행한다.**

- 전체 구조·매처 규칙: [`../docs/dev/architecture.md`](../docs/dev/architecture.md)
- 에이전트(대상 서버) 설치·운영: [`../agent/README.md`](../agent/README.md)

---

## 최초 배포 (새 서버에서)

```bash
cd deploy
./compose_runner.sh init                  # .env.dev / .env.prod 생성(템플릿 복사) → 비밀값 채우기
#   secrets/*.txt (mysql/admin/ingest/duckdns) 와 .env.prod 를 이 서버 값으로 채운다.
./compose_runner.sh doctor                # 사전 점검(훅 설치·포트 등)
./compose_runner.sh prod up -d --build    # 운영 기동 — Caddy 가 자체서명 루트 CA 를 이때 생성한다
```

기동되면 대시보드가 **`https://<도메인>`**(443, 포트 없음)에 뜬다(Caddy 가 HTTPS 종료).
평문 `http://<도메인>` 으로 들어와도 308 로 https 에 리다이렉트된다. `https://<도메인>:8080`
도 계속 동작한다 — 이미 설치된 에이전트들이 그 주소로 등록돼 있어 **하위호환**으로 열어 둔다.
포트 구성·리다이렉트 상세는 [`caddy/README.md`](caddy/README.md).

갱신은 서버에서 `bash deploy/update.sh` 한 줄 — 바뀐 파일을 보고 재빌드/pull 을 스스로 고른다.
**운영 중인 서버를 업데이트한다면** 문서 끝 [“지난 변경 — 운영 서버에서 1회 조치가 필요했던 것”](#지난-변경--운영-서버에서-1회-조치가-필요했던-것)
을 먼저 확인한다.

---

## 에이전트 CA 준비 (최초 1회, 필수)

**왜 필요한가.** 중앙 Caddy 는 자체서명(`tls internal`)으로 HTTPS 를 한다. 대상 서버의 에이전트가
이 중앙에 HTTPS 로 전송하려면 **이 Caddy 의 루트 CA 를 신뢰**해야 한다. 그 루트 CA(공개 인증서)를
꺼내 두면, 자산 화면의 “에이전트 설치 안내”에서 `caddy-root.crt` 버튼으로 받아 대상 서버에 깔 수 있다.

**왜 레포에 없나.** 루트 CA 는 **이 배포의 Caddy 가 만든 고유값**이다. 오픈소스라 레포에 커밋하면
남이 세운 배포가 내 CA 를 신뢰하게 되어 위험하다. 그래서 `agent-ca/caddy-root.crt` 는 **gitignore**
이고, 배포마다 아래 한 줄로 직접 만든다.

```bash
# 저장소 루트에서 실행 (deploy/ 아니라 그 상위). Caddy 가 뜬 뒤에 한다.
docker exec vulnagent-caddy cat /data/caddy/pki/authorities/local/root.crt > agent-ca/caddy-root.crt
```

- 컨테이너 이름은 운영에서 `vulnagent-caddy` 다(dev 는 Caddy 가 없다 — HTTP 라 CA 가 필요 없다).
- `agent-ca/` 는 web 컨테이너에 읽기전용으로 마운트돼 있어(compose), 파일을 만들면 **재시작 없이
  즉시** `agent-dl.php` 가 내보낸다.
- 이 파일은 **공개 인증서**다(개인키 아님). 공개돼도 안전하지만, 배포별 값이라 레포엔 안 넣는다.

**확인** — 서버 자신에서 loopback 으로:

```bash
curl -s http://127.0.0.1:8081/agent-dl.php?f=caddy-root.crt | head -1
#   -----BEGIN CERTIFICATE-----  → 정상. "아직 준비되지 않았습니다" → 위 추출을 안 한 것.
```

준비 전이면 다운로드 버튼은 추출 명령을 알려주며 503 을 낸다(설치가 조용히 깨지지 않게).

---

## 새 서버로 이전할 때 체크리스트

1. `secrets/*.txt` · `.env.prod` 를 새 서버 값으로 다시 채운다(gitignore 라 안 딸려온다).
2. `./compose_runner.sh prod up -d --build` — **새 서버의 Caddy 는 새 루트 CA 를 만든다.**
3. **CA 를 다시 추출한다**(위 “에이전트 CA 준비”). 옛 서버의 `caddy-root.crt` 는 새 서버에서 안 통한다.
4. 이미 설치된 대상 서버가 있으면, 새 CA 를 받아 다시 깔거나 `--ca-file` 로 갱신한다.

## CA 회전

Caddy 루트는 10년짜리라 거의 바뀌지 않는다. `data`(caddy_data) 볼륨을 지우면 새로 생성되므로,
그때만 위 추출을 다시 하고 대상 서버들의 CA 를 갱신하면 된다.

---

## DB 백업

`deploy/backup_db.sh` 가 `vulnagent-db` 컨테이너 안에서 `mysqldump`(`--single-transaction
--routines`)를 실행해 gzip 압축 후 `/apps/vulnagent/backups/vulnagent_YYYYMMDD_HHMMSS.sql.gz`
로 저장한다. 비밀번호는 항상 컨테이너 안에서 `/run/secrets/mysql_root_password` 를 읽어 쓰고
호스트엔 노출하지 않는다. 설치는 운영 서버 crontab 에 한 줄:

```bash
crontab -e
# 매일 새벽 4시
0 4 * * * /apps/vulnagent/app/deploy/backup_db.sh >> /apps/vulnagent/backups/cron.log 2>&1
```

**왜 매일인가.** 예전엔 3일 주기(`0 4 */3 * *`)에 30일치였는데, `*/3` 은 일(day-of-month)
필드라 **월 경계에서 리셋돼** 간격이 들쭉날쭉했다(30일에 돌면 다음은 다음 달 3일). 매일이면
그 함정 자체가 없고, 복구 시점도 최대 하루 전으로 좁혀진다.

보관 정책은 스크립트 상단 `KEEP=7`(매일 주기 기준 **7일치**) — `vulnagent_*.sql.gz` 만 최신
7개를 남기고 자동 정리한다. **나이(mtime)가 아니라 개수 기준인 것도 의도적이다** — 백업이 며칠
연속 실패해도 마지막 7개는 남는다. 나이 기준이면 실패가 이어질 때 남은 것까지 다 지워 0개가 된다.

기존 수동 백업(`pre_content_*`, `pre_tb_*`)은 패턴이 달라 건드리지 않는다. 실행 결과는
`$BACKUP_DIR/backup.log` 에 한 줄씩 쌓인다.

> cron 한 줄과 `KEEP` 은 **짝이다.** 한쪽만 바꾸면 보관 기간이 의도와 달라지므로
> `deploy/backup_db.sh` 를 정답으로 보고 양쪽을 함께 맞춘다.

---

## 지난 변경 — 운영 서버에서 1회 조치가 필요했던 것

새로 배포하는 서버엔 **해당 없다**(템플릿에서 만든 `.env.prod` 는 처음부터 갖춰져 있다).
**이미 돌고 있는 서버를 업데이트할 때만** 아래를 날짜 순으로 훑고, 아직 안 한 게 있으면
`update.sh` **전에** 처리한다. 앞으로 같은 성격의 공지도 여기에 날짜별로 쌓는다.

### 2026-07-27 — `.env.prod` 에 `PROD_DOMAIN` 추가

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
compose 가 `${PROD_DOMAIN:?…}` 로 거부하고, 뚫려도 Caddy 가 빈 주소를
`unrecognized global option: encode` 로 파싱해 기동에 실패한다.
