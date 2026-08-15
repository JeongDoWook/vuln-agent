# deploy — 배포 인프라

> 문서 기준: 2026-08-15 · 운영 배포는 `update.sh`, 에이전트 일괄 설치는 `install_staged_agents.sh`가 정본이다.

중앙 서버(대시보드 + 수집 API)를 컨테이너로 띄우는 곳이다. compose 파일·러너·Caddy(HTTPS
리버스 프록시)·마이그레이션 러너가 모두 여기 있다. **모든 명령은 `cd deploy` 후 실행한다.**

- 전체 구조·매처 규칙: [`../docs/dev/architecture.md`](../docs/dev/architecture.md)
- 에이전트(대상 서버) 설치·운영: [`../agent/README.md`](../agent/README.md)

---

## 최초 배포 (새 서버에서)

```bash
cd deploy
./compose_runner.sh init                  # .env.dev / .env.prod 생성(템플릿 복사) → 비밀값 채우기
#   secrets/*.txt (mysql/admin) 와 .env.prod 를 이 서버 값으로 채운다.
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

필수 운영 검증은 `bash deploy/run-gates.sh --profile central --json`으로 실행한다. 결과의 각
check에는 `id`, `required`, `passed`, `duration_ms`, `evidence`가 있고, required 실패가 하나라도
있으면 JSON의 `ok=false`와 종료코드 1이 함께 나온다. 로컬 pre-push도 같은 `deploy/gates.tsv`와
runner를 사용하므로 Docker 미기동·현재 tree stack 불응·smoke 미실행을 성공 skip으로 바꾸지 않는다.

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

## 에이전트 일괄 설치·갱신 (`install_staged_agents.sh`)

노드들에 SSH 로 닿는 곳(master)에서 저장소의 최신 `agent/vuln-inventory-agent.sh` 를 여러 노드에
한 번에 밀어 넣고 재시작·버전 확인까지 한다. 대상을 안 주면 `deploy/agent_nodes.txt` 의 목록을 쓴다.

```bash
bash deploy/install_staged_agents.sh                       # agent_nodes.txt 의 노드 전체
bash deploy/install_staged_agents.sh 10.0.0.105 user@10.0.0.201   # 대상 지정
```

- 노드 목록은 저장소에 두지 않는다(내부망 인벤토리이므로 `.gitignore`). 처음 쓸 때
  `cp deploy/agent_nodes.txt.template deploy/agent_nodes.txt` 로 만들고 대상을 적는다 —
  파일이 없으면 스크립트가 안내 후 종료한다.
- SSH 사용자·설치 경로는 `AGENT_SSH_USER`·`AGENT_PREFIX` 환경변수로 바꾼다.
- **신규 설치·토큰 발급은 하지 않는다** — 그건 그 서버에서 `install-agent.sh` 를 돌리는 일이다.
  한 노드만 본체를 갱신할 땐 `agent_push.sh` 를 쓴다([`../agent/README.md`](../agent/README.md) "갱신").
- 웹 버튼으로 만들지 않는 이유도 같다: PHP 컨테이너가 전 노드 root SSH 키를 들면 웹앱 침해가
  전 노드 장악으로 번진다. 보는 건 웹, 미는 건 CLI.

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
호스트엔 노출하지 않는다. 생성 직후 임시 `vg_restore_*` DB에 복원하고 `tb_host`·`tb_scan`
sanity check를 통과한 경우에만 `restore=pass`로 기록한다. 설치는 운영 서버 crontab 에 한 줄:

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

### 복원 rehearsal과 실패 복구

```bash
# 기존 dump를 운영 DB에 덮어쓰지 않고 임시 DB로만 검증
bash deploy/backup_db.sh --verify /apps/vulnagent/backups/vulnagent_YYYYMMDD_HHMMSS.sql.gz vulnagent-db
```

성공 기준은 gzip 무결성, 임시 DB restore, 핵심 테이블 2개 확인, 임시 DB 삭제가 모두 통과하는
것이다. 실패 dump는 정상 보관 패턴 밖의 `.failed` 파일로 0600 격리되고 자동 정리·복구 대상에
들어가지 않는다. `backup.log`의 실패 시각과 격리 파일을 보존해 원인을 조사한 뒤, 마지막
`restore=pass` 백업으로 새 DB에 복원한다. 운영 schema에 직접 시험 복원하지 않는다.

### migration preflight와 부분 실패 복구

`deploy/migrate.sh`는 적용 전에 컨테이너의 `MYSQL_DATABASE`와 호출값 일치, DB 존재, 최소 1 GiB
여유 공간, schema version을 확인한다. 운영 `update.sh`는 먼저 위 restore rehearsal을 통과한 새
백업을 만들고 그 파일을 `MIGRATION_BACKUP_FILE`로 전달한다. 확인만 할 때는 다음처럼 실행한다.

```bash
MYSQL_DATABASE=vulnagent MIGRATION_REQUIRE_BACKUP=1 \
MIGRATION_BACKUP_FILE=/apps/vulnagent/backups/vulnagent_YYYYMMDD_HHMMSS.sql.gz \
bash deploy/migrate.sh vulnagent-db --preflight
```

DDL 적용 뒤 `tb_schema_migrations` 기록만 실패하면 스크립트는 성공으로 숨기지 않고 해당 파일명을
출력한다. migration 파일은 `db/migrations/README.md` 규칙대로 멱등이므로 같은 명령을 재실행해
DDL을 확인·재적용하고 이력을 기록한다. 재실행도 실패하거나 schema sanity가 맞지 않으면 서비스를
확대 적용하지 말고, 직전 `restore=pass` 백업을 새 DB에 복원해 원인을 수정한 뒤 다시 진행한다.

> cron 한 줄과 `KEEP` 은 **짝이다.** 한쪽만 바꾸면 보관 기간이 의도와 달라지므로
> `deploy/backup_db.sh` 를 정답으로 보고 양쪽을 함께 맞춘다.

---

## 운영 설정 — 세션 만료·토큰 유효기간 (2026-08-08 추가)

컴플라이언스 감사 §7-3(ISMS-P 2.6.3 세션 · 2.5.1 / N2SF SN·AC) 대응으로 로그인 세션과
API/에이전트 토큰에 만료가 생겼다. **`.env` 나 컨테이너 환경변수로 바꾸는 값이 아니다** —
세션 만료는 **웹 화면(관리 → 설정)** 에서, 나머지는 아래 표대로 정한다.

| 무엇 | 지금 값 | 어디서 바꾸나 |
|---|---|---|
| 세션 **유휴** 만료 | 30분 | **웹 화면** 관리 → 설정(`session.idle_minutes`, 5~720분) |
| 세션 **절대** 만료 | 12시간(유휴와 무관) | **웹 화면** 관리 → 설정(`session.absolute_minutes`, 30~1440분) |
| 토큰 유효기간 선택지 | 무기한 / 30일 / 90일 / 1년 | 발급은 **웹 화면**(API 키·에이전트 키), 선택지 자체는 `server/src/tokenexpiry.php:15` |
| “만료 임박” 표시 기준 | 잔여 7일 | `server/src/tokenexpiry.php:18` `VG_TOKEN_EXPIRY_SOON_DAYS`(목록 뱃지 표시용 — 인증 판정과 무관해 설정으로 빼지 않았다) |

- 설정을 저장하지 않으면(빈 `tb_setting`) `server/src/auth.php` 의 상수
  `VG_SESSION_IDLE_SECONDS`(1800초)·`VG_SESSION_ABSOLUTE_SECONDS`(43200초)를 그대로 쓴다 —
  마이그레이션이 안 든 DB 에서도 동작이 같다. 범위를 벗어난 값은 읽을 때도 잘라 쓰므로
  DB 를 직접 고쳐도 만료를 0 이나 무한으로 만들 수 없다.

- 세션 만료 판정 기준 시각(`login_at`·`last_activity`)은 **세션에만** 둔다 — 요청마다 DB 쓰기가
  생기지 않는다. 만료되면 감사로그(`session_expire`)가 남고, 로그인 화면이 "다른 곳에서
  로그인됨"과 "시간 초과"를 다른 문구로 안내한다.
- PHP 기본 `session.gc_maxlifetime`(1440초 = 24분)이 유휴 30분보다 짧아 PHP 가 먼저 세션을
  날리던 문제는 코드에서 `ini_set` 으로 맞춰 뒀다(설정 가능한 절대 만료의 **상한**인 1440분 기준
  — 어떤 설정값이어도 GC 가 먼저 세션을 지우지 않는다). **PHP 설정을 손으로 만질 필요 없다.**
- 토큰은 `tb_agent_token` 의 `expires_at`(NULL = 무기한)으로 관리한다(Export API 읽기 토큰과
  `tb_api_token` 은 2026-08-13 폐지 — `export.php`·`sbom.php` 는 웹 로그인 세션 인증이다).
  **이 변경 이전에 발급된 토큰은 NULL 이라 그대로 무기한**이고, 만료된 토큰은 인증 실패(401)로
  처리되며 `agent_token_expired` 감사로그가 남는다. **자동 갱신·재발급은
  없다** — 만료되면 사람이 새로 발급하고 노드의 `agent.env` 를 갱신한다
  ([`../agent/README.md`](../agent/README.md) “주의점” 1번).
- 스키마는 마이그레이션 `20260808105921_token_expires_at.sql` 이 멱등하게 얹는다 —
  `update.sh`(→ `migrate.sh`)가 자동 적용하므로 운영에서 손으로 할 일은 없다.

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
compose 가 `${PROD_DOMAIN:?…}` 로 거부하고, 뚫려도 Caddy 가 빈 주소를 전역 옵션 블록으로
파싱해 기동에 실패한다(2026-08-08 이후 메시지: `server block without any key is global
configuration, and if used, it must be first`. 그 전엔 `unrecognized global option: encode`
였다 — 죽는다는 사실은 같다).

### 2026-08-08 — 보안 응답 헤더 추가 (HSTS 는 제외)

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

#### HSTS 를 붙이지 않는 이유

TLS 는 `tls internal`(Caddy 내부 CA 자체서명)이고, **이건 확정된 결정이다**(2026-08-09, 이슈 #518 —
정식 인증서 전환은 하지 않는다). 자체서명이라 브라우저는 `ERR_CERT_AUTHORITY_INVALID` 를 낸다.
이 상태에서 HSTS 를 보내면 브라우저가 그 호스트를 HSTS 목록에 올리고,
**HSTS 호스트에서는 인증서 예외("고급 → 계속 진행")가 아예 허용되지 않는다.** 즉 접속 수단이
사라지고, `max-age` 가 만료되기 전엔 사용자가 브라우저 내부 설정에서 HSTS 항목을 손으로 지우는 것
말고는 되돌릴 방법이 없다. 그래서 붙이지 않는다.

자체서명을 쓰는 이유와 그 대가(에이전트 루트 CA 배포)는
[`caddy/README.md`](caddy/README.md) **"자체서명을 쓰는 이유"** 한 곳에 둔다.
