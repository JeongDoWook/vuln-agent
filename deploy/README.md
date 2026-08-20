# deploy — 배포 인프라

> 문서 기준: 2026-08-20 · 운영 배포는 `update.sh`, 에이전트 일괄 설치는 `install_staged_agents.sh`가 정본이다.

중앙 서버(대시보드 + 수집 API)를 컨테이너로 띄우는 곳이다. compose 파일·러너·Caddy(HTTPS
리버스 프록시)·마이그레이션 러너가 모두 여기 있다. **모든 명령은 `cd deploy` 후 실행한다.**

- 전체 구조·매처 규칙: [`../docs/dev/architecture.md`](../docs/dev/architecture.md)
- 에이전트(대상 서버) 설치·운영: [`../agent/README.md`](../agent/README.md)
- 과거에 1회 조치가 필요했던 변경 기록(현행 규칙 아님):
  [`../docs/dev/archive/deploy-운영서버-1회조치.md`](../docs/dev/archive/deploy-운영서버-1회조치.md)
  — **그 시점 이전부터 돌던 서버**를 업데이트한다면 먼저 확인한다.

---

## 최초 배포 (새 서버에서)

```bash
cd deploy
./compose_runner.sh init                  # .env.dev / .env.prod 생성(템플릿 복사) → 비밀값 채우기
#   secrets/*.txt (mysql/admin) 와 .env.prod 를 이 서버 값으로 채운다.
./compose_runner.sh doctor                # 사전 점검(훅 설치·포트 등)
./compose_runner.sh prod up -d --build    # 운영 기동 — Caddy 가 자체서명 루트 CA 를 이때 생성한다
```

기동되면 대시보드가 **`https://<도메인>`**(443, 포트 없음)에 뜬다(Caddy 가 HTTPS 종료). 평문
`http://<도메인>` 은 308 로 https 에 리다이렉트되고, `https://<도메인>:8080` 도 계속 동작한다 —
이미 설치된 에이전트들이 그 주소로 등록돼 있어 **하위호환**으로 열어 둔다. 포트 구성·리다이렉트
상세는 [`caddy/README.md`](caddy/README.md).

**갱신은 서버에서 `bash deploy/update.sh` 한 줄이 전부다.** 코드가 어떤 경로로 도착했든(이
스크립트의 `git pull`, 사람이 손으로 친 `git pull`, 다른 세션의 배포) 이 한 줄이 마이그레이션·재빌드·
재생성을 빠짐없이 수행한다 — `compose_runner.sh` 를 따로 칠 일은 없다. `origin/main` 을 임시
worktree 에 먼저 checkout 해 그 버전의 migration 을 끝낸 뒤에만 운영 source 를 fast-forward 하므로
새 코드가 구 schema 를 먼저 읽는 노출 창이 없고, 어느 단계든 실패하면 운영 source 는 기존 commit 에
머물고 임시 worktree 는 자동 정리된다.

### 배포 마커 — 무엇과 비교해 재빌드를 정하나

`update.sh` 는 `[6/6]` 까지 전부 성공한 커밋 SHA 를 **`deploy/.deploy-state/last-deployed`** 에
적고, 다음 실행은 그 SHA 를 기준선으로 `git diff` 해서 재빌드/재생성을 판단한다 — 답해야 할 질문이
“이번 pull 이 무엇을 가져왔나”가 아니라 **“지금 돌고 있는 것과 무엇이 다른가”** 이기 때문이다.
예전엔 앞쪽(pull 델타)을 봐서, 코드가 손으로 먼저 pull 돼 있으면 `이미 최신` 이라며 그냥 나가
`Dockerfile`·`Caddyfile` 변경이 **영영 안 구워졌다.**

- 마커 파일은 **gitignore** 다. 추적하면 `[1/6] 사전 점검`의 `git status --porcelain` 이 더러워져
  배포 자체가 막힌다. 마커가 없으면(첫 도입·새 서버) 현재 체크아웃을 기준선으로 쓴다.
- 중간 단계가 실패하면 마커를 안 쓴다 → 다음 실행이 같은 일을 다시 시도한다(멱등).
- **한 번만 강제로 다시 굽고 싶다면** `rm deploy/.deploy-state/last-deployed` 대신
  `printf '%s\n' <옛 SHA> > deploy/.deploy-state/last-deployed` 로 기준선을 뒤로 돌린다(지우면
  “현재 체크아웃 = 기준선” 이 되어 오히려 아무것도 안 바뀐 것으로 보인다).
- 판단 로직 회귀는 `bash tests/update_sh_scenarios.sh` 가 검증한다(운영 서버 없이 도는 스텁 테스트).

### 운영 게이트 (`run-gates.sh` · `gates.tsv`)

필수 운영 검증은 `bash deploy/run-gates.sh --profile central --json`으로 실행한다. 각 check 에
`id`·`required`·`passed`·`duration_ms`·`evidence` 가 있고, required 실패가 하나라도 있으면 `ok=false`
와 종료코드 1이 함께 나온다. 로컬 pre-push 도 같은 `deploy/gates.tsv`·runner 를 쓰므로 Docker
미기동·현재 tree stack 불응·smoke 미실행을 성공 skip 으로 바꾸지 않는다.

- 검사 목록·프로파일(`pre-push` / `central`)·required 여부·의존관계는 **`deploy/gates.tsv` 한
  파일**이 정본이다. 검사를 늘리거나 required 를 바꾸려면 여기만 고친다.
- **`migration-rehearsal` 은 이 브랜치가 `origin/main` 대비 `db/migrations`·`db/*.sql` 을 실제로
  건드렸을 때만 돈다**(2026-08-20, #693 — 무거운 disposable MySQL 을 push 마다 띄우지 않기 위해).
  상세는 [`../db/migrations/README.md`](../db/migrations/README.md).
- `pre-push` 훅은 게이트를 환경변수로 우회할 수 없다. `VG_GATE_*`·`VG_SMOKE_BASE` 등 내부
  override 가 환경에 하나라도 있으면 push 자체를 거부한다(false green 차단).

---

## 에이전트 CA 준비 (최초 1회, 필수)

**왜 필요한가.** 중앙 Caddy 는 자체서명(`tls internal`)으로 HTTPS 를 한다. 대상 서버의 에이전트가
이 중앙에 HTTPS 로 전송하려면 **이 Caddy 의 루트 CA 를 신뢰**해야 한다. 꺼내 두면 자산 화면의
“에이전트 설치 안내”에서 `caddy-root.crt` 버튼으로 받아 대상 서버에 깔 수 있다.

**왜 레포에 없나.** 루트 CA 는 **이 배포의 Caddy 가 만든 고유값**이라, 오픈소스 레포에 커밋하면 남이
세운 배포가 내 CA 를 신뢰하게 되어 위험하다. `agent-ca/caddy-root.crt` 는 **gitignore** 다.

```bash
# 저장소 루트에서 실행 (deploy/ 아니라 그 상위). Caddy 가 뜬 뒤에 한다.
docker exec vulnagent-caddy cat /data/caddy/pki/authorities/local/root.crt > agent-ca/caddy-root.crt
```

- 컨테이너 이름은 운영에서 `vulnagent-caddy` 다(dev 는 Caddy 가 없다 — HTTP 라 CA 가 필요 없다).
- `agent-ca/` 는 web 컨테이너에 읽기전용으로 마운트돼 있어(compose), 파일을 만들면 **재시작 없이
  즉시** `agent-dl.php` 가 내보낸다. 준비 전이면 다운로드 버튼이 추출 명령을 알려주며 503 을 낸다.
- 이 파일은 **공개 인증서**다(개인키 아님). 공개돼도 안전하지만, 배포별 값이라 레포엔 안 넣는다.

**확인** — 서버 자신에서 loopback 으로:
```bash
curl -s http://127.0.0.1:8081/agent-dl.php?f=caddy-root.crt | head -1
#   -----BEGIN CERTIFICATE-----  → 정상. "아직 준비되지 않았습니다" → 위 추출을 안 한 것.
```

---

## 에이전트 일괄 설치·갱신 (`install_staged_agents.sh`)

노드들에 SSH 로 닿는 곳(master)에서 저장소의 최신 `agent/vuln-inventory-agent.sh` 를 여러 노드에
한 번에 밀어 넣고 재시작·버전 확인까지 한다. 대상을 안 주면 `deploy/agent_nodes.txt` 의 목록을 쓴다.

```bash
bash deploy/install_staged_agents.sh                       # agent_nodes.txt 의 노드 전체
bash deploy/install_staged_agents.sh 10.0.0.105 user@10.0.0.201   # 대상 지정
```

- 노드 목록은 저장소에 두지 않는다(내부망 인벤토리이므로 `.gitignore`). 처음 쓸 때
  `cp deploy/agent_nodes.txt.template deploy/agent_nodes.txt` 로 만들고 대상을 적는다(없으면
  스크립트가 안내 후 종료). SSH 사용자·설치 경로는 `AGENT_SSH_USER`·`AGENT_PREFIX` 로 바꾼다.
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

**CA 회전** — Caddy 루트는 10년짜리라 거의 바뀌지 않는다. `data`(caddy_data) 볼륨을 지우면 새로
생성되므로, 그때만 위 추출과 대상 서버 갱신을 다시 한다.

---

## DB 백업·복원

> **배포(`update.sh`)는 백업을 만들지 않는다.** 예전엔 배포가 백업·검증까지 했지만 2026-08-17
> (#640)에 **마이그레이션만 남기고 걷어냈다.**

| 언제 | 무엇을 | 실패하면 |
|---|---|---|
| 매일 새벽 4시(cron) | `backup_db.sh` — dump + gzip + 격리 복원 검증 → `restore=pass` 기록 | 실패 dump 는 `.failed` 로 0600 격리(정상 백업과 같은 최신 7개만 보존), `backup.log` 의 실패 시각으로 원인 조사 |
| 데이터를 지우는 마이그레이션 **전에**(사람) | `backup_db.sh` 를 손으로 돌려 `restore=pass` 확인 후 `update.sh` | 마지막 `restore=pass` 백업을 **새 DB 에 복원**한다 — 운영 schema 에 직접 시험 복원하지 않는다 |
| 기존 dump 를 다시 검증할 때 | `backup_db.sh --verify <파일> vulnagent-db` | 같음 — 원인을 고친 뒤 다시 검증한다 |
| 마이그레이션 직전·부분 실패 뒤 | `migrate.sh --preflight`, 기록만 실패했으면 같은 명령 재실행(멱등) | 재실행도 실패하면 확대 적용을 멈추고 직전 `restore=pass` 백업을 새 DB 에 복원 |

**무엇을 하는가.** `deploy/backup_db.sh` 가 `vulnagent-db` 컨테이너 안에서 `mysqldump`
(`--single-transaction --routines`)를 실행해 gzip 압축 후
`/apps/vulnagent/backups/vulnagent_YYYYMMDD_HHMMSS.sql.gz` 로 저장한다(비밀번호는 컨테이너 안에서
`/run/secrets/mysql_root_password` 를 읽어 쓰고 호스트엔 노출하지 않는다). 생성 직후 운영 DB 와
network·volume·secret 을 전혀 공유하지 않는 `--network none` 일회용 MySQL 컨테이너에 복원해, 운영
schema 의 table/column manifest 와 PK·FK·UNIQUE·NOT NULL 제약이 정확히 같고 `tb_host`·`tb_scan`
핵심 행과 참조 무결성(orphan scan 0건)을 통과할 때만 `restore=pass` 로 기록한다. crontab 에 한 줄:

```bash
crontab -e
# 매일 새벽 4시
0 4 * * * /apps/vulnagent/app/deploy/backup_db.sh >> /apps/vulnagent/backups/cron.log 2>&1
```

**왜 매일인가.** 예전엔 3일 주기(`0 4 */3 * *`)에 30일치였는데, `*/3` 은 일(day-of-month) 필드라
**월 경계에서 리셋돼** 간격이 들쭉날쭉했다(30일에 돌면 다음은 다음 달 3일).

보관 정책은 스크립트 상단 `KEEP=7`(매일 주기 기준 **7일치**) — `vulnagent_*.sql.gz` 만 최신 7개를
남긴다. **나이(mtime)가 아니라 개수 기준인 것도 의도적이다** — 나이 기준이면 실패가 며칠 이어질 때
남은 것까지 다 지워 0개가 된다. 기존 수동 백업(`pre_content_*`, `pre_tb_*`)은 패턴이 달라 건드리지
않고, 실행 결과는 `$BACKUP_DIR/backup.log` 에 한 줄씩 쌓인다.

> cron 한 줄과 `KEEP` 은 **짝이다.** 한쪽만 바꾸면 보관 기간이 의도와 달라지므로 `deploy/backup_db.sh` 를 정답으로 보고 양쪽을 함께 맞춘다.

### 데이터를 지우는 마이그레이션 전에는 백업을 먼저 돌린다

대량 `DELETE`·`DROP TABLE`·`DROP COLUMN`·조건 없는 `UPDATE` 처럼 **데이터를 지우거나 덮어쓰는** 것만
해당한다(컬럼 추가·인덱스 추가는 아니다).

```bash
# 운영 서버에서, 배포 **전에**. restore=pass 가 찍힐 때까지 기다린 뒤 update.sh 를 돌린다.
bash /apps/vulnagent/app/deploy/backup_db.sh
tail -1 /apps/vulnagent/backups/backup.log     # restore=pass 확인
bash /apps/vulnagent/app/deploy/update.sh
```

### 복원 rehearsal

```bash
# 기존 dump는 source 컨테이너의 image만 재사용하는 일회용 격리 컨테이너에서 검증
bash deploy/backup_db.sh --verify /apps/vulnagent/backups/vulnagent_YYYYMMDD_HHMMSS.sql.gz vulnagent-db
```

**검증 DB 는 RAM 이 아니라 디스크다.** 일회용 컨테이너의 `/var/lib/mysql` 은 익명 볼륨(`-v
/var/lib/mysql`)이고 `--rm`·`docker rm -fv` 가 함께 지운다. tmpfs 로 두면 복원 데이터가 **호스트
RAM** 을 DB 크기만큼 점유해 메모리가 고갈되고, 상한을 두면 이번엔 `ERROR 1114 … is full` 로
실패한다. `/var/run/mysqld`·`/tmp` 만 tmpfs 로 남는다(소켓·PID·임시파일뿐, 64m).

복원 전에 **디스크 여유를 먼저 확인**한다. 필요 용량은 덤프(압축) 크기가 아니라 원본 DB 의 실제
크기(`information_schema` 의 데이터+인덱스 합계)에 `VERIFY_DISK_HEADROOM_MULT`(기본 2)를 곱해
잡고 docker 데이터 경로(`docker info --format '{{.DockerRootDir}}'`)의 여유와 비교한다. 부족하면
컨테이너를 띄우지 않고 `backup verify: 디스크 여유 부족 …` 으로 즉시 실패한다(측정 불가 환경에선
경고만 남기고 진행).

### migration preflight와 부분 실패 복구

`deploy/migrate.sh`는 적용 전에 컨테이너의 `MYSQL_DATABASE`와 호출값 일치, DB 존재, 최소 1 GiB 여유
공간, schema version을 확인한다. `MIGRATION_REQUIRE_BACKUP`은 손으로 떠 둔 백업 파일을 지정해 돌릴
때 쓴다. 확인만 할 때:

```bash
MYSQL_DATABASE=vulnagent MIGRATION_REQUIRE_BACKUP=1 \
MIGRATION_BACKUP_FILE=/apps/vulnagent/backups/vulnagent_YYYYMMDD_HHMMSS.sql.gz \
bash deploy/migrate.sh vulnagent-db --preflight
```

DDL 적용 뒤 `tb_schema_migrations` 기록만 실패하면 스크립트는 성공으로 숨기지 않고 해당 파일명을
출력한다. migration 파일은 `db/migrations/README.md` 규칙대로 멱등이라 같은 명령을 재실행하면 된다.

---

## 운영 설정 — 세션 만료·토큰 유효기간

컴플라이언스 감사 §7-3(ISMS-P 2.6.3 세션 · 2.5.1 / N2SF SN·AC) 대응으로 로그인 세션과 에이전트
토큰에 만료가 있다. **`.env` 나 컨테이너 환경변수로 바꾸는 값이 아니다** — 아래 표대로 정한다.

| 무엇 | 지금 값 | 어디서 바꾸나 |
|---|---|---|
| 세션 **유휴** 만료 | 30분 | **웹 화면** 관리 → 설정(`session.idle_minutes`, 5~720분) |
| 세션 **절대** 만료 | 12시간(유휴와 무관) | **웹 화면** 관리 → 설정(`session.absolute_minutes`, 30~1440분) |
| 토큰 유효기간 선택지 | 무기한 / 30일 / 90일 / 1년 | 발급은 **웹 화면**(관리 → 에이전트 키), 선택지 자체는 `server/src/tokenexpiry.php` 의 `VG_TOKEN_EXPIRY_OPTIONS` |
| “만료 임박” 표시 기준 | 잔여 7일 | 같은 파일의 `VG_TOKEN_EXPIRY_SOON_DAYS`(목록 뱃지 표시용 — 인증 판정과 무관해 설정으로 빼지 않았다) |

- 설정을 저장하지 않으면(빈 `tb_setting`) `server/src/auth.php` 의 상수
  `VG_SESSION_IDLE_SECONDS`(1800초)·`VG_SESSION_ABSOLUTE_SECONDS`(43200초)를 쓴다 — 마이그레이션이
  안 든 DB 에서도 동작이 같다. 범위를 벗어난 값은 읽을 때 잘라 쓰므로 DB 를 직접 고쳐도 만료를
  0 이나 무한으로 만들 수 없다.
- 만료 판정 기준 시각(`login_at`·`last_activity`)은 **세션에만** 둔다(요청마다 DB 쓰기 없음).
  만료되면 감사로그(`session_expire`)가 남고, 로그인 화면이 "다른 곳에서 로그인됨"과 "시간 초과"를
  다른 문구로 안내한다. PHP 기본 `session.gc_maxlifetime`(1440초)이 유휴 30분보다 짧아 PHP 가
  먼저 세션을 날리던 문제는 코드가 `ini_set` 으로 맞춰 뒀다 — **손으로 만질 필요 없다.**
- 토큰은 `tb_agent_token` 의 `expires_at`(NULL = 무기한)으로 관리한다(Export API 읽기 토큰과
  `tb_api_token` 은 2026-08-13 폐지 — `export.php`·`sbom.php` 는 웹 로그인 세션 인증이다).
  **이 변경 이전에 발급된 토큰은 NULL 이라 그대로 무기한**이고, 만료된 토큰은 인증 실패(401)로
  처리되며 `agent_token_expired` 감사로그가 남는다. **자동 갱신·재발급은 없다** — 만료되면 사람이
  새로 발급하고 노드의 `agent.env` 를 갱신한다([`../agent/README.md`](../agent/README.md) “주의점” 1번).
- 스키마는 마이그레이션 `20260808105921_token_expires_at.sql` 이 멱등하게 얹는다 —
  `update.sh`(→ `migrate.sh`)가 자동 적용하므로 운영에서 손으로 할 일은 없다.

---

## 정적 자산 캐시 — 자산을 바꿨는데 옛 파일이 보일 때

`/assets/*`(app.css·app.js·페이지별 js·flatpickr 등)는 **브라우저에 5분간 캐시된다**
(`deploy/caddy/Caddyfile` 의 `Cache-Control: public, max-age=300, must-revalidate`). HTML 페이지는
대상이 아니다 — 로그인 세션이 걸린 화면은 그대로 `no-store` 다.

**보통은 배포 즉시 반영된다.** `vg_asset()`(`server/src/view/layout.php:15`)이 참조 URL 에
`?v=<파일 수정시각>` 을 붙이므로 파일이 바뀌면 URL 자체가 바뀌어 캐시를 안 탄다 — 저장소 안의
모든 자산 참조가 이 함수를 지난다. **옛 파일이 남는 경우는 두 가지뿐이다.**

| 상황 | 얼마나 | 강제 갱신 |
|---|---|---|
| 그 URL 을 직접 열었다(북마크·외부 링크·`curl`) — `?v=` 가 없다 | 최대 5분 | 강력 새로고침(`Ctrl+Shift+R`) 또는 5분 대기 |
| 중간 캐시(회사 프록시 등)가 5분치를 들고 있다 | 최대 5분 | 5분 대기 — 서버에서 무효화할 수단은 없다 |

즉시 확인이 필요하면 `?v=` 를 아무 값으로 바꿔 열면 된다(예: `/assets/app.css?v=999`). 서버에서
지워야 할 캐시는 없다 — **Caddy 는 응답을 저장하지 않는다.**

기간을 바꾸려면 `Caddyfile` 의 `max-age` 한 곳만 고친다. Caddyfile 은 이미지에 `COPY` 되지만
(`deploy/caddy/Dockerfile`) `update.sh` 의 `BUILD_RE` 가 이 파일을 이미 잡고 있어 **평소처럼
`update.sh` 만 돌리면 된다.** **`immutable` 이나 1년짜리 max-age 는 자산 파일명에 해시가 생기기
전엔 쓰지 않는다** — 위 표의 첫 줄이 영구화된다.

ETag 재검증(`If-None-Match` → `304`)은 Apache 쪽 `DeflateAlterETag NoChange`
(`server/Dockerfile`)가 담당한다. 기본값이면 gzip 응답 ETag 에 `-gzip` 이 붙어 나가는데 조건부
요청 비교는 원본 ETag 로 해서 **영원히 안 맞고 매번 본문 전체가 재전송된다**(2026-08-15 실측).
