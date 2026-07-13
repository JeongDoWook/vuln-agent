# vuln-agent

런타임 노출 맥락으로 오탐을 줄이는 자율 취약점 진단 에이전트 (2026 오픈소스 개발자대회)

> 프로젝트 전체 맥락·전략·로드맵은 [`CONTEXT.md`](CONTEXT.md) 참고.

## 구성

```
agent/    수집 에이전트 (Bash) — 패키지·런타임 노출·백포트 changelog 수집 + install-agent.sh(systemd-timer/cron 자동 배포). 설치·운영은 agent/README.md
server/   PHP 중앙 서버 — 수신 API(ingest)·Export API + 웹(대시보드·취약점·변화추적·CVE·자산·국내공지·시스템) + 매처
deploy/   배포 인프라 — compose 파일·러너·caddy(HTTPS 리버스 프록시, 운영 전용)·migrate.sh(스키마 자동 적용)·wt.sh
db/       MySQL 스키마 — tb_ 접두사 + 감사 4컬럼. 최상위 *.sql 은 빈 볼륨 초기화용, 증분 변경은 migrations/
docs/     아키텍처 · 기획안 · 설명글 · 피드소스-역할(커넥터 5종) · export-api
          (전체 프로세스 소개는 웹으로 서빙 — server/public/process.html → /process.html)
shadow-ai/  (사이드 PoC) 섀도우 AI DLP 크롬 확장 — AI 챗봇 입력창의 민감정보 탐지. 본 파이프라인과 독립
```

**꼭 볼 문서**
- [`agent/README.md`](agent/README.md) — 에이전트 설치·운영. 설치 한 번이면 systemd 타이머가 매시간 자동 재실행(계속 켜둘 필요 없음), 전송 URL 주의점.
- [`docs/피드소스-역할.md`](docs/피드소스-역할.md) — NVD/OSV·EPSS·KEV·KISA 각 커넥터가 무슨 질문에 답하는지.
- [`docs/architecture.md`](docs/architecture.md) — 시스템 구조·매처 규칙·배포 방식.
- [`docs/export-api.md`](docs/export-api.md) — 스캔 결과 내보내기 API(JSON/XML)·API 토큰 발급.

데이터 흐름: **에이전트(JSON) ─POST(HTTPS)→ `ingest.php` → MySQL(`tb_*`) → 웹 현황**

## 빠른 시작 (Docker · 러너 스크립트)

모든 것은 컨테이너로 동작한다(로컬 PHP/MySQL 불필요). 환경은 **dev / prod** 두 가지.
러너·compose 파일은 모두 `deploy/` 에 있다(`cd deploy` 후 실행).

```bash
cd deploy
./compose_runner.sh init            # .env.dev / .env.prod 생성(템플릿 복사) → 비밀값 수정
./compose_runner.sh doctor          # 사전 점검
./compose_runner.sh dev  up -d --build   # 개발 환경 기동
./compose_runner.sh dev  down            # 중지
./compose_runner.sh dev  logs -f         # 로그
```

운영 서버(리눅스)에서는 `dev` 대신 `prod`. 앞단에 **Caddy 가 자동으로 HTTPS 를 붙인다**
(Let's Encrypt DuckDNS DNS-01, 현재는 자체서명 — 상세: [`deploy/caddy/README.md`](deploy/caddy/README.md)):

```bash
cd deploy
./compose_runner.sh init                 # .env.prod 의 비밀값을 강한 값으로 교체
./compose_runner.sh prod up -d --build
```

이후 업데이트는 `deploy/update.sh` 한 줄이면 된다. **바뀐 파일을 보고 스스로 갈라진다** —
`server/` 아래 PHP 만 바뀌었으면 `git pull` 로 끝(무중단, 소스가 읽기전용으로 마운트돼 있고
opcache 가 2초마다 파일 갱신을 확인한다). `Dockerfile`·`compose*.yml`·`caddy/`·`config/` 가
바뀔 때만 재빌드한다. **스키마 변경은 `deploy/migrate.sh` 가 자동 적용한다** — `db/migrations/`
의 `NNNN_*.sql` 중 아직 안 든 것만 번호순으로 돌리고 `tb_schema_migrations` 에 기록하므로,
스키마를 바꾸려면 파일 하나만 추가하면 된다(`up` 과 `update.sh` 가 자동 호출).

```bash
bash deploy/update.sh
```

| | dev | prod |
|---|---|---|
| 소스 | `./server` 라이브 마운트(즉시 반영) | `../server` 읽기전용 마운트(PHP 는 배포=`git pull`, 무중단) |
| DB 포트 | 호스트에 노출(3307) | **미노출**(내부 네트워크만) |
| 웹 접속 | 평문 `http://localhost:8080` | **HTTPS** `https://ost-server.duckdns.org:8080` (Caddy) |
| 환경변수 | `.env.dev` | `.env.prod` |
| 프로젝트명 | `vulnagent-dev` | `vulnagent` |

`wt/<이름>/` 워크트리에서 dev 를 띄우면 프로젝트명·컨테이너명·이미지태그에 `-<이름>` 이 붙고
포트도 따로 잡히므로, 메인 dev 스택(8080)과 나란히 돌릴 수 있다. 워크트리 만들기는
`./deploy/wt.sh add feat/무엇` — 자세한 규칙은 [CLAUDE.md](CLAUDE.md#작업-파이프라인) 참고.

- 현황 페이지(dev): <http://localhost:8080>
- 현황 페이지(prod): <https://ost-server.duckdns.org:8080> (자체서명 인증서 → 브라우저 경고 뜸)
- 수신 API: `POST .../ingest.php` (헤더 `X-Agent-Token`). prod 는 web 이 외부에 직접 노출되지
  않고, 중앙서버 자신을 스캔하는 로컬 에이전트만 루프백 평문 `127.0.0.1:8081` 로 직접 전송한다.

### 파일 구조 (compose · 모두 `deploy/` 하위)

```
deploy/compose.yml         서비스 정의 (db=MySQL, web=PHP/Apache)
deploy/compose.common.yml  공통 런타임 (restart, 로깅, pids_limit)
deploy/compose.dev.yml     개발 override
deploy/compose.prod.yml    운영 override (+ caddy: HTTPS 리버스 프록시)
deploy/.env.{dev,prod}.template   → init 이 .env.{dev,prod} 로 복사(커밋 제외)
deploy/compose_runner.sh   실행 러너
deploy/caddy/ deploy/config/   caddy 이미지 · MySQL my.cnf
```

compose 경로 기준: `../server`·`../db`·`../secrets`·`../data` 는 저장소 루트, `./caddy`·`./config` 는 `deploy/` 내부.

## 에이전트 실행 & 전송

수집 대상 서버(Linux)에서:

```bash
# 로컬 저장만
./agent/vuln-inventory-agent.sh

# 수집 후 중앙 서버로 전송 (파일 저장도 유지)
./agent/vuln-inventory-agent.sh \
    --send https://중앙서버:8080/ingest.php \
    --token .env의_INGEST_TOKEN값
```

전송하려면 대상 서버에 `jq`(JSON 출력)와 `curl`이 필요합니다.

### 배포 — 각 서버에 에이전트 설치 + 주기 수집

**방식: 에이전트-사이드 push** (각 서버가 로컬 스케줄로 수집 → 중앙으로 POST).
중앙이 각 호스트로 들어갈 필요 없음(아웃바운드만). 표준적인 에이전트 모델.

대상 서버(Linux)의 **`/opt/vuln-agent/`** 에 `agent/` 의 스크립트 2개를 두고 한 번
실행하면 끝. **인자 없이 실행하면 물어본다.**

```bash
sudo mkdir -p /opt/vuln-agent && sudo cp ~/agent/*.sh /opt/vuln-agent/
cd /opt/vuln-agent
sudo bash install-agent.sh
#   중앙 서버 주소 (예: ost-server.duckdns.org:8080):   ← 도메인만 넣어도 됨(스킴·/ingest.php 자동)
#   전송 토큰 (입력은 화면에 보이지 않습니다):          ← 중앙의 secrets/ingest_token.txt 값
#   수집 주기 [hourly] (daily / '*:0/30'=30분마다):     ← Enter 치면 hourly
```

`sudo` 만 있으면 되고 `chmod`/`chown` 은 필요 없다(자세한 이유는 [`agent/README.md`](agent/README.md)).
자동화(Ansible 등)로 무인 설치할 땐 인자로 넘긴다 — TTY 가 아니면 물어보지 않는다:

```bash
sudo bash install-agent.sh \
     --server https://ost-server.duckdns.org:8080/ingest.php \
     --token  <중앙의 secrets/ingest_token.txt 값> \
     --schedule hourly          # 또는 daily, '*:0/30'(30분마다, systemd)
```

설치 내용:
- 설치물을 `--prefix`(기본 `/opt/vuln-agent`) 한 곳에 배치 — `<prefix>/bin`(실행), `<prefix>/etc/agent.env`(600, 토큰), `<prefix>/logs`(수집 결과).
  토큰은 env 로만 전달해 `ps` 노출을 막는다. 운영 서버는 `--prefix /apps/vulnagent` 로 설치.
- **systemd-timer**(우선) 또는 **cron**(폴백)으로 주기 수집 등록(기본 매시간) + 즉시 1회 실행(통신 확인)
- 컨테이너가 떠 있는 호스트에서도 다른 mount namespace(컨테이너)는 건너뛰고 **호스트 자신만** 인벤토리
  — 컨테이너 오버레이 경로를 `dpkg -S`/`rpm -qf` 로 전수조사하다 멈추는 문제를 회피
- 제거: `sudo bash install-agent.sh --uninstall`

네트워크 요건: 대상 서버 → 중앙서버 `WEB_PORT`(기본 8080) **아웃바운드 HTTPS** 하나면 됨
(운영은 Caddy 가 앞단에서 TLS 를 받는다). 중앙 서버 자신을 스캔하는 로컬 에이전트만
루프백 평문 `127.0.0.1:8081` 로 직접 전송한다.

## 상태

- [x] 0. Docker 구성 (compose dev/prod + Dockerfile + Docker Secrets)
- [x] 1. 수집 → 전송 → 저장 (에이전트 POST + PHP 수신 + DB)
- [x] 2. 매처 (외부노출 + 로드됨 + KEV = CRITICAL) · findings.php · 아키텍처 다이어그램
- [x] 3. 웹 (로그인 → 대시보드 → 호스트상세 → 취약점 → CVE상세 · 사용자관리) + 검색/필터·페이지네이션
- [x] 4a. CVE 피드 커넥터 (CISA KEV 실데이터 · OSV · NVD · EPSS) + 스케줄러 사이드카
- [x] 4b. 국내 특화 — KISA 보안공지 커넥터 + 국내공지 페이지
- [x] HTTPS 배포 — Caddy 리버스 프록시(Let's Encrypt DNS-01, 현재 자체서명)
- [x] 에이전트 자동 배포 — install-agent.sh (systemd-timer 우선/cron 폴백, 매시간)
- [x] DB 전면 개편 — 전 테이블 `tb_` 접두사 + 감사 4컬럼(`created_at/updated_at/is_deleted/deleted_at`)
      + 소프트삭제 + 활동 감사로그(`tb_activity_log` + `activity.php` 조회 화면)
- [x] 백포트 오탐 억제 — 패키지 changelog 의 CVE 수정 기록으로 "버전은 낮아도 이미 패치됨"을 증명(아래 참고)
- [x] 보안설정 점검(CCE) — 이미 수집한 sshd·계정·MAC·방화벽 설정을 판정해 호스트 상세에 표시
- [x] 변화 추적 — 최근 2개 스캔 대비 신규/해결/등급변경 (`changes.php`)
- [x] 자산 관리 · 설정형 RBAC — 호스트 자산 화면 + 역할(admin/operator/user)×메뉴 권한을 UI 에서 설정
- [x] Export API — 스캔 결과 JSON/XML 내보내기 + 웹에서 발급하는 API 토큰
- [x] 스키마 마이그레이션 자동화 — `deploy/migrate.sh` + `db/migrations/`
- [ ] 대시보드 "다음 수집 예정", 알림

**웹 화면** (좌측 사이드바 · 역할별 권한으로 노출)

| 대분류 | 화면 |
|---|---|
| 대시보드 | `/` 호스트별 최신 스캔·심각도 KPI → 서버명 클릭 시 호스트 상세 `host.php`(노출·프로세스·취약점·CCE·억제 내역) |
| 취약점 | `/findings.php` 우선순위(+조치안) · `/changes.php` 변화 추적 · `/cves.php` CVE 목록 · `/packages.php` 영향 패키지 · `/advisories.php`·`/advisory.php` 국내 보안공지 |
| 자산 | `/assets.php` 호스트 자산 관리 |
| 피드 | `/connectors.php` 피드 커넥터(설정·스케줄·미리보기·지금 실행) |
| 시스템 | `/users.php` 사용자 · `/permissions.php` 권한 설정 · `/api-tokens.php` API 토큰 · `/activity.php` 감사 로그 |

API: `POST /ingest.php`(에이전트 수집 수신) · `POST /rematch.php`(재매칭) · `GET /export.php`
(결과 내보내기 — 상세: [`docs/export-api.md`](docs/export-api.md)).

각 취약점에는 **조치안**("어느 버전 이상으로 업데이트")이 함께 표시된다(OSV 의 fixed 버전).

### 감사 로그

로그인·커넥터 저장/토글/삭제·사용자 추가/삭제·ingest 수신이 `tb_activity_log` 에 자동
기록된다(`server/src/audit.php` 의 `vg_log_activity()`). `/activity.php`(admin 전용)에서
범위(scope) 필터 + 페이지네이션으로 조회한다. 삭제는 하드 DELETE 대신 `vg_soft_delete()`
로 `is_deleted/deleted_at` 를 세운다(대상: users/feed_connectors/advisories/hosts/scans).

### 런타임 상태 구분 (오탐 감소의 핵심)

에이전트는 리스닝 소켓뿐 아니라 **실행 중인 모든 프로세스 + 소속 패키지 + 로드한 라이브러리**를
수집한다. 매처는 이를 합쳐 각 취약점을 런타임 상태로 구분한다:

| 상태 | 의미 | 심각도 방향 |
|---|---|---|
| `외부노출` | 외부(0.0.0.0) 오픈 포트로 노출 + 사용 | 최상(+KEV=CRITICAL) |
| `로컬리스닝` | 리스닝하지만 로컬(127.0.0.1)만 | 중 |
| `실행중` | 실행 중이나 포트 미개방 | 중 |
| `사용중` | 실행 프로세스가 라이브러리 로드 | 중 |
| `설치만` | 설치만, 아무도 안 씀 | 하 |

"설치=취약"으로 전부 올리지 않고 **실제 노출·실행·사용 여부로 우선순위를 가른다.**

### 백포트 오탐 억제 (버전은 낮아도 이미 패치됨)

배포판은 버전 번호를 그대로 두고 보안 패치만 이식(백포트)한다. 버전만 보는 스캐너는 이걸
"취약"으로 잘못 잡는다. 1차로 OSV 버전필터(배포판 전체버전으로 대조)가 걸러내고, 그걸
통과한 건은 **패키지 changelog** 로 한 번 더 검증한다.

- 에이전트가 `rpm -q --changelog` / dpkg changelog 에서 **CVE 줄만** 뽑아 함께 보낸다
  (기본 수집. 가장 무거운 단계라 `--no-changelog` 로 끌 수 있다).
- 매처가 "이 빌드의 changelog 에 그 CVE 수정 기록이 있으면" 취약점으로 올리지 않고
  `tb_suppressed_findings` 로 **분리**한다 → 위험 집계·화면은 그대로 두고 오탐만 사라진다.
- 억제한 건은 숨기지 않고 **호스트 상세에 근거와 함께** 보여준다(설명가능성).

### 보안설정 점검 (CCE)

"취약한 버전"(CVE)이 아니라 **"잘못된 설정"** 을 본다. 새로 수집하지 않고 에이전트가 이미
보내온 `security`/`users` 섹션을 서버(`src/cce.php`)가 판정해 `tb_cce_findings` 에 저장하고
호스트 상세에 PASS/FAIL/NA 로 표시한다. 항목: SSH root 로그인 차단 · SSH 패스워드 인증 제한
· root 외 UID 0 계정 금지 · 강제접근제어(SELinux/AppArmor) 활성 · 호스트 방화벽 정책 존재.

### 권한 (설정형 RBAC)

역할은 **admin / operator / user** 3단계. `admin` 은 코드에서 항상 전체 허용(잠금 방지)이고,
`operator`·`user` 는 **역할 × 메뉴** 허용 여부를 `/permissions.php` 에서 켜고 끈다
(`tb_role_permissions`). 각 페이지는 `vg_require_menu('<메뉴코드>')` 하나로 가드한다.

### 피드 커넥터

외부 CVE 소스를 UI에서 설정·스케줄·수집한다 (admin → "피드").

- **CISA KEV** (기본 활성): 실제 악용 취약점 카탈로그 JSON, 무인증. 매일 자동 수집.
- **OSV.dev** (기본 활성): 수집된 **모든 패키지**를 OSV querybatch 로 조회(배포판별 ecosystem 자동, deb 는 소스패키지·설치버전 기준) → `cve_affected_packages` 를 실제로 채워 매처가 전 패키지를 검사. 시드 3개가 아니라 서버의 실제 취약점 전체를 발굴.
- **NVD 2.0**: 전체 CVE(약 36만건, CVSS·설명 포함). 주기 수집은 **수정일(lastMod) 기준** 증분이라 뒤늦게 CVSS 가 붙는 CVE 도 따라잡는다(120일 상한). 전체 이력은 `bin/backfill_nvd.php` 로 1회 백필(멱등, `--start-index` 재개). API 키는 DB(`connection_json.api_key`)에만 두고 코드·저장소엔 없다. `/cves.php` 에서 목록 조회.
- **FIRST EPSS** (기본 활성): CVE별 악용확률(0~1)을 매일 갱신 → KEV(이미 악용됨) + EPSS(악용 가능성)로 우선순위/정렬. findings·호스트 상세에 EPSS % 표시.
- **KISA 보안공지** (기본 활성): 보호나라 RSS 수집 → 국내공지 페이지. 해외 도구가 안 하는 국내 특화. 신규 공지는 **상세 본문까지 수집**해 `/advisory.php` 에서 그대로 보여준다(과거분은 `bin/backfill_kisa_content.php` 로 1회 채움).
- 스케줄러 사이드카(`scheduler` 컨테이너)가 1분마다 due 커넥터를 실행하고, 수집 후 전체 스캔을 재매칭. 중단돼 `running` 으로 굳은 실행도 정리한다.
- 수동 실행: 커넥터 행의 "지금 실행", 또는 `docker compose exec web php bin/sync.php <id>`.

**bin 스크립트(1회성 유지보수 — 웹 UI 로는 못 하는 일만 남겼다)**: `backfill_nvd.php`(NVD 전체 백필)
· `backfill_kisa.php`(국내공지 과거 이력) · `backfill_kisa_content.php`(공지 본문) ·
`rebuild_advisory_cveids.php`(cve_ids 재계산) · `sync.php`(커넥터 수동 실행).

> 백필이 왜 필요한가: KISA RSS 는 **피드당 최신 10건**(3종 = 30건)만 준다. 주기 수집으로는
> 과거 공지를 영원히 못 가져오므로 과거 이력은 `backfill_kisa.php` 로만 채울 수 있다.
> NVD 도 주기 수집은 수정일 기준 증분이라 전체 36만 건은 `backfill_nvd.php` 로 1회 채운다.

## 테스트

스택이 떠 있는 상태에서 API~웹 로그인까지 자동 검증:

```bash
./tests/smoke.sh            # 기본 http://localhost:8080
```

수집→저장→매칭(CRITICAL/HIGH 산출), 토큰 인증, 로그인 흐름을 curl 로 점검한다.
(브라우저 E2E는 나중에 Playwright 로 추가 예정)

## 라이선스

MIT — [`LICENSE`](LICENSE)
