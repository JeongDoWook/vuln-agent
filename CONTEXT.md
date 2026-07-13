# CONTEXT.md — 프로젝트 맥락 (Claude Code 최우선 참고)

> 이 파일은 개발을 이어받는 사람(및 Claude Code)이 **가장 먼저 읽는** 요약이다.
> 쉬운 설명은 `docs/설명글.md`, 대회용 기획 문서는 `docs/기획안_v1.0.html`
> (둘 다 현행 구현 기준으로 갱신됨). 구조·규칙의 최종 기준은 이 파일과 `docs/architecture.md`.
> 전체 프로세스 소개 페이지는 웹으로 서빙된다 — `server/public/process.html` → `/process.html`
> (사본을 두지 않는다. 예전에 `docs/` 에도 같은 파일이 있었는데 두 벌이 어긋났다).

---

## 1. 이 프로젝트가 뭔가

**취약점을 스스로 조사·판단·조치하는 자율 보안 에이전트.**
각 서버에 경량 에이전트를 두고, 설치된 패키지·런타임 정보를 중앙으로 모아
CVE와 매칭한다. 단순 스캐너와 다른 점은 **"이 취약점이 이 서버에서 실제로
위험한가"를 맥락으로 판단**해 오탐을 줄이고 우선순위를 매긴다는 것.

- 대회: 2026 오픈소스 개발자대회 (자유과제 / 보안·안전)
- 라이선스: 직접 작성 코드는 **MIT** (OSI 인증, 규정 제8조)
- 저장소: **Public 유지** (규정 제10조, 수상 시 5년)

---

## 2. 핵심 전략 (가장 중요 — 여기서 방향이 갈린다)

**매칭 정확도로 경쟁하지 않는다.**
"이 패키지 버전에 이 CVE 가 영향을 주는가"는 이미 잘 정리된 데이터(OSV·NVD·KEV·EPSS)가 있다.
직접 규칙을 짜면 오히려 오탐이 는다.

→ **매칭 판정은 검증된 피드(OSV API 직접 조회)에서 상속받고, 우리 기여는 그 위 레이어에 둔다.**
   (Trivy·Grype 같은 스캐너 바이너리를 호출하는 방식은 검토했으나 채택하지 않았다 — OSV 를
   직접 조회하는 편이 배포판 ecosystem·소스패키지 단위로 다루기 단순했다.)

### 우리의 차별점 (강한 순서)
1. **런타임 노출 상관** ★최우선 — "취약 라이브러리 → 그걸 로드한 프로세스 →
   그 프로세스가 연 외부 포트"를 이어서 판단. 설치만 된 것과 실제 노출된 것을 구분.
2. **EPSS + CISA KEV** — 실제 악용 확률/악용된 목록으로 우선순위. CVSS만 안 봄.
3. **설명가능한 오탐 억제** — 백포트 changelog 를 근거로 억제하고, **왜 안전한지 근거를 화면에
   남긴다**(숨기지 않는다). VEX 문서 산출은 하지 않기로 했다 — 소비할 곳이 없다(YAGNI).
4. **경량 상주 에이전트 + 시계열** — 매시간 수집, 변화 추적(`changes.php`), 함대 대시보드.
5. **KISA 국내 연동** — 해외 도구가 안 하는 국내 보안공지 매칭.

---

## 3. 확정된 스택

| 영역 | 스택 | 시점 |
|---|---|---|
| 수집 에이전트 | **Bash 쉘 스크립트** | 완성됨 |
| 웹 + 백엔드 + 매처 | **PHP** | 완성됨(핵심) |
| DB | **MySQL** | 완성됨(핵심) |
| 인프라 | **Docker + docker-compose** (PHP + MySQL) | 완성됨 |
| HTTPS 배포 | **Caddy 리버스 프록시** (Let's Encrypt DNS-01, 현재 자체서명) | 완성됨 |
| AI 문서 생성 | **Python** (오픈웨이트 로컬 모델) | **범위 제외** — 결과는 `GET /export.php`(JSON/XML)로 넘긴다 |

> 1~2단계(수집·매칭·표시)엔 AI 불필요(DB 조회지 추론 아님). AI 보고서 생성기는 본체에 넣지 않고
> **Export API 로 분리**해 외부 시스템이 가져가게 했다(경계가 깨끗하고, 본체가 AI 에 묶이지 않는다).
> 상용 API(Claude/GPT)는 코드 작성 보조로만 사용 → 규정상 자유, 보고서에 기재.

---

## 4. 이미 만들어진 것 (재사용)

### `agent/vuln-inventory-agent.sh` (v2.1) — 수집 에이전트, 동작 검증 완료
읽기 전용. 서버에 무리 안 감(nice 19 / ionice idle / 명령별 timeout / 피크 메모리 ~7MB).
jq 있으면 JSON, 없으면 섹션 텍스트로 출력. RHEL/Debian 계열 자동 감지.

**수집 항목(취약점 매핑에 중요한 것 위주):**
- `pkg` — 전체 패키지 목록. **NEVRA(릴리스번호 포함) + 소스패키지명 + 벤더**.
  (릴리스번호·소스패키지가 백포트 인식/오탐 감소의 핵심)
- `exposure` — **런타임 노출 상관** (차별점 ①). 리스닝 소켓마다: `pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs`
  - `scope` = EXTERNAL(0.0.0.0/::) / LOCAL(127.0.0.1) / BOUND(특정IP)
- `runtime.processes` — **실행 중인 모든 프로세스**(포트 없어도): `pid|comm|user|exe_pkg|loaded_pkgs`
  - 리스닝만이 아니라 "실행중/사용중"까지 잡아 상태를 정밀 구분(→ §7)
- `updates` — 미적용 보안업데이트 + 이미 적용된 보안권고(오탐 감소용)
- `changelog` — 패키지 changelog 의 **CVE 수정 기록**(백포트 억제의 근거 → §7). 기본 수집,
  가장 무거운 단계라 `--no-changelog` 로 끌 수 있고 `--limit` 로 cgroup CPU/메모리 상한을 건다
- `net` / `services` — 포트, 실행 서비스/프로세스
- `system` — OS/커널/CPE (어떤 OVAL로 대조할지 힌트)
- 그 외: 커널 CPU취약점 완화상태, 컨테이너 이미지, 언어패키지(pip/npm), 보안설정 등

### `agent/install-agent.sh` — 배포 설치기
각 대상 서버에서 `sudo bash install-agent.sh` — 인자 없이 실행하면 서버 주소·토큰·주기를 물어본다
(TTY 아니면 종전대로 `--server/--token` 인자 필수. 도메인만 넣어도 스킴·`/ingest.php` 자동 보정).
systemd-timer(우선)/cron 으로 주기 수집(기본 매시간) 등록 + 즉시 1회 실행(통신 확인). 설치물은
`--prefix`(기본 `/opt/vuln-agent`) 아래 `bin`/`etc`/`logs` 로 모이고, 토큰은
`<prefix>/etc/agent.env`(600) 로 관리(ps 노출 방지). 컨테이너가 떠 있는 호스트에서도 다른
mount namespace(컨테이너)는 건너뛰고 **호스트 자신만** 인벤토리(`collect_processes`) — 컨테이너
오버레이 경로의 `dpkg -S` 전수조사로 멈추는 문제를 회피.

---

## 5. 폴더 구조 (목표)

```
vuln-agent/
├── CONTEXT.md  README.md  CLAUDE.md(개발원칙)
├── deploy/       # 배포 인프라 (compose·러너·caddy·config)
│   ├── compose.yml  compose.common/dev/prod.yml  compose_runner.sh   # dev/prod 도커
│   ├── update.sh  .env.{dev,prod}.template                           # 운영 업데이트·설정 템플릿
│   ├── caddy/     # HTTPS 리버스 프록시(운영 전용): Dockerfile·Caddyfile·entrypoint.sh
│   └── config/mysql/my.cnf   # 운영 MySQL 튜닝
├── secrets/(*.txt gitignore)   data/(mysql, gitignore)              # 비밀값·DB 데이터 (루트 유지)
├── agent/
│   ├── vuln-inventory-agent.sh   # 수집(패키지·노출·실행프로세스), --send 전송
│   └── install-agent.sh          # 각 서버 배포·스케줄(systemd-timer/cron)
├── server/
│   ├── Dockerfile
│   ├── public/   # ingest·rematch·export·feed_preview(API) + login/index/host/findings/changes/cves/cve/
│   │             #   packages/advisories/advisory/assets/connectors/users/permissions/api-tokens/activity/profile(웹)
│   │             #   process.html — 프로세스 소개(로그인 불필요, /process.html 로 공유)
│   ├── src/      # config·db·auth(RBAC)·view·matcher(+백포트억제)·feeds·cce·apitoken·audit(감사로그·소프트삭제)
│   └── bin/      # scheduler.php(사이드카)·sync.php·backfill_nvd/kisa/kisa_content·rebuild_advisory_cveids
├── db/           # 01~13 *.sql (빈 볼륨 initdb 전용, tb_ 접두사+감사4컬럼)
│   └── migrations/    # NNNN_*.sql — deploy/migrate.sh 가 자동 적용(tb_schema_migrations 기록)
├── docs/         # 아키텍처·기획안·설명글·피드소스-역할·export-api
└── shadow-ai/    # (사이드 PoC) 섀도우 AI DLP 크롬 확장 — 본 파이프라인과 독립
```

---

## 6. 데이터 흐름 (확정)

```
[원격 대상 서버]                    [중앙 서버 · Docker]
쉘 에이전트 ── 매시간(systemd-timer) ──▶ Caddy(HTTPS:8080) ──▶ ingest.php ──▶ MySQL(tb_*)
(수집, install-agent.sh 로 배포)     JSON POST                              │
                                                                           ▼
[중앙 서버 자신(로컬 에이전트)] ─▶ web:8081(루프백 평문) ──────────────────┘
                                                                           │
                                                     로컬 CVE 미러(NVD·OSV·KISA)와 매칭
                                                     + 런타임 노출 상관 + EPSS/KEV 가중
                                                                           │
                                                                           ▼
                                          PHP 웹 대시보드 (우선순위·변화추적·억제근거·감사로그)
```

---

## 7. 매처 핵심 규칙 (구현됨)

수집한 `packages` + `exposures`(포트) + `processes`(실행/로드)를 CVE와 조인해
각 취약점의 **런타임 상태**를 5단계로 판정하고 우선순위를 매긴다.

| 상태 | 조건 | 레벨 |
|---|---|---|
| `EXTERNAL` 외부노출 | 외부(0.0.0.0) 오픈 포트로 노출 + 사용 | 3 (HIGH) |
| `LISTENING` 로컬리스닝 | 리스닝하지만 127.0.0.1만 | 2 (MEDIUM) |
| `RUNNING` 실행중 | 실행 중이나 포트 미개방 | 2 (MEDIUM) |
| `LOADED` 사용중 | 실행 프로세스가 라이브러리 로드 | 2 (MEDIUM) |
| `INSTALLED` 설치만 | 아무 프로세스도 안 씀 | 1 (LOW) |

- **KEV 등재** 시 한 단계 상향 → 외부노출 + KEV = **CRITICAL**.
- **EPSS**(악용확률) · CVSS 는 같은 등급 내 정렬에 사용.
- **백포트 억제**(2단): ① OSV 버전필터(배포판 전체버전 대조)로 1차 제거 → ② 그걸 통과한 건도
  패키지 **changelog 에 그 CVE 수정 기록이 있으면** finding 으로 올리지 않고 `tb_suppressed_findings`
  로 분리한다. 위험 집계·화면은 그대로 두고 오탐만 빠지며, 억제 근거는 호스트 상세에 노출된다.

즉 "설치=취약"으로 전부 올리지 않고, **실제 노출·실행·사용 여부로 우선순위를 가른다.**

**보안설정 점검(CCE)** 은 같은 수집물을 다른 눈으로 본다 — CVE(취약한 버전)가 아니라 잘못된 설정
(SSH root 로그인·패스워드 인증·UID 0 계정·SELinux/AppArmor·방화벽)을 `src/cce.php` 가 판정해
`tb_cce_findings` 에 저장한다. 신규 수집은 없다.

---

## 8. 개발 현황 (2026-07 기준 — 파이프라인·HTTPS·감사 + 오탐억제/CCE/변화추적/Export 완성)

- [x] **0. Docker** — compose dev/prod + Dockerfile + Docker Secrets(txt) + 러너
- [x] **1. 수집→전송→저장** — 에이전트 `--send` POST + `ingest.php` 수신 + DB
- [x] **2. 매처** — 노출 맥락 우선순위(외부노출+로드+KEV=CRITICAL), findings + 아키텍처 다이어그램
- [x] **3. 웹** — 로그인(users 세션) → 대시보드 → 호스트 상세 → 취약점(+조치·EPSS·상태) · 사용자관리
- [x] **4a. CVE 피드 커넥터** — 커넥터 5종(KEV/OSV/NVD/KISA/EPSS), UI 설정·미리보기·cron 스케줄, 스케줄러 사이드카
- [x] **4b. 국내특화** — KISA 보안공지 수집·표시(상세 본문까지) + 공지 상세 페이지 `advisory.php`
- [x] **NVD 전체 데이터** — tb_cves 약 36만건. 주기 수집을 수정일(lastMod) 기준으로 전환(뒤늦게 CVSS 붙는 CVE 추적, 120일 상한).
      전체 백필 `bin/backfill_nvd.php`(멱등·재개, 병렬 워커로 가속). CVE 목록 페이지 `cves.php`(검색·심각도/KEV/연도 필터·CVSS/EPSS 정렬).
      API 키는 DB 저장(코드·저장소에 없음). 일시 오류 재시도·CVE-ID 형식 검증·긴 텍스트 컬럼 확장(summary MEDIUMTEXT, cve_ids/note TEXT).
- [x] **정밀 런타임 수집** — 실행 프로세스 전체(실행중/사용중) + 노출(포트) → 상태 5단계 구분
- [x] **OSV 자동 매칭** — 수집 전 패키지를 OSV 조회(배포판 ecosystem, 소스패키지·버전필터) → 취약점 전체 발굴 + 조치안(fixed_version)
- [x] **EPSS/KEV** — 악용확률 + 악용목록으로 우선순위·정렬
- [x] **배포 설치기** — `agent/install-agent.sh` (systemd-timer 우선/cron 폴백, 매시간 자동 수집)
- [x] **HTTPS 배포** — `caddy/` 리버스 프록시가 TLS 종료(Let's Encrypt DNS-01, 현재 자체서명).
      접속 `https://ost-server.duckdns.org:8080`. web·db 는 내부망/루프백(`127.0.0.1:8081`)만 노출.
- [x] **무중단 배포** — prod 가 `../server` 를 읽기전용 마운트. PHP 만 바뀌면 `deploy/update.sh`(=`git pull`)로 끝(opcache 가 2초 내 반영).
      Dockerfile·compose·caddy 변경 시에만 재빌드. 서버 디렉토리는 `/apps/vulnagent/{app,bin,etc,logs,data,backups}` 로 통합.
- [x] **웹 대개편** — 페이지네이션(`vg_page_nav`) · 검색/필터(`vg_toolbar`, findings/advisories/cves)
      · CVE 목록 `cves.php` · CVE 상세 `cve.php` · 공지 상세 `advisory.php` · 공통 렌더(`vg_table`) · 긴 텍스트 말줄임(`vg_trunc`)
- [x] **DB 대개편** — 전 테이블 `tb_` 접두사 통일 + 감사 4컬럼(`created_at/updated_at/is_deleted/deleted_at`)
      · 소프트삭제(`vg_soft_delete()`: users/feed_connectors/advisories/hosts/scans, findings 등 재계산
      캐시는 예외) · 활동 감사로그 `tb_activity_log`(`vg_log_activity()` — 로그인·커넥터저장/삭제/실행·
      사용자추가/삭제·ingest 수신을 기록) + 조회 화면 `activity.php`(scope 필터·페이지네이션).
- [x] **백포트 억제(차별점 ③ 설명가능한 오탐 억제)** — 에이전트 changelog 의 CVE 수정 기록으로
      "버전은 낮아도 이미 패치됨"을 증명해 finding 을 `tb_suppressed_findings` 로 분리(위험 집계에서 자동 제외).
      숨기지 않고 근거와 함께 호스트 상세에 표시. 스케줄 수집에서 changelog 가 기본값.
- [x] **보안설정 점검(CCE)** — 이미 수집한 sshd·계정·MAC·방화벽 값을 `src/cce.php` 가 판정 → `tb_cce_findings`,
      호스트 상세에 PASS/FAIL/NA. 신규 수집 없음(수집물 재활용).
- [x] **변화 추적(차별점 ④ 시계열)** — `changes.php`: 최근 2개 스캔을 대조해 신규/해결/등급상승·하락.
      새 테이블 없이 `tb_findings` 만 비교((cve_id, package_name) 기준).
- [x] **자산 관리 + 설정형 RBAC** — `assets.php`(호스트 자산·소프트삭제) · 역할 3단계(admin/operator/user) ·
      역할×메뉴 권한을 `permissions.php` 에서 설정(`tb_role_permissions`, 가드는 `vg_require_menu()`).
      admin 은 코드에서 항상 전체 허용(잠금 방지).
- [x] **Export API** — `GET /export.php`(JSON/XML, 호스트·심각도·KEV·EPSS 필터). 전용 읽기 토큰을
      `api-tokens.php` 에서 발급(DB 엔 SHA-256 해시만, 원문은 1회 표시). 인증 헤더 `X-API-Token`
      또는 `Authorization: Bearer`(Apache 가 스트립해도 우회). 상세: `docs/export-api.md`.
- [x] **스키마 마이그레이션 자동화** — `deploy/migrate.sh` 가 `db/migrations/NNNN_*.sql` 중 미적용분만
      순서대로 적용하고 `tb_schema_migrations` 에 기록(`up`·`update.sh` 가 자동 호출, 수동 apply 불필요).
      최상위 `db/01~13*.sql` 은 빈 볼륨 initdb 전용이라 기존 볼륨엔 안 들어간다 → 증분은 `migrations/` 로.
- [x] **UI** — 좌측 사이드바(대분류/중분류) · CVE 목록 탭(전체/KEV/EPSS 상위) · 영향 패키지 목록 `packages.php`
      · EPSS 백분위 병기 · 필터 즉시 적용.
- [ ] 대시보드 "다음 수집 예정", 알림

> 매칭 자체는 OSV 등 검증된 소스에서 상속. 우리 기여는 그 위 레이어(런타임 상태·백포트 억제·KEV/EPSS·설명가능성).
> Python AI 문서생성은 본체 범위에서 제외 — Export API 로 결과만 넘긴다.
> `shadow-ai/`(섀도우 AI DLP 크롬 확장)는 같은 저장소의 **사이드 PoC** 로, 위 파이프라인과 무관하게 독립 동작한다.
