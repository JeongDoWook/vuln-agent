# CONTEXT.md — 프로젝트 맥락 (Claude Code 최우선 참고)

> 이 파일은 개발을 이어받는 사람(및 Claude Code)이 **가장 먼저 읽는** 요약이다.
> 세부 기획은 `docs/기획안_v1.0.html`, 쉬운 설명은 `docs/설명글.md` 참고.

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
OS 패키지 ↔ CVE 매칭 자체는 Trivy·Grype·OpenSCAP 등 검증된 스캐너가 이미
배포판 보안 피드로 백포트까지 인식해 잘한다. 직접 만들면 오히려 오탐이 는다.

→ **매칭은 검증된 도구를 호출해 상속받고, 우리 기여는 그 위 레이어에 둔다.**

### 우리의 차별점 (강한 순서)
1. **런타임 노출 상관** ★최우선 — "취약 라이브러리 → 그걸 로드한 프로세스 →
   그 프로세스가 연 외부 포트"를 이어서 판단. 설치만 된 것과 실제 노출된 것을 구분.
2. **EPSS + CISA KEV** — 실제 악용 확률/악용된 목록으로 우선순위. CVSS만 안 봄.
3. **설명가능한 오탐 억제 → VEX** — 왜 안전/위험한지 근거 제시.
4. **경량 상주 에이전트 + 시계열** — 매일 수집, 변화 추적, 함대 대시보드.
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
| AI 문서 생성 | **Python** (오픈웨이트 로컬 모델) | 나중(마지막) |

> AI 모델은 3~4단계에서만 등장. 1~2단계(수집·매칭·표시)엔 AI 불필요(DB 조회지 추론 아님).
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
│   ├── public/   # ingest·rematch·feed_preview(API) + login/index/host/findings/cve/cves/advisories/advisory/connectors/users/activity(웹)
│   ├── src/      # config·db·auth·view·matcher·feeds·audit(감사로그·소프트삭제)
│   └── bin/      # scheduler.php(사이드카)·sync.php·enrich_osv.php·backfill_nvd/kisa/kisa_content·rebuild_advisory_cveids
├── db/           # 01~11 *.sql (초기화 시 자동 적용, tb_ 접두사+감사4컬럼)
│   └── _migrations/   # 기존 프로덕션 볼륨용 수동 1회 마이그레이션
└── docs/         # 아키텍처·기획안·설명글·프로세스
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
                                              PHP 웹 대시보드 (우선순위·변화·VEX·감사로그)
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
- 백포트 오탐: OSV 버전필터(배포판 전체버전으로 대조)가 이미 걸러냄(설치 버전에 실제 영향 주는 것만).

즉 "설치=취약"으로 전부 올리지 않고, **실제 노출·실행·사용 여부로 우선순위를 가른다.**

---

## 8. 개발 현황 (2026-07 기준 — 핵심 파이프라인 + HTTPS/감사 완성)

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
      사용자추가/삭제·ingest 수신을 기록) + 조회 화면 `activity.php`(admin 전용, scope 필터·페이지네이션).
      마이그레이션: `db/01~11`(신규 볼륨) + `db/_migrations/*.sql`(기존 프로덕션 볼륨 in-place, 1회성).
- [ ] 대시보드 "다음 수집 예정", 시계열/추이, 알림, Python AI(제외)

> 매칭 자체는 OSV 등 검증된 소스에서 상속. 우리 기여는 그 위 레이어(런타임 상태·KEV/EPSS·설명가능성).
> Python AI 문서생성은 범위에서 제외됨.
