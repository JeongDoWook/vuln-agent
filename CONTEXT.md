# CONTEXT.md — 프로젝트 맥락 (Claude Code 최우선 참고)

> 이 파일은 개발을 이어받는 사람(및 Claude Code)이 **가장 먼저 읽는** 요약이다.
> 쉬운 설명은 `docs/dev/설명글.md`, 대회용 기획 문서는 `docs/dev/기획안_v1.0.html`
> (둘 다 현행 구현 기준으로 갱신됨). 구조·규칙의 최종 기준은 이 파일과 `docs/dev/architecture.md`.
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
읽기 전용. 서버에 무리 안 감(nice 19 / ionice idle / 명령별 timeout).
**피크 메모리는 실측 61.6MB**(Debian 12 · 91패키지 — 마지막에 jq 로 전 섹션을 한 번에 조립하는
단계가 1등 요인이라 페이로드 크기에 비례한다). 수치·외삽·재측정법은
`docs/dev/에이전트-리소스-프로파일.md`, 실측기는 `tests/agent-bench.sh`.
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
- `containers` — **컨테이너 내부 패키지 인벤토리**(`collect_containers`). 실행 중 컨테이너의
  rootfs 를 직접 읽는다(docker CLI 비의존 → podman/containerd 도 잡힘). 호스트 패키지와는
  `container_id` 로 구분 저장. 호스트 스캔에서 통째로 빠지던 미탐 영역이었다.
- `errata` / `debsecan` — **오탐 억제 근거**(→ §7). 벤더가 "이 빌드에서 고쳤다"고 확인한
  권고 목록, 데비안 보안 트래커의 "이 버전에 아직 남은 CVE" 목록.
- **재시작·재부팅 필요** — 패치됐지만 프로세스가 옛 `.so` 를 물고 있거나(stale), 커널이
  패치됐지만 재부팅 전인 상태. **억제를 막는** 신호다(→ §7).
- `net` / `services` — 포트, 실행 서비스/프로세스
- `system` — OS/커널/CPE (어떤 OVAL로 대조할지 힌트)
- 그 외: 커널 CPU취약점 완화상태, 언어패키지(pip/npm), 보안설정 등

### `agent/install-agent.sh` — 배포 설치기
각 대상 서버에서 `sudo bash install-agent.sh` — 인자 없이 실행하면 서버 주소·토큰·주기를 물어본다
(TTY 아니면 종전대로 `--server/--token` 인자 필수. 도메인만 넣어도 스킴·`/ingest.php` 자동 보정).
systemd-timer(우선)/cron 으로 주기 수집(기본 매시간) 등록 + 즉시 1회 실행(통신 확인). 설치물은
`--prefix`(기본 `/opt/vuln-agent`) 아래 `bin`/`etc`/`logs` 로 모이고, 토큰은
`<prefix>/etc/agent.env`(600) 로 관리(ps 노출 방지). **프로세스** 인벤토리(`collect_processes`)는
다른 mount namespace(컨테이너)를 건너뛰고 호스트 자신만 본다 — 컨테이너 오버레이 경로의 `dpkg -S`
전수조사로 멈추는 문제를 회피. (컨테이너를 안 보는 게 아니다 — **패키지**는 `collect_containers`
가 rootfs 를 직접 읽어 따로 수집한다.)

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
│   │             #   packages/advisories/advisory/assets/connectors/users/user/permissions/api-tokens/
│   │             #   agent-tokens/activity/profile + remediations(조치관리)/vendor(벤더 판정 근거)/
│   │             #   compliance_rules·compliance_rule(SSG 룰셋 카탈로그) (웹)
│   │             #   agent-dl.php — 에이전트 설치 파일 배포(자산 화면 설치 모달의 다운로드 대상)
│   │             #   process.html — 프로세스 소개(로그인 불필요, /process.html 로 공유)
│   ├── src/      # config·db·auth(RBAC)·view·matcher(+백포트억제)·feeds·cce·apitoken·audit(감사로그·소프트삭제)
│   └── bin/      # scheduler.php(사이드카)·sync.php·backfill_nvd/kisa/kisa_content·rebuild_advisory_cveids
├── db/           # 01~18 *.sql (빈 볼륨 initdb 전용, tb_ 접두사+감사4컬럼)
│   └── migrations/    # YYYYMMDDHHMMSS_*.sql — deploy/migrate.sh 가 자동 적용(tb_schema_migrations 기록)
│                      #   연번(0001…)은 금지 — 동시 브랜치가 같은 번호를 집는다. pre-push 가 막는다.
│                      #   기존 0001~0020 은 그대로 둔다(사전순이라 옛 것이 먼저 돈다).
├── tests/        # smoke.sh(API~로그인 curl) · e2e.sh+e2e/(브라우저 JS, Playwright — 게이트 밖)
│                 #   · ui_lint.sh(죽은 CSS·인라인 style) · vercmp_test.php(버전비교 단위)
│                 #   · agent-bench.sh(에이전트 리소스 실측)
├── docs/         # 아키텍처·기획안·설명글·피드소스-역할·export-api·에이전트-리소스-프로파일
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
각 취약점의 **런타임 상태**를 7단계로 판정하고 우선순위를 매긴다(`vg_classify`).

| 상태 | 조건 | 레벨 |
|---|---|---|
| `EXTERNAL` 외부노출 | 외부(0.0.0.0) 오픈 포트로 노출 + 사용 | 3 (HIGH) |
| `LAN` 로컬 세그먼트 노출 | 링크로컬 멀티캐스트(mDNS/LLMNR/SSDP 등) — 0.0.0.0 이지만 **라우터를 못 넘어 같은 세그먼트만 닿음** | 2 (MEDIUM) |
| `FILTERED` 방화벽차단 | 전체 인터페이스에 떠 있지만 **방화벽이 그 포트를 막아 외부에서 못 닿음** | 2 (MEDIUM) |
| `LISTENING` 로컬리스닝 | 리스닝하지만 127.0.0.1만 | 2 (MEDIUM) |
| `RUNNING` 실행중 | 실행 중이나 포트 미개방 | 2 (MEDIUM) |
| `LOADED` 사용중 | 실행 프로세스가 라이브러리 로드 | 2 (MEDIUM) |
| `INSTALLED` 설치만 | 아무 프로세스도 안 씀 | 1 (LOW) |

- **KEV 등재** 시 한 단계 상향 → 외부노출 + KEV = **CRITICAL**.
- **EPSS**(악용확률) · CVSS 는 같은 등급 내 정렬에 사용.
- `FILTERED` 가 없으면 방화벽 뒤의 내부 서비스가 **전부 HIGH/CRITICAL 로 뜬다**(오탐).
  에이전트가 firewalld/ufw 허용 포트와 대조해 판정한다.

**오탐 억제는 4겹이다(데비안 중심).** 통과 못 한 건은 finding 이 아니라 `tb_suppressed_finding` 으로 분리된다
— 위험 집계·화면은 그대로 두고 오탐만 빠지며, **근거는 호스트 상세에 그대로 노출된다**(숨기지 않는다).

| 겹 | 근거 | 판정 |
|---|---|---|
| ① OSV 버전필터 | 배포판 전체버전 대조 | 영향 없는 버전이면 제거 |
| ② changelog | 패키지 changelog 의 CVE 수정 기록 | 있으면 억제 (핵심 13개 패키지) |
| ③ errata | 벤더가 "이 설치 빌드에서 고쳤다"고 확인한 권고 | 있으면 억제 (**시스템 전체** 커버) |
| ④ debsecan | 데비안 보안 트래커의 "아직 남은 CVE" 목록 | **없으면** 백포트로 고쳐진 것 → 억제 |

> debsecan 은 방향이 반대라 안전장치를 두 겹 뒀다 — `os_id=debian` 일 때만 쓰고(우분투는 OSV 의
> USN 경로로 이미 커버), **목록이 비면 억제하지 않는다**(수집 실패와 "취약점 0"을 구분할 수 없어
> 믿었다간 전부 억제해 버린다).

**RHEL 계열·우분투·커널은 각자의 벤더 소스로 별도 판정한다.** 데비안 4겹과 별개로, RHEL 계열은
`tb_vendor_errata`(OVAL 조치 EVR)+`tb_vendor_unfixed`(조치 불가), 우분투는 `tb_ubuntu_oval` 한
테이블이 조치 EVR·조치 불가를 모두 표현, 커널은 `tb_kernel_cve`(kernel.org CNA)가 배포판 밖의
커널(라즈베리·자체빌드)까지 판정한다. 벤더가 "아직 안 고쳤다"고 확인한 CVE 는 `tb_finding.no_fix`
로 표시한다 — 오탐 제거와는 다른 축으로, 등급은 그대로 두되 "지금 고칠 수 있는 것"과 "조치 불가"를
화면에서 분리한다.

**억제를 취소하는 두 신호** — "패치됨"이 곧 "안전함"이 아닌 경우다. 이게 없으면 미탐이 된다.

- **재시작 필요**(`tb_stale_lib`): 패치됐지만 프로세스가 옛 `.so` 를 메모리에 물고 있다 →
  그 프로세스는 **여전히 옛 코드를 실행 중**이므로 억제하지 않는다. 조치는 프로세스 재시작.
- **커널 재부팅 필요**: 커널을 패치해도 재부팅 전엔 옛 커널이 돈다 → 억제하지 않는다.
  조치는 **재부팅**(프로세스 재시작으로는 안 고쳐진다).

**미지원 배포판**(Amazon Linux · Oracle Linux · CentOS)은 피드가 안 덮어 매칭이 0건이 된다.
조용히 "취약점 없음"으로 보이면 위험하므로 `vg_distro_unsupported`(`src/distro.php`)가 판정해
ingest 응답과 취약점 화면에 **경고로 띄운다**.

즉 "설치=취약"으로 전부 올리지 않고, **실제 노출·실행·사용 여부로 우선순위를 가른다.**

**보안설정 점검(CCE)** 은 같은 수집물을 다른 눈으로 본다 — CVE(취약한 버전)가 아니라 잘못된 설정
(SSH root 로그인·패스워드 인증·UID 0 계정·SELinux/AppArmor·방화벽)을 `src/cce.php` 가 판정해
`tb_cce_finding` 에 저장한다. 신규 수집은 없다.

---

## 8. 개발 현황 (2026-07 기준 — 파이프라인·HTTPS·감사 + 오탐억제/CCE/변화추적/Export 완성)

- [x] **0. Docker** — compose dev/prod + Dockerfile + Docker Secrets(txt) + 러너
- [x] **1. 수집→전송→저장** — 에이전트 `--send` POST + `ingest.php` 수신 + DB
- [x] **2. 매처** — 노출 맥락 우선순위(외부노출+로드+KEV=CRITICAL), findings + 아키텍처 다이어그램
- [x] **3. 웹** — 로그인(users 세션) → 대시보드 → 호스트 상세 → 취약점(+조치·EPSS·상태) · 사용자관리
- [x] **4a. CVE 피드 커넥터** — 커넥터 11종(고정 5종 KEV/OSV/NVD/KISA/EPSS + 벤더 판정 6종 데비안 트래커·RHEL 계열 OVAL·Red Hat 미수정·우분투 OVAL·리눅스 커널 CNA·SCAP Security Guide) + 범용 API 커넥터(generic_api) = **합계 12종**, UI 설정·미리보기·cron 스케줄, 스케줄러 사이드카
- [x] **4b. 국내특화** — KISA 보안공지 수집·표시(상세 본문까지) + 공지 상세 페이지 `advisory.php`
- [x] **NVD 전체 데이터** — tb_cve 약 36만건. 주기 수집을 수정일(lastMod) 기준으로 전환(뒤늦게 CVSS 붙는 CVE 추적, 120일 상한).
      전체 백필 `bin/backfill_nvd.php`(멱등·재개, 병렬 워커로 가속). CVE 목록 페이지 `cves.php`(검색·심각도/KEV/연도 필터·CVSS/EPSS 정렬).
      API 키는 DB 저장(코드·저장소에 없음). 일시 오류 재시도·CVE-ID 형식 검증·긴 텍스트 컬럼 확장(summary MEDIUMTEXT, cve_ids/note TEXT).
- [x] **정밀 런타임 수집** — 실행 프로세스 전체(실행중/사용중) + 노출(포트) → 상태 7단계 구분
- [x] **OSV 자동 매칭** — 수집 전 패키지를 OSV 조회(배포판 ecosystem, 소스패키지·버전필터) → 취약점 전체 발굴 + 조치안(fixed_version)
- [x] **EPSS/KEV** — 악용확률 + 악용목록으로 우선순위·정렬
- [x] **배포 설치기** — `agent/install-agent.sh` (systemd-timer 우선/cron 폴백, 매시간 자동 수집)
- [x] **HTTPS 배포** — `caddy/` 리버스 프록시가 TLS 종료(Let's Encrypt DNS-01, 현재 자체서명).
      접속 `https://<운영-도메인>`(평문 80 은 https 로 308 리다이렉트, 기존 `:8080` 도 계속 동작).
      도메인은 저장소에 두지 않고 `.env.prod` 의 `PROD_DOMAIN` 으로 주입한다(Caddyfile 이 `{$PROD_DOMAIN}` 로 읽는다).
      web·db 는 내부망/루프백(`127.0.0.1:8081`)만 노출.
- [x] **무중단 배포** — prod 가 `../server` 를 읽기전용 마운트. PHP 만 바뀌면 `deploy/update.sh`(=`git pull`)로 끝(opcache 가 2초 내 반영).
      Dockerfile·compose·caddy 변경 시에만 재빌드. 서버 디렉토리는 `/apps/vulnagent/{app,bin,etc,logs,data,backups}` 로 통합.
- [x] **웹 대개편** — 페이지네이션(`vg_page_nav`) · 검색/필터(`vg_toolbar`, findings/advisories/cves)
      · CVE 목록 `cves.php` · CVE 상세 `cve.php` · 공지 상세 `advisory.php` · 공통 렌더(`vg_table`) · 긴 텍스트 말줄임(`vg_trunc`)
- [x] **DB 대개편** — 전 테이블 `tb_` 접두사 통일 + 감사 4컬럼(`created_at/updated_at/is_deleted/deleted_at`)
      · 소프트삭제(`vg_soft_delete()`: users/feed_connectors/advisories/hosts/scans, findings 등 재계산
      캐시는 예외) · 활동 감사로그 `tb_activity_log`(`vg_log_activity()` — 로그인·커넥터저장/삭제/실행·
      사용자추가/삭제·ingest 수신을 기록) + 조회 화면 `activity.php`(scope 필터·페이지네이션).
- [x] **백포트 억제(차별점 ③ 설명가능한 오탐 억제)** — 에이전트 changelog 의 CVE 수정 기록으로
      "버전은 낮아도 이미 패치됨"을 증명해 finding 을 `tb_suppressed_finding` 으로 분리(위험 집계에서 자동 제외).
      숨기지 않고 근거와 함께 호스트 상세에 표시. 스케줄 수집에서 changelog 가 기본값.
- [x] **보안설정 점검(CCE)** — 이미 수집한 sshd·계정·MAC·방화벽 값을 `src/cce.php` 가 판정 → `tb_cce_finding`,
      호스트 상세에 PASS/FAIL/NA. 신규 수집 없음(수집물 재활용).
- [x] **변화 추적(차별점 ④ 시계열)** — `changes.php`: 최근 2개 스캔을 대조해 신규/해결/등급상승·하락.
      새 테이블 없이 `tb_finding` 만 비교((cve_id, package_name) 기준).
- [x] **자산 관리 + 설정형 RBAC** — `assets.php`(호스트 자산·소프트삭제) · 역할 3단계(admin/operator/user) ·
      역할×메뉴 권한을 `permissions.php` 에서 설정(`tb_role_permission`, 가드는 `vg_require_menu()`).
      admin 은 코드에서 항상 전체 허용(잠금 방지).
- [x] **Export API** — `GET /export.php`(JSON/XML, 호스트·심각도·KEV·EPSS 필터). 전용 읽기 토큰을
      `api-tokens.php` 에서 발급(DB 엔 SHA-256 해시만, 원문은 1회 표시). 인증 헤더 `X-API-Token`
      또는 `Authorization: Bearer`(Apache 가 스트립해도 우회). 상세: `docs/dev/export-api.md`.
- [x] **컨테이너 스캔** — `collect_containers` 가 실행 중 컨테이너의 rootfs 를 읽어 **내부 패키지**를
      수집(`tb_container`, `tb_package.container_id`). docker CLI 비의존(podman/containerd 도 잡힘).
      호스트 스캔에서 통째로 빠지던 미탐 영역이었다. 호스트 상세·취약점 목록에서 컨테이너별로 본다.
- [x] **재시작·재부팅 필요 판정** — "패치됐지만 아직 안 안전한" 상태를 잡는다.
      옛 `.so` 를 물고 있는 프로세스(`tb_stale_lib`)와 재부팅 전 커널은 **억제하지 않고** 근거와 함께
      올린다(조치: 프로세스 재시작 / 재부팅). 이 판정이 없으면 "패치됨=안전"으로 착각해 미탐이 난다.
- [x] **억제 근거 확장(errata·debsecan)** — changelog(핵심 13개)만으로는 좁아서, 벤더 권고
      `tb_applied_errata`(시스템 전체)와 데비안 보안 트래커 `tb_debsecan`(역방향 판정)을 더했다 → 억제 4겹(§7).
- [x] **벤더별 판정 확장(RHEL·우분투·커널)** — 데비안 4겹과 별개로, RHEL 계열(`tb_vendor_errata`·
      `tb_vendor_unfixed`)·우분투(`tb_ubuntu_oval`)·커널(`tb_kernel_cve`)이 각자의 벤더 소스로
      백포트 판정 + 조치 불가(`no_fix`)를 담당한다(커넥터: rhoval/rhunfixed/ubuntuoval/kcve).
- [x] **방화벽 차단(FILTERED) 분류** — 전체 인터페이스에 떠 있어도 방화벽이 막고 있으면 외부노출이 아니다.
      이 판정이 없으면 방화벽 뒤 내부 서비스가 전부 HIGH/CRITICAL 로 뜬다(오탐).
- [x] **미지원 배포판 경고** — Amazon Linux·Oracle Linux·CentOS 는 피드가 안 덮어 매칭 0건이 된다.
      조용히 "취약점 없음"으로 보이지 않도록 `src/distro.php` 가 판정해 ingest 응답·화면에 경고.
- [x] **패키지 출처 판정** — dpkg 는 vendor 를 안 주므로 apt 라벨(`o=Debian`/`o=Docker`/`o=LP-PPA-…`)로
      서드파티(PPA·Docker·NodeSource)를 가려낸다(URL 로 보면 사내 미러가 서드파티로 오분류된다).
- [x] **스키마 마이그레이션 자동화** — `deploy/migrate.sh` 가 `db/migrations/*.sql` 중 미적용분만
      **파일명 사전순**으로 적용하고 `tb_schema_migrations` 에 기록(`up`·`update.sh` 가 자동 호출, 수동 apply 불필요).
      파일명은 **타임스탬프**(`YYYYMMDDHHMMSS_이름.sql`) — 연번은 동시 브랜치가 같은 번호를 집어 충돌한다
      (실제로 `0003`·`0014` 가 각각 두 개 생겼다). `deploy/hooks/pre-push` 가 신규 연번 파일을 막는다.
      최상위 `db/01~18*.sql` 은 빈 볼륨 initdb 전용이라 기존 볼륨엔 안 들어간다 → 증분은 `migrations/` 로.
- [x] **UI** — 좌측 사이드바(대분류/중분류) · CVE 목록 탭(전체/KEV/EPSS 상위) · 영향 패키지 목록 `packages.php`
      · EPSS 백분위 병기 · 필터 즉시 적용.
- [x] 대시보드 "다음 수집 예정" — enabled·비manual 커넥터 중 가장 이른 next_run_at 을 헤더 아래 표시.
      (알림은 만들지 않기로 — 외부 채널 수신지가 없어 YAGNI. 필요해지면 그때.)
- [x] **조치 관리 · SLA** — 지금까지는 "찾은 것"까지였고 "누가 언제까지 고치나"가 없었다.
      `tb_sla_policy`(심각도별 조치기한 정책)로 기한을 자동 산정해 `tb_remediation_case`(자산×CVE×패키지
      단위 케이스: 담당자·기한·예외·상태)를 만들고 `remediations.php` 에서 관리한다. 상태 변경은
      admin/operator 만(CSRF 검증), 대시보드에도 OPEN/IN_PROGRESS 건수를 카드로 띄운다.
- [x] **벤더 판정 조회 화면** — `vendor.php`. 벤더 데이터(debtracker·rhoval·rhunfixed·ubuntuoval·kcve)는
      지금까지 매처가 억제에만 썼고, 억제가 의심스러우면 DB 에 직접 붙어야 했다. 원본을 소스 필터와 함께
      한 화면에서 보여줘 **억제 근거를 사람이 확인할 수 있게** 했다(설명가능성 — 차별점 ③의 연장).
- [x] **보안설정 룰셋(SSG) 카탈로그** — `tb_compliance_rule`(약 2,493개 룰) + 목록·검색 `compliance_rules.php`
      · 상세 `compliance_rule.php`(`?rule=<rule_id>`). CCE 판정이 인용하는 CIS/NIST/STIG 기준이 뭔지
      화면에서 확인한다 — 근거를 못 보면 FAIL 이 떠도 무엇을 고쳐야 하는지 알 수 없다.
      (SSG 커넥터 자체는 4a 에 이미 있다 — 여기 추가된 건 **화면**이다.)
- [x] **정밀 판정 플랫폼** — `tb_finding_evidence`(판정 근거를 `tb_finding` 1:1 로 구조화 저장) +
      `tb_collection_stage`(수집 단계별 완전성 기록). 에이전트가 어떤 수집 단계를 못 채우면 그 영역은
      조용히 "취약점 없음"이 된다 → 단계 누락을 호스트 상세에 **경고로 드러내** 미탐을 미탐인 채로
      넘기지 않는다(미지원 배포판 경고와 같은 취지).
- [x] **경계 방화벽 뒤 외부노출 선언** — `tb_host_ext_port`. 서버 자신은 0.0.0.0 에 떠 있어도 경계
      방화벽이 막으면 실제로 외부에서 못 닿는다. 호스트별로 "경계가 실제로 열어 준 포트"를 선언해
      그 외 포트는 EXTERNAL 로 올리지 않는다(호스트 내 firewalld/ufw 만 보는 FILTERED 로는 못 잡는
      층이다). 변경은 감사로그 `host_perimeter_update` 로 남는다 — 등급을 낮추는 선언이라 이력이 필요하다.
- [x] **패키지 요약 사전집계** — `tb_package_summary`(자연키 `(package_name, ecosystem)`). `packages.php`
      가 92만 행을 매 요청마다 GROUP BY 하느라 8초 걸리던 것을 사전집계 조회로 바꿔 약 0.05초가 됐다
      (갱신은 OSV 커넥터 실행 시 — 목록이 웹 요청을 붙잡지 않게 한다).
- [x] **에이전트 재전송 공격 방지** — `tb_agent_replay_nonce`(복합키 `(agent_token_id, nonce_hash)`).
      토큰이 유효해도 가로챈 요청을 그대로 다시 보내면 옛 수집물이 최신으로 덮인다 → 요청별 nonce 를
      1회만 허용한다. 허용 시계오차는 `AGENT_NONCE_MAX_SKEW_SECONDS`(기본 600초, 코드에 안 박는다).
- [x] **에이전트 설치 파일 웹 배포** — `agent-dl.php`. 대상 서버가 저장소 체크아웃 없이 스크립트 2개 +
      **배포별** 루트 CA 를 받아 설치한다(자산 화면의 설치 모달이 여기를 가리킨다). CA 는 배포마다 값이
      달라 저장소에 두지 않는다(`agent-ca/`, gitignore).
- [x] **재매칭 지문** — `tb_scan.match_fingerprint`. 피드가 갱신돼도 판정 결과가 같으면 트랜잭션조차
      열지 않는다. 예전엔 1비트도 안 바뀐 경우까지 통째 삭제·재삽입해 binlog 가 하루 20GB 넘게 쌓였다
      (운영 실측: 디스크 105G 중 76G). 상세는 `docs/dev/architecture.md §2`.
- [x] **브라우저 E2E** — `tests/e2e.sh` + `tests/e2e/run.cjs`(Playwright, 전용 컨테이너). `smoke.sh` 는
      curl 이라 HTML 만 받는다 — **클라이언트 JS(`assets/app.js` 408줄 + `assets/js/connectors.js` 283줄)가
      통째로 깨져도 88개 검사가 전부 통과**한다. 그 구멍만 덮는다("화면이 뜨는지"는 smoke 가 이미 본다).
      덮는 것: ① 로그인→대시보드 ② 테마 토글(클릭·저장·다른 화면 복원·실제 배경색 변화) ③ 밀도 토글
      ④ 모바일 사이드바(375폭, 백드롭·Escape 닫기 + 필터 토글 노출) ⑤ 커넥터 화면 JS(`connectors.js`)
      + 모달 — 타입별 폼 토글·역할 매핑 재렌더·헤더 행 추가/삭제·모달 열고 닫기. ⑤의 기대값은
      JS 에 박지 않고 `#connForm` 의 `data-type-meta`(PHP 카탈로그 `VG_CONNECTOR_TYPES`)와 비교하므로
      **PHP 카탈로그와 화면이 어긋나면 걸린다**. **안 덮는 것: 필터 즉시적용.** 커넥터의 미리보기·지금
      실행·저장·활성토글·삭제도 **일부러 안 덮는다** — 누르면 외부 소스를 실제로 치거나 공용 dev DB 를
      바꾸고 세션 락을 오래 쥔다(E2E 는 폼을 채우기만 하고 제출하지 않는다).
      브라우저 기동이 느려 pre-push 게이트에는 넣지 않았다
      (CI 가 없어 훅이 곧 매 push 다) — opt-in 으로 직접 돌린다.

> 매칭 자체는 OSV 등 검증된 소스에서 상속. 우리 기여는 그 위 레이어(런타임 상태·백포트 억제·KEV/EPSS·설명가능성).
> Python AI 문서생성은 본체 범위에서 제외 — Export API 로 결과만 넘긴다.
> `shadow-ai/`(섀도우 AI DLP 크롬 확장)는 같은 저장소의 **사이드 PoC** 로, 위 파이프라인과 무관하게 독립 동작한다.
