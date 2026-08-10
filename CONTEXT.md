# CONTEXT.md — 프로젝트 맥락 (Claude Code 최우선 참고)

> 현행 기준: 2026-08-09 · 에이전트 3.10 · 계정 인벤토리·자산 등급(N2SF)·컴플라이언스 스냅샷 포함.

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
4. **경량 상주 에이전트 + 시계열** — 상시 데몬으로 주기 수집(웹에서 즉시/예약/주기변경), 변화 추적(`changes.php`), 함대 대시보드.
5. **KISA 국내 연동** — 해외 도구가 안 하는 국내 보안공지 매칭.

---

## 3. 확정된 스택

| 영역 | 스택 | 시점 |
|---|---|---|
| 수집 에이전트 | **Bash 쉘 스크립트** | 완성됨 |
| 웹 + 백엔드 + 매처 | **PHP** | 완성됨(핵심) |
| DB | **MySQL** | 완성됨(핵심) |
| 인프라 | **Docker + docker-compose** (PHP + MySQL) | 완성됨 |
| HTTPS 배포 | **Caddy 리버스 프록시** (내부 CA 자체서명 — 확정) | 완성됨 |
| AI 문서 생성 | **Python** (오픈웨이트 로컬 모델) | **범위 제외** — 결과는 `GET /export.php`(JSON/XML)로 넘긴다 |

> 1~2단계(수집·매칭·표시)엔 AI 불필요(DB 조회지 추론 아님). AI 보고서 생성기는 본체에 넣지 않고
> **Export API 로 분리**해 외부 시스템이 가져가게 했다(경계가 깨끗하고, 본체가 AI 에 묶이지 않는다).
> 상용 API(Claude/GPT)는 코드 작성 보조로만 사용 → 규정상 자유, 보고서에 기재.

---

## 4. 이미 만들어진 것 (재사용)

### `agent/vuln-inventory-agent.sh` (v3.10) — 수집 에이전트, 동작 검증 완료
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
- **언어 패키지** — pip/npm/gem/composer/maven/nuget/cargo/go 8개 생태계. 설치본 고신뢰 소스
  (`site-packages/*.dist-info/METADATA`·`composer/installed.json`·`Cargo.lock`·`package-lock.json`·
  `Gemfile.lock`·`specifications/*.gemspec`·`*.jar/war/ear`)에 더해, 선언 파일 `go.mod`/`requirements.txt`/`pom.xml` 을 직접 파싱해 보충한다
  (설치본이 없거나 못 읽는 환경 대응). OSV 커넥터(`vg_osv_lang_queries`)가 이 8개 생태계 전부를
  자기 ecosystem 으로 조회해 CVE 매칭한다 — 매니페스트 직접 파싱은 go.mod/requirements.txt/pom.xml
  3종뿐이고 npm/gem/maven/nuget/cargo 는 설치본(lock 파일·jar 등) 스캔만 한다.
- **라이선스 식별** — SBOM(CycloneDX/SPDX, `SBOM_DIR` 오프라인 입력) + pip `METADATA` +
  composer `installed.json` 에서 SPDX 식별자를 수집해 permissive/copyleft/unknown 으로 분류
  (`server/src/license_risk.php`). 시그니처·스니펫·바이너리 스캔이나 npm/gem/maven/nuget/cargo
  매니페스트 직접 파싱을 통한 라이선스 식별은 하지 않는다 — 위 세 소스가 없으면 미상(unknown)이다.
- `users` — **계정 인벤토리 원자료**(`account_passwd`/`account_shadow`/`account_lastlog`/
  `account_sudoers`/`sudo_group`). 중앙(`src/account_inventory.php`)이 계정 1행으로 조립해
  `tb_host_account` 에 저장하고 ISMS-P 2.5.x·N2SF AC 관점으로 판정한다. **패스워드 해시는 어떤
  형태로도 수집·전송하지 않는다** — shadow 에서는 정책 필드와 잠금 여부(1/0)만 환산해 보낸다.
  못 읽으면(비-root) 파일을 아예 안 만들어 중앙에서 NA 가 된다(PASS 로 위장하지 않는다).
- **패키지 의존성 그래프** — 직접/전이 의존 관계(`tb_package_dependency`). `pom.xml` 은 원문을
  base64 로 올려 중앙이 DOMDocument 로 파싱한다(에이전트 awk 파싱은 `<exclusions>`/`<parent>` 를
  구분 못 해 오탐이 났다). 조회 화면은 `depgraph.php`(자산 상세에서 진입).
- 그 외: 커널 CPU취약점 완화상태, 보안설정 등

### `agent/install-agent.sh` — 배포 설치기
각 대상 서버에서 `sudo bash install-agent.sh` — 인자 없이 실행하면 서버 주소·토큰·주기를 물어본다
(TTY 아니면 종전대로 `--server/--token` 인자 필수. 도메인만 넣어도 스킴·`/ingest.php` 자동 보정).
systemd 가 있으면 **상시 데몬**(`vuln-agent.service`, `Type=simple`)으로 등록해 `run.sh` 가 10초마다
중앙의 `agent-poll.php` 를 poll 한다 — 초기 정기수집 주기(`--schedule`, 기본 hourly)는 시작값일
뿐이고, 이후 주기는 poll 응답의 `poll_schedule_seconds` 를 따른다(중앙 웹의 호스트 상세에서
바꾸면 다음 poll 에 즉시 반영, SSH 재설치 불필요). "지금 수집" 예약도 poll 로 실려온다.
systemd 가 없는 노드만 **cron 폴백**(`run.sh --once` 를 주기 실행, 정기수집만 가능)한다. 즉시 1회
실행(통신 확인)은 스케줄 방식과 무관하게 항상 수행한다. 설치물은
`--prefix`(기본 `/opt/vuln-agent`) 아래 `bin`/`etc`/`logs` 로 모이고, 토큰은
`<prefix>/etc/agent.env`(600) 로 관리(ps 노출 방지). **프로세스** 인벤토리(`collect_processes`)는
다른 mount namespace(컨테이너)를 건너뛰고 호스트 자신만 본다 — 컨테이너 오버레이 경로의 `dpkg -S`
전수조사로 멈추는 문제를 회피. (컨테이너를 안 보는 게 아니다 — **패키지**는 `collect_containers`
가 rootfs 를 직접 읽어 따로 수집한다.)

---

## 5. 폴더 구조 (목표)

**파일은 책임대로 놓는다.** 개별 파일명을 여기 다 적지 않는다 — 화면·헬퍼는 계속 늘고 줄어서
목록을 두면 곧 어긋난다. 어디에 무엇이 들어가는지만 고정한다.

```
vuln-agent/
├── CONTEXT.md  README.md  CLAUDE.md(개발원칙)  AGENTS.md
├── deploy/       # 배포 인프라: compose.{common,dev,dev-db,dev-net,prod}.yml · compose_runner.sh
│   │             #   · migrate.sh · update.sh · backup_db.sh · wt.sh · .env.{dev,prod}.template
│   ├── caddy/    # HTTPS 리버스 프록시(운영 전용): Dockerfile·Caddyfile
│   ├── config/mysql/my.cnf   # 운영 MySQL 튜닝
│   └── hooks/pre-push        # 검증 게이트(저장소가 들고 있다)
├── secrets/(*.txt gitignore)   data/(mysql, gitignore)   agent-ca/(gitignore)
├── agent/
│   ├── vuln-inventory-agent.sh   # 수집(패키지·노출·실행프로세스·계정·의존성), --send 전송
│   └── install-agent.sh          # 각 서버 배포·스케줄(systemd 상시 데몬/cron 폴백)
├── server/
│   ├── public/   # HTTP 로 노출되는 것 = URL. 웹 화면(*.php) + 토큰 인증 API(ingest·agent-poll/
│   │             #   progress·export·agent-dl) + 화면이 뒤에서 부르는 엔드포인트(feed_preview 등)
│   │             #   · process.html — 프로세스 소개(로그인 불필요, /process.html 로 공유)
│   │             #   화면 목록의 정본은 src/view/nav.php 의 vg_nav_sections() 와 사이트맵 다이어그램
│   ├── src/      # 공용 라이브러리(URL 로 안 열린다): db·auth(RBAC·세션만료)·view/·matcher(+억제)
│   │             #   · feeds/(커넥터 12종)·cce·compliance·account_inventory·assetgrade·setting 등
│   └── bin/      # CLI 전용: scheduler.php(사이드카)·sync.php·backfill_*·rebuild_*
├── db/           # 01~18 *.sql (빈 볼륨 initdb 전용, tb_ 접두사+감사4컬럼)
│   └── migrations/    # YYYYMMDDHHMMSS_*.sql — deploy/migrate.sh 가 자동 적용(tb_schema_migrations 기록)
│                      #   연번(0001…)은 금지 — 동시 브랜치가 같은 번호를 집는다. pre-push 가 막는다.
│                      #   기존 0001~0020 은 그대로 둔다(사전순이라 옛 것이 먼저 돈다).
├── tests/        # smoke.sh(API~로그인 curl) · e2e.sh+e2e/(브라우저, Playwright — 게이트 밖)
│                 #   · ui_lint.sh(죽은 CSS·인라인 style) · vercmp_test.php(버전비교 단위)
│                 #   · agent-bench.sh(에이전트 리소스 실측) · *_test.php/*_test.sh(단위·문서 일관성)
├── docs/         # dev/(아키텍처·데이터베이스·피드소스-역할·설명글·화면-안내·조치가이드·리소스 프로파일)
│                 #   · specs/diagrams/(PlantUML 6종 + 렌더 SVG) · ui-configuration.md
└── shadow-ai/    # (사이드 PoC) 섀도우 AI DLP 크롬 확장 — 본 파이프라인과 독립
```

---

## 6. 데이터 흐름 (확정)

```
[원격 대상 서버]                    [중앙 서버 · Docker]
쉘 에이전트 ── 상시 데몬(10초 poll) ──▶ Caddy(HTTPS:8080) ──▶ ingest.php ──▶ MySQL(tb_*)
(수집, install-agent.sh 로 배포)     JSON POST(주기가 되면)                  │
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

**오탐 억제는 데비안 중심의 4겹**(①OSV 버전필터 ②changelog ③errata ④debsecan 역방향)**이고,
RHEL 계열·우분투·커널은 각자의 벤더 소스로 별도 판정한다.** 억제된 건은 `tb_finding` 이 아니라
`tb_suppressed_finding` 으로 가서 위험 집계·화면은 그대로 두고 오탐만 빠지며, **근거는 호스트
상세에 그대로 노출된다**(숨기지 않는다). 벤더가 "아직 안 고쳤다"고 확인한 CVE 는
`tb_finding.no_fix` 로 표시한다 — 오탐 제거와 다른 축이라 등급은 그대로 두고 "지금 고칠 수 있는
것"과 화면에서만 분리한다.

**억제를 취소하는 두 신호**가 있다 — 패치됐어도 프로세스가 옛 `.so` 를 물고 있거나(`tb_stale_lib`,
조치는 재시작) 커널 재부팅 전이면(조치는 재부팅) 억제하지 않는다. 이게 없으면 "패치됨=안전"으로
착각해 미탐이 난다.

> **겹별 근거 테이블·커버리지·debsecan 역방향의 안전장치·벤더별 판정 규칙의 정본은
> [`docs/dev/architecture.md` §2](docs/dev/architecture.md) 다.** 같은 표를 여기 두 벌로 두지 않는다.

**미지원 배포판**(Amazon Linux · CentOS)은 피드가 안 덮어 매칭이 0건이 된다. 조용히
"취약점 없음"으로 보이면 위험하므로 `vg_distro_unsupported`(`src/distro.php`)가 판정해
ingest 응답과 취약점 화면에 **경고로 띄운다**. Oracle Linux는 OSV 대신 Oracle ELSA OVAL로
릴리스별 영향 여부와 수정 EVR을 판정한다.

즉 "설치=취약"으로 전부 올리지 않고, **실제 노출·실행·사용 여부로 우선순위를 가른다.**

**보안설정 점검(CCE)** 은 같은 수집물을 다른 눈으로 본다 — CVE(취약한 버전)가 아니라 잘못된 설정
(SSH·계정·패스워드 정책·파일 권한·MAC/방화벽에 더해 시간동기화 `CCE-TIME-*`·로그설정 `CCE-LOG-*`·
암호화 `CCE-CRYPTO-*`)을 `src/cce.php` 가 39개 항목으로 판정해 `tb_cce_finding` 에 저장한다.
같은 판정 결과를 어느 기준의 증적으로 볼지는 `tb_control_mapping`(U-코드·ISMS-P·N2SF)이 정하고
`control_mapping.php`·`control.php` 가 보여준다 — 기준을 화면 문자열이나 주석에 다시 적지 않는다(SSOT).

**계정 인벤토리**(`src/account_inventory.php` → `tb_host_account`)는 CCE 와 같은 원칙을 따른다 —
못 읽은 항목은 PASS 가 아니라 NA 이고, 공유계정·퇴직자 계정 추정은 FAIL 이 아니라 REVIEW(사람 확인)다.
호스트 상세의 "계정" 탭에서 본다.

---

## 8. 개발 현황 (2026-08-09 기준)

파이프라인(수집→전송→저장→매칭→표시)·HTTPS·감사에 더해 오탐억제/CCE/변화추적/Export,
그리고 컴플라이언스·계정 인벤토리·자산 등급까지 동작한다. 아래는 **무엇이 있는지**와
**왜 그렇게 했는지**만 남긴 요약이다 — 화면·테이블·함수의 상세는 각 정본 문서가 갖는다
(`docs/dev/architecture.md`, `docs/dev/데이터베이스.md`, `docs/ui-configuration.md`).

### 기반 — 파이프라인·배포

- **Docker**(compose dev/prod + Docker Secrets + 러너) · **수집→전송→저장**(에이전트 `--send`
  POST → `ingest.php` → MySQL) · **웹**(로그인 → 대시보드 → 호스트 상세 → 취약점) · **설정형
  RBAC**(admin/operator/user × 메뉴, admin 은 코드에서 항상 허용해 잠금을 막는다).
- **HTTPS 배포** — Caddy 가 TLS 종료(`tls internal` 자체서명 — 정식 인증서 전환은 하지 않기로
  확정, 대신 에이전트에 내부 루트 CA 를 배포한다). 도메인은 저장소에 두지 않고 `.env.prod` 의
  `PROD_DOMAIN` 으로 주입한다. 평문 80 은 308
  리다이렉트, 기존 `:8080` 은 설치된 에이전트 호환으로 계속 연다. web·db 는 내부망/루프백만.
- **무중단 배포** — prod 가 `../server` 를 읽기전용 마운트해 PHP 만 바뀌면 `update.sh`(=`git pull`)
  로 끝난다(opcache 가 곧 반영). Dockerfile·compose·caddy 변경 시에만 재빌드.
- **스키마 마이그레이션 자동화** — `deploy/migrate.sh` 가 미적용분만 파일명 사전순으로 적용하고
  `tb_schema_migrations` 에 기록한다. 파일명은 타임스탬프 — 연번은 동시 브랜치가 같은 번호를
  집어 실제로 `0003`·`0014` 가 각각 두 개 생겼다. `deploy/hooks/pre-push` 가 신규 연번을 막는다.
- **DB 규약** — 전 테이블 `tb_` 접두사 + 감사 4컬럼, 소프트삭제(`vg_soft_delete()`), 테이블명 단수 +
  PK `<엔티티>_id`(조인 양쪽 이름을 맞춘다). 상세·예외는 `docs/dev/데이터베이스.md`.
- **상시 데몬 전환 + 웹 수집 제어** — 에이전트를 systemd 타이머에서 상시 데몬(10초 poll)으로
  바꿔, 즉시 실행·예약·주기 변경을 중앙 웹에서 한다(SSH 재설치가 필요 없어졌다).
  `deploy/agent_schedule.sh` 는 아직 전환 전인 구버전·cron 폴백 노드용 보조 수단으로만 남는다.
- **에이전트 설치 파일 웹 배포**(`agent-dl.php`) — 대상 서버가 저장소 체크아웃 없이 스크립트 2개 +
  **배포별** 루트 CA 를 받는다. CA 는 배포마다 값이 달라 저장소에 두지 않는다(`agent-ca/`, gitignore).
- **에이전트 재전송 공격 방지** — 요청별 nonce 를 1회만 허용한다(`tb_agent_replay_nonce`). 토큰이
  유효해도 가로챈 요청을 그대로 다시 보내면 옛 수집물이 최신으로 덮이기 때문. 허용 시계오차는
  `AGENT_NONCE_MAX_SKEW_SECONDS`(코드에 안 박는다).
- **에이전트 속도 티어**(`src/agentspeedtier.php`) — CPU·조립 타임아웃·메모리 상한을 호스트별로
  내려보낸다. CPU 만 조여도 조립 단계가 메모리를 밀어 올려 `mem_max_mb` 를 뒤에 더했다.

### 판정 — 매칭·억제·벤더

- **피드 커넥터 12종** = 고정 11종(KEV/OSV/NVD/KISA/EPSS + 벤더·업스트림 판정 debtracker·rhoval·
  rhunfixed·ubuntuoval·kcve·ssg) + 범용 API(`generic_api`). UI 설정·미리보기·스케줄(manual/
  interval/daily/cron) + 스케줄러 사이드카. 역할별 차이는 `docs/dev/피드소스-역할.md`.
- **NVD 전체 데이터**(약 36만 건) — 주기 수집은 **수정일(lastMod) 기준**이다(뒤늦게 CVSS 가 붙는
  CVE 를 발행일 기준이면 영원히 놓친다). 전체 백필은 `bin/backfill_nvd.php`(멱등·재개·병렬).
  API 키는 DB 에만 둔다.
- **정밀 런타임 수집 + 7단계 상태** · **OSV 자동 매칭**(배포판 ecosystem·소스패키지·버전필터) ·
  **EPSS/KEV 우선순위** · **FILTERED 분류**(방화벽 뒤 내부 서비스가 전부 HIGH 로 뜨는 오탐 제거).
- **억제 4겹과 억제 취소 두 신호** — §7 요약, 정본은 `docs/dev/architecture.md §2`.
  changelog(핵심 13개 패키지)만으로는 좁아 errata(시스템 전체)·debsecan(역방향)을 더했고,
  RHEL 계열·우분투·커널은 각자의 벤더 소스가 백포트 판정과 조치 불가(`no_fix`)를 담당한다.
- **미지원 배포판 경고** — Amazon Linux·CentOS 는 피드가 안 덮어 0건이 된다. 조용히 "취약점 없음"이
  되지 않도록 `src/distro.php` 가 판정해 ingest 응답·화면에 경고를 띄운다.
- **패키지 출처 판정** — dpkg 는 vendor 를 안 주므로 apt 라벨(`o=Debian`/`o=Docker`/`o=LP-PPA-…`)로
  서드파티를 가린다. URL 로 보면 사내 미러가 서드파티로 오분류된다.
- **재매칭 지문**(`tb_scan.match_fingerprint`) — 결과가 같으면 트랜잭션조차 열지 않는다. 예전엔
  1비트도 안 바뀐 경우까지 통째 삭제·재삽입해 binlog 가 하루 20GB 넘게 쌓였다(운영 실측 105G 중 76G).
  판정 로직·저장 컬럼을 바꾸면 `VG_MATCH_FP_VERSION` 을 올려야 한다.
- **정밀 판정 플랫폼** — `tb_finding_evidence`(판정 근거를 finding 1:1 로 구조화) +
  `tb_collection_stage`(수집 단계 완전성). 에이전트가 한 단계를 못 채우면 그 영역이 조용히
  "취약점 없음"이 되므로 단계 누락을 호스트 상세에 경고로 드러낸다.

### 화면·기능

- **컨테이너 스캔** — `collect_containers` 가 실행 중 컨테이너 rootfs 를 직접 읽어 내부 패키지를
  수집한다(docker CLI 비의존). 호스트 스캔에서 통째로 빠지던 미탐 영역이었다. 대장은 호스트 상세의
  **컨테이너 탭**(#536)에서 본다 — k8s 위치·워크로드 참조·이미지 다이제스트·SBOM 은 수집만 하고
  읽는 화면이 없었다. 도커 단독 호스트에선 이 값들이 비어 있어 열로 세우지 않고 값이 있는 행에만 붙인다.
- **변화 추적**(`changes.php`) — 최근 2개 스캔의 `tb_finding` 만 비교한다(새 테이블 없이).
- **벤더 판정 조회**(`vendor.php`) — 억제에만 쓰이던 벤더 원본을 사람이 확인할 수 있게 노출(설명가능성).
- **보안설정 룰셋(SSG) 카탈로그** — `tb_compliance_rule`(약 2,493개) + 목록·상세 화면. FAIL 이 떠도
  무엇을 고쳐야 하는지 알려면 인용한 CIS/NIST/STIG 기준을 볼 수 있어야 한다.
- **컴플라이언스**(ISMS-P·ISO 27001) — 자동판정 가능한 통제 3개(`patch`/`asset`/`secops`)만 SLA
  기준일 대비 위반 건수로 판정하고, 정책·승인이력류는 체크리스트로만 둔다(못 채우는 걸 억지로
  채우지 않는 의도적 한계). 판정 어휘는 **준수·판정 불가·부분준수·미준수** 4종 — 근거가 모자라
  0건인 것을 준수로 쓰면 심사 증빙이 허위 안심이 된다(#493). 로직은 `src/compliance.php` 한 곳에
  두어 화면과 스케줄러가 같은 함수를 쓰고, 스케줄러가 하루 1건 스냅샷을 남긴다(#498).
- **통제 기준 매핑**(#499) + **통제 상세**(#509) — 같은 CCE 결과를 ISMS-P·U-코드·N2SF 중 어느 기준의
  증적으로 볼지 고르고, 통제가 무엇을 요구하고 어떻게 고치는지를 함께 본다. 긴 조치 원문은
  `docs/dev/보안설정-조치가이드.md`.
- **CCE 룰 3계열 확장**(#494) — 시간동기화·로그설정·암호화. 확인 못 한 항목은 전부 NA.
- **계정 인벤토리**(#490) — 계정 정책만 보고 실제 계정 목록은 안 봐서 ISMS-P 2.5.x·N2SF AC 가 통째로
  공백이었다. 패스워드 해시는 수집·저장·표시하지 않고, 열람은 감사로그 대상이다.
- **자산 중요도·N2SF 보안등급**(#495, #510) — 확정값과 시스템 제안값을 **다른 컬럼**에 담는다(등급
  확정은 기관의 법적 처분이라 시스템이 대신할 수 없다). 목록에서 일괄 확정이 가능하되 해제는 상세에서
  한 대씩이고, 여러 등급이 섞이면 가장 높은 등급을 승계한다.
- **제거·대체 검토 권고**(#489) — 벤더 미수정이 한 패키지에 몰리면 CVE 수십 줄 대신 (호스트×패키지)로
  묶는다. 실측: 한 호스트의 `libqt5webkit5` 에 no_fix 43건, 실제 조치는 `apt purge` 한 번이었다.
  EOL 이라고 단정하지 않고 관측 + 권고만 한다.
- **미조치 사유·승인자**(#491) — 결재 워크플로 없이 사유·승인자만 두고 `export.php` 로 넘긴다.
  키는 스캔이 바뀌어도 유지되는 자연키(`container_id` 는 스캔마다 재발급이라 못 쓴다).
- **Export API** — `GET /export.php`(JSON/XML). 읽기 전용 토큰은 DB 에 해시만, 원문은 1회 표시.
  상세: `docs/dev/export-api.md`.
- **SCA** — 8개 언어 생태계 매칭은 OSV 커넥터가 이미 하던 일이고, 여기에 `go.mod`/`requirements.txt`/
  `pom.xml` 직접 파싱(설치본이 없는 환경 보충)과 라이선스 식별(SBOM·pip METADATA·composer
  installed.json → permissive/copyleft/unknown)을 더했다. 목록·KPI 는 사전집계
  `tb_package_license_summary` 를 읽고, 이 갱신은 **OSV 게이트에 묶지 않는다** — 라이선스는 OSV 가
  아니라 ingest 로 들어와서, 묶으면 OSV 미등록 동안 KPI 가 영구히 0으로 보인다(PR#468).
- **패키지 요약 사전집계**(`tb_package_summary`) — 92만 행을 매 요청마다 GROUP BY 하느라 8초 걸리던
  목록을 사전집계 조회로 바꿔 0.1초 미만이 됐다(갱신은 OSV 커넥터 실행 시).
- **패키지 의존성 그래프**(#480, 화면 #527) — 직접/전이 의존을 수집·저장하고 `depgraph.php` 가
  "무엇이 이 패키지를 끌어왔나"를 역추적/정방향/트리로 보여준다. 진입은 자산 상세(`host.php`)에서만
  한다 — 엣지 유니크 키의 좌측 접두가 (스캔, 컨테이너)라 그 둘로 좁혀야 인덱스를 탄다. `pom.xml` 은
  원문을 올려 중앙이 DOMDocument 로 파싱하고(에이전트 awk 파싱은 `<exclusions>`/`<parent>` 를 구분
  못 해 오탐이 났다), SBOM 은 CycloneDX `dependencies` 와 SPDX `relationships`(#528) 에서 뽑는다.
  유니크 키가 3,072바이트를 넘어 `edge_hash` 생성컬럼으로 대체했다(#502).
- **접속기록 5요소 + 월 1회 점검**(#496) · **세션·토큰 유효기간**(#492) · **Caddy 보안 응답 헤더**(#497,
  HSTS 는 자체서명 확정이라 붙이지 않는다) — 상세는 `docs/dev/architecture.md §6`·`docs/ui-configuration.md`.
- **제품 범위 정리** — 내부 SLA·담당자·상태·예외를 추적하는 조치 관리 기능은 제거했다. 알림도 만들지
  않는다(외부 채널 수신지가 없어 YAGNI). 제품은 스캔 결과와 판정 근거를 정확히 보여주는 데 집중한다.

### 검증

- `tests/smoke.sh`(curl) 가 게이트이고, 그 앞단에서 `ui_lint.sh`(죽은 CSS·인라인 style)와
  단위 테스트(`vercmp_test.php` 등)를 먼저 돌린다.
- **브라우저 E2E**(`tests/e2e.sh` + Playwright)는 게이트 **밖**이다 — smoke 는 curl 이라 클라이언트
  JS 가 통째로 깨져도 전부 통과한다. 그 구멍만 덮는다: 로그인, 테마·밀도 토글, 모바일 사이드바,
  커넥터 화면 JS·모달. 기대값을 JS 에 박지 않고 `#connForm` 의 `data-type-meta`(PHP 카탈로그
  `VG_CONNECTOR_TYPES`)와 비교하므로 **PHP 카탈로그와 화면이 어긋나면 걸린다**. 커넥터의 미리보기·
  지금 실행·저장·삭제는 **일부러 안 덮는다**(외부 소스를 실제로 치거나 공용 dev DB 를 바꾼다).
  브라우저 기동이 느려 pre-push 게이트에는 넣지 않았다(CI 가 없어 훅이 곧 매 push 다).
- `tests/documentation_consistency_test.php` 가 DB 문서·ERD·사이트맵·README 를 코드와 대조한다 —
  문서가 조용히 뒤처지는 것을 막는 정적 회귀 테스트다.

> 매칭 자체는 OSV 등 검증된 소스에서 상속. 우리 기여는 그 위 레이어(런타임 상태·백포트 억제·KEV/EPSS·설명가능성).
> Python AI 문서생성은 본체 범위에서 제외 — Export API 로 결과만 넘긴다.
> `shadow-ai/`(섀도우 AI DLP 크롬 확장)는 같은 저장소의 **사이드 PoC** 로, 위 파이프라인과 무관하게 독립 동작한다.
