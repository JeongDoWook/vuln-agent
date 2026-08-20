# CONTEXT.md — 프로젝트 맥락 (Claude Code 최우선 참고)

> 현행 기준: 2026-08-20 · 에이전트 3.13 · 자산 탐색(섀도우 IT)·세그먼트 맵·기반시설 U-코드
> 커버리지·에이전트 무인 자동 업데이트(Ed25519 서명 검증) 포함.

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
   (Trivy·Grype 바이너리 호출은 검토 후 기각 — OSV 직접 조회가 배포판 ecosystem·소스패키지 단위로 단순했다.)

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

수집 에이전트 **Bash** · 웹/백엔드/매처 **PHP** · DB **MySQL** · 인프라 **Docker compose** ·
HTTPS **Caddy**(내부 CA 자체서명 — 확정). 전부 완성됐고 바꿀 계획 없다.

> **AI 문서 생성(Python)은 범위 제외다.** 1~2단계(수집·매칭·표시)는 DB 조회지 추론이 아니라 AI 가
> 필요 없고, 보고서 생성기는 본체에 넣는 대신 **Export API 로 분리**해 외부가 `GET /export.php`
> (JSON/XML)로 가져가게 했다 — 경계가 깨끗하고 본체가 AI 에 묶이지 않는다. 상용 API(Claude/GPT)는
> 코드 작성 보조로만 쓴다(규정상 자유, 보고서에 기재).

---

## 4. 이미 만들어진 것 (재사용)

### `agent/` — 수집 에이전트 v3.13 + 설치기 (동작 검증 완료)

읽기 전용이고 서버에 무리 안 간다(nice 19 / ionice idle / 명령별 timeout). 피크 메모리는 실측
**61.6MB**(Debian 12 · 91패키지 — 마지막 jq 조립이 1등 요인이라 페이로드 크기에 비례한다. 수치·
외삽·재측정법은 `docs/dev/에이전트-리소스-프로파일.md`, 실측기는 `tests/agent-bench.sh`).
jq 있으면 JSON, 없으면 섹션 텍스트. RHEL/Debian 계열 자동 감지. 설치는 각 서버에서
`sudo bash install-agent.sh` 하나이고, systemd 가 있으면 상시 데몬(10초 poll)·없으면 cron 폴백이다.

> **수집 항목 전체 목록과 설치·권한·갱신·자동 업데이트·속도 티어·실행 옵션의 정본은
> [`agent/README.md`](agent/README.md)** 다(§무엇을 수집하나). 같은 목록을 여기 두 벌로 두지 않는다.

아래 §7·§8 이 실제로 물고 있는 **계약**만 여기 남긴다.

- **판정 입력 3종** — `pkg`(NEVRA + 소스패키지 + 벤더 — 릴리스번호·소스패키지가 백포트 인식의 핵심) ·
  `exposure`(리스닝 소켓마다 `scope` = EXTERNAL(0.0.0.0/::) / LOCAL(127.0.0.1) / BOUND(특정IP)) ·
  `runtime.processes`(포트가 없어도 실행 중인 전부). 이 셋이 §7 의 7단계를 만든다.
- **억제 근거와 억제 취소** — `changelog`·`errata`·`debsecan`·`updates` 가 억제 근거이고, 재시작 필요(옛 `.so` 를 문 프로세스)·커널 재부팅 전은 반대로 **억제를 막는** 신호다(→ §7).
- **네트워크 원자료** — `net.interfaces`/`net.routes` → 중앙이 `tb_host_address`(IP)·`tb_host_route`
  (직결 서브넷·기본 게이트웨이)로 푼다. 자산 탐색의 IP 대조와 세그먼트 맵이 이 둘을 읽는다(→ §8).
- **언어 생태계 8종**(pip/npm/gem/composer/maven/nuget/cargo/go) — 기본은 설치본이고 선언 파일
  직접 파싱은 `go.mod`/`requirements.txt`/`pom.xml` **3종뿐**이다. OSV 커넥터(`vg_osv_lang_queries`)가
  8개 전부를 자기 ecosystem 으로 조회한다. 라이선스는 SBOM + pip `METADATA` + composer
  `installed.json` 의 SPDX 만 보고(`src/license_risk.php`), 셋이 없으면 미상(unknown)이다.
- **개인정보 경계** — 계정 인벤토리(`users` → `src/account_inventory.php` → `tb_host_account`)는
  **패스워드 해시를 어떤 형태로도 수집·전송하지 않고**, 못 읽으면(비-root) 섹션을 아예 안 만들어
  중앙에서 NA 가 된다(PASS 로 위장하지 않는다).
- **선택 수집·근거 수집** — 패키지 무결성(`--verify-files`, **기본 꺼짐**)은 잘리면
  `partial`/`truncated` 를 함께 보낸다(잘린 0건을 "깨끗함"으로 읽으면 안 된다). CPU 취약점 완화
  상태(`hardware.cpu_vulnerabilities`)·커널 라이브패치는 **근거로 수집만** 하고 억제엔 안 쓴다.

---

## 5. 폴더 구조

**파일은 책임대로 놓는다.** 개별 파일명을 여기 다 적지 않는다 — 화면·헬퍼는 계속 늘고 줄어서
목록을 두면 곧 어긋난다. 어디에 무엇이 들어가는지만 고정한다.

```
vuln-agent/
├── CONTEXT.md  README.md  CLAUDE.md(개발원칙)  AGENTS.md  AGENTS-review-kit.md
├── deploy/       # 배포 인프라: compose.{common,dev,dev-db,dev-net,prod}.yml · compose_runner.sh
│   │             #   · migrate.sh · update.sh · backup_db.sh · wt.sh · agent_push.sh · agent_sign.sh
│   ├── caddy/    # HTTPS 리버스 프록시(운영 전용): Dockerfile·Caddyfile
│   ├── config/mysql/my.cnf   # 운영 MySQL 튜닝
│   ├── hooks/pre-push        # 검증 게이트(저장소가 들고 있다)
│   └── orchestrator/         # 병렬 워커 스폰(PowerShell) — 규약은 그 폴더의 README
├── secrets/(*.txt gitignore)   data/(mysql, gitignore)   agent-ca/(gitignore)
├── agent/        # 대상 서버에 설치되는 것: vuln-inventory-agent.sh(수집, --send 전송) ·
│                 #   install-agent.sh(배포·스케줄) · *.pub/*.sig(자동 업데이트 서명 공개키·서명)
├── server/
│   ├── public/   # HTTP 로 노출되는 것 = URL. 웹 화면(*.php) + 토큰 인증 API(ingest·agent-poll/
│   │             #   progress·export·sbom·agent-dl) + 화면이 뒤에서 부르는 엔드포인트(feed_preview 등)
│   │             #   · assets/ — app.css·app.js·vendor/(chartjs·flatpickr, CDN 없이 로컬 벤더링)
│   │             #   · process.html — 프로세스 소개(로그인 불필요, /process.html 로 공유)
│   │             #   화면 목록의 정본은 src/view/nav.php 의 vg_nav_sections() 와 사이트맵 다이어그램
│   ├── src/      # 공용 라이브러리(URL 로 안 열린다). 두 층이다 — ① 단일 파일 헬퍼(db·auth·matcher·
│   │             #   cce·compliance·discovery(+_enrich)·account_inventory·setting·vercmp·purl 등)
│   │             #   ② 화면·주제별 하위 디렉터리. 한 화면이 커지면 그 이름으로 가르고 **활성 탭/섹션
│   │             #   파일만** 읽어 그린다:
│   │             #     assets/ assetgrade/ cce/{,checks/} changes/{,tabs/} compliance/ connectors/
│   │             #     container/{,tabs/} cve/{,sections/} dashboard/{,sections/} format/
│   │             #     findings/{,queries/,tabs/} host/{,tabs/} ingest/{,store/} matcher/(판정 6분할)
│   │             #     feeds/(커넥터 12종 + http·upsert 헬퍼) view/{,components/}(레이아웃·nav·차트·표)
│   └── bin/      # CLI 전용: scheduler.php(사이드카) · sync.php · discover.php(자산 탐색 집행)
│                 #   · backfill_*(nvd·kisa·kisa_content·host_address·host_route)
├── db/           # 01~19 *.sql (빈 볼륨 initdb 전용, tb_ 접두사+감사4컬럼)
│   └── migrations/    # YYYYMMDDHHMMSS_*.sql — deploy/migrate.sh 가 자동 적용(tb_schema_migrations 기록)
│                      #   연번(0001…)은 금지 — 동시 브랜치가 같은 번호를 집는다. pre-push 가 막는다.
│                      #   기존 0001~0020 은 그대로 둔다(사전순이라 옛 것이 먼저 돈다).
├── tests/        # smoke.sh(API~로그인 curl) · e2e.sh+e2e/(브라우저, Playwright — 게이트 밖)
│                 #   · ui_lint.sh(죽은 CSS·인라인 style) · vercmp_test.php(버전비교 단위)
│                 #   · agent-bench.sh(에이전트 리소스 실측) · *_test.php/*_test.sh(단위·문서 일관성)
└── docs/         # dev/(아키텍처·데이터베이스·피드소스-역할·설명글·화면-안내·조치가이드·자산등급
                  #   ·UI 디자인 시스템·리소스 프로파일) · specs/diagrams/(PlantUML + 렌더 SVG)
                  #   · ui-configuration.md
```

> 하위 디렉터리는 **화면 하나를 잘게 쪼갠 것**이라 진입점은 여전히 `server/public/<화면>.php`
> 하나다(#621~#633 리팩터). 새 파일을 만들 때 그 화면 디렉터리 안인지 공용 헬퍼인지부터 정한다.

---

## 6. 데이터 흐름 (확정)

```
[원격 대상 서버]                        [중앙 서버 · Docker]
쉘 에이전트 ─ 상시 데몬(10초 poll) ─▶ Caddy(HTTPS:8080) ─▶ ingest.php ─┐
[중앙 서버 자신(로컬 에이전트)] ────▶ web:8081(루프백 평문) ───────────┤
                                                                       ▼
                                                                 MySQL(tb_*)
   로컬 CVE 미러(NVD·OSV·KISA) 매칭 + 런타임 노출 상관 + EPSS/KEV 가중 ─┘
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

- **KEV 등재** 시 한 단계 상향 → 외부노출 + KEV = **CRITICAL**. **EPSS**(악용확률)·CVSS 는 같은
  등급 안에서의 정렬에만 쓴다.
- `FILTERED` 가 없으면 방화벽 뒤의 내부 서비스가 **전부 HIGH/CRITICAL 로 뜬다**(오탐).
  에이전트가 firewalld/ufw 허용 포트와 대조해 판정한다.

**오탐 억제는 데비안 중심의 4겹**(①OSV 버전필터 ②changelog ③errata ④debsecan 역방향)**이고,
RHEL 계열·우분투·커널은 각자의 벤더 소스로 별도 판정한다.** 억제된 건은 `tb_finding` 이 아니라
`tb_suppressed_finding` 으로 가서 위험 집계에서만 빠지고 **근거는 화면에 그대로 남는다**
(숨기지 않는다). 벤더가 "아직 안 고쳤다"고 확인한 CVE 는 `tb_finding.no_fix` — 오탐 제거와 다른
축이라 등급은 그대로 두고 "지금 고칠 수 있는 것"과 화면에서만 분리한다. **억제를 취소하는 두
신호**도 있다: 패치됐어도 프로세스가 옛 `.so` 를 물고 있거나(`tb_stale_lib`, 조치는 재시작)
커널이 재부팅 전이면 억제하지 않는다 — 이게 없으면 "패치됨=안전"으로 착각해 미탐이 난다.

> **겹별 근거 테이블·커버리지·debsecan 역방향의 안전장치·벤더별 판정 규칙의 정본은
> [`docs/dev/architecture.md` §2](docs/dev/architecture.md) 다.** 같은 표를 여기 두 벌로 두지 않는다.

**미지원 배포판**(Amazon Linux · CentOS)은 피드가 안 덮어 매칭이 0건이 된다. 조용히 "취약점 없음"
으로 보이면 위험하므로 `vg_distro_unsupported`(`src/distro.php`)가 판정해 ingest 응답과 화면에
**경고로 띄운다**. Oracle Linux 는 OSV 대신 Oracle ELSA OVAL 로 릴리스별 영향·수정 EVR 을 판정한다.

즉 "설치=취약"으로 전부 올리지 않고, **실제 노출·실행·사용 여부로 우선순위를 가른다.**

**보안설정 점검(CCE)** 은 같은 수집물을 다른 눈으로 본다 — CVE(취약한 버전)가 아니라 잘못된 설정
(SSH·계정·패스워드 정책·파일 권한·MAC/방화벽·시간동기화·로그설정·암호화)을 `src/cce.php` 가
**39개 항목**으로 판정해 `tb_cce_finding` 에 저장한다. 그 결과를 **어느 기준의 증적으로 볼지**는
`tb_control_mapping`(U-코드·ISMS-P·N2SF)이 정하고, **기준 전체 중 몇 개를 덮는지**는
`tb_control_catalog`(기반시설 U-코드 72개)가 분모로 답한다 — 역할이 다른 두 표다. 기준을 화면
문자열이나 주석에 다시 적지 않는다(SSOT).

**계정 인벤토리**(`src/account_inventory.php` → `tb_host_account`)는 CCE 와 같은 원칙을 따른다 —
못 읽은 항목은 PASS 가 아니라 NA 이고, 공유계정·퇴직자 계정 추정은 FAIL 이 아니라 REVIEW(사람 확인)다.

---

## 8. 개발 현황 (2026-08-20 기준)

파이프라인(수집→전송→저장→매칭→표시)·HTTPS·감사에 더해 오탐억제/CCE/변화추적/Export, 컴플라이언스·
계정 인벤토리·자산 등급, 그리고 자산 탐색·세그먼트 맵까지 동작한다. 아래는 **무엇이 있는지**와
**왜 그렇게 했는지**만 남긴다 — 변경 이력은 git 이, 상세는 각 정본 문서가 갖는다.

### 기반 — 파이프라인·배포

- **더 손댈 것 없는 기본기**: Docker compose dev/prod + Docker Secrets + 러너 · 수집→전송→저장
  (`--send` → `ingest.php` → MySQL) · 로그인→대시보드→자산 상세→취약점 · 설정형 RBAC(admin 은
  코드에서 항상 허용해 잠금을 막는다) · Caddy HTTPS(자체서명 확정, 도메인은 `.env.prod` 의
  `PROD_DOMAIN`) · 무중단 배포(prod 가 `../server` 를 ro 마운트해 PHP 만 바뀌면 `update.sh` 로 끝) ·
  접속기록 5요소 · 세션·토큰 유효기간 · Caddy 보안 응답 헤더.
- **스키마 마이그레이션 자동화** — `deploy/migrate.sh` 가 미적용분만 사전순으로 적용하고
  `tb_schema_migrations` 에 기록한다. 파일명은 **타임스탬프** — 연번은 동시 브랜치가 같은 번호를
  집어 실제로 `0003`·`0014` 가 각각 두 개 생겼다(pre-push 가 신규 연번을 막는다). DB 규약은
  `tb_` 접두사 + 감사 4컬럼 + 소프트삭제 + 테이블명 단수 · PK `<엔티티>_id` — 상세는
  `docs/dev/데이터베이스.md`.
- **에이전트 운용** — 상시 데몬(10초 poll)이라 즉시 실행·예약·주기 변경을 중앙 웹에서 한다(SSH
  재설치 불필요). 설치 파일은 `agent-dl.php` 로 받고(배포별 루트 CA 는 `agent-ca/`, gitignore),
  재전송은 요청별 nonce 1회 허용(`tb_agent_replay_nonce`)으로 막으며, 호스트별 CPU·조립 타임아웃·
  메모리 상한은 속도 티어(`src/agentspeedtier.php`)로 내려보낸다.
- **무인 자동 업데이트 + 커밋 시점 Ed25519 서명 검증**(#683·#687) — poll 응답에 새 버전·sha256·
  서명이 실리면 에이전트가 스스로 갈아탄다. 서명은 유지보수자가 커밋 전에 로컬 개인키로 만들고
  (`deploy/agent_sign.sh`) 웹은 파일을 읽어 전달만 한다 — **웹 티어가 뚫려도 위조가 안 된다.**
  설치 때 공개키를 핀으로 고정하고, 공개키·서명이 없거나 검증에 실패하면 **자동 업데이트만**
  건너뛴다(수집·poll 은 계속). 다운그레이드는 거부하고 결과는 `agent_auto_update` 로 감사에 남는다.

### 판정 — 매칭·억제·벤더

- **피드 커넥터 12종** = 고정 11종(KEV/OSV/NVD/KISA/EPSS + 벤더·업스트림 판정 debtracker·rhoval·
  rhunfixed·ubuntuoval·kcve·ssg) + 범용 API(`generic_api`). UI 설정·미리보기·스케줄(manual/
  interval/daily/cron) + 스케줄러 사이드카. 역할별 차이는 `docs/dev/피드소스-역할.md`.
- **NVD 전체 데이터**(약 36만 건) — 주기 수집은 **수정일(lastMod) 기준**이다(뒤늦게 CVSS 가 붙는
  CVE 를 발행일 기준이면 영원히 놓친다). 전체 백필은 `bin/backfill_nvd.php`(멱등·재개·병렬),
  API 키는 DB 에만 둔다.
- **정밀 런타임 수집 + 7단계 상태** · **OSV 자동 매칭**(배포판 ecosystem·소스패키지·버전필터) ·
  **EPSS/KEV 우선순위** · **FILTERED 분류** · **억제 4겹과 억제 취소 두 신호** · **미지원 배포판
  경고**(`src/distro.php`) — §7 요약, 정본은 `docs/dev/architecture.md §2`.
- **패키지 출처 판정** — dpkg 는 vendor 를 안 주므로 apt 라벨(`o=Debian`/`o=Docker`/`o=LP-PPA-…`)로 서드파티를 가린다(URL 로 보면 사내 미러가 오분류된다).
- **재매칭 지문**(`tb_scan.match_fingerprint`) — 결과가 같으면 트랜잭션조차 열지 않는다. 예전엔
  1비트도 안 바뀐 경우까지 통째 삭제·재삽입해 binlog 가 하루 20GB 넘게 쌓였다. 판정 로직·저장
  컬럼을 바꾸면 `VG_MATCH_FP_VERSION` 을 올려야 한다.
- **판정 근거의 구조화** — `tb_finding_evidence`(근거 1:1) + `tb_collection_stage`(한 단계가 비면
  그 영역이 조용히 "취약점 없음"이 되므로 자산 상세에 경고로 띄운다).

### 화면·기능

> 화면마다 "왜 이렇게 보여주나"(판정 조건·걷어낸 요소·믿을 수 있는 범위)는
> **[`docs/dev/화면-안내.md`](docs/dev/화면-안내.md)** 가 갖는다. 여기는 무엇이 있는지만 적는다.

- **자산 탐색(섀도우 IT)**(#643~#646·#654·#660) — 관리 대역(CIDR)을 등록하면 중앙이 **2단계 TCP
  connect 스윕**으로 에이전트 미설치 IP 를 찾고(`src/discovery.php`), 역DNS·서비스 힌트·가벼운
  배너로 정체를 채워 `tb_host_address` 와 대조한다. **웹은 스캔을 돌리지 않는다** — 화면은
  `tb_discovery_run` 에 pending 을 넣고 집행은 스케줄러 틱(또는 `bin/discover.php --pending`)이
  한다(#654 이전엔 "지금 스캔"이 영원히 대기했다). 화면 `/discovery.php`, 스키마
  `tb_discovery_target`·`tb_discovery_run`·`tb_discovered_asset`·`tb_discovered_port`.
- **세그먼트 맵**(#666) — 라우팅 테이블(`tb_host_route`)로 "게이트웨이 아래 어떤 대역에 어떤 자산이
  있나"를 대역별 카드로 그린다(발견 자산도 CIDR 이 맞으면 같은 카드). 실제 트래픽 엣지는 수집
  데이터가 없어 그리지 않는다 — 없는 것을 채우면 틀린 그림이 사실처럼 보인다. `/segment-map.php`.
- **기반시설 U-코드 커버리지**(#651·#652·#676) — `tb_control_catalog` 가 KISA 상세가이드 UNIX 부문
  **72개를 분모로** 세우고 `tb_control_mapping` 을 왼쪽 조인해 **덮지 않는 항목까지** 드러낸다
  (덮는 것만 보이면 커버리지가 100%처럼 보인다). 화면 `/kisa-u.php`.
- **컨테이너·SBOM** — 실행 중 컨테이너 rootfs 를 직접 읽어(docker CLI 비의존) 내부 패키지를 수집하고
  컨테이너 탭 → `container.php` 로 드릴다운한다(#536, 호스트 스캔에서 통째로 빠지던 미탐 영역).
  산출은 `GET /sbom.php`(CycloneDX 1.5 / SPDX 2.3, **자산 하나당 문서 하나**, serialNumber 가 스캔
  기준 결정적 UUIDv5 라 문서 diff 가 성립한다) + **호스트 SBOM 임포트**(#647, 예약 cid `_host`) +
  **브라우저 보기**(`sbom.php?view=html`, #682).
- **의존성 그래프와 조치 연결**(#480·#527·#560·#565·#692) — 직접/전이 의존을 수집·저장하고
  `depgraph.php` 가 루트별 카드 + org-chart 로 보여준다. 취약점 행이 전이면 조치를 "**직접 조치
  불가 — X 가 끌어옴**"으로 바꾸고, 부모별로 묶어 "이 하나를 올리면 N건 해결"을 최고 심각도→건수
  순으로 올린다. **올릴 버전은 제안하지 않는다**(설치되지 않은 부모가 무엇을 끌어오는지 수집물로
  알 수 없다). 진입은 자산 상세에서만 — 엣지 유니크 키 좌측 접두가 (스캔, 컨테이너)다.
- **탐지 결과 한 화면**(#555·#556) — CVE·보안설정(CCE)·노출을 `findings.php` 의 `?type=` 탭으로 묶고
  변화 추적·제거 권고도 같은 탭 줄로 들어온다. 세 표를 UNION 하지 않는다(`tb_finding` 이 커서 합쳐
  정렬·페이징하면 인덱스가 죽는다). 탭 라벨·순서의 정본은 `view/nav.php` 하나다.
- **컴플라이언스와 기준 매핑** — 자동판정 통제 **4종**(patch/asset/secops/account)을 한 줄씩 요약하고
  근거는 링크로 넘긴다. 판정 어휘는 준수·부분준수·미준수·**판정 불가** 4종 — 근거가 모자라 0건인
  것을 준수로 쓰면 심사 증빙이 허위 안심이 된다(#493). `patch` 는 버킷(KEV/CRITICAL/HIGH)별로
  판정하고, 증적이 **제품 밖**에 있는 4건은 수동 체크리스트로 강등했다(삭제가 아니다). 로직은
  `src/compliance.php` 한 곳이라 화면·스케줄러가 같은 함수를 쓰고 하루 1건 스냅샷을 남긴다. 같은 CCE
  결과를 어느 기준의 증적으로 볼지는 `control_mapping.php`·`control.php` 가, 39개 점검 항목 자체는
  `cce-rules.php`·`cce-rule.php` 가 보여준다(조치 원문은 `docs/dev/보안설정-조치가이드.md`).
- **자산 중요도·N2SF 보안등급** — 확정값과 시스템 제안값을 **다른 컬럼**에 담는다(등급 확정은 기관의
  법적 처분이라 시스템이 대신할 수 없다). 제안 이력은 append-only 이고 상태가 `SUGGESTED`/
  `NO_MATCH`/`NOT_EVALUATED` 셋이라 "근거가 없어졌다"와 "수집이 빠져 판정을 못 했다"를 구분한다.
  정본은 `docs/dev/자산등급.md`(코드는 `src/assetgrade.php`).
- **그 밖의 읽는 화면** — 변화 추적(`changes.php`, 최근 2개 스캔의 `tb_finding` 비교, 새 테이블 없이) ·
  벤더 판정 조회(`vendor.php`) · SSG 룰 카탈로그(약 2,493개) · 제거·대체 검토 권고(벤더 미수정이 한
  패키지에 몰리면 호스트×패키지로 묶는다 — 관측이지 EOL 확정이 아니다) · 미조치 사유·승인자와 조치
  상태 4종(담당자·결재선·만료는 없다) · 계정 인벤토리 · 패키지 무결성(미수행/정상/원본과 다름 —
  검사 여부·부분 결과는 `tb_scan` 의 스캔 단위 사실이다) · Export API(`docs/dev/export-api.md`).
- **성능 사전집계** — `tb_package_summary`(92만 행 GROUP BY 8초 → 0.1초 미만, 갱신은 OSV 실행 시)와
  `tb_package_license_summary`. 후자는 **OSV 게이트에 묶지 않는다** — 라이선스는 OSV 가 아니라
  ingest 로 들어와서, 묶으면 OSV 미등록 동안 KPI 가 영구히 0으로 보인다(PR#468).
- **화면 전면 재구성**(#650~#692) — 목록·표 위주였던 화면 다수를 카드·도넛·랭킹 차트로 바꿨다.
  Chart.js 로컬 벤더링(`assets/vendor/chartjs`, `vg_chart()`) · 형태·간격·타이포·숫자·행 밀도 다섯
  축의 디자인 토큰 · 빈 상태 아이콘을 이모지 → 공용 SVG 세트(`view/icons.php`) · 자산 상세 탭 2단 →
  **1단**(억제를 취약점 탭의 보기 필터로 내려 9개 → 8개) · 컴플라이언스 이력 표 제거 · 탐지 결과 탭
  줄의 건수 제거(지금 탭이 아닌 유형까지 매 요청 COUNT 해야 했다) · 목록 기본 10건.
  기준은 `docs/dev/ui-design-system.md`.
- **제품 범위 정리** — 담당자·결재선·예외 만료를 추적하는 조치 관리, 접속기록 월간 검토 저장·승인,
  정책·절차 문서 심사 카드는 제거·강등했다. 제품은 스캔 결과와 판정 근거를 정확히 보여주는 데 집중한다.

### 검증

- `tests/smoke.sh`(curl) 가 게이트이고, 그 앞단에서 `ui_lint.sh`(죽은 CSS·인라인 style)와
  단위 테스트(`vercmp_test.php` 등)를 먼저 돌린다.
- **브라우저 E2E**(`tests/e2e.sh` + Playwright)는 게이트 **밖**이다 — smoke 는 curl 이라 클라이언트
  JS 가 통째로 깨져도 전부 통과한다. 그 구멍만 덮는다(로그인·테마/밀도 토글·모바일 사이드바·커넥터
  화면 JS·모달). 기대값은 `#connForm` 의 `data-type-meta`(PHP 카탈로그 `VG_CONNECTOR_TYPES`)와
  비교하므로 **카탈로그와 화면이 어긋나면 걸린다**. 커넥터의 미리보기·지금 실행·저장·삭제는
  **일부러 안 덮는다**(외부 소스를 실제로 치거나 공용 dev DB 를 바꾼다).
- `tests/documentation_consistency_test.php` 가 DB 문서·ERD·사이트맵·README 를 코드와 대조한다(문서가 조용히 뒤처지는 것을 막는 정적 회귀 테스트).
