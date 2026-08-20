# CONTEXT.md — 프로젝트 맥락 (Claude Code 최우선 참고)

> 현행 기준: 2026-08-20 · 에이전트 3.14 · 자산 탐색(섀도우 IT)·세그먼트 맵·기반시설 U-코드
> 커버리지·에이전트 무인 자동 업데이트(Ed25519 서명 검증) 포함.

> 이 파일은 개발을 이어받는 사람(및 Claude Code)이 **가장 먼저 읽는** 요약이다 — **왜 만드는지,
> 무엇을 만들었는지, 지금 어디까지 왔는지**만 담는다. 구조·규칙의 정본은
> [`docs/dev/architecture.md`](docs/dev/architecture.md), 쉬운 설명은 `docs/dev/설명글.md`, 기획 문서는
> `docs/dev/기획안_v1.0.html`, 프로세스 소개는 `server/public/process.html`(→ `/process.html`, 사본 금지).

---

## 1. 이 프로젝트가 뭔가

**취약점을 스스로 조사·판단·조치하는 자율 보안 에이전트.**
각 서버에 경량 에이전트를 두고 설치 패키지·런타임 정보를 중앙으로 모아 CVE와 매칭한다. 단순 스캐너와
다른 점은 **"이 취약점이 이 서버에서 실제로 위험한가"를 맥락으로 판단**해 오탐을 줄인다는 것.

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

> **AI 문서 생성(Python)은 범위 제외다.** 수집·매칭·표시는 DB 조회지 추론이 아니라 AI 가 필요 없고,
> 보고서 생성기는 본체 대신 **Export API 로 분리**해 외부가 `GET /export.php`(JSON/XML)로 가져가게 했다 —
> 본체가 AI 에 묶이지 않는다. 상용 API 는 코드 작성 보조로만 쓴다(규정상 자유, 보고서에 기재).

---

## 4. 이미 만들어진 것 (재사용)

### `agent/` — 수집 에이전트 v3.14 + 설치기 (동작 검증 완료)

읽기 전용이고 서버에 무리 안 간다(nice 19 / ionice idle / 명령별 timeout). 피크 메모리는 실측 **61.6MB**
(Debian 12 · 91패키지 — 페이로드 크기에 비례. 수치·재측정법은 `docs/dev/에이전트-리소스-프로파일.md`).
jq 있으면 JSON, 없으면 섹션 텍스트. RHEL/Debian 자동 감지. 설치는 `sudo bash install-agent.sh` 하나이고,
systemd 가 있으면 상시 데몬(10초 poll)·없으면 cron 폴백이다.

> **수집 항목 전체 목록과 설치·권한·갱신·자동 업데이트·속도 티어·실행 옵션의 정본은
> [`agent/README.md`](agent/README.md)** 다(§무엇을 수집하나). 같은 목록을 여기 두 벌로 두지 않는다.

아래 §7·§8 이 실제로 물고 있는 **계약**만 여기 남긴다.

- **판정 입력 3종** — `pkg`(NEVRA + 소스패키지 + 벤더 — 릴리스번호·소스패키지가 백포트 인식의 핵심) ·
  `exposure`(소켓마다 `scope` = EXTERNAL/LOCAL/BOUND) · `runtime.processes`(포트가 없어도 실행 중인
  전부). 이 셋이 §7 의 7단계를 만든다.
- **억제 근거와 억제 취소** — `changelog`·`errata`·`debsecan`·`updates` 가 억제 근거이고, 재시작 필요(옛 `.so` 를 문 프로세스)·커널 재부팅 전은 반대로 **억제를 막는** 신호다(→ §7).
- **네트워크 원자료** — `net.interfaces`/`net.routes` → 중앙이 `tb_host_address`(IP)·`tb_host_route`
  (직결 서브넷·기본 게이트웨이)로 푼다. 자산 탐색의 IP 대조와 세그먼트 맵이 이 둘을 읽는다(→ §8).
- **언어 생태계 8종**(pip/npm/gem/composer/maven/nuget/cargo/go) — 기본은 설치본이고 선언 파일 직접
  파싱은 `go.mod`/`requirements.txt`/`pom.xml` **3종뿐**. 라이선스 근거가 없으면 미상(unknown)이다.
- **개인정보 경계** — 계정 인벤토리(`src/account_inventory.php` → `tb_host_account`)는 **패스워드 해시를
  어떤 형태로도 수집·전송하지 않고**, 못 읽으면 섹션을 안 만들어 NA 가 된다(PASS 로 위장하지 않는다).
- **선택 수집·근거 수집** — 패키지 무결성(`--verify-files`, **기본 꺼짐**)은 잘리면 `partial`/`truncated`
  를 함께 보낸다(잘린 0건을 "깨끗함"으로 읽으면 안 된다). CPU 완화 상태·커널 라이브패치는 **근거로
  수집만** 하고 억제엔 안 쓴다.

---

## 5. 폴더 구조

**파일은 책임대로 놓는다.** 개별 파일명을 여기 다 적지 않는다 — 화면·헬퍼는 계속 늘고 줄어서
목록을 두면 곧 어긋난다. 어디에 무엇이 들어가는지만 고정한다.

```
vuln-agent/
├── deploy/          # 배포 인프라(compose·compose_runner·migrate·update·backup·wt·agent_push/sign) ·
│                    #   caddy/ · hooks/pre-push(검증 게이트) · orchestrator/(병렬 워커 스폰)
├── agent/           # 대상 서버에 설치되는 것: 수집 스크립트 · 설치기 · 자동 업데이트 서명 공개키/서명
├── server/          # public/(= URL. 화면·토큰 인증 API·assets·process.html — 화면 목록의 정본은
│                    #   src/view/nav.php) · src/(공용 라이브러리, URL 로 안 열린다) · bin/(CLI 전용)
├── db/              # initdb 전용 *.sql + migrations/(YYYYMMDDHHMMSS_*.sql — 연번 금지, pre-push 가 막는다)
├── tests/           # smoke.sh(게이트) · e2e.sh(브라우저, 게이트 밖) · ui_lint.sh · *_test.php/*_test.sh
├── docs/            # dev/(아키텍처·데이터베이스·설명글·화면-안내·자산등급 등) · specs/diagrams/
└── secrets/ · data/ · agent-ca/   # 전부 gitignore
```

> 하위 디렉터리는 **화면 하나를 잘게 쪼갠 것**이라 진입점은 여전히 `server/public/<화면>.php`
> 하나다(#621~#633 리팩터). 새 파일을 만들 때 그 화면 디렉터리 안인지 공용 헬퍼인지부터 정한다.

---

## 6. 데이터 흐름 (확정)

쉘 에이전트(상시 데몬, 10초 poll)가 Caddy(HTTPS:8080) → `ingest.php` → MySQL 로 사실을 넣고(중앙 서버
자신의 로컬 에이전트는 web:8081 루프백 평문), 그 사실을 로컬 CVE 미러(NVD·OSV·KISA) 매칭 + 런타임 노출
상관 + EPSS/KEV 가중으로 판정해 PHP 웹 대시보드가 보여준다. 그림과 파이프라인 분기는
[`docs/dev/architecture.md` §1](docs/dev/architecture.md).

---

## 7. 매처 핵심 규칙 (구현됨)

수집한 `packages` + `exposures`(포트) + `processes`(실행/로드)를 CVE와 조인해 각 취약점의 **런타임
상태**를 7단계로 판정한다(`vg_classify`) — `EXTERNAL` 외부노출(3/HIGH) · `LAN`·`FILTERED`·
`LISTENING`·`RUNNING`·`LOADED`(2/MEDIUM) · `INSTALLED` 설치만(1/LOW). **KEV 등재** 시 한 단계 상향해
외부노출 + KEV = **CRITICAL** 이고, **EPSS**·CVSS 는 같은 등급 안에서의 정렬에만 쓴다. `FILTERED` 가
없으면 방화벽 뒤의 내부 서비스가 **전부 HIGH/CRITICAL 로 뜬다**(오탐).

**오탐 억제는 데비안 중심의 4겹**(①OSV 버전필터 ②changelog ③errata ④debsecan 역방향)**이고,
RHEL 계열·우분투·커널은 각자의 벤더 소스로 별도 판정한다.** 억제된 건은 `tb_finding` 이 아니라
`tb_suppressed_finding` 으로 가서 위험 집계에서만 빠지고 **근거는 화면에 그대로 남는다**(숨기지
않는다). 벤더가 "아직 안 고쳤다"고 확인한 CVE 는 `tb_finding.no_fix` — 등급은 그대로 두고 "지금
고칠 수 있는 것"과 화면에서만 분리한다. **억제를 취소하는 두 신호**도 있다: 패치됐어도 프로세스가
옛 `.so` 를 물고 있거나(`tb_stale_lib`, 조치는 재시작) 커널이 재부팅 전이면 억제하지 않는다 — 이게
없으면 "패치됨=안전"으로 착각해 미탐이 난다.

**미지원 배포판**(Amazon Linux · CentOS)은 피드가 안 덮어 매칭이 0건이 되므로, 조용히 "취약점 없음"으로
보이지 않게 `vg_distro_unsupported`(`src/distro.php`)가 **경고로 띄운다**(Oracle Linux 는 ELSA OVAL).

**보안설정 점검(CCE)** 은 같은 수집물을 다른 눈으로 본다 — 잘못된 설정을 `src/cce.php` 가 **39개 항목**
으로 판정하고, 그 결과를 **어느 기준의 증적으로 볼지**는 `tb_control_mapping` 이 **기준 전체 중 몇 개를
덮는지**는 `tb_control_catalog`(U-코드 72개)가 분모로 답한다 — 역할이 다른 두 표다(SSOT). **계정
인벤토리**도 같은 원칙이다 — 못 읽은 항목은 NA, 공유·퇴직자 계정 추정은 FAIL 이 아니라 REVIEW다.

> **7단계 판정 조건표·겹별 근거 테이블·커버리지·벤더별 판정 규칙·CCE 항목의 정본은
> [`docs/dev/architecture.md` §2](docs/dev/architecture.md) 다.** 같은 표를 두 벌로 두지 않는다.

---

## 8. 개발 현황 (2026-08-20 기준)

파이프라인(수집→전송→저장→매칭→표시)·HTTPS·감사에 더해 오탐억제/CCE/변화추적/Export, 컴플라이언스·
계정 인벤토리·자산 등급, 자산 탐색·세그먼트 맵까지 동작한다. 아래는 **무엇이 있는지**와 **왜 그렇게
했는지**만 남긴다 — 변경 이력은 git 이, 상세는 각 정본 문서가 갖는다.

### 기반 — 파이프라인·배포

- **더 손댈 것 없는 기본기**: Docker compose dev/prod + Docker Secrets + 러너 · 수집→전송→저장 · 로그인→
  대시보드→자산 상세→취약점 · 설정형 RBAC(admin 은 코드에서 항상 허용해 잠금을 막는다) · Caddy HTTPS ·
  무중단 배포(prod 가 `../server` 를 ro 마운트) · 접속기록 5요소 · 세션·토큰 유효기간 · 보안 응답 헤더.
- **스키마 마이그레이션 자동화** — `deploy/migrate.sh` 가 미적용분만 사전순으로 적용하고
  `tb_schema_migrations` 에 기록한다. 파일명은 **타임스탬프** — 연번은 동시 브랜치가 같은 번호를 집어
  실제로 `0003`·`0014` 가 두 개씩 생겼다(pre-push 가 막는다). DB 규약은 `docs/dev/데이터베이스.md`.
- **에이전트 운용** — 상시 데몬(10초 poll)이라 즉시 실행·예약·주기 변경을 중앙 웹에서 한다(SSH 재설치
  불필요). 설치 파일은 `agent-dl.php` 로 받고(배포별 루트 CA 는 `agent-ca/`, gitignore), 재전송은 요청별
  nonce 1회 허용으로 막으며, 호스트별 자원 상한은 속도 티어(`src/agentspeedtier.php`)가 내려보낸다.
- **무인 자동 업데이트 + 커밋 시점 Ed25519 서명 검증**(#683·#687) — 서명은 유지보수자가 커밋 전에 로컬
  개인키로 만들고(`deploy/agent_sign.sh`) 웹은 파일을 읽어 전달만 한다 — **웹 티어가 뚫려도 위조가 안
  된다.** 검증 실패 시 **자동 업데이트만** 건너뛰고(수집·poll 은 계속), 다운그레이드는 거부하며 결과는
  `agent_auto_update` 로 감사에 남는다.

### 판정 — 매칭·억제·벤더

- **피드 커넥터 12종** = 고정 11종(KEV/OSV/NVD/KISA/EPSS + debtracker·rhoval·rhunfixed·ubuntuoval·
  kcve·ssg) + 범용 API. UI 설정·미리보기·스케줄 + 스케줄러 사이드카. 역할은 `docs/dev/피드소스-역할.md`.
- **NVD 전체 데이터**(약 36만 건) — 주기 수집은 **수정일(lastMod) 기준**이다(뒤늦게 CVSS 가 붙는 CVE 를
  발행일 기준이면 영원히 놓친다). 전체 백필은 `bin/backfill_nvd.php`, API 키는 DB 에만 둔다.
- **패키지 출처 판정** — dpkg 는 vendor 를 안 주므로 apt 라벨로 서드파티를 가린다(URL 로 보면 사내
  미러가 오분류된다).
- **재매칭 지문**(`tb_scan.match_fingerprint`) — 결과가 같으면 트랜잭션조차 열지 않는다(예전엔 1비트도 안
  바뀐 경우까지 삭제·재삽입해 binlog 가 하루 20GB 쌓였다). 판정 로직·저장 컬럼을 바꾸면
  `VG_MATCH_FP_VERSION` 을 올린다.
- **판정 근거의 구조화** — `tb_finding_evidence` + `tb_collection_stage`(한 단계가 비면 그 영역이 조용히 "취약점 없음"이 되므로 자산 상세에 경고로 띄운다).

### 화면·기능

> 화면마다 "왜 이렇게 보여주나"(판정 조건·걷어낸 요소·믿을 수 있는 범위)는
> **[`docs/dev/화면-안내.md`](docs/dev/화면-안내.md)** 가 갖는다. 여기는 무엇이 있는지만 적는다.

- **자산 탐색(섀도우 IT)**(#643~#660) — 관리 대역(CIDR)의 미설치 IP 를 2단계 TCP connect 스윕으로 찾아
  `tb_host_address` 와 대조한다. **웹은 스캔을 돌리지 않는다** — pending 만 넣고 스케줄러 틱이 집행한다.
- **세그먼트 맵**(#666) — 라우팅 테이블로 대역별 카드를 그린다. 실제 트래픽 엣지는 수집 데이터가 없어
  그리지 않는다 — 없는 것을 채우면 틀린 그림이 사실처럼 보인다.
- **기반시설 U-코드 커버리지**(#651·#652·#676) — `tb_control_catalog` 72개를 분모로 세우고 왼쪽 조인해
  **덮지 않는 항목까지** 드러낸다(덮는 것만 보이면 100%로 보인다).
- **컨테이너·SBOM** — 실행 중 컨테이너 rootfs 를 직접 읽어(docker CLI 비의존) 내부 패키지를 수집한다(#536,
  호스트 스캔에서 통째로 빠지던 미탐 영역). 산출은 `GET /sbom.php`(CycloneDX 1.5 / SPDX 2.3, 자산 하나당
  문서 하나, serialNumber 가 결정적 UUIDv5 라 diff 가 성립) + 호스트 임포트 + 브라우저 보기.
- **의존성 그래프와 조치 연결**(#480~#692) — `depgraph.php` 가 루트별 카드로 보여주고, 취약점 행이 전이면
  조치를 "**직접 조치 불가 — X 가 끌어옴**"으로 바꿔 부모별로 묶는다. **올릴 버전은 제안하지 않는다.**
  진입은 자산 상세에서만 — 엣지 유니크 키 좌측 접두가 (스캔, 컨테이너)다.
- **탐지 결과 한 화면**(#555·#556) — CVE·CCE·노출을 `findings.php` 의 `?type=` 탭으로 묶는다. 세 표를
  UNION 하지 않는다(`tb_finding` 이 커서 합쳐 정렬·페이징하면 인덱스가 죽는다). 정본은 `view/nav.php`.
- **컴플라이언스와 기준 매핑** — 자동판정 통제 **4종**(patch/asset/secops/account), 판정 어휘 4종(준수·
  부분준수·미준수·**판정 불가**) — 0건을 준수로 쓰면 심사 증빙이 허위 안심이 된다(#493). 증적이 **제품
  밖**인 4건은 수동 체크리스트로 강등했다(삭제가 아니다). 로직은 `src/compliance.php` 한 곳이고 하루
  1건 스냅샷을 남긴다.
- **자산 중요도·N2SF 보안등급** — 확정값과 제안값을 **다른 컬럼**에 담는다(등급 확정은 기관의 법적 처분
  이라 시스템이 대신할 수 없다). 제안 이력은 append-only, 상태 3종. 정본은 `docs/dev/자산등급.md`.
- **그 밖의 읽는 화면** — 변화 추적(`changes.php`) · 벤더 판정 조회 · SSG 룰 카탈로그 · 제거·대체 검토 권고
  (EOL 확정이 아니다) · 조치 상태 4종 · 계정 인벤토리 · 패키지 무결성(미수행/정상/다름) · Export API.
- **성능 사전집계** — `tb_package_summary`(92만 행 GROUP BY 8초 → 0.1초 미만)와 `tb_package_license_summary`.
  후자는 **OSV 게이트에 묶지 않는다** — 묶으면 OSV 미등록 동안 KPI 가 영구히 0으로 보인다(PR#468).
- **화면 전면 재구성**(#650~#692) — 목록·표 위주였던 화면을 카드·도넛·랭킹 차트로 바꿨다(Chart.js 로컬
  벤더링 · 디자인 토큰 · 공용 SVG 아이콘 · 자산 상세 탭 1단 · 탐지 결과 탭 건수 제거). 기준은
  `docs/dev/ui-design-system.md`.
- **제품 범위 정리** — 담당자·결재선·예외 만료를 추적하는 조치 관리, 접속기록 월간 검토 저장·승인,
  정책·절차 문서 심사 카드는 제거·강등했다. 제품은 스캔 결과와 판정 근거에 집중한다.

### 검증

- `tests/smoke.sh`(curl) 가 게이트이고, 앞단에서 `ui_lint.sh`·단위 테스트(`vercmp_test.php` 등)를 돌린다.
- **브라우저 E2E**(`tests/e2e.sh` + Playwright)는 게이트 **밖**이다 — smoke 는 curl 이라 클라이언트 JS 가
  통째로 깨져도 전부 통과하므로 그 구멍만 덮는다. 기대값을 `#connForm` 의 `data-type-meta`(PHP 카탈로그
  `VG_CONNECTOR_TYPES`)와 비교하므로 **카탈로그와 화면이 어긋나면 걸린다**. 커넥터의 미리보기·실행·
  저장·삭제는 **일부러 안 덮는다**(외부 소스를 치거나 공용 dev DB 를 바꾼다).
- `tests/documentation_consistency_test.php` 가 DB 문서·ERD·사이트맵·README 를 코드와 대조한다.
