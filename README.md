# vuln-agent

> 문서 기준: 2026-08-04 · 중앙 웹 `main` · 에이전트 3.8

런타임 노출 맥락으로 오탐을 줄이는 자율 취약점 진단 에이전트 (2026 오픈소스 개발자대회)

버전만 비교하는 스캐너는 "설치돼 있으면 취약"으로 판정하기 때문에, 아무 프로세스도 쓰지 않는
패키지까지 전부 경고가 되어 오탐이 쌓인다. vuln-agent 는 각 서버의 경량 에이전트가 설치 패키지뿐
아니라 **런타임 노출(열린 포트)·실행 중인 프로세스·로드한 라이브러리**까지 수집하고, 중앙 매처가
그 맥락으로 "이 서버에서 실제로 위험한가"를 7단계 상태로 갈라 우선순위를 매긴다. 매칭 판정 자체는
검증된 피드(OSV·NVD·KEV·EPSS)에서 상속받고, 기여는 그 위 레이어에 둔다. 차별점은 세 가지다 —
**백포트 오탐 억제**(changelog·errata·debsecan 근거 4겹으로 "버전은 낮아도 이미 패치됨"을 증명),
**국내 특화**(KISA 보안공지 연동), 그리고 억제한 건을 숨기지 않고 **근거와 함께 보여주는
설명가능성**이다.

> 프로젝트 전체 맥락·전략·로드맵은 [`CONTEXT.md`](CONTEXT.md) 참고.

## 목차

- [이게 뭔가](#이게-뭔가)
- [빠른 시작](#빠른-시작)
- [문서 지도](#문서-지도)
- [웹 화면 · API](#웹-화면--api)
- [오탐을 줄이는 방법](#오탐을-줄이는-방법)
  - [런타임 상태 구분](#런타임-상태-구분)
  - [백포트 오탐 억제 (근거 4겹)](#백포트-오탐-억제-근거-4겹)
  - ["패치됨"이 곧 "안전함"은 아니다 — 재시작·재부팅 필요](#패치됨이-곧-안전함은-아니다--재시작재부팅-필요)
  - [컨테이너 내부까지 본다](#컨테이너-내부까지-본다)
  - [미지원 배포판은 조용히 넘어가지 않는다](#미지원-배포판은-조용히-넘어가지-않는다)
  - [보안설정 점검 (CCE)](#보안설정-점검-cce)
- [피드 커넥터](#피드-커넥터)
- [에이전트 설치 · 운영](#에이전트-설치--운영)
- [배포 · 운영](#배포--운영)
- [권한 · 감사 로그](#권한--감사-로그)
- [테스트](#테스트)
- [진행 상태](#진행-상태)
- [라이선스](#라이선스)
- [병렬 워커 오케스트레이터](#병렬-워커-오케스트레이터)

## 이게 뭔가

데이터 흐름: **에이전트(JSON) ─POST(HTTPS)→ `ingest.php` → MySQL(`tb_*`) → 웹 현황**

```
agent/    수집 에이전트 (Bash) — 패키지·런타임 노출·백포트 changelog 수집 + install-agent.sh(systemd 상시 데몬/cron 폴백 자동 배포). 설치·운영은 agent/README.md
server/   PHP 중앙 서버 — 수신 API(ingest)·Export API + 웹(대시보드·취약점·자산·수집·계정·연동·기록) + 매처
deploy/   배포 인프라 — compose 파일·러너·caddy(HTTPS 리버스 프록시, 운영 전용)·migrate.sh(스키마 자동 적용)·wt.sh
db/       MySQL 스키마 — tb_ 접두사 + 감사 4컬럼. 최상위 *.sql 은 빈 볼륨 초기화용, 증분 변경은 migrations/
docs/     아키텍처 · 기획안 · 설명글 · 피드소스-역할(커넥터 12종: 고정 5종 + 벤더판정 6종 + 범용 API) · export-api · 에이전트-리소스-프로파일
          (전체 프로세스 소개는 웹으로 서빙 — server/public/process.html → /process.html)
shadow-ai/  (사이드 PoC) 섀도우 AI DLP 크롬 확장 — AI 챗봇 입력창의 민감정보 탐지. 본 파이프라인과 독립
```

## 빠른 시작

모든 것은 컨테이너로 동작한다(로컬 PHP/MySQL 불필요). 환경은 **dev / prod** 두 가지.
러너·compose 파일은 모두 `deploy/` 에 있다(`cd deploy` 후 실행).

```bash
cd deploy
./compose_runner.sh init            # .env.dev / .env.prod 생성(템플릿 복사) → 비밀값 수정
./compose_runner.sh doctor          # 사전 점검
./compose_runner.sh dev  up -d           # 개발 환경 기동(소스 라이브 마운트 → 재빌드 불필요, Dockerfile 바뀔 때만 --build)
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

업데이트 절차·마이그레이션 순서·compose 파일 구조는 [배포 · 운영](#배포--운영) 참고.

| | dev | prod |
|---|---|---|
| 소스 | `./server` 라이브 마운트(즉시 반영) | `../server` 읽기전용 마운트(PHP 는 배포=`git pull`, 무중단) |
| DB 포트 | 호스트에 노출(3307) | **미노출**(내부 네트워크만) |
| 웹 접속 | 평문 `http://localhost:8000` | **HTTPS** `https://<운영-도메인>` (Caddy · `:8080` 도 계속 동작) |
| 환경변수 | `.env.dev` | `.env.prod` |
| 프로젝트명 | `vulnagent-dev` | `vulnagent` |

- 현황 페이지(dev): <http://localhost:8000>
- 현황 페이지(prod): `https://<운영-도메인>` — `<운영-도메인>` 은 운영 배포 시 정해 `.env.prod` 의
  `PROD_DOMAIN` 에 넣는 값이다(저장소에는 두지 않는다). 자체서명 인증서라 브라우저 경고가 뜬다.
  평문 `http://<운영-도메인>` 으로 들어와도 https 로 자동 리다이렉트(308)된다.
  기존 `https://<운영-도메인>:8080` 도 하위호환으로 그대로 동작한다(설치된 에이전트가 쓰는 주소).
- 수신 API: `POST .../ingest.php` (헤더 `X-Agent-Token`). prod 는 web 이 외부에 직접 노출되지
  않고, 중앙서버 자신을 스캔하는 로컬 에이전트만 루프백 평문 `127.0.0.1:8081` 로 직접 전송한다.

## 문서 지도

- [`agent/README.md`](agent/README.md) — 에이전트 설치·운영의 단일 출처(설치·권한·갱신·주기 변경·제거·수집 항목). 설치 한 번이면 systemd 상시 데몬이 10초마다 poll 하며 주기가 되면 알아서 재수집(계속 켜둘 필요 없음, 중앙 웹에서 즉시/예약/주기변경 가능), 전송 URL 주의점.
- [`docs/dev/피드소스-역할.md`](docs/dev/피드소스-역할.md) — NVD/OSV·EPSS·KEV·KISA 각 커넥터가 무슨 질문에 답하는지.
- [`docs/dev/architecture.md`](docs/dev/architecture.md) — 시스템 구조·매처 규칙·배포 방식.
- [`docs/dev/export-api.md`](docs/dev/export-api.md) — 스캔 결과 내보내기 API(JSON/XML)·API 토큰 발급.
- [`docs/dev/데이터베이스.md`](docs/dev/데이터베이스.md) — DB 테이블·컬럼 레퍼런스(정규화 현황 포함).
- [`docs/specs/테이블명세서.xlsx`](docs/specs/테이블명세서.xlsx) — 외부 전달용 테이블 명세서(엑셀).
- [`docs/specs/diagrams/`](docs/specs/diagrams/) — 시스템 구조·ERD 등 PlantUML 다이어그램 6종.

## 웹 화면 · API

자산 영역은 `자산 목록`과 `전체 설치 패키지`를 상단 탭으로 제공한다. 자산 상세에서는
호스트별 패키지·런타임·보안 설정·리소스·최근 10회 스캔 이력을 조회하고, 즉시/예약 수집과
주기 변경 및 실행 중 수집 취소를 제어한다. 진행 중 명령은 약 5초마다 heartbeat와 취소 요청을 확인한다.

좌측 사이드바 · 역할별 권한으로 노출.

| 대분류 | 화면 |
|---|---|
| (대분류 없음) | `/` 대시보드 — 호스트별 최신 스캔·심각도 KPI → 서버명 클릭 시 호스트 상세 `host.php`(노출·프로세스·취약점·CCE·억제 내역) |
| 취약점 | `/findings.php` 탐지 결과(+수정 버전·판정 근거, `/changes.php` 변화 추적) · `/cves.php` CVE · `/packages.php` 패키지 · `/vendor.php` 판정 근거 · `/compliance_rules.php` 보안 설정 · `/advisories.php` 보안 공지 |
| 바로가기 | `/assets.php` 자산 · `/connectors.php` 데이터 수집 |
| 관리 | `/users.php` 사용자 · `/permissions.php` 권한 · `/agent-tokens.php` 에이전트 키 · `/api-tokens.php` API 키 · `/activity.php` 감사 로그 |

사이드바 밖: `/profile.php` 내 프로필(상단바 사용자 메뉴 — 로그인 사용자 전원, 본인 비밀번호 변경).

API: `POST /ingest.php`(에이전트 수집 수신) · `GET /export.php`
(결과 내보내기 — 상세: [`docs/dev/export-api.md`](docs/dev/export-api.md)) ·
`GET /agent-dl.php`(에이전트 설치 파일 배포 — 자산 화면의 설치 안내 모달이 링크) ·
`GET /feed_preview.php`(커넥터 미리보기, perm=connectors).

각 취약점에는 **조치안**("어느 버전 이상으로 업데이트")이 함께 표시된다(OSV 의 fixed 버전).

## 오탐을 줄이는 방법

이 프로젝트의 핵심이다. "설치=취약"으로 전부 올리지 않고, 런타임 맥락과 벤더 근거로 걸러낸다.

### 런타임 상태 구분

에이전트는 리스닝 소켓뿐 아니라 **실행 중인 모든 프로세스 + 소속 패키지 + 로드한 라이브러리**를
수집한다. 매처는 이를 합쳐 각 취약점을 런타임 상태로 구분한다:

| 상태 | 의미 | 심각도 방향 |
|---|---|---|
| `외부노출` | 외부(0.0.0.0) 오픈 포트로 노출 + 사용 | 최상(+KEV=CRITICAL) |
| `로컬세그먼트` | 링크로컬 멀티캐스트(mDNS 등)로 **같은 세그먼트에만 노출 — 라우터를 넘지 않음** | 중 |
| `방화벽차단` | 전체 인터페이스에 떠 있지만 **방화벽이 막아 외부에서 못 닿음** | 중 |
| `로컬리스닝` | 리스닝하지만 로컬(127.0.0.1)만 | 중 |
| `실행중` | 실행 중이나 포트 미개방 | 중 |
| `사용중` | 실행 프로세스가 라이브러리 로드 | 중 |
| `설치만` | 설치만, 아무도 안 씀 | 하 |

"설치=취약"으로 전부 올리지 않고 **실제 노출·실행·사용 여부로 우선순위를 가른다.**
`방화벽차단`이 없으면 방화벽 뒤의 내부 서비스가 전부 HIGH/CRITICAL 로 떠버린다(오탐).

### 백포트 오탐 억제 (근거 4겹)

배포판은 버전 번호를 그대로 두고 보안 패치만 이식(백포트)한다. 버전만 보는 스캐너는 이걸
"취약"으로 잘못 잡는다. **근거 4겹**으로 걸러낸다:

| 겹 | 근거 | 판정 |
|---|---|---|
| ① OSV 버전필터 | 배포판 전체버전 대조 | 영향 없는 버전이면 제거 |
| ② changelog | `rpm -q --changelog`/dpkg changelog 의 **CVE 줄** | 있으면 억제 (핵심 13개 패키지) |
| ③ errata | 벤더가 "이 설치 빌드에서 고쳤다"고 확인한 권고 | 있으면 억제 (**시스템 전체**) |
| ④ debsecan | 데비안 보안 트래커의 "아직 남은 CVE" 목록 | **없으면** 이미 고쳐진 것 → 억제 |

억제된 건은 `tb_suppressed_findings` 로 **분리**된다 → 위험 집계·화면은 그대로 두고 오탐만
사라지며, 숨기지 않고 **호스트 상세에 근거와 함께** 보여준다(설명가능성).

위 4겹은 데비안 중심이다. **RHEL 계열(`tb_vendor_errata`·`tb_vendor_unfixed`)·우분투(`tb_ubuntu_oval`)·
커널(`tb_kernel_cves`)은 각자의 벤더 소스로 별도 판정한다** — 배포판마다 조치 EVR 표기 방식이 달라
한 테이블로 합칠 수 없다. 또한 벤더가 "아직 안 고쳤다"고 확인한 CVE 는 `tb_findings.no_fix` 로
표시한다 — 오탐 제거와는 다른 축으로, 등급은 그대로 두되 "지금 고칠 수 있는 것"과 "조치 불가"를
화면에서 분리한다.

### "패치됨"이 곧 "안전함"은 아니다 — 재시작·재부팅 필요

억제를 **취소하는** 두 신호가 있다. 이게 없으면 미탐이 난다.

- **재시작 필요**: 패치됐지만 프로세스가 옛 `.so` 를 메모리에 물고 있다 → 그 프로세스는 여전히
  옛 코드를 실행 중이다. 억제하지 않고 근거(어느 프로세스가 어느 라이브러리를)와 함께 올린다.
- **커널 재부팅 필요**: 커널을 패치해도 재부팅 전엔 옛 커널이 돈다. 조치는 프로세스 재시작이
  아니라 **재부팅**이므로 그렇게 안내한다.

### 컨테이너 내부까지 본다

에이전트가 실행 중 컨테이너의 rootfs 를 직접 읽어 **내부 패키지 인벤토리**를 뜬다
(`collect_containers` — docker CLI 에 의존하지 않아 podman·containerd 도 잡힌다). 호스트
패키지와 `container_id` 로 구분해 저장하고 호스트 상세·취약점 목록에서 컨테이너별로 본다.
호스트만 스캔하면 컨테이너 안은 통째로 미탐이었다.

### 미지원 배포판은 조용히 넘어가지 않는다

Amazon Linux·CentOS 는 현재 연결된 배포판 피드가 없어 매칭이 **0건**이 될 수 있다. 이걸 그냥
두면 "취약점 없음"처럼 보여 더 위험하므로, `src/distro.php` 가 판정해 ingest 응답과 취약점
화면에 **경고를 띄운다**(자체 피드가 필요하다는 뜻). Oracle Linux는 OSV에는 없지만
Oracle ELSA OVAL 커넥터가 릴리스별 영향 여부와 수정 EVR을 직접 제공한다.

### 보안설정 점검 (CCE)

"취약한 버전"(CVE)이 아니라 **"잘못된 설정"** 을 본다. 새로 수집하지 않고 에이전트가 이미
보내온 `security`/`users` 섹션을 서버(`src/cce.php`)가 판정해 `tb_cce_findings` 에 저장하고
호스트 상세에 PASS/FAIL/NA 로 표시한다. 항목: SSH root 로그인 차단 · SSH 패스워드 인증 제한
· root 외 UID 0 계정 금지 · 강제접근제어(SELinux/AppArmor) 활성 · 호스트 방화벽 정책 존재.

## 피드 커넥터

외부 보안 데이터 소스를 UI에서 설정·스케줄·수집한다(admin → "데이터 수집").

- **CISA KEV** (기본 활성): 실제 악용 취약점 카탈로그 JSON, 무인증. 매일 자동 수집.
- **OSV.dev** (기본 활성): 수집된 **모든 패키지**를 OSV querybatch 로 조회(배포판별 ecosystem 자동, deb 는 소스패키지·설치버전 기준) → `cve_affected_packages` 를 실제로 채워 매처가 전 패키지를 검사. 시드 3개가 아니라 서버의 실제 취약점 전체를 발굴.
- **NVD 2.0**: 전체 CVE(약 36만건, CVSS·설명 포함). 주기 수집은 **수정일(lastMod) 기준** 증분이라 뒤늦게 CVSS 가 붙는 CVE 도 따라잡는다(120일 상한). 전체 이력은 `bin/backfill_nvd.php` 로 1회 백필(멱등, `--start-index` 재개). API 키는 DB(`connection_json.api_key`)에만 두고 코드·저장소엔 없다. `/cves.php` 에서 목록 조회.
- **FIRST EPSS** (기본 활성): CVE별 악용확률(0~1)을 매일 갱신 → KEV(이미 악용됨) + EPSS(악용 가능성)로 우선순위/정렬. findings·호스트 상세에 EPSS % 표시.
- **KISA 보안공지** (기본 활성): 보호나라 RSS 수집 → 국내공지 페이지. 해외 도구가 안 하는 국내 특화. 신규 공지는 **상세 본문까지 수집**해 `/advisory.php` 에서 그대로 보여준다(과거분은 `bin/backfill_kisa_content.php` 로 1회 채움).
- **벤더 판정 6종**(데비안 보안 트래커 · RHEL 계열 OVAL · Red Hat 미수정 CVE · 우분투 보안 OVAL · 리눅스 커널 CNA · SCAP Security Guide): 배포판/커널 벤더가 "이 빌드가 아직도 취약한가"를 직접 판정한 데이터로, 버전만 비교하면 나는 백포트 오탐을 걸러낸다. 각 소스가 무슨 질문에 답하는지는 [`docs/dev/피드소스-역할.md`](docs/dev/피드소스-역할.md) 참고.
- **범용 API 커넥터**(`generic_api`): 위 고정 5종+벤더 6종이 못 미치는 조직별 커스텀 REST API 를 UI 에서 직접 등록(URL 템플릿·헤더·페이징·응답 매핑). 상세: [`docs/dev/피드소스-역할.md`](docs/dev/피드소스-역할.md).
- 스케줄러 사이드카(`scheduler` 컨테이너)가 1분마다 due 커넥터를 실행하고, 수집 후 전체 스캔을 재매칭. 중단돼 `running` 으로 굳은 실행도 정리한다.
- 수동 실행: 커넥터 행의 "지금 실행", 또는 `docker compose exec web php bin/sync.php <id>`.

**bin 스크립트(1회성 유지보수 — 웹 UI 로는 못 하는 일만 남겼다)**: `backfill_nvd.php`(NVD 전체 백필)
· `backfill_kisa.php`(국내공지 과거 이력) · `backfill_kisa_content.php`(공지 본문) ·
`rebuild_advisory_cveids.php`(cve_ids 재계산) · `sync.php`(커넥터 수동 실행).

> 백필이 왜 필요한가: KISA RSS 는 **피드당 최신 10건**(3종 = 30건)만 준다. 주기 수집으로는
> 과거 공지를 영원히 못 가져오므로 과거 이력은 `backfill_kisa.php` 로만 채울 수 있다.
> NVD 도 주기 수집은 수정일 기준 증분이라 전체 36만 건은 `backfill_nvd.php` 로 1회 채운다.

## 에이전트 설치 · 운영

방식은 **에이전트-사이드 push** — 각 서버가 상시 데몬(systemd, 10초마다 중앙을 poll)으로 주기가
되면 수집해 중앙으로 POST 한다. 중앙이 각 호스트로 들어가지 않으므로 대상 서버엔 아웃바운드
HTTPS 하나만 열면 된다. 중앙 웹(호스트 상세)에서 즉시 실행·예약 실행·주기 변경이 가능하고
다음 poll 에 바로 반영된다 — SSH 재설치가 필요 없다.

대상 서버(Linux)에서 스크립트 2개와 루트 CA 를 `/opt/vuln-agent/` 에 두고 한 번 실행하면 끝이다.
세 파일은 자산 화면의 "에이전트 설치 안내" 에서 받고, **인자 없이 실행하면** 중앙 주소·토큰·주기를
물어본다:

```bash
cd /opt/vuln-agent && sudo bash install-agent.sh
```

나머지는 [`agent/README.md`](agent/README.md) 가 갖는다 — 설치 전 선행 검사(자체서명 CA 등록 ·
헤어핀 NAT), 대상 서버 요구사항(패키지를 새로 깔지 않는다), root 가 필요한 이유, 무인 설치 인자,
갱신(`deploy/agent_push.sh`) · 주기 일괄 변경(`deploy/agent_schedule.sh`), 상태 확인, 제거,
무엇을 수집하나, 실행 옵션.

## 배포 · 운영

<details>
<summary>운영 배포·업데이트 절차 — update.sh · 마이그레이션 순서 · compose 파일 구조 · 워크트리 (펼치기)</summary>

운영에 한 번 올린 뒤의 업데이트는 `deploy/update.sh` 한 줄이면 된다. **바뀐 파일을 보고 스스로 갈라진다** —
`server/` 아래 PHP 만 바뀌었으면 `git pull` 로 끝(무중단, 소스가 읽기전용으로 마운트돼 있고
opcache 가 2초마다 파일 갱신을 확인한다). `Dockerfile`·`compose*.yml`·`caddy/`·`config/` 가
바뀔 때만 재빌드한다. **스키마 변경은 `deploy/migrate.sh` 가 자동 적용한다** — `db/migrations/`
의 `*.sql` 중 아직 안 든 것만 파일명 사전순으로 돌리고 `tb_schema_migrations` 에 기록하므로,
스키마를 바꾸려면 파일 하나만 추가하면 된다(`up` 과 `update.sh` 가 자동 호출).
파일명은 **타임스탬프**로 짓는다(`$(date +%Y%m%d%H%M%S)_이름.sql`) — 연번은 동시에 작업하는
브랜치들이 같은 번호를 집어 충돌한다.

```bash
bash deploy/update.sh
```

**마이그레이션은 코드 반영보다 먼저 돈다.** 소스가 라이브 마운트라 `git pull` 하는 순간
새 PHP 가 이미 디스크에 있고 opcache 가 2초 안에 로드한다. 스키마를 뒤에 올리면 그 사이
들어온 수집이 `Unknown column …` 으로 500 이 난다(실제로 겪었다). 반대 순서는 안전하다 —
컬럼 추가·인덱스 확장은 옛 코드에 무해하다.

### 에이전트 배포 순서 — 서버 먼저, 에이전트 나중

에이전트가 새 항목을 수집하게 됐다면(컨테이너 내부 패키지, 패키지 출처, CCE 점검값 등)
**서버를 먼저 올리고 에이전트를 나중에** 업데이트한다. 반대로 하면 새 필드를 서버가 모른다.

구 에이전트가 보내는 옛 페이로드는 새 서버가 그대로 처리한다(검증됨) — 새 필드가 없으면
그 기능만 비활성이고 수집은 계속된다. 그러니 **에이전트는 급하지 않다.**

업데이트는 **스크립트 교체 한 줄**이면 된다. 데몬·토큰(`etc/agent.env`)은 그대로 두면 되므로
`install-agent.sh` 를 다시 돌릴 필요가 없다(다시 돌리면 서버 주소·토큰을 또 물어본다). 여러
노드를 한 번에 올리려면 `deploy/agent_push.sh` 를 쓴다(agent/README.md 참고).

```bash
# 각 대상 서버에서 — 새 agent/ 를 받아온 뒤
sudo cp vuln-inventory-agent.sh /opt/vuln-agent/bin/vuln-inventory-agent.sh
sudo /opt/vuln-agent/bin/run.sh --once   # 즉시 1회 수집해 확인(선택). --once 없이 돌리면
                                          # 데몬(while-loop)이라 끝나지 않는다 — 상시 서비스는
                                          # 이미 systemctl 로 돌고 있으니 보통은 안 건드려도 된다.
```

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

### 워크트리에서 dev 띄우기

`wt/<이름>/` 워크트리에서 dev 를 띄우면 프로젝트명·컨테이너명·이미지태그에 `-<이름>` 이 붙고
포트도 따로 잡히므로, 메인 dev 스택(8000)과 나란히 돌릴 수 있다. 워크트리 만들기는
`./deploy/wt.sh add feat/무엇` — 자세한 규칙은 [CLAUDE.md](CLAUDE.md#작업-파이프라인) 참고.

dev 에서 `git pull` 한 뒤에는 `./deploy/compose_runner.sh dev up -d` 를 다시 돌린다. 소스가
라이브 마운트라 코드는 즉시 바뀌지만 **DB 스키마는 따라오지 않는다** — 남이 머지한 마이그레이션이
있으면 새 코드가 없는 컬럼을 찾아 500 이 난다. `up` 이 `migrate.sh` 를 불러 미적용분만 적용하며,
컨테이너는 그대로 두므로 싸다.

</details>

## 권한 · 감사 로그

### 감사 로그

로그인·커넥터 저장/토글/삭제·사용자 추가/삭제·ingest 수신이 `tb_activity_log` 에 자동
기록된다(`server/src/audit.php` 의 `vg_log_activity()`). `/activity.php`(admin 전용)에서
범위(scope) 필터 + 페이지네이션으로 조회한다. 삭제는 하드 DELETE 대신 `vg_soft_delete()`
로 `is_deleted/deleted_at` 를 세운다(대상: users/feed_connectors/advisories/hosts/scans).

### 권한 (설정형 RBAC)

역할은 **admin / operator / user** 3단계. `admin` 은 코드에서 항상 전체 허용(잠금 방지)이고,
`operator`·`user` 는 **역할 × 메뉴** 허용 여부를 `/permissions.php` 에서 켜고 끈다
(`tb_role_permissions`). 각 페이지는 `vg_require_menu('<메뉴코드>')` 하나로 가드한다.

## 테스트

스택이 떠 있는 상태에서 API~웹 로그인까지 자동 검증:

```bash
./tests/smoke.sh            # 기본 http://localhost:8000
```

수집→저장→매칭(CRITICAL/HIGH 산출), 토큰 인증, 로그인 흐름을 curl 로 점검한다.

curl 은 HTML 만 받으므로 **클라이언트 JS**(`assets/app.js` — 테마·밀도·모바일 내비,
`assets/js/connectors.js` — 커넥터 폼)는 위에서 안 덮인다. 그 구멍만 브라우저로 확인한다
(Playwright, 전용 컨테이너에서 실행):

```bash
./tests/e2e.sh http://localhost:8000    # 로그인 · 테마 · 밀도 · 모바일 사이드바 · 커넥터 폼/모달 5종
```

커넥터 시나리오는 **폼을 채우기만 하고 제출하지 않는다** — 미리보기·지금 실행·저장·활성토글·삭제는
누르면 외부 소스를 실제로 치거나 공용 dev DB 를 바꾸므로 **일부러 안 덮는다**.
브라우저 기동이 느려 **pre-push 게이트에는 넣지 않는다** — 필요할 때 직접 돌린다.

## 진행 상태

**파이프라인은 끝까지 돈다** — 수집(에이전트) → 전송 → 저장 → 매칭 → 웹까지 전 구간이 동작한다.
그 위에 이 프로젝트의 기여인 **런타임 상태 7단계 · 백포트 오탐 억제(근거 4겹 + RHEL/우분투/커널
벤더별 판정) · 컨테이너 스캔 · CCE · 변화 추적 · Export API** 와, 피드 커넥터 12종(고정 5종 +
벤더 판정 6종 + 범용 API)이 올라가 있다. 운영 쪽은 HTTPS(Caddy) 배포 · 에이전트 자동 설치 ·
스키마 마이그레이션 자동화 · 설정형 RBAC · 감사 로그까지 갖췄다.
검증은 `tests/smoke.sh`(curl) 위에 **브라우저 E2E(`tests/e2e.sh`, Playwright)** 가 얹혀 클라이언트
JS 의 핵심 5종까지 덮는다(필터 즉시적용은 아직, 커넥터의 미리보기·실행·저장은 부작용 때문에 일부러
제외) — 알림은 외부 채널 수신지가 없어 만들지 않기로 했다.

> 항목별 상세 목록(각 항목을 왜 그렇게 만들었는지까지)은
> [`CONTEXT.md` §8 개발 현황](CONTEXT.md#8-개발-현황-2026-07-기준--파이프라인https감사--오탐억제cce변화추적export-완성)
> 이 갖는다. 두 곳에 같은 목록을 두면 어긋나므로 이 README 는 요약만 둔다.

## 라이선스

MIT — [`LICENSE`](LICENSE)

## 병렬 워커 오케스트레이터

`deploy/orchestrator/` 에 마일스톤 세션과 병렬 워커(탭) 오케스트레이터가 있다 — 여러 작업을
탭 단위 워커로 나눠 동시에 돌리고 마일스톤 단위로 묶어 진행한다. 설정·실행 등 자세한 사용법은
[`deploy/orchestrator/README.md`](deploy/orchestrator/README.md) 를 참고한다.
