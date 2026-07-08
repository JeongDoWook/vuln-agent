# vuln-agent

런타임 노출 맥락으로 오탐을 줄이는 자율 취약점 진단 에이전트 (2026 오픈소스 개발자대회)

> 프로젝트 전체 맥락·전략·로드맵은 [`CONTEXT.md`](CONTEXT.md) 참고.

## 구성

```
agent/    수집 에이전트 (Bash) — 서버에서 패키지·런타임 노출 정보를 수집
server/   PHP 중앙 서버 — 수신 API(ingest) + 현황 페이지, 매처(예정)
db/       MySQL 스키마 (컨테이너 최초 기동 시 자동 적용)
docs/     기획안 · 설명글
```

데이터 흐름: **에이전트(JSON) ─POST→ `ingest.php` → MySQL → 웹 현황**

## 빠른 시작 (Docker · 러너 스크립트)

모든 것은 컨테이너로 동작한다(로컬 PHP/MySQL 불필요). 환경은 **dev / prod** 두 가지.

```bash
./compose_runner.sh init            # .env.dev / .env.prod 생성(템플릿 복사) → 비밀값 수정
./compose_runner.sh doctor          # 사전 점검
./compose_runner.sh dev  up -d --build   # 개발 환경 기동
./compose_runner.sh dev  down            # 중지
./compose_runner.sh dev  logs -f         # 로그
```

운영 서버(리눅스)에서는 `dev` 대신 `prod`:

```bash
./compose_runner.sh init                 # .env.prod 의 비밀값을 강한 값으로 교체
./compose_runner.sh prod up -d --build
```

| | dev | prod |
|---|---|---|
| 소스 | `./server` 라이브 마운트(즉시 반영) | 이미지에 구움(배포=재빌드) |
| DB 포트 | 호스트에 노출(3307) | **미노출**(내부 네트워크만) |
| 환경변수 | `.env.dev` | `.env.prod` |
| 프로젝트명 | `vulnagent-dev` | `vulnagent` |

- 현황 페이지: <http://localhost:8080>
- 수신 API: `POST http://localhost:8080/ingest.php` (헤더 `X-Agent-Token`)

### 파일 구조 (compose)

```
compose.yml         서비스 정의 (db=MySQL, web=PHP/Apache)
compose.common.yml  공통 런타임 (restart, 로깅, pids_limit)
compose.dev.yml     개발 override
compose.prod.yml    운영 override
.env.{dev,prod}.template   → init 이 .env.{dev,prod} 로 복사(커밋 제외)
compose_runner.sh   실행 러너
```

## 에이전트 실행 & 전송

수집 대상 서버(Linux)에서:

```bash
# 로컬 저장만
./agent/vuln-inventory-agent.sh

# 수집 후 중앙 서버로 전송 (파일 저장도 유지)
./agent/vuln-inventory-agent.sh \
    --send http://중앙서버:8080/ingest.php \
    --token .env의_INGEST_TOKEN값
```

전송하려면 대상 서버에 `jq`(JSON 출력)와 `curl`이 필요합니다.

## 상태

- [x] 0. Docker 구성 (compose dev/prod + Dockerfile + Docker Secrets)
- [x] 1. 수집 → 전송 → 저장 (에이전트 POST + PHP 수신 + DB)
- [x] 2. 매처 (외부노출 + 로드됨 + KEV = CRITICAL) · findings.php · 아키텍처 다이어그램
- [x] 3. 웹 (로그인 → 대시보드 → 취약점 · 사용자관리)
- [x] 4a. CVE 피드 커넥터 (CISA KEV 실데이터 · OSV · NVD) + 스케줄러 사이드카
- [x] 4b. 국내 특화 — KISA 보안공지 커넥터 + 국내공지 페이지

- 취약점 우선순위(+조치안): <http://localhost:8080/findings.php>
- 호스트 상세(노출·취약점 한눈에): 대시보드에서 서버명 클릭 → `host.php`
- 피드 커넥터(admin): <http://localhost:8080/connectors.php>
- 국내 보안공지: <http://localhost:8080/advisories.php>

각 취약점에는 **조치안**("어느 버전 이상으로 업데이트")이 함께 표시된다(OSV 의 fixed 버전).

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
백포트 오탐은 OSV 버전필터(배포판 전체버전으로 대조)가 이미 걸러낸다.

### 피드 커넥터

외부 CVE 소스를 UI에서 설정·스케줄·수집한다 (admin → "피드").

- **CISA KEV** (기본 활성): 실제 악용 취약점 카탈로그 JSON, 무인증. 매일 자동 수집.
- **OSV.dev** (기본 활성): 수집된 **모든 패키지**를 OSV querybatch 로 조회(배포판별 ecosystem 자동, deb 는 소스패키지·설치버전 기준) → `cve_affected_packages` 를 실제로 채워 매처가 전 패키지를 검사. 시드 3개가 아니라 서버의 실제 취약점 전체를 발굴.
- **NVD 2.0**: 필요 시 활성. 최근 N일 CVE(CVSS 포함) 증분. API 키·주기 UI 설정.
- **FIRST EPSS** (기본 활성): CVE별 악용확률(0~1)을 매일 갱신 → KEV(이미 악용됨) + EPSS(악용 가능성)로 우선순위/정렬. findings·호스트 상세에 EPSS % 표시.
- **KISA 보안공지** (기본 활성): 보호나라 RSS 수집 → 국내공지 페이지. 해외 도구가 안 하는 국내 특화.
- 스케줄러 사이드카(`scheduler` 컨테이너)가 1분마다 due 커넥터를 실행하고, 수집 후 전체 스캔을 재매칭.
- 수동 실행: 커넥터 행의 "지금 실행", 또는 `docker compose exec web php bin/sync.php <id>`.

## 테스트

스택이 떠 있는 상태에서 API~웹 로그인까지 자동 검증:

```bash
./tests/smoke.sh            # 기본 http://localhost:8080
```

수집→저장→매칭(CRITICAL/HIGH 산출), 토큰 인증, 로그인 흐름을 curl 로 점검한다.
(브라우저 E2E는 나중에 Playwright 로 추가 예정)

## 라이선스

MIT — [`LICENSE`](LICENSE)
