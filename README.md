# vuln-agent

> 설치된 취약점의 개수보다, **지금 이 서버에서 실제로 위험한 취약점**을 먼저 보여주는 경량 취약점 진단 플랫폼

일반적인 버전 비교는 패키지가 설치돼 있다는 이유만으로 많은 경고를 만듭니다. `vuln-agent`는 설치
패키지에 더해 **실행 중인 프로세스, 로드된 라이브러리, 열린 포트와 방화벽 상태**를 함께 수집하고,
중앙 서버가 이 실행 맥락과 검증된 보안 피드를 결합해 대응 우선순위를 판단합니다. 억제한 결과도
숨기지 않고 “배포판이 보안 패치를 백포트했기 때문”처럼 **판정 근거와 조치**를 웹에 남깁니다.

<picture>
  <source media="(max-width: 700px)" srcset="docs/readme-flow-mobile.svg">
  <img src="docs/readme-flow.svg" width="100%" alt="vuln-agent가 서버 정보를 수집하고 실행 맥락과 벤더 근거를 검증해 우선순위와 조치를 제시하는 흐름">
</picture>

| 프로젝트 이해하기 | 직접 사용하기 | 구조 살펴보기 |
|---|---|---|
| [왜 만들었고 무엇이 다른가](docs/dev/설명글.md) | [에이전트 설치·운영](agent/README.md) | [아키텍처와 판정 흐름](docs/dev/architecture.md) |
| [웹에서 제공하는 기능](#핵심-기능) | [개발·운영 배포](deploy/README.md) | [ERD·배포·사이트맵](docs/specs/diagrams/README.md) |

## 무엇이 다른가

| 흔한 취약점 목록 | vuln-agent |
|---|---|
| 설치 버전만 보고 취약 여부 판정 | 실행·로드·리스닝·외부 노출까지 연결해 7단계 상태로 구분 |
| 백포트된 패키지도 오래된 버전처럼 보여 오탐 발생 | OSV 범위와 changelog·errata·벤더 OVAL을 교차 확인 |
| 지원하지 않는 대상도 취약점 0건으로 보일 수 있음 | 피드나 패키지 DB가 없으면 안전이 아닌 **판정 불가**로 표시 |
| 패치 여부만 안내 | 프로세스 재시작, 커널 재부팅, 이미지 재빌드, 부모 패키지 올리기 등 실제 조치 구분 |

억제 이력 보존·KISA 국내 보안공지 연동을 포함한 전체 비교는 [쉬운 말 설명](docs/dev/설명글.md)에 있습니다.

### 핵심 기능

웹 화면은 여섯 갈래로 묶입니다. 화면별 판정 조건과 배경 설명은 [화면 안내](docs/dev/화면-안내.md),
화면 전체 지도는 [사이트맵 다이어그램](docs/specs/diagrams/사이트맵.svg)에 있습니다.

- **판정** — 런타임 노출 상관(7단계), 설명 가능한 오탐 억제, 패치 후 잔여 위험(옛 `.so`·재부팅 전 커널), KEV·EPSS 우선순위 → [아키텍처 §2](docs/dev/architecture.md) · [피드 소스 역할](docs/dev/피드소스-역할.md)
- **인벤토리** — 호스트와 컨테이너의 패키지·프로세스·노출, 계정(UID·셸·잠금·sudo), 패키지 무결성 검증 → [화면 안내](docs/dev/화면-안내.md)
- **자산 등급** — 업무 중요도(상·중·하)와 N2SF C/S/O 등급. 확정은 「정보공개법」 제9조에 따른 기관의 법적 처분이라 확정값과 시스템 제안값을 분리한다 → [자산 등급](docs/dev/자산등급.md)
- **설정 점검·컴플라이언스** — CCE 점검을 PASS·FAIL·판정 불가로 구분하고 ISMS-P·ISO 27001로 자동 판정, 하루 1건 스냅샷 → [보안설정 조치 가이드](docs/dev/보안설정-조치가이드.md)
- **SCA·SBOM·의존성** — 8개 언어 생태계 매칭과 라이선스 분류, CycloneDX 1.5·SPDX 2.3 산출, 전이 의존성 역추적과 제거·대체 권고 → [Export API](docs/dev/export-api.md)
- **운영** — 자산별 즉시·예약 수집과 진행률, 조치 상태·미조치 사유, 피드 수집 이력, 역할 권한과 호스트별 에이전트 키, 변화·감사 이력 → [아키텍처 §6](docs/dev/architecture.md) · [설정 레퍼런스](docs/ui-configuration.md)

## 동작 방식

1. 각 Linux 서버의 Bash 에이전트가 패키지와 런타임 사실을 읽습니다.
2. 에이전트가 아웃바운드 HTTPS로 중앙 서버에 전송합니다. 중앙에서 대상 서버로 접속하지 않습니다.
3. 중앙 매처가 NVD·OSV·KEV·EPSS와 배포판·커널 벤더 피드를 대조합니다.
4. 웹에서 위험도, 실행 맥락, 판정 근거, 조치 버전과 변화 이력을 확인합니다.

에이전트는 systemd 상시 서비스로 10초마다 명령을 확인하고 무거운 수집은 호스트별 주기에만 실행합니다
— 실측 리소스는 [에이전트 리소스 프로파일](docs/dev/에이전트-리소스-프로파일.md)에 있습니다.

## 빠르게 실행해 보기

로컬 PHP나 MySQL 설치 없이 Docker Compose로 띄웁니다.

```bash
cd deploy
./compose_runner.sh init && ./compose_runner.sh doctor && ./compose_runner.sh dev up -d
```

웹은 <http://localhost:8000>. 이 명령은 로컬 확인을 위한 최소 경로입니다 — 비밀값 설정, 운영 HTTPS,
CA 준비, 백업과 업데이트는 [배포 가이드](deploy/README.md)를, 대상 서버에 에이전트를 붙이는
방법은 [에이전트 설치·운영 가이드](agent/README.md)를 따르세요.

수집부터 웹 표시까지 전체 파이프라인이 동작하며 현재 에이전트 버전은 **3.13**입니다.
`./tests/smoke.sh <BASE>` 가 수집·매칭·인증·주요 화면을, `./tests/e2e.sh <BASE>` 가 테마·반응형
내비게이션·모달을 실제 Chromium에서 검증합니다.

## 문서

기능별 문서는 위 [핵심 기능](#핵심-기능)에서 바로 링크합니다. 그 밖에 자주 찾는 것:

- DB 테이블과 컬럼 — [데이터베이스 명세](docs/dev/데이터베이스.md) · [Excel 명세서](docs/specs/테이블명세서.xlsx)
- ERD·시스템·배포·사이트맵 — [다이어그램](docs/specs/diagrams/README.md)
- 외부 시스템 연동 — [Export API](docs/dev/export-api.md) · SBOM 산출 `GET /sbom.php`
- 개발 원칙과 저장소 작업 규칙 — [CONTEXT.md](CONTEXT.md) · [CLAUDE.md](CLAUDE.md)
- 지난 작업의 실측 기록(현행 규칙 아님) — [docs/dev/archive/](docs/dev/archive/)

## 라이선스

[MIT License](LICENSE)
