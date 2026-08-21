# vuln-agent

![License](https://img.shields.io/badge/license-AGPL--3.0-blue) ![Contest](https://img.shields.io/badge/2026%20오픈소스%20개발자대회-자유과제-informational) ![PHP](https://img.shields.io/badge/PHP-8.3-777bb4) ![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1)

> 설치된 취약점의 **개수**가 아니라 **지금 이 서버에서 실제로 위험한 것**을 먼저 보여주는 경량 취약점 진단 플랫폼.
> 실행 맥락으로 판단하고, 억제한 결과도 판정 근거와 조치를 남겨 숨기지 않습니다.

<picture>
  <source media="(max-width: 700px)" srcset="docs/readme-flow-mobile.svg">
  <img src="docs/readme-flow.svg" width="100%" alt="vuln-agent가 에이전트가 있는 서버와 없는 IP 양쪽에서 사실을 모으고, 실행 맥락과 벤더 근거·컴플라이언스 기준을 검증해 우선순위와 조치를 제시하는 흐름">
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
| 에이전트를 깐 서버만 목록에 존재 | 관리 대역을 스윕해 **에이전트가 없는 IP**까지 자산으로 세움(섀도우 IT) |

### 핵심 기능

| 기능 | 설명 | 더 보기 |
|---|---|---|
| 판정 | 런타임 노출 7단계, 설명 가능한 오탐 억제, KEV·EPSS 우선순위 | [아키텍처 §2](docs/dev/architecture.md) |
| 인벤토리 | 호스트·컨테이너의 패키지·프로세스·노출, 계정과 패키지 무결성, **에이전트가 없는 IP**를 찾는 자산 탐색 | [화면 안내](docs/dev/화면-안내.md) |
| 자산 등급 | 업무 중요도(상·중·하)와 N2SF C/S/O 등급, 확정값과 시스템 제안값 분리 | [자산 등급](docs/dev/자산등급.md) |
| 설정 점검·컴플라이언스 | CCE를 PASS·FAIL·판정 불가로 구분, ISMS-P·ISO 27001 자동 판정, 기반시설 U-코드 72개를 분모로 둔 커버리지 | [보안설정 조치 가이드](docs/dev/보안설정-조치가이드.md) |
| SCA·SBOM·의존성 | 8개 언어 생태계 매칭과 라이선스 분류, CycloneDX 1.5·SPDX 2.3 산출, 전이 의존성 역추적 | [Export API](docs/dev/export-api.md) |
| 운영 | 즉시·예약 수집과 진행률, 역할 권한과 호스트별 에이전트 키, 무인 자동 업데이트(Ed25519 서명 검증) | [설정 레퍼런스](docs/ui-configuration.md) |

## 동작 방식

수집 → 연결 → 검증 → 조치의 네 단계는 맨 위 흐름도에 있습니다. 그림이 말하지 않는 것만 적으면 —
에이전트는 systemd 상시 서비스로 10초마다 명령을 확인하고([리소스 프로파일](docs/dev/에이전트-리소스-프로파일.md)),
전송은 **아웃바운드 HTTPS 한 방향**입니다. 예외는 하나, 에이전트가 없는 IP는 중앙이 직접 스윕합니다.

## 빠르게 실행해 보기

```bash
cd deploy && ./compose_runner.sh init && ./compose_runner.sh doctor && ./compose_runner.sh dev up -d
```

웹은 <http://localhost:8000>(로컬 PHP·MySQL 설치 불필요). 비밀값·운영 HTTPS·CA 준비·백업은 [배포 가이드](deploy/README.md), 대상 서버 연결은 [에이전트 설치·운영 가이드](agent/README.md)를 보세요.
에이전트 버전은 **3.22**이고, 게이트는 `./tests/smoke.sh <BASE>`(수집·매칭·인증·화면)와 `./tests/e2e.sh <BASE>`(Chromium)입니다.

## 출품 범위

클론해서 그대로 띄우면 아래 "출품작 본체"만으로 전 기능을 실행·검증할 수 있습니다. 나머지는 이 저장소를
만드는 데 쓴 도구이거나, 우리 저장소 밖 서버가 있어야 도는 선택 기능이라 **기본적으로 꺼져 있습니다**.

| 구분 | 경로 | 설명 |
|---|---|---|
| 출품작 본체 | `server/` · `agent/` · `db/` · `deploy/` · `tests/` | 중앙 서버·에이전트·스키마·배포·검증. 심사 대상은 이것입니다 |
| 개발 도구(출품작 아님) | `kit/` · `scripts/` · `deploy/orchestrator/` · `.claude/` | 이 저장소를 개발하는 데 쓴 파이프라인이며 제품 코드가 아닙니다 |
| 선택적 외부 연동(기본 꺼짐) | AI 보고서 — `server/src/report_job.php` | 별도의 외부 보고서 API 가 필요하고 **그 생성기 소스는 이 저장소에 없습니다** |

AI 보고서는 설정(설정 화면 → AI 보고서 → 보고서 API 주소)에 주소를 넣어야 켜지고, 비어 있으면 호스트
상세에 카드 자체가 나오지 않습니다. 이 연동은 인증 없는 내부 API 를 전제하므로 **신뢰된 내부망 전용**입니다 —
인터넷에 노출된 주소를 넣지 마세요. 켜지 않아도 수집·매칭·판정·리포팅 등 나머지 기능은 그대로 동작합니다.

## 문서

- 명세 — [데이터베이스](docs/dev/데이터베이스.md) · [Excel 명세서](docs/specs/테이블명세서.xlsx) · [Export API](docs/dev/export-api.md)(SBOM 은 `GET /sbom.php`)
- 규칙 — [CONTEXT.md](CONTEXT.md) · [CLAUDE.md](CLAUDE.md) · [지난 작업의 실측 기록](docs/dev/archive/)

## 라이선스

[AGPL-3.0](LICENSE) 으로 배포합니다. Copyright (C) 2026 JeongDoWook.
**네트워크로 이 소프트웨어를 이용자에게 제공하는 경우에도 그 이용자에게 소스코드를 제공해야 합니다**(AGPL 제13조). 화면 하단의 `소스코드 (AGPL-3.0)` 링크가 그 통로이고, 포크해 배포한다면 설정 화면에서 자기 저장소 주소로 바꾸세요.
라이선스 이력 — 이 저장소는 2026-07-07 부터 MIT 로 배포되었고 2026-08-21 부터 AGPL-3.0 입니다. 전환 이전 커밋 시점의 코드는 MIT 조건으로 배포된 상태가 그대로 유지됩니다.

활용한 제3자 오픈소스의 출처·라이선스는 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) 에 정리했다.
