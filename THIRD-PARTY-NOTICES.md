# 제3자 오픈소스 고지 (Third-Party Notices)

이 문서는 vuln-agent 가 활용한 **타인의 저작물**(오픈소스 라이브러리·프레임워크·컨테이너 이미지·
외부 데이터)의 출처와 라이선스를 한 곳에 모은 고지다. 2026년 오픈소스 개발자대회 운영규정
제8조 ⑤·⑥("타인의 저작물을 활용한 경우 출처와 라이선스를 명시", "활용한 모든 오픈소스
라이브러리·프레임워크·모델의 출처와 라이선스를 명확히 공개")에 대응한다.
저장소 자체의 라이선스는 루트 [LICENSE](LICENSE)(MIT)이며, 이 문서에 적힌 항목들은 각자의
라이선스를 그대로 따른다.

**여기 적힌 것은 저장소에 실제로 들어 있거나 실행·빌드·검증에 실제로 쓰이는 것뿐이다.**
목록은 `server/public/assets/vendor/` 전수 확인, 각 `Dockerfile` 의 `FROM`,
`deploy/compose.*.yml` 의 `image:`, `server/src/feeds/` 의 커넥터 카탈로그(`VG_CONNECTOR_TYPES`)를
직접 읽어 작성했다.

---

## 1. 저장소에 포함된 제3자 코드

빌드 파이프라인·CDN 을 쓰지 않는 저장소라, 프런트엔드 라이브러리는 배포본을
`server/public/assets/vendor/` 아래에 그대로 넣어 자체 호스팅한다.

| 이름 | 버전 | 용도 | 라이선스 | 출처 URL |
|---|---|---|---|---|
| Chart.js | 4.5.1 | 대시보드·통계 화면의 차트 렌더 (`assets/vendor/chartjs/chart.umd.js`) | MIT ([사본](server/public/assets/vendor/chartjs/LICENSE)) | https://github.com/chartjs/Chart.js |
| flatpickr | 4.6.13 | 예약 실행·기간 필터의 날짜 입력 (`assets/vendor/flatpickr/`) | MIT ([사본](server/public/assets/vendor/flatpickr/LICENSE)) | https://github.com/flatpickr/flatpickr |
| spec-review-kit | commit `b706e175` (2026-08-08 이식) | 설계 게이트·코드리뷰 방법론 본체 (`kit/`, `.claude/skills/`, `scripts/`) | 저장소 저작자와 동일인의 다른 저장소 — 루트 MIT 가 그대로 적용된다. 자세한 내용은 [kit/README.md](kit/README.md) | https://github.com/JeongDoWook/spec-review-kit |

에이전트(`agent/vuln-inventory-agent.sh`)는 대상 서버에 아무것도 설치하지 않는 순수 POSIX 셸
스크립트이고, `scripts/` 의 Node 도구는 Node 내장 모듈만 쓴다 — 둘 다 제3자 코드를 번들하지 않는다
(저장소에 `package.json`·`node_modules` 가 없다).

---

## 2. 실행에 쓰는 컨테이너 이미지

서비스 구동에 쓰는 이미지다. 모두 공식 이미지를 그대로 받아 쓰며, 이미지 안의 소프트웨어를
수정해 재배포하지 않는다.

| 이름 | 버전 | 용도 | 라이선스 | 출처 URL |
|---|---|---|---|---|
| PHP (php:8.3-apache) | 8.3 | 웹·스케줄러 컨테이너 베이스 (`server/Dockerfile`) | PHP License v3.01 (PHP), Apache-2.0 (Apache HTTP Server). 베이스 Debian 패키지는 각 패키지의 라이선스 | https://hub.docker.com/_/php |
| bzip2 (libbz2) | Debian 패키지 | PHP `bz2` 확장 — Red Hat/Ubuntu OVAL 의 `.bz2` 피드 스트리밍 파싱 | bzip2 라이선스 (BSD 계열) | https://sourceware.org/bzip2/ |
| MySQL Community Server (mysql) | 8.0 (`MYSQL_VERSION` 기본값) | 데이터베이스 (`deploy/compose.yml`) | GPL-2.0 (FOSS License Exception 포함) | https://hub.docker.com/_/mysql |
| Caddy (caddy:2) | 2.x | 리버스 프록시·TLS 종단 (`deploy/caddy/Dockerfile`) | Apache-2.0 | https://hub.docker.com/_/caddy |

---

## 3. 개발·검증에만 쓰는 도구

배포물에 포함되지 않고, 테스트·문서 생성 시점에만 컨테이너로 실행한다.

| 이름 | 버전 | 용도 | 라이선스 | 출처 URL |
|---|---|---|---|---|
| Playwright (이미지 + npm 패키지) | 1.62.0 | 브라우저 E2E 테스트 (`tests/e2e/Dockerfile`) | Apache-2.0 | https://github.com/microsoft/playwright |
| PlantUML | plantuml/plantuml (태그 미고정) | 설계 다이어그램(PUML→SVG) 렌더 (`docs/specs/diagrams/Dockerfile`) | GPL — **아래 주석 참고** | https://plantuml.com/ |
| 나눔글꼴 (Debian `fonts-nanum`) | Debian 패키지 | PlantUML 렌더 이미지의 한글 폰트 | SIL Open Font License 1.1 | https://hangeul.naver.com/font |
| Go (golang:1.22) | 1.22 | Go 바이너리 buildinfo 수집 회귀 테스트 (`tests/go_buildinfo_host_test.sh`) | BSD-3-Clause | https://go.dev/ |
| PHP CLI (php:8.3-cli) | 8.3 | 호스트 PHP 버전과 무관하게 단위 테스트·lint 실행 (`tests/smoke.sh`) | PHP License v3.01 | https://hub.docker.com/_/php |

> **PlantUML(GPL)에 관한 명시** — PlantUML 은 GPL 라이선스지만, 이 저장소는 **다이어그램을 그리는
> 도구로 컨테이너 안에서 실행만** 한다. PlantUML 코드를 저장소에 포함하지도, 수정하지도, 우리
> 코드와 링크(정적·동적)하지도 않는다. 산출물은 PlantUML 이 출력한 SVG 이미지 파일이며 이는
> 도구의 출력물이므로 GPL 의 파생저작물 조항이 이 저장소 코드에 전파되지 않는다.

---

## 4. 외부 데이터 피드

취약점 판정에 쓰는 외부 데이터의 출처다. **코드가 아니라 데이터**라서 규정 제8조 ⑥(라이브러리·
프레임워크·모델)의 직접 대상은 아니지만, 출처 명시(제8조 ⑤) 취지에 맞춰 정리해 둔다.
목록은 `server/src/feeds.php` 의 `VG_CONNECTOR_TYPES` 카탈로그와 `server/src/feeds/*.php` 의
기본 주소에서 뽑았다.

| 피드 | 제공자 | 용도 | 이용 조건 | 출처 URL |
|---|---|---|---|---|
| CISA KEV | 미국 CISA | 실제 악용된 취약점 목록 | 미국 정부 저작물 — 자유 이용 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| OSV.dev | Open Source Vulnerabilities | 패키지 생태계별 취약점 조회 | 스키마·도구는 Apache-2.0. 데이터는 각 원 출처의 라이선스를 따른다 | https://osv.dev/ |
| NVD 2.0 | 미국 NIST | CVE 상세·CVSS 점수 | 미국 정부 저작물 — 자유 이용. CVE® 는 MITRE 의 등록상표 | https://nvd.nist.gov/developers |
| KISA 보안공지 | 한국인터넷진흥원 보호나라 | 국내 보안공지·권고문 | 원 사이트 이용 조건(공공누리 표기)을 따름 — ★ | https://www.boho.or.kr/ |
| FIRST EPSS | FIRST.org | 악용 확률 점수 | 무료 제공, 출처 표시 요청 | https://www.first.org/epss/ |
| 데비안 보안 트래커 | Debian Project | 데비안 릴리스별 미수정 취약점 | Debian 공개 데이터 — ★ | https://security-tracker.debian.org/tracker/ |
| RHEL/Oracle/AlmaLinux OVAL | Red Hat · Oracle · AlmaLinux | RPM 계열 패치 판정 | 각 벤더가 공개 제공 — ★ | https://security.access.redhat.com/data/oval/v2/ |
| Red Hat 미수정 (hydra API) | Red Hat | 수정본 없는 취약점 상태 | Red Hat 공개 보안 데이터 — ★ | https://access.redhat.com/hydra/rest/securitydata/ |
| Ubuntu OVAL | Canonical | 우분투 패치 판정 | Canonical 공개 데이터 — ★ | https://security-metadata.canonical.com/oval/ |
| SCAP 보안 기준 (ComplianceAsCode/content) | ComplianceAsCode 프로젝트 | 보안 설정 점검 기준(SSG) | BSD-3-Clause | https://github.com/ComplianceAsCode/content |
| 커널 CNA (vulns.git) | kernel.org | 리눅스 커널 CVE 레코드 | 커널 저장소와 동일(GPL-2.0) | https://git.kernel.org/pub/scm/linux/security/vulns.git/ |

> ★ 표시는 "무료로 공개 제공된다"는 사실은 확인했지만 **명시적인 라이선스 식별자를 원 사이트에서
> 재확인하지 않은** 항목이다. 출품 전에 각 사이트의 이용 조건을 한 번 더 대조하는 것을 권한다.

---

## 갱신 규칙

`server/public/assets/vendor/` 에 파일을 추가하거나, `Dockerfile` 의 `FROM`·`compose.*.yml` 의
`image:` 를 바꾸거나, 새 피드 커넥터를 등록하면 이 문서도 같은 커밋에서 갱신한다.
벤더링한 자산에는 `LICENSE` 와 `VERSION` 파일을 함께 넣는다(chartjs·flatpickr 가 그 형식이다).
