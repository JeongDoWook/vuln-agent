# 제3자 오픈소스 고지 (Third-Party Notices)

이 문서는 vuln-agent 가 활용한 **타인의 저작물**(오픈소스 라이브러리·프레임워크·컨테이너 이미지·
외부 데이터)의 출처와 라이선스를 한 곳에 모은 고지다. 2026년 오픈소스 개발자대회 운영규정
제8조 ⑤·⑥("타인의 저작물을 활용한 경우 출처와 라이선스를 명시", "활용한 모든 오픈소스
라이브러리·프레임워크·모델의 출처와 라이선스를 명확히 공개")에 대응한다.
저장소 자체의 라이선스는 루트 [LICENSE](LICENSE)(AGPL-3.0)이며, 이 문서에 적힌 항목들은 각자의
라이선스를 그대로 따른다(라이선스 전환 이력은 [README.md 라이선스 절](README.md#라이선스) 참고).

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
| spec-review-kit | commit `b706e175` (2026-08-08 이식) | 설계 게이트·코드리뷰 방법론 — 이 저장소를 개발하는 데 쓴 도구이며 심사 대상이 아니다(README.md "출품 범위" 표 참고) | 저장소 저작자와 동일인의 다른 저장소 — 루트 [LICENSE](LICENSE)(AGPL-3.0)가 그대로 적용된다 | https://github.com/JeongDoWook/spec-review-kit |

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
기본 주소에서 뽑았고, **이용 조건은 2026-08-21 에 각 원 사이트에서 직접 확인했다.**

| 피드 | 제공자 | 용도 | 이용 조건 (원 사이트 확인) | 출처 URL |
|---|---|---|---|---|
| CISA KEV | 미국 CISA | 실제 악용된 취약점 목록 | 미국 정부 저작물 — 자유 이용 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| OSV.dev | Open Source Vulnerabilities | 패키지 생태계별 취약점 조회 | 스키마·도구는 Apache-2.0. 데이터는 각 원 출처의 라이선스를 따른다 | https://osv.dev/ |
| NVD 2.0 | 미국 NIST | CVE 상세·CVSS 점수 | 미국 정부 저작물 — 자유 이용. CVE® 는 MITRE 의 등록상표 | https://nvd.nist.gov/developers |
| KISA 보안공지 | 한국인터넷진흥원 보호나라 | 국내 보안공지·권고문 | **명시된 라이선스 없음** — 푸터 `Copyright(C) 2023 KISA. All rights reserved.`, 게시물에 공공누리 표기 없음. 이용안내는 "인용 시 자료 배포 기관을 명시" 만 요구 | https://www.boho.or.kr/ |
| FIRST EPSS | FIRST.org | 악용 확률 점수 | 무료 제공, 출처 표시 요청 | https://www.first.org/epss/ |
| 데비안 보안 트래커 | Debian Project | 데비안 릴리스별 미수정 취약점 | **명시된 라이선스 없음** — security-tracker 저장소에 LICENSE·COPYING 이 없고 트래커 사이트에도 문구가 없다 | https://security-tracker.debian.org/tracker/ |
| RHEL OVAL · Red Hat 미수정(hydra API) | Red Hat | RPM 계열 패치 판정 · 수정본 없는 취약점 상태 | **CC BY 4.0** — "The data resources linked on this page as well as their alternative representations available through the Security Data API are licensed under the Creative Commons Attribution 4.0 International License." 재배포·수정 시 Red Hat, Inc. 출처 표시 필요 | https://access.redhat.com/security/data |
| Oracle Linux OVAL | Oracle | Oracle Linux 패치 판정 | **Oracle 사이트 이용약관 적용** — `linux.oracle.com` 푸터가 oracle.com/legal 로 연결된다. 제3조 Use of Materials: 개인·정보 목적의 **비상업적 이용만**, 변경 금지, **재배포 금지**. 지금 저장 범위와 경계는 아래 주의 참고 | https://www.oracle.com/legal/terms.html |
| AlmaLinux OVAL | AlmaLinux OS Foundation | AlmaLinux 패치 판정 | **명시된 라이선스 없음** — OVAL XML·wiki 문서·security 페이지 어디에도 표기가 없다 | https://security.almalinux.org/oval/ |
| Ubuntu OVAL | Canonical | 우분투 패치 판정 | 배포 파일에는 라이선스 헤더가 없다. 원천인 Ubuntu CVE Tracker 는 Launchpad 프로젝트 메타데이터에 `"licenses": ["GNU GPL v2"]` 로 선언돼 있다 | https://launchpad.net/ubuntu-cve-tracker |
| SCAP 보안 기준 (ComplianceAsCode/content) | ComplianceAsCode 프로젝트 | 보안 설정 점검 기준(SSG) | BSD-3-Clause | https://github.com/ComplianceAsCode/content |
| 커널 CNA (vulns.git) | kernel.org | 리눅스 커널 CVE 레코드 | 커널 저장소와 동일(GPL-2.0) | https://git.kernel.org/pub/scm/linux/security/vulns.git/ |

> **Oracle Linux OVAL — 지금 형태는 약관 안에 있다**
> Oracle 이용약관이 제한하는 것은 Materials 의 **비상업적 이용·변경·재배포**다. 이 제품이
> Oracle OVAL 에서 실제로 저장하는 값은 `vendor · release_major · pkg_name · cve_id ·
> fixed_evr · advisory(ELSA-ID) · severity` 뿐이고(`server/src/feeds/rhoval.php`), 권고 제목·
> 설명·CVSS 는 **가져오지 않는다**(그 상세는 NVD 가 채운다). 즉 표현물을 복제하지도, 원본이나
> 그 파생물을 외부에 다시 배포하지도 않는다. 저장소에도 Oracle 원본은 없다 —
> `tests/fixtures/rhel-oval/oracle.oval.xml` 은 스키마만 흉내 낸 손으로 쓴 축소판이다.
>
> 선을 넘는 것은 다음 세 가지이고, 그중 하나라도 하게 되면 그때 Oracle 분기를 빼거나 별도
> 합의가 필요하다: ⑴ 취약점 DB 자체를 내보내는 기능(오프라인 설치 번들·피드 덤프 등. 지금의
> SBOM export 는 우리 스캔 결과라 해당하지 않는다) ⑵ 테스트 픽스처를 **원본 파일에서 잘라
> 붙여** 갱신하는 것(공개 저장소이므로 그 순간 재배포가 된다) ⑶ 폐쇄망 고객에게 피드를 미리
> 받아 동봉해 배포하는 것.
>
> **명시된 라이선스가 없는 항목(KISA · Debian · AlmaLinux)** 은 "확인을 안 했다"가 아니라
> **"원 사이트에 표기 자체가 없음을 확인했다"** 는 뜻이다. 공개적으로 무상 제공되고 기계 판독을
> 전제로 배포되지만 재배포 권리는 명시돼 있지 않으므로, 이 제품도 원본을 재배포하지 않고
> 판정 결과만 저장·표시한다.

---

## 갱신 규칙

`server/public/assets/vendor/` 에 파일을 추가하거나, `Dockerfile` 의 `FROM`·`compose.*.yml` 의
`image:` 를 바꾸거나, 새 피드 커넥터를 등록하면 이 문서도 같은 커밋에서 갱신한다.
벤더링한 자산에는 `LICENSE` 와 `VERSION` 파일을 함께 넣는다(chartjs·flatpickr 가 그 형식이다).

`tests/fixtures/` 의 피드 샘플은 **원본 파일에서 잘라 붙이지 않는다** — 스키마만 흉내 낸 손으로 쓴
축소판을 유지한다. 이 저장소는 공개되므로 원본 발췌를 커밋하면 그 자체가 재배포가 되고,
재배포를 금지하는 제공자(Oracle)가 실제로 있다.
