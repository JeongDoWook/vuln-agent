# vuln-agent 아키텍처

> 현행 기준: 2026-08-15 · 에이전트 3.13 · pull 명령 큐, 진행 heartbeat/취소, 관리 IP 보고,
> 계정 인벤토리·자산 등급(제안 이력 포함)·의존성 그래프(수집·조회 화면), 컴플라이언스 스냅샷,
> 패키지 무결성 검증, SBOM 산출 API 포함.

지금까지 확정·구현된 구조를 그림으로 정리한다.
다이어그램은 [`docs/specs/diagrams/`](../specs/diagrams/) 에 PlantUML(`.puml`)로 분리해 두었다.

관련 문서: 전략·로드맵은 [`CONTEXT.md`](../../CONTEXT.md), 실행법은 [`README.md`](../../README.md).

---

## 1. 시스템 개요 (데이터 흐름)

다이어그램: [`docs/specs/diagrams/시스템개요.puml`](../specs/diagrams/시스템개요.puml)

> 중앙 서버 자신을 모니터링하는 로컬 에이전트는 루프백 평문 포트(`127.0.0.1:8081`)로 Caddy 를
> 거치지 않고 직접 `ingest.php` 로 전송한다(§4 배포 구성 참고).

**핵심:** 매칭 정확도는 검증된 스캐너/피드에서 상속하고, 우리 기여는 그 위 레이어
(**런타임 노출 상관 · KEV/EPSS 우선순위 · 설명가능성**)에 둔다.

---

## 2. 매처 판정 로직 — "실제로 위험한가"

설치되었다고 전부 올리지 않는다. **런타임 상태(노출·실행·사용) + KEV** 로 우선순위를 가른다.
exposures(포트) + processes(실행/로드) 를 합쳐 7단계 상태를 판정한다(`vg_classify`).

다이어그램: [`docs/specs/diagrams/매처판정로직.puml`](../specs/diagrams/매처판정로직.puml)

> 상태: EXTERNAL > LAN ≈ FILTERED ≈ LISTENING > RUNNING > LOADED > INSTALLED. KEV 시 한 단계 상향,
> EPSS·CVSS 는 같은 등급 내 정렬. 각 판정에 근거(어떤 프로세스·포트·라이브러리)가 남는다.
> **LAN** — mDNS/LLMNR/SSDP 같은 링크로컬 멀티캐스트다. 0.0.0.0 에 떠 있어도 라우터를 넘지
> 못해 같은 세그먼트에서만 닿으므로 EXTERNAL 로 올리지 않는다.
> **FILTERED** — 전체 인터페이스에 바인딩됐지만 방화벽(firewalld/ufw)이 그 포트를 막아 외부에서
> 못 닿는 경우다. 이 판정이 없으면 방화벽 뒤의 내부 서비스가 **전부 HIGH/CRITICAL 로 뜬다**(오탐).

**오탐 억제는 4겹이다(데비안 중심).** 배포판은 버전을 안 올리고 패치만 이식하므로 버전 비교만으로는 오탐이 난다.

| 겹 | 근거 테이블 | 판정 | 커버리지 |
|---|---|---|---|
| ① OSV 버전필터 | `tb_cve_affected_package` | 배포판 전체버전 대조 → 영향 없으면 제거 | 전체 |
| ② changelog | `tb_pkg_changelog_cve` | 그 CVE 수정 기록이 있으면 억제 | 핵심 13개 패키지(하드코딩) |
| ③ errata | `tb_applied_errata` | 벤더가 "이 빌드에서 고쳤다"고 확인 → 억제 | **시스템 전체** |
| ④ debsecan | `tb_debsecan` | "아직 남은 CVE" 목록에 **없으면** 고쳐진 것 → 억제 | 데비안 전용 |

억제된 건은 `tb_finding` 이 아니라 `tb_suppressed_finding` 으로 간다 — **기존 위험 집계·화면을
하나도 안 건드리고 오탐만 빠진다.** 숨기지 않고 호스트 상세에서 근거와 함께 보여준다(설명가능성).

> debsecan 은 방향이 반대(있는 게 아니라 **없는** 게 근거)라 안전장치를 두 겹 뒀다 —
> `os_id=debian` 일 때만 쓰고(우분투는 OSV 의 USN 경로로 커버), **목록이 비면 억제하지 않는다**
> (수집 실패와 "취약점 0"을 구분할 수 없어, 믿었다간 전부 억제해 버린다).

**RHEL 계열·우분투·커널은 각자의 벤더 소스로 별도 판정한다.** 위 4겹은 데비안 트래커 중심으로
자란 규칙이라, 배포판마다 조치 EVR 표기 방식이 다른 다른 벤더는 한 테이블로 합칠 수 없었다.

| 벤더 | 근거 테이블 | 판정 |
|---|---|---|
| RHEL 계열(Red Hat/AlmaLinux/Oracle) | `tb_vendor_errata`(OVAL 조치 EVR) + `tb_vendor_unfixed`(조치 불가) | 릴리스별 조치 EVR 대조, 수정본 없는 CVE 는 별도 API 로 확인 |
| 우분투 | `tb_ubuntu_oval` | 테스트에 조치 EVR 이 있으면 억제, 없으면 아직 수정본 없음(조치 불가) — 한 테이블에서 둘 다 표현 |
| 리눅스 커널(배포판 밖) | `tb_kernel_cve`(kernel.org CNA) | 구동 커널의 업스트림 버전과 스트림별 수정 버전 대조. 라즈베리·자체빌드처럼 배포판 트래커·OVAL 이 관할하지 않는 커널만 담당 |

벤더가 "아직 안 고쳤다"고 확인한 CVE 는 `tb_finding.no_fix` 로 표시한다 — **오탐 제거와는 다른
축**이다. 등급(런타임 노출 기준)은 그대로 두되, "지금 고칠 수 있는 것"과 "조치 불가"를 화면에서
분리해 조치 불가 수백 건이 고칠 수 있는 몇 건을 덮지 않게 한다.

**억제를 취소하는 두 신호 — "패치됨"이 곧 "안전함"은 아니다.**

- **재시작 필요**(`tb_stale_lib`): 패치됐지만 프로세스가 옛 `.so` 를 메모리에 물고 있으면 그
  프로세스는 여전히 옛 코드를 실행 중이다 → 억제하지 않고 근거(프로세스 → 라이브러리 경로)를 남긴다.
- **커널 재부팅 필요**(`tb_scan.kernel_reboot_needed`): 커널을 패치해도 재부팅 전엔 옛 커널이
  돈다 → 억제하지 않는다. 조치는 프로세스 재시작이 아니라 **재부팅**이라고 안내한다.

이 두 신호가 없으면 "설치 버전이 패치됨"만 보고 억제해 **미탐**이 된다.

**미지원 배포판.** Amazon Linux·CentOS 는 피드가 안 덮어 매칭이 0건이 된다. 조용히
"취약점 없음"으로 보이면 더 위험하므로 `vg_distro_unsupported`(`src/distro.php`)가 판정해
ingest 응답과 취약점 화면에 경고를 띄운다(자체 피드가 필요하다는 뜻). Oracle Linux는
OSV 대신 Oracle ELSA OVAL 커넥터가 릴리스별 영향 여부와 수정 EVR을 제공한다.

**재매칭은 결과가 같으면 아무것도 쓰지 않는다.** 피드가 갱신돼도 특정 스캔의 판정 결과는 대부분
그대로인데, 예전엔 1비트도 안 바뀐 경우까지 `tb_finding`/`tb_suppressed_finding` 를 통째
삭제·재삽입해 **binlog 가 하루 20GB 넘게** 쌓였다(운영 실측: 디스크 105G 중 76G). 지금은
`vg_match_scan()` 이 판정을 전부 메모리에서 끝낸 뒤 결과 지문(sha1)을 `tb_scan.match_fingerprint`
와 비교해, 같으면 트랜잭션조차 열지 않고 카운트만 돌려준다. 다르면 예전과 똑같이 통째 재작성하고
같은 트랜잭션 안에서 지문을 갱신한다(행 단위 diff 로 하지 않는다 — 비교 컬럼을 하나 빠뜨리면
stale 값이 영구히 남는다).

> **판정 로직이나 저장 컬럼을 바꾸면 `VG_MATCH_FP_VERSION`(`src/matcher.php`)을 올려야 한다.**
> 입력이 같으면 지문도 같아 **새 코드로 재계산한 결과가 영영 저장되지 않는** 함정이 있다.
> 이 상수는 지문에 섞여 들어가므로, 올리면 전 스캔이 한 번씩 다시 쓰인다.
> 피드 수집·에이전트 수집 경로가 필요한 스캔을 내부에서 직접 재매칭한다.
> 외부에서 전체 스캔을 강제로 다시 쓰는 공개 API는 제공하지 않는다.

**보안설정 점검(CCE)** 은 별도 경로다. 같은 수집물의 `security`/`users` 섹션을 `src/cce.php` 가
판정해 `tb_cce_finding`(PASS/FAIL/NA)에 저장한다 — CVE 가 아니라 **설정**을 본다(현재 39개 항목:
SSH·계정·패스워드 정책·파일 권한·MAC/방화벽 + 시간동기화 `CCE-TIME-*`·로그설정 `CCE-LOG-*`·
암호화 `CCE-CRYPTO-*`). 그중 31개는 SSG 룰 ID 에 묶여 있고 나머지 8개는 화면에서 "자체 기준"으로
드러낸다(`vg_cce_ssg_map()`). 신규 수집은 하지 않는다.
한 점검 결과가 **어느 기준의 증적인가**는 `tb_control_mapping`(U-코드/ISMS-P/N2SF 다중 매핑)이
정본이다 — 예전엔 이 지식이 `cce.php` 주석과 화면 문자열에 흩어져 있어 같은 결과를 다른 기준으로
볼 수 없었다. 조회는 `src/control_mapping.php`, 화면은 `/control_mapping.php`. 매핑 행 자체가
마이그레이션 시드이고, **근거가 없으면 행을 만들지 않는다**(억지 매핑 금지).

**계정 인벤토리**도 같은 수집물에서 나온다. 에이전트의 `users` 섹션(`account_passwd`·
`account_shadow`·`account_lastlog`·`account_sudoers`·`sudo_group`)을 `src/account_inventory.php` 가
계정 1행으로 조립해 `tb_host_account` 에 저장하고 파생 판정을 계산한다. 지금까지는 계정 "설정
정책"만 봤고 **실제 계정 목록**은 안 봐서 ISMS-P 2.5.x·N2SF AC 계정관리가 통째로 공백이었다.
원칙은 CCE 와 같다 — **패스워드 해시는 받지도 저장하지도 않고**, `/etc/shadow`·sudoers 를 못 읽은
값(NULL)은 정상(PASS)이 아니라 **판정 불가(NA)** 이며, 공유계정·퇴직자 계정 추정은 FAIL 이 아니라
REVIEW(사람이 확인)다.

**자산 중요도·N2SF 보안등급**(`src/assetgrade.php`)은 `tb_host` 에 붙는다. 지키는 경계는 하나 —
**판정은 사람이, 초안은 시스템이.** 등급 기준은 「정보공개법」 제9조 호 매핑이고 업무정보 등급
확정은 기관의 법적 처분이라 시스템이 대신할 수 없다. 그래서 사람이 확정한 값(`grade`·
`grade_reason`·`approved_by`·`approved_at`)과 시스템 초안(`grade_suggested`·
`grade_suggested_reason`)을 **다른 컬럼에** 담고, 제안 함수는 확정값을 절대 쓰지 않는다. 확정은
사람 손으로만 하며 — 호스트 상세(`host.php`)의 관리자 폼과 자산 목록(`assets.php`)의 일괄 확정이
`vg_asset_grade_confirm()` **한 함수**를 공유한다(두 벌이면 화면마다 검증과 감사 증적이 갈린다).
일괄 확정은 지금 보고 있는 페이지에서 고른 자산만 대상으로 하고 **확정만** 한다 — 해제는 되돌리기
어려워 상세에서 한 대씩이다. 여러 업무정보 등급이 한 시스템에 있으면 **가장 높은 등급을 승계**한다
(C > S > O).

초안 분류기는 에이전트가 저장한 노출 의미를 그대로 따른다. 원격 로그 수신 근거로 인정하는 범위는
비루프백 도달/바인딩을 뜻하는 `EXTERNAL`·`LAN`·`BOUND`뿐이며, 방화벽 차단 `FILTERED`, 루프백
`LOCAL`, 미지정·알 수 없는 범위는 원격 수신으로 표현하지 않는다. 로그·백업 프로세스도
서버·저장소(강한 S 근거), 전달자·클라이언트(검토 근거), 일회성 도구(약한 근거)로 구분한다.
한 스캔의 일치 근거는 모두 모아 결정적인 255자 이내 설명으로 만들고, S와 외부노출 O가 함께 있으면
S가 우선하되 O 근거도 설명에 남긴다. 어느 경우에도 초안이 사람의 확정 등급을 대신하지 않는다.

제안은 수집 때마다 `tb_asset_grade_suggestion_history` 에 **append-only 로 관찰 기록**된다
(`src/assetgrade_history.php` 의 `vg_asset_grade_observe()`, ingest 트랜잭션 안). 같은 스캔·같은
결과의 재전송은 `(host_id, scan_id, result_fingerprint)` 로 한 줄만 남고, 결과가 바뀌면 새 줄이
쌓인다. 판정 상태는 셋이다 — 근거를 찾은 `SUGGESTED`, 근거가 없는 `NO_MATCH`, 그리고 그 판정에
필요한 수집 단계(로그 수신 근거면 `network_exposure`, 프로세스 근거면 `runtime_processes`,
그 밖에는 둘 다)가 `MISSING` 이라 **판정 자체를 못 한** `NOT_EVALUATED`. 판정 불가일 때는 현재
제안 컬럼(`tb_host.grade_suggested`)을 지우지 않는다 — 수집이 한 번 빠졌다고 기존 제안이
사라지면 "근거가 없어졌다"와 구별되지 않기 때문이다. 지연 도착한 과거 스캔도 이력엔 남기되
더 새로운 관찰이 있으면 현재 제안 컬럼을 되돌리지 않는다. 이 경로는 확정값(`grade`·`approved_*`)을
절대 쓰지 않는다.

**패키지 의존성 그래프**는 SBOM(CycloneDX `dependencies` · SPDX `relationships`)과 pom.xml 최상위
`<dependencies>` 에서 부모→자식 엣지를 뽑아 `tb_package_dependency` 에 넣는다(`src/ingest_store.php`).
SPDX 는 `DEPENDS_ON`(정방향)과 `DEPENDENCY_OF`/`RUNTIME_DEPENDENCY_OF`(역방향)만 의존으로 채택한다 —
`CONTAINS` 까지 엣지로 보면 이미지의 모든 패키지가 루트의 직접 의존이 되어 직접/전이 구분이 사라진다
(`src/ingest_parse.php` 의 `VG_SPDX_REL_FORWARD`/`REVERSE`). 엣지 유일성은
9개 컬럼 복합키가 InnoDB 인덱스 상한(3,072바이트)을 넘겨 **해시 생성컬럼**(`edge_hash`)으로 건다 —
접두 길이 방식은 접두가 겹치는 서로 다른 패키지를 같은 키로 묶어 정상 엣지를 조용히 버린다.
조회 화면은 `/depgraph.php`(읽기 전용 헬퍼 `src/packagedep.php`) — 대상 패키지를 지정하면 역추적
("무엇이 끌어왔나")·정방향·트리 탭이 열린다. 진입은 자산 상세(`host.php`)에서만 한다: `uk_pkg_dep_edge`
좌측 접두가 (`scan_id`, `container_id`)라 그 둘로 좁혀야 인덱스를 타고 패키지명 전역 검색은 풀스캔이
된다. 엣지는 그 단위로 한 번에 읽어 메모리에서 조립하고(재귀 SQL 은 깊이만큼 N+1), 상한에 걸리면
**잘린 사실을 화면에 밝힌다**. 그래프 라이브러리는 들이지 않는다(접이식 목록으로 충분 — KISS).

**이 그래프는 조치 문구까지 바꾼다.** `vg_pkgdep_origin()` 이 취약점 행을 `direct`/`transitive`/
`unknown` 으로 판정해, 전이면 조치 열을 "**직접 조치 불가 — X 가 끌어옴**"으로 **대체**하고
의존성 경로로 링크한다(그 패키지만 갈아끼우면 부모가 깨진다). `unknown` 은 아무것도 표시하지
않는다 — 엣지가 없는 자산이 다수라 표시하면 화면이 "모름"으로 도배된다. 매칭은 (이름+버전) 정확
일치 → 표기 차이(rpm epoch·빌드 메타데이터)만 지운 재시도까지이고 **이름만으로는 맞추지 않는다**
(같은 스캔의 alpine `openssl 3.1.4-r2` 와 rpm `openssl 1:3.0.7-24.el9` 가 서로의 부모를
물려받으면 틀린 조치가 나간다). 여기에 `vg_pkgdep_scan_rollup()` 이 **부모별로 묶어**
"이 하나를 올리면 N건 해결"을 취약점 탭 상단 카드로 올리고 **최고 심각도 → 건수** 순으로 정렬한다
(= 조치 순서). 집계는 화면의 행이 아니라 **스캔 전체** 기준이다 — 페이지마다 답이 달라지는
우선순위는 우선순위가 아니다. **올릴 버전은 제안하지 않는다**: 설치되지 않은 부모 버전이 무엇을
끌어오는지는 수집물로 알 수 없다(purl 과 같은 원칙 — 틀린 제안은 없는 것보다 나쁘다).
이 둘은 **`host.php` 에만 붙고 `findings.php` 전역 목록에는 없다** — 위 유니크 키 제약 때문에
(스캔, 컨테이너) 단위 조회만 인덱스를 타므로, 전 호스트 목록에 붙이면 행마다 그래프를 적재하게
되어 성능 사고가 난다. 호출도 `$depEdgeTotal > 0` 게이트 안에서만 하므로 엣지가 없는 자산에서는
쿼리가 한 건도 늘지 않는다.

> **회귀 방어의 빈 곳(알려진 한계).** 집계 로직 자체는 `tests/pkgdep_rollup_test.php`(DB 없이 도는
> 순수 함수 단위테스트)가 덮지만, `tests/sample-scan.json` 픽스처에는 **그래프에 있으면서 취약한
> 패키지가 없다**(SBOM·pom 이 실어 보내는 `myco-*` 는 CVE 에 안 걸린다). 그래서 조치 열의 전이
> 셀과 "먼저 올릴 대상" 카드는 스모크에서 **한 번도 렌더되지 않는다** — 그 화면 경로가 깨져도
> 게이트는 통과한다.

**패키지 무결성 검증**은 CVE 판정과 별개 축이다 — "설치 이후 파일이 바뀌었나"(N2SF 제6장 IN
구성요소 무결성)를 본다. 에이전트가 `--verify-files`(기본 꺼짐)로 `rpm -Va`/`dpkg --verify` 를
돌린 결과만 들어오고, 행은 `tb_package_integrity`(스캔 CASCADE)에, **검사 여부·부분 결과·전체
건수는 `tb_scan.integrity_checked`/`_partial`/`_total`** 에 나눠 담는다. 행이 0개라는 사실만으로는
"검사했는데 깨끗함"과 "아예 검사 안 함(기본 꺼짐·구버전 에이전트)"을 구분할 수 없고, 둘을 합치면
"검사도 안 했는데 깨끗하다"로 읽힌다 — `tb_collection_stage`·자산등급 제안 이력과 같은 취지다.
플래그 문자열은 rpm/dpkg 원문 그대로 저장하고 해석은 화면이 한다(`vg_integrity_flag_label()`).
어휘도 "변조됨"이 아니라 **"패키지 원본과 다름(관측)"** 이다 — 운영자가 직접 바꾼 파일일 수 있다.

**미조치 사유·승인자**(`src/remediation_note.php` → `tb_remediation_note`)는 억제와 **다른 축**이다.
억제는 매처의 자동 판정이고, 이건 사람이 남기는 메모다 — "왜 지금 고치지 않는가"와 "누가 언제
그렇게 판단했는가"만 붙들고 결재선·상태 전이·기한은 두지 않는다. 키는 스캔이 바뀌어도 유지되는
자연키(호스트 + 컨테이너 **이름** + CVE + 패키지명)다. 본격 조치 워크플로는 이 메모를
`export.php` 로 가져가는 외부 시스템의 몫이다(`docs/dev/export-api.md`).

**SCA 라이선스 식별** 은 CVE 매칭과 별개 축이다. 에이전트가 SBOM(CycloneDX/SPDX, `SBOM_DIR`
오프라인 입력)·pip `METADATA`(구식 `*.egg-info/PKG-INFO` 포함 — 같은 필드 구조라 같은 경로로
수집된다)·composer `installed.json` 에서 라이선스 문자열을 수집해 보내면,
`src/license_risk.php`(`vg_license_classify`)가 SPDX 식별자·자유서술 별칭·복합 표현식(`OR`/`AND`)을
permissive/copyleft/unknown 3단계로 판정해 `tb_package.license`/판정 결과를 `/packages.php?tab=lang`
(언어 패키지·라이선스 탭)에 보여준다. **npm/gem/maven/nuget/cargo 매니페스트 직접 파싱이나 시그니처·바이너리 스캔으로는
라이선스를 식별하지 않는다** — 위 세 소스가 없으면 미상(unknown)으로 남는다. 목록·KPI 는
`tb_package_license_summary`(`src/license_summary.php`, 스케줄러가 매 틱 무조건 재구성 — OSV 게이트와
무관하다. tb_package_summary 와 달리 OSV 실행에 안 묶은 이유는 라이선스 데이터가 OSV 가 아니라
에이전트 ingest 로 들어오기 때문이다)만 읽는다 —
`tb_package` 를 화면 요청마다 직접 GROUP BY 하면 packages.php 40초 사고(92만 행 무인덱스 재집계)와
같은 문제가 재현된다.

**KISA ISMS-P·ISO 27001 컴플라이언스 판정**의 로직은 `src/compliance.php` 에 있다(웹·CLI 공용).
화면(`public/compliance.php`)은 이걸로 "지금"을 렌더하고 스케줄러는 같은 함수로 증적을 적재한다 —
판정 로직이 두 벌이면 화면과 증적이 서로 다른 답을 내기 시작한다. findings(severity·in_kev·
no_fix·needs_restart)·자산 연결상태·`tb_cce_finding`(설정 취약)·`tb_host_account`(계정 인벤토리)
등 기존 판정 결과만 다시 읽어 통제 4개
(`patch`/`asset`/`secops`/`account` — `VG_COMPLIANCE_CONTROLS` 가 SSOT)를
판정한다. `account` 는 판정 로직을 새로 만들지 않고 `vg_account_judgments()`(host.php 계정 탭이
쓰는 것)를 재사용해 집계만 한다. `patch` 는 통제 전체가 아니라 **버킷(KEV/CRITICAL/HIGH)별로**
판정한다 — 이력이 짧아 판정 불가인 버킷 하나가 잘 지킨 나머지 버킷까지 회색으로 누르지 않게.
**정책·승인이력처럼 vuln-agent 가 갖고 있지 않은 근거가 필요한 통제는 판정하지 않고 체크리스트로만
노출한다** — 남은 4개(정책문서·접근권한 검토·사고대응·재해복구, `VG_COMPLIANCE_MANUAL_CHECKLIST`)는
증적이 제품 밖에 있어 사람이 직접 심사해야 한다는 게 이 화면의 의도적 한계다.
접근권한 검토(ISMS-P 2.5.3)는 한때 자동판정이었으나, 근거였던 접속기록 점검 기능이 제거되면서
(`20260813001657_drop_activity_review.sql`) 다시 수동 체크리스트로 내려왔다 — 근거가 없는 통제를
준수로 찍지 않는다.

**판정 어휘는 4종이다 — 준수 / 판정 불가 / 부분준수 / 미준수**(`vg_compliance_status()` 가 SSOT).
위반 0건이라고 무조건 "준수"로 쓰지 않는다: 볼 수 있는 근거가 모자라서 0건인 것을 준수로 표기하면
심사 증빙에 **허위 안심**을 싣게 된다. 보유한 스캔 이력이 SLA 보다 짧아 위반을 검출할 방법 자체가
없는 호스트, 최초 발견 시각을 못 찾은 건, 에이전트가 비-root 라 외부노출을 부분 수집한 호스트는
전부 판정 불가로 **따로 센다**(예전엔 조용히 넘겨 "준수" 쪽에 흡수됐다). CCE 가 이미 지키는
원칙("NA 를 PASS 와 구분한다")을 컴플라이언스 판정에도 똑같이 적용한 것이다.

**SLA 기준일과 컷라인은 설정값이다**(`tb_setting` ← `src/setting.php`). SLA 는 업계 관행값이 아니라
조직 내부 규정이라 코드를 고쳐야 바꿀 수 있으면 제품으로 쓸 수 없다. 코드의 상수
(KEV 15일·CRITICAL 30일·HIGH 60일, 부분준수 상한 5건)는 지우지 않고 **설정 행이 없을 때의
폴백**으로 남는다 — 마이그레이션이 아직 안 든 DB 에서도 동작이 같아야 한다. 최초 발견 시각을 되짚는
구간은 절대 일수가 아니라 "가장 긴 SLA + 여유일"로 묶어 둔다: SLA 만 올리고 구간이 그대로면 경과일이
구간 길이에서 잘려 위반이 아예 검출되지 않는다(허위 안심이 설정 실수로 재현된다).

**판정은 스냅샷으로 쌓인다.** 심사 증적의 본질은 시점이 아니라 시계열인데 그동안은 저장이 없어
"작년 심사 시점엔 어땠나"에 답할 수 없었다. 스케줄러(`bin/scheduler.php`)가 due 커넥터 유무와
무관하게 하루 1건씩 `tb_compliance_snapshot`(+`_control`)에 통제별 판정을 남긴다 — 커넥터가 없는
날에도 증적은 남아야 한다. 오늘 것이 이미 있으면 건너뛰고, UPSERT 라 두 번 돌아도 행이 늘지 않는다.
스냅샷은 위반 건수뿐 아니라 **판정 불가 건수(`unjudged_count`)까지** 저장한다(안 그러면 나중에
"위반 0건 = 준수"로 되읽는다). 근거 JSON 은 500건 상한이고 넘으면 **잘렸다는 사실 자체**를
`truncated=true` 로 남긴다. 스냅샷도 화면과 같은 `vg_compliance_policy()`(=`tb_setting` 반영)를
쓴다 — 스케줄러만 상수를 쓰면 설정을 바꾼 조직에서 화면과 증적의 기준이 갈라진다(증적 오염).

---

## 3. CVE 피드 커넥터 (외부 소스 수집)

claude-pipeline 의 Connector/CollectionLog 패턴을 참고. UI에서 소스를 설정·스케줄하면
스케줄러가 주기적으로 당겨와 매처가 재계산한다.

다이어그램: [`docs/specs/diagrams/피드커넥터.puml`](../specs/diagrams/피드커넥터.puml)

커넥터 = `{type(12종 — 고정 11종 = 기준정보·우선순위 5종 kev/osv/nvd/kisa/epss + 벤더·업스트림 판정 5종 debtracker/rhoval/rhunfixed/kcve/ubuntuoval + 설정 룰셋 ssg, 여기에 범용 generic_api 1종), connection(url·key·ecosystem 등 타입별), schedule, enabled}`.
타입 카탈로그의 SSOT 는 `VG_CONNECTOR_TYPES`(`server/src/feeds.php`) 하나이고, 역할별 차이는 [`피드소스-역할.md`](피드소스-역할.md).
스케줄은 **manual / interval(N분) / daily(HH:MM) / cron(5필드 표현식)** 지원 — UI에서 지정하면
스케줄러 사이드카가 매 tick(60s) 판정해 그 시각에 수집·재매칭한다(Quartz 유사, 중앙 실행).
수집 이력·상태는 `tb_feed_collection_log` 에 남고 커넥터 행에 마지막 상태로 표시된다.

---

## 4. 배포 구성 (dev / prod)

다이어그램: [`docs/specs/diagrams/배포구성.puml`](../specs/diagrams/배포구성.puml)

> web·scheduler 는 같은 이미지(`vulnagent-app`)를 공유하고, 환경/시크릿은 compose 앵커
> (`x-app-env`/`x-app-secrets`)로 DRY 하게 재사용한다. dev 는 caddy 없이 `web` 을 `${WEB_PORT:-8000}`
> 으로 평문 직접 노출한다(§ Caddy README 참고: `deploy/caddy/README.md`).
>
> dev 는 web+scheduler 가 워크트리별 독립 컴포즈 프로젝트(`vulnagent-dev-<워크트리이름>`)로 뜨고,
> db 는 메인 트리 프로젝트(`vulnagent-dev`) 하나만 존재한다 — 서로 다른 프로젝트지만 외부 네트워크
> `vulnagent-dev-net`(`compose.dev-net.yml`)을 공유해 컨테이너명(`vulnagent-db-dev`)으로 붙는다.

| | dev | prod |
|---|---|---|
| 소스 | `./server` 라이브 마운트 | `../server` 읽기전용 마운트(PHP 는 배포=`git pull`, 무중단) |
| DB 포트 | 노출(3307) | 미노출(내부망만) |
| 웹 접속 | `http://localhost:8000` (평문) | `https://<운영-도메인>` (`.env.prod` 의 `PROD_DOMAIN` · Caddy, 자체서명 · 평문 80 은 308 리다이렉트 · `:8080` 도 계속 동작) |
| my.cnf | 미적용(기본값) | 적용(charset/보안 튜닝) |
| 프로젝트 | `vulnagent-dev`(메인) · `vulnagent-dev-<워크트리>`(web+scheduler) | `vulnagent` |

각 대상 서버는 `agent/install-agent.sh` 로 systemd 가 있으면 **상시 데몬**(`vuln-agent.service`,
`run.sh` 가 10초마다 `agent-poll.php` 를 poll하고 초기 주기(기본 60분, `--schedule`)로
정기수집을 시작한다. 이후 주기는 poll 응답의 `poll_schedule_seconds` 를 따르므로, 중앙 웹의
호스트 상세에서 주기를 바꾸면 다음 poll 에 바로 반영된다(SSH 재설치 불필요) — "지금 수집" 같은
예약 명령도 같은 poll 로 실려온다. systemd 가 없는 노드만 cron 폴백(`run.sh --once` 정기 실행,
정기수집만 가능)한다. 중앙 서버 자신을 스캔하는 로컬 에이전트만 루프백(`8081`)
평문 경로를 쓰고, 그 외 원격 서버 에이전트는 모두 Caddy 의 HTTPS 엔드포인트로 전송한다.

**보안 응답 헤더는 Caddy 가 한 곳에서 붙인다**(`deploy/caddy/Caddyfile` 의 `(security_headers)`
snippet → 각 사이트 블록에서 `import`). 사이트마다 복붙하지 않는다. 현재 세트는
`X-Content-Type-Options: nosniff` · `X-Frame-Options: DENY` ·
`Referrer-Policy: strict-origin-when-cross-origin` · CSP(`default-src 'self'` 기준, 서드파티 런타임
의존성이 0개라 가능하다) 이고, `Server`/`X-Powered-By` 는 지운다. CSP 에 `'unsafe-inline'` 이 남은
이유는 실측으로 확인한 인라인 사용처(테마 초기화 스크립트·인라인 핸들러·`process.html` 의 `<style>`)
때문이다 — 그걸 걷어내기 전에 지우면 화면이 통째로 깨진다.
**HSTS 는 붙이지 않는다.** TLS 는 `tls internal`(자체서명)이고 정식 인증서 전환은 하지 않기로
확정했다(2026-08-09, 이슈 #518 — 자세한 이유는 `deploy/caddy/README.md`). 자체서명이라 브라우저가
이미 인증서 오류를 내는데, HSTS 를 보내면 그 호스트에서 **인증서 예외를 아예 허용하지 않아**
접속 수단이 사라지고 max-age 만료 전엔 되돌릴 방법도 없다.

**스키마 적용**은 `deploy/migrate.sh` 가 맡는다 — `db/migrations/*.sql` 중 아직 안 든 것만
**파일명 사전순**으로 db 컨테이너에 파이프하고 `tb_schema_migrations(filename, applied_at)` 에
기록한다. 파일명은 타임스탬프(`YYYYMMDDHHMMSS_이름.sql`)다 — 연번은 동시에 작업하는 브랜치들이
같은 번호를 집어 충돌한다(실제로 `0003`·`0014` 가 각각 두 개 생겼다). 기존 연번 파일은 그대로
두는데, 사전순이라 `0…` 이 `2…` 보다 앞서 옛 파일이 먼저 도는 순서가 지켜진다.
`compose_runner.sh up` 과 `update.sh` 가 자동 호출하므로 수동 apply 가 필요 없다. 최상위
`db/*.sql` 은 **빈 볼륨 initdb 전용**이라 기존 볼륨엔 적용되지 않는다 — 증분 변경은 전부
`db/migrations/` 에 둔다.

---

## 5. 데이터 모델 (ERD)

> 아래는 **관계도**다. 테이블별 전체 컬럼·책임·정규화 현황은 `docs/dev/데이터베이스.md` 참고.

다이어그램: [`docs/specs/diagrams/erd.puml`](../specs/diagrams/erd.puml)

**범위**: 도메인 엔티티 **52개 전부**(= 전체 53테이블 − `tb_schema_migrations`)를 그린다.
`tb_schema_migrations` 는 마이그레이션 러너 자신의 인프라 테이블이라 도메인 모델이 아니어서 뺐다.
엔티티가 많아 영역별 `package` 로 묶었다 — 수집·인벤토리 / CVE 도메인 / 벤더 판정 소스 /
판정 결과 / 피드 운영·인증·감사. **실선은 FK 가 실제로 걸린 관계, 점선은 FK 없이
애플리케이션이 자연키로 조인하는 관계**다. 컬럼은 전부 적지 않는다(PK/FK 와 이해에 필요한 것만) —
테이블별 전체 컬럼은 `docs/dev/데이터베이스.md`.

**명명규칙**: 테이블명은 **단수**(`tb_host`·`tb_finding`), 대리키 PK 는 **`<단수 테이블명>_id`**
(`tb_host.host_id`), FK 는 **부모 PK 이름을 그대로** 쓴다(`tb_scan.host_id`). 예전엔 PK 가 전부
`id` 라 `ON h.id = s.host_id` 처럼 조인 양쪽 이름이 어긋났다. 예외(자연키·복합키·FK-as-PK 라
대리키를 두지 않는 테이블: `tb_cve`·`tb_kev_catalog`·`tb_package_summary`·`tb_schema_migrations`
등)는 `docs/dev/데이터베이스.md` 의 예외표에 정리돼 있다.

*(tb_cve / tb_kev_catalog / tb_cve_affected_package / tb_finding 은 2단계 매처, tb_feed_* 는
4a 피드 커넥터(connector_type: kev/osv/nvd/kisa/epss/debtracker/rhoval/rhunfixed/ssg/kcve/
ubuntuoval/generic_api), tb_advisory 는 4b KISA 국내공지,
tb_user 는 3단계 인증, tb_activity_log 는 감사 추적, tb_cce_finding 은 보안설정 점검,
tb_role_permission 은 설정형 RBAC.
(tb_api_token 은 Export API 읽기 토큰이었으나 2026-08-13 폐지 — export/sbom 은 로그인 세션 인증.)
**억제 계열**(§2): 근거는 tb_pkg_changelog_cve(②)·tb_applied_errata(③)·tb_debsecan(④),
억제 결과는 tb_suppressed_finding, **억제를 취소**하는 신호가 tb_stale_lib(재시작 필요).
tb_container 는 컨테이너 인벤토리이고 컨테이너 내부 패키지는 tb_package 에 `container_id>0` 으로
같이 들어간다(호스트는 0). tb_pkg_change 는 패키지 변화 이력.
**벤더 판정 소스**: tb_debian_tracker(데비안 트래커 중앙 수집)·tb_ubuntu_oval·tb_vendor_errata·
tb_vendor_unfixed·tb_kernel_cve/tb_kernel_cve_fix 는 스캔에 매달리지 않고 매처가 참조만 한다.
**정밀 판정 플랫폼**: tb_finding_evidence(판정 근거 구조화, tb_finding 1:1)·tb_collection_stage
(수집 단계 완전성 — 단계 누락을 미탐 대신 경고로).
tb_host_account 는 **계정 인벤토리**(스캔별 계정 대장 — 계정명·UID/GID·셸·홈·잠금·sudo·정책·
마지막 로그인). 패스워드 해시는 수집도 저장도 하지 않는다. 값이 NULL 이면 "없음"이 아니라
"판정 불가"다(비-root 실행이면 /etc/shadow·sudoers 를 못 읽는다) — ISMS-P 2.5.x·N2SF AC 통제의 근거 데이터.
tb_agent_replay_nonce 는 에이전트 재전송 공격 방지.
tb_package_license_summary 는 SCA 라이선스 위험도 사전집계(tb_package.license 기반, tb_package_summary 와 같은 패턴).
tb_package_dependency 는 패키지 의존성 엣지(SBOM/pom, 스캔에 CASCADE).
tb_remediation_note 는 미조치 사유·승인자 메모(자연키라 스캔이 바뀌어도 유지).
tb_finding_status 는 같은 자연키에 조치 상태 4종과 메모만 보관한다. EXCEPTED 는 사람이 정한 상태이고
tb_suppressed_finding 의 자동 억제와 다르며, 완료·예외는 SLA 남은 일수에서 제외된다.
tb_control_mapping 은 CCE 룰 ↔ U-코드/ISMS-P/N2SF 다중 매핑,
tb_compliance_snapshot/tb_compliance_snapshot_control 은 하루 1건 컴플라이언스 판정 증적,
tb_setting 은 SLA 등 전역 운영 설정.
tb_asset_grade_review 는 자산 등급 확정의 **구조화된 사람 검토**(호스트당 1행),
tb_asset_grade_suggestion_history 는 **시스템 제안의 append-only 관찰 이력**(제안값은 확정값이 아니다),
tb_package_integrity 는 패키지 원본과 다른 파일 목록(스캔 단위 사실은 tb_scan 의 integrity_* 3컬럼).
스키마 적용 이력은 `tb_schema_migrations`(deploy/migrate.sh) — ERD 범위 밖.*
*모든 테이블에 감사 4컬럼(`created_at`/`updated_at`/`is_deleted`/`deleted_at`)이 통일되어 있다
(다이어그램엔 `is_deleted` 만 표기, 나머지 생략). 삭제는 하드삭제 대신 `vg_soft_delete()` 로
`is_deleted=1` 표시(대상: tb_user/tb_feed_connector/tb_advisory/tb_host/tb_scan —
tb_finding 등 재계산 캐시성 테이블은 소프트삭제 대상에서 제외).*
*tb_advisory 는 CVE 와 느슨한 연계(제목의 CVE best-effort)라 FK 없음. tb_activity_log 는
`user_id` 가 NULL 가능(SYSTEM 행위, 예: ingest 수신)이라 FK 없이 논리적 연계만 유지)*

---

## 6. 웹 화면 구성 (사이트맵 · 인증)

좌측 사이드바는 **업무 화면**(라벨 없는 최상위 묶음 — 대시보드/탐지 결과/자산/보안 공지/컴플라이언스),
**데이터**(수집 상태/CVE 카탈로그/패키지 카탈로그/판정 근거/CCE 카탈로그), 관리(사용자/권한/에이전트 키/
감사 로그/설정)로 묶고, **역할×메뉴 권한**에서
허용된 링크만 렌더한다(링크가 하나도 안 남은 섹션은 라벨째 숨김). 대분류·링크 구성의 SSOT 는
`server/src/view/nav.php` 의 `vg_nav_sections()` 하나이며, 사이드바와 브레드크럼이 같이 참조한다.

**사이드바에 항목을 늘리지 않고 서브탭으로 들어오는 화면들이 있다.** 변화 추적(`changes.php`)·
제거 권고(`nofix-packages.php`)는 '탐지 결과' 의 탭 줄로, 전체 설치 패키지(`asset-packages.php`)는
'자산' 의 탭으로 들어온다.
어느 탭에 있어도 대표 항목이 활성으로 남도록 링크마다 `active_keys` 를 둔다(안 그러면 사용자가
현재 위치를 잃는다).

**'데이터' 의 다섯 번째 자리는 SSG 룰 카탈로그에서 CCE 카탈로그(`cce-rules.php`)로 바뀌었다.**
그 자리에 있던 `compliance_rules.php`(SSG 룰 약 2,493건)는 우리가 판정하지 않는 외부 참조
데이터라, 실제로 판정하는 CCE 39개 항목을 대신 세웠다. SSG 화면 두 개는 **지우지 않았다** —
CCE 상세(`cce-rule.php`)가 "참조 근거" 로 링크하므로 URL·인가·감사로그가 그대로 산다
(사이드바에서만 내려온 강등이다. `control_mapping.php` 와 같은 처리).
점검 항목의 목록·제목·심각도는 `server/src/cce.php` 의 `vg_cce_rules()` 가 정본이고
(판정 함수에서 뽑아 쓴다 — 목록을 따로 적으면 판정 로직과 어긋난다), 기준 문자열(U-코드·
ISMS-P·N2SF)의 정본은 `tb_control_mapping` 이다. `control.php` 와는 방향이 반대다 —
저기는 "기준 하나 → 걸린 CCE 결과", 여기는 "CCE 하나 → 기준·위반 자산" 이고 서로 링크한다.

**통제 기준 매핑(`control_mapping.php`)은 사이드바에 없고 '컴플라이언스' 의 서브탭으로만 들어온다.**
`compliance.php`·`control_mapping.php` 두 화면이 `vg_compliance_subtabs()` 로 같은 줄을 그리고,
사이드바 '컴플라이언스' 항목의 `active_keys` 가 `control_mapping` 을 포함해 어느 탭에 있어도 현재
위치를 잃지 않는다. 한동안은 서브탭 없이 본문 링크 한 줄로만 닿았는데(발견성 하향), 두 화면이
같은 계열이라는 사실이 화면 어디에도 없어 서브탭으로 되돌렸다 — 사이드바 항목은 그대로 하나다.
탭 줄의 라벨·순서·목적지는 `vg_findings_subtab_labels()`/`vg_findings_subtabs()`,
`vg_compliance_subtab_labels()`/`vg_compliance_subtabs()` 한 곳이 정본이다 — 예전엔 세 화면이
각자 그려 개수(3 vs 5)와 라벨이 어긋났다.

**컨테이너 상세(`container.php`)도 사이드바에 없고 자산 상세의 컨테이너 탭에서만 들어온다.**
컨테이너는 호스트에 딸린 자산이라 자기 목록 화면을 갖지 않는다 — 어느 호스트의 어느 스캔인지가
정해져야 조회 단위가 성립한다(`tb_container` 의 자연키가 `(scan_id, cid)` 다). URL 도 그 자연키를
쓴다(`?id=<host_id>&cid=<컨테이너 cid>`) — 숫자 `container_id` 는 스캔마다 새로 발급돼 북마크가
다음 수집에서 깨진다. 인가는 자산 상세와 같은 `vg_require_menu_any('assets','findings')` 다.
SBOM(`sbom.php`)은 호스트·컨테이너 두 범위를 지원하되 **한 문서에 섞지 않으며**, 자산 상세와
컨테이너 상세 첫 화면에서 링크한다(예전엔 화면 링크가 하나도 없었다).

다이어그램: [`docs/specs/diagrams/사이트맵.puml`](../specs/diagrams/사이트맵.puml)

- **세션 인증**(`tb_user`) : 웹 화면 전부. 역할은 **`admin` / `operator` / `user`** 3단계.
  세션은 기본 **유휴 30분·절대 12시간**에 만료된다(관리 → 설정의 `session.idle_minutes`/
  `session.absolute_minutes`, 설정이 없으면 `src/auth.php` 의 동명 상수로 폴백). 만료되면 `session_expire` 감사로그를 남기고 `tb_user.session_token` 을 지운 뒤
  로그인 화면에 사유를 안내한다. 활성 세션은 계정당 1개라 다른 곳에서 로그인하면 앞의 세션이 끊긴다
  (`session_token` 을 덮어쓰는 것 자체가 무효화다).
- **설정형 RBAC**: `admin` 은 코드에서 항상 전체 허용(잠금 방지)이라 권한 행을 두지 않는다.
  `operator`·`user` 는 **역할 × 메뉴코드**(dashboard/assets/findings/advisories/compliance/
  connectors/catalog/users/agenttokens/activity/permissions/settings) 허용 여부를 `tb_role_permission`
  에 두고 `/permissions.php` 에서 켜고 끈다. 각 페이지 가드는 `vg_require_menu('<메뉴코드>')` 하나로 통일.
  메뉴코드 정본은 `vg_menus()`(`server/src/auth.php`) 이고 `nav.php` 의 `'perm'` 과 반드시 일치해야
  한다(어긋나면 사이드바에 보이는데 눌러보면 403 나는 링크가 생긴다). 단 **`permissions`·`settings`
  둘은 admin 전용이라 `/permissions.php` 매트릭스에서 제외**된다(`settings` 는 판정
  기준값을 바꾸는 화면이다) — 정본에는 남기되 화면에서 켤 수
  없고, 시드 행이 없어 `vg_can()` 의 기본 거부로 operator·user 는 항상 불가다.
  기본 시드 — operator: 대시보드/취약점/공지/자산/수집과 에이전트 키 허용, 사용자·권한·감사 로그 불가.
  user: 대시보드/취약점/공지만. `findings` 를 쪼갤 때 기존 배포본의 `findings` 허용값을
  `compliance`·`catalog` 에도 복제해(마이그레이션) operator·user 가 보던 화면을 잃지 않게 했다.
  **메뉴코드는 사이드바 링크와 1:1 이다.** 예전엔 `findings` 하나가 링크 6개(탐지 결과·컴플라이언스·
  카탈로그 4종)를 함께 열어서 "탐지 결과만 끄기"가 불가능했다 — `compliance`·`catalog` 로 쪼갰다
  (카탈로그 4종은 성격이 같아 한 코드를 공유한다). 사이드바에 없는 **상세 화면**은 두 섹션에서
  함께 열리므로(CVE 상세 ← 탐지 결과·CVE 카탈로그·보안 공지, 자산 상세 ← 자산·탐지 결과)
  `vg_require_menu_any('a','b')` 로 "하나라도 있으면 통과"를 쓴다 — 한 코드로 고정하면 반대편
  섹션만 가진 사용자가 방금 본 목록의 행을 눌렀는데 403 을 받는다.
- **토큰 인증**(사람 로그인과 분리):
  - 에이전트 → `ingest.php` : **호스트별 개별 토큰**(`X-Agent-Token`). `/agent-tokens.php` 에서
    호스트(fqdn)마다 발급하고, 토큰은 발급 시 정한 fqdn 만 갱신할 수 있다 — `ingest.php` 가
    바인딩을 강제해, 본문이 다른 호스트를 주장하면 **403 으로 거부**(침해된 대상 1대가 남의
    스캔을 위조·덮어쓰는 것을 차단). DB 엔 SHA-256 해시만 저장(원문 1회 표시), 폐기는 `is_revoked`.
    활성 토큰은 호스트당 하나(재발급 시 기존분 자동 폐기). 공유 수집 토큰은 허용하지 않는다.
  - **`export.php`·`sbom.php` 는 토큰을 쓰지 않는다.** 전용 읽기 토큰(`X-API-Token`)과 발급 화면
    (`/api-tokens.php`)·`tb_api_token` 은 2026-08-13 폐지했다 — 결과를 가져가는 외부 시스템이 DB 를
    직접 조회하기로 해서 유지할 이유가 없어졌다. 두 엔드포인트는 이제 **웹 로그인 세션**
    (`vg_require_menu('assets')`)으로 인증하고, 미로그인은 다른 화면과 같이 로그인으로 리다이렉트된다.
    감사로그(`export_data`/`export_sbom`)에는 토큰 대신 실제 사용자 ID 가 찍힌다.
    `sbom.php` 는
    `?host=` 또는 `?scan_id=` + `?format=cyclonedx|spdx` 로 자산 하나의 부품표를 CycloneDX 1.5 /
    SPDX 2.3 으로 내보낸다. purl 생성은 `src/purl.php`, serialNumber 는 스캔 기준 결정적 UUIDv5 라
    같은 스캔이면 문서가 항상 같다(매 호출 난수면 SBOM diff 가 성립하지 않는다). 열람은
    `export_sbom` 으로 감사로그에 남는다.
  - **에이전트 토큰은 유효기간을 갖는다**(`expires_at`). 발급 선택지는 무기한/30일/90일/1년이고
    **NULL = 무기한**이라 기존 발급분은 그대로 쓰인다(하위호환). 만료된 토큰은 검증 경로가 인증
    실패로 처리하고 `agent_token_expired` 감사로그를 남긴다. 어휘·판정의 SSOT 는
    `src/tokenexpiry.php` 하나다(둘로 흩어지면 조용히 어긋난다). 자동 갱신·자동 재발급은 두지
    않는다 — 만료되면 사람이 새로 발급한다. 대응 기준: ISMS-P 2.5.1 · N2SF AC-1(4).
- 최초 admin 은 `secrets/admin_password` 로 부트스트랩.
- **감사 로깅**: 로그인·커넥터 저장/삭제/실행·사용자 추가/삭제·ingest 수신이 `tb_activity_log` 에
  자동 기록된다(`server/src/audit.php` 의 `vg_log_activity()`, 각 페이지가 require 해서 호출).
  `/activity.php` 에서 scope 필터 + 페이지네이션으로 조회한다.
- **접속기록 5요소**(ISMS-P 2.9.4): 식별자·접속일시·접속지 IP·처리한 정보주체·수행업무를 각각
  독립 컬럼으로 갖는다. 앞의 셋은 원래 있었고, `subject`(처리 대상)와 `action`(수행업무 정규화
  동사 — READ/CREATE/UPDATE/DELETE/EXPORT/LOGIN/EXECUTE/OTHER, 어휘는 `vg_activity_action()`)만
  나중에 붙였다(일부가 `data` JSON 안에 묻혀 정렬·조회가 안 됐다). 이 제품은 개인정보를 처리하지
  않으므로 "처리한 정보주체" 자리에는 그 행위가 다룬 **대상 자원**(호스트 FQDN·CVE·패키지·계정)을 담는다.
- **소프트 삭제**: `vg_soft_delete()` 가 하드 DELETE 대신 `is_deleted/deleted_at` 를 세운다.
  화이트리스트 대상: `tb_user`/`tb_feed_connector`/`tb_advisory`/`tb_host`/`tb_scan`.
