# 정리 증거 (#599)

기준 시점은 2026-08-15, W4 시작 커밋은 `6f318b3`이다. 수정 전 대상 10개 경로를
`codelore.context_for_change(project="vuln-agent")`로 조회하고, 기존 파일 9개에는 각각
`codelore.history`도 조회했다. 새 문서 경로는 당시 저장소에 없어 미탐으로 기록됐다.

## W4 확정 데드코드

저장소 전체 `rg`로 함수명·설정명·생성 class를 검색하고 동적 호출 문자열도 같은 검색에
포함했다. 다음 항목은 정의와 전용 스타일 외 소비자가 없었다.

| 제거 항목 | 제거 전 참조 증거 | 보존한 경계 |
|---|---|---|
| `vg_info_icon()` / `.info-icon` | 함수 정의와 전용 CSS만 존재 | 실제 `.help` tooltip 스타일 |
| `vg_stacked_bar()` | 함수 정의와 `.riskbar--lg`만 존재 | 기본 `.riskbar`; `host.php`가 직접 쓰는 `.legend--inline` |
| `vg_gauge()` / `vg_sparkline()` | 각 함수가 생성하는 class와 전용 CSS만 존재 | 사용 중인 rank/trend/donut 차트 |
| `vg_ui_dashboard_actionable_statuses()` / 설정 | 정의, 단위 테스트, 설정 문서만 존재; 런타임 호출 없음 | `UI_DASHBOARD_URGENT_LIMIT` 등 사용 중인 설정 |
| `.page--api-tokens` | 삭제된 `/api-tokens.php` 전용 selector만 존재 | `/agent-tokens.php` 너비 규칙 |
| connectors의 `form` 지역 변수 | `vgGenericCollect()`에서 선언 뒤 읽지 않음 | init/submit에서 사용하는 별도 `form` 변수 |
| `refresh(schedule)` 인자 | 함수 본문에서 읽지 않고 모든 호출이 `true` 전달 | 갱신 주기와 close/open 동작 |
| `host.php` 상수 설명 주석 | 설명 뒤 상수가 사라지고 빈 줄만 존재 | 살아 있는 preview 상수와 탭 조회 설명 |

`tests/dead_code_contract_test.php`가 폐기 식별자와 전용 selector의 재등장, 공용 CSS의
실수 삭제를 함께 검사한다. 코드 rollback은 이 커밋 revert이며 DB 변경은 없다.

## W4 인덱스 보류

아래 후보는 live DB/Docker 증거를 사용할 수 없어 수정하지 않았다. 이는 고유성·정렬,
실제 query 사용, 전후 EXPLAIN/성능, rollback DDL을 모두 요구하는 HC-04에 따른 것이다.

| 후보 | 빠진 증거 / 재검토 조건 |
|---|---|
| `tb_control_mapping.idx_control_mapping_rule` | SHOW INDEX·information_schema, query digest, 전후 EXPLAIN/시간, disposable rollback rehearsal |
| `tb_package_summary.idx_psum_cve` | 동일 |
| `tb_package_summary.idx_psum_epss` | 동일 |

## W5 보류 목록

모든 후보의 owner는 후속 W5 운영 관측 작업이다. 성공한 피드 동기화·자산 스캔·주요
UI/보고서 실행을 포함한 관측 기간과 access/query evidence, rollback이 갖춰질 때 재검토한다.

| 후보 | 현재 근거와 부족한 증거 |
|---|---|
| `idx_fe_source`, `idx_collection_status`, `idx_asset_grade_review_next` | query digest와 비파괴 invisible/EXPLAIN, 성능·rollback 없음 |
| `language-packages.php`, `control_mapping.php` 호환 경로 | W0 registry가 `legacy_bookmark` 소비자를 기록; 소비 부재 access log 없음 |
| `styleguide.php` | W0 registry의 외부 소비자가 `unknown`; access log 없음 |
| `server/bin/backfill_{nvd,kisa,kisa_content}.php` | 문서와 화면에 수동 운영 경로로 남아 있음; 실행 이력·대체 절차 없음 |
| agent cron fallback / `deploy/agent_schedule.sh` | 설치기·문서·테스트가 cron 노드를 지원; fleet에 cron 노드가 없다는 관측 없음 |
| `function_exists` guards | 지원 PHP/runtime·bootstrap 조합별 실행 증거와 외부 include 소비자 확인 없음 |

따라서 W5 코드 삭제, DB table/column drop, migration 변경은 모두 0건이다.

## 2026-08-16 데드코드·DB 감사

`db/` 의 `CREATE TABLE` 을 훑으면 테이블 이름이 61종이고 그중 29종이 `server/`·`tests/` 어디서도
문자열로 안 나온다 — 이 29종이 이번 감사의 출발 후보였다. **판정의 유일한 근거는 실제 DB** 다.
공용 dev DB(`vulnagent-db-dev`)의 `information_schema` 를 읽어 대조했고, 스키마는 저장소
마이그레이션 97개가 전부 적용된 상태였다(미적용 0건).

**결론부터: 29종 중 실재하는 것은 0개다.** dev DB 의 테이블 55개는 전부 단수형이며 코드 참조도
전부 1건 이상이다. 즉 이 목록은 "미사용 테이블"이 아니라 **이미 정리가 끝난 이름의 잔상**이다.

### 3분류 판정표

| 분류 | 테이블 | 실제 DB | 조치 |
|---|---|---|---|
| **① 옛 이름(단수형으로 대체됨)** | `tb_advisories` `tb_advisory_cves` `tb_agent_replay_nonces` `tb_agent_tokens` `tb_cce_findings` `tb_collection_stages` `tb_compliance_rules` `tb_containers` `tb_cve_affected_packages` `tb_cves` `tb_exposures` `tb_feed_collection_logs` `tb_feed_connectors` `tb_findings` `tb_kernel_cve_fixes` `tb_packages` `tb_pkg_changelog_cves` `tb_pkg_changes` `tb_processes` `tb_role_permissions` `tb_stale_libs` `tb_users` (22종) | 없음 — 단수 대체본이 살아 있고 쓰인다 | **건드리지 않는다.** 최상위 `db/*.sql` 은 빈 볼륨 initdb 전용이라 옛 이름이 남아 있는 게 정상이다(`20260726115611_pk_naming_unification.sql` 이 initdb 직후 개명한다) |
| **② 이미 지워진 것** | `tb_cves_summary_ko_bak` `tb_kev_note_ko_bak` (20260726110105) · `tb_saved_views` (20260727104951) · `tb_remediation_cases` `tb_sla_policies` (20260730120000) · `tb_host_ext_ports` (20260730173000) (6종) | 없음 | **조치 불필요.** 앞선 마이그레이션이 이미 DROP 했다 |
| ②' 작업 임시 테이블 | `tb_package_dependency_new` (1종) | 없음 | **조치 불필요.** `20260809005223_pkgdep_edge_key_fix.sql` 이 만들고 같은 파일이 `RENAME` 으로 소비한다 |
| **③ 진짜 미사용** | `tb_activity_review` (후보 목록 밖 — 실측으로 새로 찾음) | **있음, 0행** | `20260816002646_drop_dead_tables.sql` 로 DROP |

`tb_sla_policies` 는 `server/src/finding_sla.php` 가 있어 단수 대체본을 의심했으나, 그 파일은
조치 기한을 `tb_setting` 의 정책값으로 계산하며 SLA 테이블을 읽지 않는다. 대체본 없이 기능이
설정 기반으로 재구현된 사례다.

### ③ 의 근거 — `tb_activity_review`

접속기록 "월 1회 점검" 기능과 함께 폐기됐고 `20260813001657_drop_activity_review.sql` 이 이미
DROP 했다(dev 적용 시각 2026-08-13 00:21:38). 그런데 실측하니 **생성시각 00:46:16 으로 다시
있었다**(0행). 적용 이력에 없는 경로로 되살아난 dev 잔재다. `migrate.sh` 는 적용된 파일을 다시
돌리지 않으므로 새 파일이 필요하다. 운영엔 이미 없어 무동작이며, 읽고 쓰는 코드는 저장소에
없다(`server/src/compliance.php` 주석 1줄, `tests/documentation_consistency_test.php` 의
"폐기됨" 단언이 전부). 열린 PR 0건, 원격 브랜치 3개 모두 이 테이블을 쓰지 않음을 확인했다.

### 미사용 컬럼 — 0건

dev DB 의 컬럼 626개(`tb_schema_migrations` 제외)를 `server/`·`tests/`·`agent/` 전문(全文)과
대조했다. 코드에 한 번도 안 나오는 컬럼은 25개였고, 전수 확인 결과 **전부 오탐**이다.

- 24개는 `<엔티티>_id` 형태의 **대리키(AUTO_INCREMENT PK)** 다(`cve_affected_package_id`,
  `vendor_errata_id` …). 애플리케이션이 이름으로 부르지 않을 뿐 구조상 필수다 — PK 명명규칙
  통일(#336)이 만든 정상 결과.
- 1개는 `tb_package_dependency.edge_hash` 로, `UNIQUE KEY uk_pkg_dep_edge` 가 쓰는
  **생성 컬럼(STORED)** 이다. 지우면 유니크 제약이 깨진다.
- `tb_activity_review` 의 컬럼 4개는 테이블째 DROP 되므로 별도 항목으로 세지 않았다.

DROP 한 컬럼은 없다. 컬럼이 남아 있는 것은 무해하므로 확신이 안 서는 것은 남기는 쪽을 택했다.

### 죽은 PHP 코드 — 0건

- **함수**: `server/src`·`server/public` 에 정의된 `vg_*` 함수 441개 전부에 대해, 정의 줄을 뺀
  호출부와 문자열 참조(동적 호출)를 `server/`·`tests/`·`agent/`·`deploy/` 전문에서 셌다.
  호출 0건은 **0개**였다. 2026-08-15 의 W4 정리(#599)가 이 층을 이미 걷어낸 상태다.
- **파일**: `server/src/*.php` 중 다른 파일에서 한 번도 언급되지 않는 것은 **없다**.
  최소 참조는 `asset_grade_review.php`·`finding_evidence.php`·`purl.php` 의 2건이며 셋 다
  실제 소비자(화면 또는 테스트)가 있다.

### 지우지 않고 남긴 것

| 남긴 것 | 이유 |
|---|---|
| 최상위 `db/*.sql` 의 복수형 테이블 22종 | initdb 전용 파일이다. 빈 볼륨에서 이 파일들이 만든 뒤 `20260726115611` 이 단수로 개명한다. 여기를 고치면 신규 설치가 깨진다 |
| 이미 DROP 된 6종 + 임시 테이블 1종을 언급하는 옛 마이그레이션 | 마이그레이션 파일은 적용 이력이지 현재 스키마가 아니다. 수정 금지 |
| 대리키 컬럼 24개 · `edge_hash` | 코드가 이름으로 안 부를 뿐 구조상 필수 |
| `server/bin/backfill_*.php` 등 W5 보류 목록 | 위 "W5 보류 목록" 절의 조건(운영 관측·access log)이 아직 안 갖춰졌다. 이번 감사도 그 조건을 바꾸지 못한다 |

**다음 사람에게**: 위 22종을 "코드에서 안 쓰이니 지우자"로 다시 집어들지 말 것. 코드 grep 만으로는
매번 같은 결론이 나온다 — 판별은 반드시 실제 DB(`information_schema`)와 대조해야 한다.
