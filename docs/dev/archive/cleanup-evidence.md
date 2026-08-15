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
