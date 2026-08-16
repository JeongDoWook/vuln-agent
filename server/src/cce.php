<?php
declare(strict_types=1);

/**
 * cce.php — 보안설정 점검(CCE)의 **진입점**. 에이전트가 이미 수집한 security/users 섹션을
 *   서버에서 판정해 tb_cce_finding 에 저장한다. (CVE=취약한 버전, CCE=잘못된 설정)
 *
 *   신규 수집 없음 — vuln-inventory-agent.sh 의 12)보안자세 · 13)사용자/인증 섹션을 재활용.
 *   각 점검은 [코드, 제목, 결과(PASS/FAIL/NA), 위험도, 근거값, 판정사유] 를 남긴다(설명가능성).
 *   수집값이 없으면(비-root 실행 등) NA — 통과로 위장하지 않고 "미점검"을 드러낸다.
 *
 *   **경계는 쓰임새(웹/ingest/테스트)가 아니라 점검 도메인이다.** 부르는 쪽이 어느 파일을
 *   읽을지 고르기 시작하면 판정 경로가 갈라지므로 진입점은 이 파일 하나로 유지한다.
 *
 *     cce/parse.php       수집 원자료 파서 + 판정 임계값(판정은 하지 않는다)
 *     cce/checks.php      점검 39종을 도메인 파일에 나눠 부르고 순서대로 잇는다
 *     cce/checks/*.php    ssh · accounts · system · timelog · crypto
 *     cce/catalog.php     점검 목록 + SSG 룰 매핑(빈 칸은 의도된 상태 — 채우지 않는다)
 *     cce/store.php       tb_cce_finding 적재
 */

require_once __DIR__ . '/db.php';

// 중복 로드 가드 — ingest.php 등이 require(once 아님)로 읽는 경로가 있어 남긴다.
//   상수 define() 은 require_once 로 막히지 않으므로 이 가드가 실제로 필요하다.
if (!function_exists('vg_sshd_val')) {
    require_once __DIR__ . '/cce/parse.php';
    require_once __DIR__ . '/cce/checks.php';
    require_once __DIR__ . '/cce/catalog.php';
    require_once __DIR__ . '/cce/store.php';
}
