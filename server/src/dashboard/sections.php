<?php
declare(strict_types=1);

/**
 * dashboard/sections.php — 대시보드 섹션 렌더의 진입점. **섹션 하나가 파일 하나**다.
 *
 *   자산 상세(host/tabs.php)와 달리 여기서는 활성 섹션을 고르지 않는다 — 대시보드는 한 화면에
 *   모든 섹션이 함께 서는 구조라(탭이 없다) 전부 읽는다. 나눈 이유는 지연 로딩이 아니라
 *   "이 화면이 무엇으로 이뤄져 있나"를 파일 이름으로 읽히게 하려는 것이다.
 *
 *   각 렌더 함수는 조회를 하지 않는다 — 쓰는 값은 index.php 가 인자로 넘긴 것뿐이다
 *   (섹션이 자기 숫자를 다시 세면 같은 화면 안에서 값이 갈린다).
 */

require_once __DIR__ . '/sections/funnel.php';     // 좁혀지는 퍼널 4칸
require_once __DIR__ . '/sections/next_feed.php';  // 다음 수집 예정 한 줄
require_once __DIR__ . '/sections/trend.php';      // 최근 N일 High 이상 추세
require_once __DIR__ . '/sections/signals.php';    // 주요 취약점 신호(KEV·노출·심각도 순)
require_once __DIR__ . '/sections/severity.php';   // 등급별 분포(증감·도넛) — 접힘
require_once __DIR__ . '/sections/hosts.php';      // 호스트별 현황 목록 + 페이지네이션
