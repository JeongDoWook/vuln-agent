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

require_once __DIR__ . '/../format.php';           // vg_dash_section_head() 의 vg_h()
require_once __DIR__ . '/../view/icons.php';       // vg_dash_section_head() 의 vg_icon()
                                                   //   ↑ 둘 다 index.php 의 우연한 로드 순서에 기대지 않는다(funnel.php 가 같은 이유로 고쳐졌다)
require_once __DIR__ . '/sections/rank.php';       // 자산 순위 막대 — 상단 왼쪽
require_once __DIR__ . '/sections/waterfall.php';  // 처리 흐름(사유를 남기는 워터폴 5칸) — 상단 오른쪽
require_once __DIR__ . '/sections/signals.php';    // 구성 도넛 두 장(등급 · 노출·실행) — 카드도 둘이다
require_once __DIR__ . '/sections/trend.php';      // 최근 N일 High 이상 추세 — 도넛 옆 넓은 칸
require_once __DIR__ . '/sections/hosts.php';      // 호스트별 현황 목록 + 페이지네이션(페이저가 화면을 닫는다)

/**
 * 위젯 묶음의 머리. **장식이 아니라 구분이다** — 카드가 여러 장이면 어디까지가 한 묶음인지
 * 경계가 안 보인다(사용자 지적: "칸마다 딱 구분해서 보기 좋은데, 우린 좀 붙어 있고 쭉 나열된 느낌").
 *
 * 카드 제목(--fs-lg + strong)보다 한 단 물러난 라벨로 둔다 — 머리가 카드보다 강하면 묶음이
 * 아니라 제목들의 나열이 된다. **묶음마다 달지 않는다**: 머리 하나가 세로 40px 안팎을 먹어서
 * 넷을 달면 이 작업이 줄이려는 세로 길이를 도로 까먹는다(이 화면은 둘이다).
 *
 * $icon 은 icons.php 세트의 이름이다 — 여기서 새 아이콘을 만들지 않는다(모르는 이름이면 안 그린다).
 */
function vg_dash_section_head(string $title, string $icon = ''): void {
    echo '<h2 class="dash-head">' . ($icon !== '' ? vg_icon($icon) : '') . vg_h($title) . '</h2>';
}
