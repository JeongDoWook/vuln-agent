<?php
declare(strict_types=1);

/**
 * icons.php — 인라인 SVG 아이콘 데이터. **데이터만** 둔다(SRP: 컴포넌트 로직은 components.php).
 *
 * 왜 인라인인가: CSP 가 `default-src 'self'` 라 아이콘 폰트·외부 스프라이트를 못 쓴다(오프라인
 * 배포 전제이기도 하다). 이모지도 안 쓴다 — 환경에 따라 컬러 이모지 폰트로 렌더돼
 * currentColor 를 안 따라가고, 한글 폰트 환경에서 광학 크기·베이스라인이 제각각이라
 * 나란히 놓으면 줄이 안 맞는다(vg_signal_icon() 주석의 ⚡ 사고와 같은 이유).
 *
 * 규약: viewBox 0 0 24 24 · fill=none · stroke=currentColor · stroke-width 고정(1.9) ·
 *       aria-hidden="true". 색은 부모에서 상속하므로 라이트/다크가 자동으로 따라온다.
 *       크기는 CSS(.vg-ico)가 정한다 — 호출부가 픽셀을 정하지 않는다.
 *
 * 세트는 실제 쓸 것만 둔다(YAGNI). 늘릴 때는 여기 배열에 한 줄만 더한다.
 */

/** 아이콘 이름 → SVG 내부 path 마크업. 모양의 뜻을 주석으로 붙여 둔다(장식이 아니라 표시다). */
const VG_ICON_PATHS = [
    // 자산 — 랙 마운트 두 단
    'host'      => '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><line x1="7" y1="7.5" x2="7.01" y2="7.5"/><line x1="7" y1="16.5" x2="7.01" y2="16.5"/>',
    // 컨테이너 — 닫힌 상자(모서리가 보이는 정육면체)
    'container' => '<path d="M21 16V8l-9-5-9 5v8l9 5 9-5z"/><polyline points="3.3 7.5 12 12.5 20.7 7.5"/><line x1="12" y1="12.5" x2="12" y2="21.5"/>',
    // 패키지 — 겹쳐 쌓인 층(부품표)
    'package'   => '<polygon points="12 2.5 2.5 7 12 11.5 21.5 7 12 2.5"/><polyline points="2.5 12 12 16.5 21.5 12"/><polyline points="2.5 16.5 12 21 21.5 16.5"/>',
    // 취약점 — 벌레(CVE)
    'cve'       => '<rect x="8" y="6" width="8" height="12" rx="4"/><line x1="3" y1="12" x2="8" y2="12"/><line x1="16" y1="12" x2="21" y2="12"/><line x1="5" y1="7" x2="8.5" y2="9"/><line x1="19" y1="7" x2="15.5" y2="9"/><line x1="5" y1="17" x2="8.5" y2="15"/><line x1="19" y1="17" x2="15.5" y2="15"/>',
    // 피드 — 바깥에서 흘러 들어오는 신호
    'feed'      => '<path d="M4.5 11.5a8 8 0 0 1 8 8"/><path d="M4.5 4.5a15 15 0 0 1 15 15"/><circle cx="5.2" cy="18.8" r="1.6"/>',
    // 판정·보호 — 방패
    'shield'    => '<path d="M12 2.5 4.5 5.8v5.5c0 4.6 3.2 8.9 7.5 10.2 4.3-1.3 7.5-5.6 7.5-10.2V5.8L12 2.5z"/>',
    // 실행중 프로세스 — CPU
    'process'   => '<rect x="6.5" y="6.5" width="11" height="11" rx="2"/><rect x="10" y="10" width="4" height="4"/><line x1="9" y1="2.5" x2="9" y2="6.5"/><line x1="15" y1="2.5" x2="15" y2="6.5"/><line x1="9" y1="17.5" x2="9" y2="21.5"/><line x1="15" y1="17.5" x2="15" y2="21.5"/><line x1="2.5" y1="9" x2="6.5" y2="9"/><line x1="2.5" y1="15" x2="6.5" y2="15"/><line x1="17.5" y1="9" x2="21.5" y2="9"/><line x1="17.5" y1="15" x2="21.5" y2="15"/>',
    // 포트·노출 — 바깥으로 뻗은 연결
    'port'      => '<circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="19" cy="18" r="2.5"/><line x1="7.4" y1="11" x2="16.6" y2="7"/><line x1="7.4" y1="13" x2="16.6" y2="17"/>',
    // 시각·주기 — 시계
    'clock'     => '<circle cx="12" cy="12" r="9"/><polyline points="12 6.5 12 12 16 14"/>',
    // 통과·완료
    'check'     => '<polyline points="4 12.5 9.5 18 20 6.5"/>',
    // 경고 — 사이드바 "탐지 결과"·vg_signal_icon('severity') 와 같은 삼각형(같은 뜻은 같은 모양)
    'warn'      => '<path d="m10.29 3.86-8.4 14.55A2 2 0 0 0 3.62 21h16.76a2 2 0 0 0 1.73-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    // 차단·해당 없음
    'block'     => '<circle cx="12" cy="12" r="9"/><line x1="5.6" y1="5.6" x2="18.4" y2="18.4"/>',
    // 다음 단계로
    'arrow'     => '<polyline points="9 5 16 12 9 19"/>',
    // 찾기 — 검색 결과가 없는 빈 상태(툴바 검색창 배경 SVG 와 같은 모양)
    'search'    => '<circle cx="11" cy="11" r="7"/><line x1="16.2" y1="16.2" x2="21" y2="21"/>',
    // 추이·순위 — 그릴 데이터가 모자란 빈 상태
    'chart'     => '<polyline points="3 20 3 4"/><polyline points="3 20 21 20"/><polyline points="6.5 15.5 11 10.5 14.5 13.5 19.5 7"/>',
    // 발급된 키(에이전트 토큰)
    'key'       => '<circle cx="8" cy="12" r="4"/><line x1="12" y1="12" x2="21" y2="12"/><line x1="18" y1="12" x2="18" y2="15.5"/><line x1="21" y1="12" x2="21" y2="16.5"/>',
    // 사람 — 사용자·계정
    'user'      => '<circle cx="12" cy="8" r="3.5"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/>',
];

/**
 * 이름으로 인라인 SVG 아이콘 마크업을 얻는다. 정적 마크업이라 이스케이프 없이 그대로 쓴다.
 * 모르는 이름이면 빈 동그라미 — 화면이 깨지는 대신 "자리는 있는데 뜻이 없다"로 보이게 한다.
 */
function vg_icon(string $name): string {
    $p = VG_ICON_PATHS[$name] ?? '<circle cx="12" cy="12" r="9"/>';
    return '<svg class="vg-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        . ' stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        . $p . '</svg>';
}
