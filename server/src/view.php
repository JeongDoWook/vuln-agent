<?php
declare(strict_types=1);

/**
 * view.php — 렌더 헬퍼 aggregator. 21개 페이지가 전부 이 파일을 require 하므로,
 *   실제 구현은 server/src/view/ 아래 4개 파일로 나뉘어 있고 이 파일은 그걸 순서대로
 *   불러오기만 한다(호출부의 require 경로를 하나도 안 바꾸기 위함):
 *     - view/charts.php     — 차트(SVG): 심각도 도넛·리소스 추이·가로 막대.
 *     - view/nav.php        — 네비게이션: 사이드바·브레드크럼·활동로그 라벨.
 *     - view/components.php — 위젯: 모달·히어로·서브탭·빈상태·알림·테이블·툴바·페이지네이션.
 *     - view/layout.php     — 레이아웃: 페이지 골격(head/body/사이드바 뼈대).
 *   vg_h() 이스케이프, vg_header($title,$active) 로 시작, vg_footer() 로 끝난다.
 *   스타일·스크립트는 public/assets/app.{css,js} 가 소유한다. 여기에 색상을 하드코딩하지 않는다.
 *   순수 포맷 함수(뱃지·EPSS/리소스 셀·vg_trunc 등, side-effect 없음)는 format.php 에 있다.
 */

require_once __DIR__ . '/format.php';
require_once __DIR__ . '/view/charts.php';
require_once __DIR__ . '/view/nav.php';
require_once __DIR__ . '/view/components.php';
require_once __DIR__ . '/view/layout.php';
