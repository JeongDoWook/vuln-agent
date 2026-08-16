<?php
declare(strict_types=1);

/**
 * components.php — 페이지가 공유하는 위젯 컴포넌트의 진입점. 실제 구현은 view/components/
 *   아래 7개 파일에 책임별로 나뉘어 있고, 이 파일은 그걸 불러오기만 한다(호출부·require
 *   경로를 하나도 바꾸지 않기 위함 — nav.php·charts.php·layout.php·view.php 가 이 경로를 쓴다):
 *     - components/prop.php   — 소품: 출력 캡처·내부 링크 검증·복사 버튼·SBOM 줄·수집 CTA
 *     - components/page.php   — 페이지 뼈대: 제목·결론 배너·히어로·섹션 탭
 *     - components/modal.php  — 모달: 여는 버튼·<dialog>·공용 확인창
 *     - components/notice.php — 알림·플래시·빈 상태
 *     - components/paging.php — 목록의 URL 상태: 쿼리스트링·페이지·페이지당 개수·페이저
 *     - components/table.php  — 목록 렌더: 카드+테이블·검색 툴바
 *     - components/signal.php — 지표·시각 설명: KPI·판단 신호·흐름 도식·범례·판단 순서
 *   각 파일은 자기가 쓰는 것(format.php·ui_config.php·icons.php·서로)을 스스로 require 한다 —
 *   로드 순서에 얹혀 동작하지 않게(#271 에서 한 번 겪은 문제).
 */

require_once __DIR__ . '/../format.php';
require_once __DIR__ . '/../ui_config.php';
require_once __DIR__ . '/icons.php';

require_once __DIR__ . '/components/prop.php';
require_once __DIR__ . '/components/page.php';
require_once __DIR__ . '/components/modal.php';
require_once __DIR__ . '/components/notice.php';
require_once __DIR__ . '/components/paging.php';
require_once __DIR__ . '/components/table.php';
require_once __DIR__ . '/components/signal.php';
