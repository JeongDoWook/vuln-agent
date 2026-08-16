<?php
declare(strict_types=1);

/**
 * format.php — 순수 포맷/변환 헬퍼. 입력값 → 이스케이프된 문자열(또는 배열), side-effect 없음.
 *   echo 하지 않는다 — DB·세션·파일시스템에 안 닿는다. 그래서 서버 없이 단위테스트가 가능하다.
 *   레이아웃·테이블 렌더(echo 하는 것들)는 view.php 에 남는다. view.php 가 이 파일을 require 한다.
 *
 *   함수 자체는 **주제별로** server/src/format/ 아래에 나눠 뒀다(아래 require 블록). 이 파일은
 *   진입점만 남는다 — 저장소 전역의 호출부(화면 수십 개)는 예전처럼 이 파일만 require 하면 된다.
 *   나눈 축: 문자열 → 톤 프리미티브 → 어휘(심각도·상태) → 판정(자산상태) → 수치 → 링크.
 *   서로 부르는 방향은 한쪽뿐이다(위가 아래를 모른다) — 그래서 순환이 없다.
 */

require_once __DIR__ . '/format/text.php';        // vg_h · 말줄임 · 도움말 (아래 전부가 vg_h 위에 선다)
require_once __DIR__ . '/format/badge.php';       // 톤 프리미티브 — 뱃지 · 게이지 마크업
require_once __DIR__ . '/format/severity.php';    // 심각도 어휘 · CVSS 점수구간 · 벡터 해독 · 등급막대
require_once __DIR__ . '/format/labels.php';      // 코드값 → 한글 어휘(런타임·조치·노출범위·무결성·수집단계)
require_once __DIR__ . '/format/asset_state.php'; // 자산 연결 상태 — PHP 판정 + 같은 임계값의 SQL CASE 식
require_once __DIR__ . '/format/metrics.php';     // 수치 셀 — EPSS · 에이전트 자기계측(메모리·CPU·사용률)
require_once __DIR__ . '/format/links.php';       // 참조 URL 안전성 · 조치 열 · 벤더 공식 페이지
