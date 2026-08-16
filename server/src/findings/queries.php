<?php
declare(strict_types=1);

/**
 * findings/queries.php — 탐지 결과 화면의 조회층. **탭마다 함수 하나**다.
 *
 *   ⚠ 세 탭을 한 함수로 "통합" 하지 마라. 세 표(tb_finding·tb_cce_finding·tb_exposure)를
 *   UNION 하면 큰 tb_finding 을 섞어 정렬·페이징하게 되어 인덱스가 죽는다 — 대시보드에서
 *   파생테이블로 리라이트했다가 **235ms → 42초**가 된 운영 실측이 있다(PR #555). 탭마다
 *   자기 쿼리 하나가 정답이고, 그래서 이 파일의 함수도 탭 수만큼이다.
 *
 *   각 함수는 findings.php 가 이미 검증한 값(화이트리스트를 통과한 필터·대상 스캔 집합)만
 *   받는다. SQL·바인딩 순서·정렬은 findings.php 에 있던 것을 그대로 옮긴 것이다.
 *
 *   "탭마다 쿼리 하나" 라는 규칙을 **파일 경계로도** 굳혔다 — 탭 하나의 조회가 파일 하나다
 *   (렌더 쪽 findings/tabs/ 와 같은 축). 이 파일은 진입점만 남고, 호출부(findings.php)는
 *   예전처럼 이 파일만 require 하면 된다.
 */

require_once __DIR__ . '/queries/common.php';    // 대상 스캔 집합(호스트·컨테이너) · 탭 머리 건수
require_once __DIR__ . '/queries/cve.php';       // CVE 탭 — 등급 KPI · 행동 큐 · 목록
require_once __DIR__ . '/queries/cce.php';       // 보안설정(CCE) 탭 — 결과 분포 · 목록
require_once __DIR__ . '/queries/exposure.php';  // 노출 탭 — 범위 분포 · 목록 · 행별 CVE 건수
