<?php
declare(strict_types=1);

/**
 * compliance.php — KISA ISMS-P / ISO 27001 통제 자동판정 로직(웹·CLI 공용)의 **진입점**.
 *   원래 server/public/compliance.php 안에 있던 판정 함수들을 그대로 옮겨 온 파일이고,
 *   지금은 그 안을 다시 책임 단위(server/src/compliance/)로 갈라 여기서 묶어 읽는다.
 *   웹 화면(public/compliance.php)은 이 파일을 읽어 "지금" 을 렌더하고,
 *   스케줄러(bin/scheduler.php)는 같은 함수로 하루 1건 스냅샷을 적재한다 —
 *   판정 로직이 두 벌이면 화면과 증적이 서로 다른 답을 내기 시작한다(DRY).
 *
 *   **경계는 쓰임새(웹/CLI)가 아니라 도메인(통제 항목)이다.** 웹용·스냅샷용으로 가르면
 *   두 벌이 조금씩 다른 집계를 갖게 된다 — 그래서 통제 하나가 파일 하나이고, 웹도 CLI 도
 *   같은 파일의 같은 함수를 부른다. 진입점을 이 파일 하나로 유지하는 이유도 같다:
 *   부르는 쪽이 어느 파일을 읽을지 고르기 시작하면 그 순간 경로가 갈라진다.
 *
 *     compliance/policy.php     판정 기준값·판정 어휘·통제 목록(SSOT)
 *     compliance/patch.php      통제 1 패치관리
 *     compliance/asset.php      통제 2 정보자산 식별
 *     compliance/secconfig.php  통제 3 보안시스템 운영
 *     compliance/account.php    통제 4 계정 관리
 *     compliance/snapshot.php   판정 결과 저장·추이 조회(판정하지 않는다)
 *
 *   ※ 이 파일은 CLI 에서도 로드된다. 세션·인가(vg_require_menu)·출력은 여기 두지 않는다.
 */

require_once __DIR__ . '/compliance/policy.php';
require_once __DIR__ . '/compliance/patch.php';
require_once __DIR__ . '/compliance/asset.php';
require_once __DIR__ . '/compliance/secconfig.php';
require_once __DIR__ . '/compliance/account.php';
require_once __DIR__ . '/compliance/snapshot.php';
