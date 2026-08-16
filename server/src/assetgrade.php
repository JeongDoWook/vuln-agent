<?php
declare(strict_types=1);

/**
 * assetgrade.php — 자산 중요도·N2SF 보안등급(C/S/O)의 어휘와 **초안 제안 규칙**.
 *
 * 이 파일이 지키는 경계는 하나다 — **판정은 사람이, 초안은 시스템이.**
 *   등급 판정 기준은 「정보공개법」 제9조 비공개 대상정보의 호 매핑이고, 업무정보 등급 확정은
 *   기관의 법적 처분이라 시스템이 대신할 수 없다. 그래서 이 파일의 제안 함수는
 *   tb_host.grade(확정값)를 **절대 쓰지 않는다** — grade_suggested/grade_suggested_reason
 *   에만 쓴다. 확정은 사람이 고른 값으로만 하고, 그 처리는 vg_asset_grade_confirm() 한 곳이
 *   맡는다 — 호스트 상세(host.php)와 자산 목록의 일괄 확정(assets.php)이 같은 함수를 쓴다.
 *
 * 규칙의 근거는 원문이 직접 준 두 줄뿐이다(억지 제안 금지 — 확신이 없으면 아무것도 제안하지 않는다):
 *   · "기타: 로그 및 임시백업 등"이 명시적 S  → 로그 수신·백업 처리 역할이면 S 후보
 *   · 외부에 열린 자산                        → O 영역 후보
 * 「개인정보 패턴 탐지 → S」는 이 제품이 개인정보를 수집하지 않으므로 구현 대상이 아니다.
 *
 * 속은 책임별로 assetgrade/ 아래에 나눠 두었다 — 이 파일은 **진입점(파사드)**이다.
 *   부르는 쪽은 예전처럼 이 파일 하나만 require 하면 된다.
 *     vocab.php       어휘(C/S/O·상중하)·보호수준 순위·최고등급 승계·범례·뱃지
 *     signal_defs.php 무엇을 신호로 칠지의 정의 + 근거 문자열·프로세스 목록 헬퍼
 *     signals.php     한 스캔에서 신호를 모으는 조회층
 *     suggest.php     모은 신호로 초안 등급을 판정(C 자동 제안 없음)
 *     confirm.php     사람의 판정을 쓰는 **유일한** 확정 경로(감사로그 포함)
 */

require_once __DIR__ . '/assetgrade/vocab.php';
require_once __DIR__ . '/assetgrade/signal_defs.php';
require_once __DIR__ . '/assetgrade/signals.php';
require_once __DIR__ . '/assetgrade/suggest.php';
require_once __DIR__ . '/assetgrade/confirm.php';
