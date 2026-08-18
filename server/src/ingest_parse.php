<?php
declare(strict_types=1);

/**
 * ingest_parse.php — ingest.php 가 받는 에이전트 원시 페이로드를 정규화된 배열로
 *   바꾸는 **순수 함수만** 모은다. DB·인증·감사로그는 여기 없다(ingest.php 에 남는다).
 *   모든 함수는 같은 입력엔 같은 출력을 내고 부작용이 없다 — tests/ingest_parse_test.php 참고.
 *
 *   파서는 **수집 스트림 단위**로 server/src/ingest/ 아래에 나눠 뒀다(아래 require 블록).
 *   이 파일에는 어느 스트림에도 속하지 않는 스칼라 변환 하나만 남는다.
 *   호출부(ingest.php·tests/ingest_parse_test.php)는 예전처럼 이 파일만 require 하면 된다.
 */

require_once __DIR__ . '/vercmp.php';       // vg_ver_cmp — vg_ingest_parse_kernel 에서 커널 버전 비교용
require_once __DIR__ . '/license_risk.php'; // vg_license_normalize_token — pkg_license 정규화

// 수집 스트림별 파서(순수 이동 — 함수 이름·시그니처·본문 불변).
//   서로를 부르지 않는다(vg_pkg_ident_valid 만 ingest/sbom.php 안에서 자기 파일 안으로 쓰인다) —
//   그래서 require 순서에 의존하지 않는다. 위 두 공용 라이브러리만 먼저 오면 된다.
require_once __DIR__ . '/ingest/packages.php';        // 설치 패키지 · 출처 · 언어 패키지 · 라이선스
require_once __DIR__ . '/ingest/runtime.php';         // 노출 · 프로세스 · 재시작 필요 · 무결성
require_once __DIR__ . '/ingest/vendor_evidence.php'; // changelog · errata · debsecan (억제 근거의 원재료)
require_once __DIR__ . '/ingest/container.php';       // 컨테이너 목록 · 내부 패키지 · 프로세스 · 노출
require_once __DIR__ . '/ingest/sbom.php';            // CycloneDX/SPDX SBOM · pom.xml → 패키지 + 의존 그래프
require_once __DIR__ . '/ingest/kernel.php';          // 실행/설치 커널 → 재부팅 필요
require_once __DIR__ . '/ingest/network.php';        // 호스트 인터페이스 IPv4(자산 IP 대조의 좌변)
require_once __DIR__ . '/ingest/snapshot.php';        // 내용 해시 · 패키지 맵 · 스냅샷 간 변경 목록

// ── collected_at (ISO-8601) → MySQL DATETIME ──────────────────────────────
function vg_ingest_parse_collected_at($raw): ?string
{
    if (empty($raw)) { return null; }
    $ts = strtotime((string) $raw);
    if ($ts === false) { return null; }
    return date('Y-m-d H:i:s', $ts);
}
