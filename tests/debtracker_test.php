<?php
declare(strict_types=1);

/**
 * debtracker 단위 테스트 — 데비안 보안 트래커 파서(feeds/debtracker.php)와
 *   취약 판정(src/debtracker.php). 네트워크·DB 없이 도는 순수 함수라 스모크 앞단에서 돈다.
 *
 * 판정이 틀리면 두 방향으로 다 위험하다:
 *   느슨하면 → 이미 고쳐진 CVE 가 남는다(오탐, 지금 잡으려는 것)
 *   빡빡하면 → 진짜 취약점을 "고쳐졌다"고 지운다(미탐, 훨씬 나쁘다)
 * 그래서 규칙은 debsecan 원본(Vulnerability.is_vulnerable)과 한 줄씩 대조해 옮겼다.
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/debtracker_test.php
 */

require_once __DIR__ . '/../server/src/debtracker.php';

// 커넥터 파일은 VgFeedConnector 인터페이스를 구현하므로, 파서만 쓰려면 계약을 먼저 로드해야 한다.
require_once __DIR__ . '/../server/src/feeds.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── 파싱 — 실제 릴리스 데이터와 같은 구조(섹션 3개, 빈 줄로 구분) ───────────
$raw = implode("\n", [
    'VERSION 1',
    'CVE-2024-0001,,openssl 설명',
    'CVE-2024-0002,,foo 설명',
    'CVE-2024-0003,,bar 설명',
    '',
    'openssl,0,S  F,3.0.15-1~deb12u1,',      // 소스 항목 · 수정본 있음
    'foo,1,B  F,1.2-3,',                     // 바이너리 항목(flags[0]=B)
    'bar,2,SM  ,,1.0-1 2.0-1',               // 수정본 없음 + 예외 버전 2개 · 긴급도 M
    '',
    'openssl,libssl3 openssl',               // 소스→바이너리 매핑(우리는 안 쓴다)
    '',
]);

$rows = vg_debtracker_parse($raw);
$eq('행 3개', count($rows), 3);
$eq('CVE 인덱스 → 이름',   $rows[0]['cve'], 'CVE-2024-0001');
$eq('소스 항목',           $rows[0]['is_binary'], 0);
$eq('수정 버전',           $rows[0]['fixed'], '3.0.15-1~deb12u1');
$eq('수정본 있음(F)',      $rows[0]['has_fix'], 1);
$eq('바이너리 항목(B)',    $rows[1]['is_binary'], 1);
$eq('수정본 없음 → 빈값',  $rows[2]['fixed'], '');
$eq('예외 버전 보존',      $rows[2]['others'], '1.0-1 2.0-1');
$eq('긴급도 M → medium',   $rows[2]['urgency'], 'medium');

// ── 판정: 소스 항목 ────────────────────────────────────────────────────────
$openssl = $rows[0];
$eq('설치 < 수정 → 취약',
    vg_debtracker_is_vulnerable($openssl, 'libssl3', '3.0.14-1', 'openssl', '3.0.14-1'), true);
// 백포트로 고쳐진 빌드 — 이걸 취약으로 남기는 게 오탐의 정체였다.
$eq('설치 = 수정(백포트) → 안전',
    vg_debtracker_is_vulnerable($openssl, 'libssl3', '3.0.15-1~deb12u1', 'openssl', '3.0.15-1~deb12u1'), false);
$eq('설치 > 수정 → 안전',
    vg_debtracker_is_vulnerable($openssl, 'libssl3', '3.0.16-1', 'openssl', '3.0.16-1'), false);
$eq('다른 패키지면 해당 없음',
    vg_debtracker_is_vulnerable($openssl, 'curl', '8.0-1', 'curl', '8.0-1'), false);

// ── 판정: 바이너리 항목 — 소스가 아니라 **바이너리 이름**으로 맞춘다 ───────
$foo = $rows[1];
$eq('바이너리 이름 일치 + 낮은 버전 → 취약',
    vg_debtracker_is_vulnerable($foo, 'foo', '1.2-2', 'foosrc', '1.2-2'), true);
$eq('바이너리 이름 일치 + 수정 버전 → 안전',
    vg_debtracker_is_vulnerable($foo, 'foo', '1.2-3', 'foosrc', '1.2-3'), false);
$eq('바이너리 항목인데 소스 이름만 같으면 해당 없음',
    vg_debtracker_is_vulnerable($foo, 'other', '1.0', 'foo', '1.0'), false);

// ── 판정: 수정본이 없는 CVE(fixed 빈값) ────────────────────────────────────
$bar = $rows[2];
$eq('수정본 없음 → 취약',
    vg_debtracker_is_vulnerable($bar, 'bar', '3.0-1', 'bar', '3.0-1'), true);
$eq('예외 버전 목록에 있으면 안전',
    vg_debtracker_is_vulnerable($bar, 'bar', '2.0-1', 'bar', '2.0-1'), false);

// ── 데비안 버전 규칙(epoch·틸드)이 실제로 적용되는지 — 문자열 비교면 여기서 틀린다 ──
$epoch = ['pkg' => 'linux', 'is_binary' => 0, 'cve' => 'CVE-X', 'fixed' => '1:6.1.0-2', 'others' => ''];
$eq('epoch 있는 수정버전: 설치 1:6.1.0-1 → 취약',
    vg_debtracker_is_vulnerable($epoch, 'linux-image-x', '1:6.1.0-1', 'linux', '1:6.1.0-1'), true);
$eq('epoch 있는 수정버전: 설치 1:6.1.0-2 → 안전',
    vg_debtracker_is_vulnerable($epoch, 'linux-image-x', '1:6.1.0-2', 'linux', '1:6.1.0-2'), false);

// ── 코드명 매핑 — 트래커는 코드명으로만 데이터를 준다 ──────────────────────
$eq('VERSION_ID 12 → bookworm', vg_debian_codename('12'), 'bookworm');
$eq('VERSION_ID 13 → trixie',   vg_debian_codename('13'), 'trixie');
$eq('모르는 버전 → 빈값(억제 안 함)', vg_debian_codename('99'), '');
$eq('빈값 → 빈값', vg_debian_codename(null), '');

if ($fail === 0) {
    echo "debtracker: 모든 검사 통과\n";
    exit(0);
}
printf("debtracker: %d 개 실패\n", $fail);
exit(1);
