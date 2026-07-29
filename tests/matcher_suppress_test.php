<?php
declare(strict_types=1);

/**
 * 매처 억제 게이트 단위 테스트 — vg_match_decide_cve() 의 "무엇이 무엇을 막는가".
 *
 * 억제 판정은 오탐(잘못 떠 있음)과 미탐(잘못 숨김)이 직접 갈리는 자리다. 특히
 * **어느 근거가 어느 가드에 걸리는지**는 눈으로 읽어선 회귀를 못 잡는다 —
 * 실제로 changelog 억제가 서드파티 가드에 막혀 운영에서 억제 0건이었다
 * (docs/dev/changelog-억제층-실측.md).
 *
 * 여기서 고정하는 계약:
 *   · 런타임 보류(재시작·재부팅 대기)는 **근거의 종류를 가리지 않고** 막는다.
 *   · 서드파티 가드는 **버전 비교 계열만** 막는다. changelog 는 안 막는다.
 *   · changelog 는 **호스트 전용**이다(컨테이너에 적용하면 미탐).
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/matcher_suppress_test.php
 */

require_once __DIR__ . '/../server/src/matcher.php';

$fail = 0;

/** 판정에 필요한 기본 맥락 — 라즈베리파이의 서드파티 openssl(운영 실측 형태). */
function ctx(array $over = []): array
{
    return $over + [
        'staleEv'          => null,
        'isKernelPkg'      => false,
        'kernelPending'    => false,
        'kernelNotRunning' => false,
        'isDistroPkg'      => false,      // 서드파티 저장소
        'hostEvidenceOk'   => false,      // = (호스트) && isDistroPkg
        'le'               => null,
        'running'          => false,
        'pkgLoaded'        => false,
        'exposed'          => false,
        'loaded'           => false,
        'scope'            => null,
    ];
}

function sup(array $over = []): array
{
    return $over + [
        'backport'     => [],
        'stale'        => [],
        'debsecan'     => [],
        'useDebsecan'  => [],
        'trackerLabel' => [],
        'errata'       => [],
        'vendorErrata' => [],
        'unfixed'      => [],
    ];
}

$PKG = [
    'name'        => 'openssl',
    'source_pkg'  => 'openssl',
    'version'     => '3.5.6-1~deb13u2+rpt1',
    'origin'      => 'Raspberry Pi Foundation',
];
$SCAN = ['os_id' => 'debian', 'os_version' => '13', 'running_kernel' => '6.12.0', 'kernel_latest' => '6.12.0', 'kernel_reboot_needed' => 0];
$CVE  = 'CVE-2026-9076';
// 설치 버전이 조치안보다 **낮아 보이는** 후보 — 버전 비교로는 안 걸린다(백포트의 전형).
$CAND = ['cvss' => 7.5, 'fixed' => '3.6.0-1', 'cmpver' => '3.5.6-1~deb13u2+rpt1'];
// changelog 에 이 CVE 수정 기록이 있는 상태
$CLOG = sup(['backport' => ['openssl' => [$CVE => 'openssl (3.5.6-1) ... fix CVE-2026-9076']]]);

$check = static function (string $label, array $got, bool $wantSuppress, ?string $reasonHas = null) use (&$fail): void {
    if (($got['suppress'] ?? false) !== $wantSuppress) {
        printf("  ✗ [%s] 억제 기대 %s, 실제 %s (%s)\n", $label,
            $wantSuppress ? 'true' : 'false',
            ($got['suppress'] ?? false) ? 'true' : 'false',
            (string) ($got['reason'] ?? $got['why'] ?? ''));
        $fail++;
        return;
    }
    if ($reasonHas !== null && strpos((string) ($got['reason'] ?? ''), $reasonHas) === false) {
        printf("  ✗ [%s] 근거에 '%s' 가 없다: %s\n", $label, $reasonHas, (string) ($got['reason'] ?? ''));
        $fail++;
    }
};

$decide = static function (array $ctx, array $sup, ?array $ctr = null, int $ctrId = 0, ?array $cand = null) use ($CVE, $CAND, $PKG, $SCAN): array {
    return vg_match_decide_cve($CVE, $cand ?? $CAND, $PKG, 'dpkg', $ctr, $ctrId, $SCAN, $ctx, [], [], $sup);
};

// ── changelog 억제: 서드파티 저장소에도 적용된다(이 PR 의 변경점) ──────────────
$check('서드파티 호스트 + changelog', $decide(ctx(), $CLOG), true, 'changelog');
$check('서드파티 근거에 출처 표기', $decide(ctx(), $CLOG), true, 'Raspberry Pi Foundation');

// ── 런타임 보류는 근거 종류를 가리지 않는다 ────────────────────────────────────
$check('재시작 대기면 changelog 도 억제 안 함',
    $decide(ctx(['staleEv' => 'nginx → /usr/lib/libssl.so.3']), $CLOG), false);
$check('재부팅 대기면 changelog 도 억제 안 함',
    $decide(ctx(['isKernelPkg' => true, 'kernelPending' => true]), $CLOG), false);

// ── changelog 는 호스트 전용 — 컨테이너에 새면 미탐이다 ────────────────────────
$check('컨테이너에는 changelog 억제 안 함',
    $decide(ctx(), $CLOG, ['cid' => 'abc123', 'os' => 'debian', 'eco' => 'Debian:12', 'family' => 'deb'], 7), false);

// ── 서드파티 가드는 버전 비교 계열에 그대로 살아 있다 ──────────────────────────
$check('서드파티 + changelog 없음 → 억제 안 함', $decide(ctx(), sup()), false);
$check('서드파티는 설치≥조치여도 억제 안 함',
    $decide(ctx(), sup(), null, 0, ['cvss' => 7.5, 'fixed' => '3.0.0', 'cmpver' => '3.5.6-1~deb13u2+rpt1']), false);

// ── 배포판 패키지의 기존 억제 경로는 그대로다 ──────────────────────────────────
$distro = ctx(['isDistroPkg' => true, 'hostEvidenceOk' => true]);
$check('배포판 + 설치≥조치 → 버전 억제',
    $decide($distro, sup(), null, 0, ['cvss' => 7.5, 'fixed' => '3.0.0', 'cmpver' => '3.5.6-1~deb13u2+rpt1']),
    true, '이미 패치됨');
$check('배포판 + 트래커가 해당없음 → 트래커 억제',
    $decide($distro, sup(['useDebsecan' => [0 => true], 'debsecan' => [0 => ['openssl' => ['CVE-9999-1' => true]]],
                          'trackerLabel' => [0 => '데비안 보안 트래커']])),
    true, '백포트로 이미 수정됨');
$check('배포판 + 트래커가 아직 취약 → changelog 로 억제',
    $decide($distro, sup(['useDebsecan' => [0 => true],
                          'debsecan' => [0 => ['openssl' => [$CVE => true]]],
                          'trackerLabel' => [0 => '데비안 보안 트래커'],
                          'backport' => ['openssl' => [$CVE => 'fix CVE-2026-9076']]])),
    true, 'changelog');

// ── 커널: 실행 중이 아닌 이미지는 근거와 무관하게 억제된다(기존 계약) ──────────
$check('실행 중이 아닌 커널은 억제',
    $decide(ctx(['isKernelPkg' => true, 'kernelNotRunning' => true]), sup()), true, '실행 중이 아닌 커널');

if ($fail === 0) {
    echo "matcher 억제 게이트: 전체 통과\n";
    exit(0);
}
printf("matcher 억제 게이트: %d건 실패\n", $fail);
exit(1);
