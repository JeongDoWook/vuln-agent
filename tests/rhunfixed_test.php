<?php
declare(strict_types=1);

/**
 * rhunfixed 단위 테스트 — Red Hat 미수정 CVE(조치 불가) 판정.
 *
 * 두 가지가 틀리면 조용히 미탐이 된다:
 *   1) 컴포넌트 매핑 — Red Hat 은 **소스 패키지**(bzip2)로 상태를 매기는데 설치된 건 바이너리
 *      (bzip2-libs)다. 바이너리 이름으로 물으면 API 가 0건을 준다(실측 확인).
 *   2) 릴리스 매칭 — package_state 의 product_name("Red Hat Enterprise Linux 8")에서 메이저를
 *      잘못 읽으면 남의 릴리스 상태를 가져다 쓴다.
 *
 * 실행: docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/rhunfixed_test.php
 */

require_once __DIR__ . '/../server/src/feeds.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── 컴포넌트(소스 패키지) 매핑 ─────────────────────────────────────────────
$eq('소스 rpm → 컴포넌트',      vg_rpm_component('bzip2-1.0.6-26.el8.src.rpm', 'bzip2-libs'), 'bzip2');
$eq('이름에 - 가 든 컴포넌트',  vg_rpm_component('python3-urllib3-1.24.2-9.el8_10.src.rpm', 'python3-urllib3'), 'python3-urllib3');
$eq('epoch 붙은 릴리스',        vg_rpm_component('vim-8.0.1763-23.el8_10.src.rpm', 'vim-minimal'), 'vim');
$eq('소스 정보 없으면 바이너리', vg_rpm_component('', 'openssl-libs'), 'openssl-libs');
$eq('소스 정보 null',           vg_rpm_component(null, 'curl'), 'curl');

// ── 릴리스별 fix_state 판정 ────────────────────────────────────────────────
$detail = ['package_state' => [
    ['product_name' => 'Red Hat Enterprise Linux 7',  'package_name' => 'bzip2', 'fix_state' => 'Out of support scope'],
    ['product_name' => 'Red Hat Enterprise Linux 8',  'package_name' => 'bzip2', 'fix_state' => 'Fix deferred'],
    ['product_name' => 'Red Hat Enterprise Linux 9',  'package_name' => 'bzip2', 'fix_state' => 'Will not fix'],
    ['product_name' => 'Red Hat Enterprise Linux 10', 'package_name' => 'bzip2', 'fix_state' => 'Not affected'],
]];

$eq('RHEL8 상태',  vg_rhcve_fix_state($detail, '8', 'bzip2'), 'Fix deferred');
$eq('RHEL9 상태',  vg_rhcve_fix_state($detail, '9', 'bzip2'), 'Will not fix');
// "…Linux 1" 이 "…Linux 10" 에 걸리면 안 된다 — 메이저 숫자가 끝나는 경계를 봐야 한다.
$eq('RHEL1 은 RHEL10 이 아니다', vg_rhcve_fix_state($detail, '1', 'bzip2'), null);
$eq('RHEL10 상태', vg_rhcve_fix_state($detail, '10', 'bzip2'), 'Not affected');
$eq('다른 컴포넌트는 해당 없음', vg_rhcve_fix_state($detail, '8', 'openssl'), null);
$eq('package_state 없음',        vg_rhcve_fix_state([], '8', 'bzip2'), null);

// ── 목록의 수정본 판정 — 여기서 잘못 걸러내면 CVE 를 통째로 놓친다(실제로 겪었다) ──
//   curl CVE-2023-27534: affected_packages 에 "jbcs-httpd24-curl-0:8.0.1-1.el8jbcs" 가 있었다.
//   JBoss Core Services 의 수정본인데 이걸 RHEL8 수정본으로 오인해 건너뛰었다 → 미탐.
$eq('el8jbcs 는 RHEL8 이 아니다',
    vg_rhcve_fixed_in_release(['jbcs-httpd24-curl-0:8.0.1-1.el8jbcs'], 'curl', '8'), false);
$eq('다른 컴포넌트의 수정본은 무관',
    vg_rhcve_fixed_in_release(['bzip2-main-1.0.8-23.2.hum1'], 'bzip2', '8'), false);
$eq('진짜 RHEL8 수정본',
    vg_rhcve_fixed_in_release(['curl-0:7.61.1-34.el8'], 'curl', '8'), true);
$eq('el8_10 z-stream 수정본',
    vg_rhcve_fixed_in_release(['curl-0:7.61.1-34.el8_10.2'], 'curl', '8'), true);
$eq('el9 수정본은 RHEL8 이 아니다',
    vg_rhcve_fixed_in_release(['curl-0:7.76.1-26.el9_3'], 'curl', '8'), false);
$eq('수정본 없음', vg_rhcve_fixed_in_release([], 'curl', '8'), false);

// ── 어떤 상태가 "조치 불가" 인가 ───────────────────────────────────────────
$eq('Affected',            vg_rhcve_is_unfixed('Affected'),            true);
$eq('Fix deferred',        vg_rhcve_is_unfixed('Fix deferred'),        true);
$eq('Will not fix',        vg_rhcve_is_unfixed('Will not fix'),        true);
$eq('Under investigation', vg_rhcve_is_unfixed('Under investigation'), true);
$eq('Out of support scope',vg_rhcve_is_unfixed('Out of support scope'),true);
// Not affected 는 취약하지 않다 — 저장은 하되(재조회 방지 캐시) 취약점으로 세면 안 된다.
$eq('Not affected 는 아니다', vg_rhcve_is_unfixed('Not affected'), false);

if ($fail === 0) {
    echo "rhunfixed: 모든 검사 통과\n";
    exit(0);
}
printf("rhunfixed: %d 개 실패\n", $fail);
exit(1);
