<?php
declare(strict_types=1);

/**
 * 억제 근거 겹 분류(server/src/suppression.php) 검증 — DB 없이 돈다.
 *   ① 화면이 쓰는 고정 문구가 matcher.php 의 실제 reason 조립부에 **아직 있는지**
 *      (문구를 바꾸면 화면이 조용히 '근거 미분류'로 떨어진다 — 이 검사가 그걸 막는다).
 *   ② 실제 reason 예시가 의도한 겹으로 분류되는지(겹끼리 문구가 겹치는 자리 포함).
 */
require_once __DIR__ . '/../server/src/suppression.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ① 문구가 판정 코드에 실제로 있는가 — 정본은 matcher.php(+커널 CNA 는 kernelcve.php,
//    벤더 OVAL 근거는 vendorerrata.php 가 만든다).
//    매처가 자기 속을 server/src/matcher/** 로 나눠 뒀으므로(억제 게이트는 matcher/decide.php)
//    그 디렉터리까지 따라간다 — 안 그러면 파일만 옮겨도 "문구가 사라졌다"고 오탐한다.
$judge = file_get_contents(__DIR__ . '/../server/src/matcher.php')
       . file_get_contents(__DIR__ . '/../server/src/kernelcve.php')
       . file_get_contents(__DIR__ . '/../server/src/vendorerrata.php');
foreach (glob(__DIR__ . '/../server/src/matcher/*.php') ?: [] as $split) {
    $judge .= (string) file_get_contents($split);
}
foreach (VG_SUPPRESS_LAYERS as $key => $def) {
    $eq("[$key] 근거 문구가 판정 코드에 존재", str_contains($judge, $def['match']), true);
}

// ② 실제 reason 모양 → 겹. 순서가 중요한 자리를 특히 본다.
$cases = [
    // 벤더 OVAL 근거에도 '≥ 조치' 가 들어 있다 — 버전 겹으로 떨어지면 안 된다.
    'openssl — RHSA-2024:1234 가 이 빌드에서 고침 (설치 1:3.0.7-24 ≥ 조치 1:3.0.7-27)' => 'vendor_oval',
    '설치 1.1.1n-0+deb11u5 ≥ 조치 1.1.1n-0+deb11u4 → 이미 패치됨' => 'version',
    '데비안 보안 트래커가 curl 의 CVE-2023-1 을 해당 없음으로 판정 → 백포트로 이미 수정됨' => 'tracker',
    'zlib 에 적용된 벤더 보안권고가 CVE-2022-2 를 고침(백포트) → 이미 패치됨 · zlib-1.2.11-40' => 'errata',
    'bash changelog 에 CVE-2019-3 수정 기록(백포트) → 버전이 낮아 보여도 패치됨' => 'changelog',
    '실행 중이 아닌 커널(설치만 됨) — 지금 도는 커널은 6.1.0-18 다. 부팅해야 활성화된다' => 'kernel_inactive',
    'kernel.org CNA: 구동 커널 6.18.34 ≥ 6.18.y 수정본 6.18.20 → 이미 포함됨' => 'kernel_cna',
    '알 수 없는 새 근거' => 'other',
    '' => 'other',
];
foreach ($cases as $reason => $want) {
    $eq('분류: ' . mb_strimwidth($reason, 0, 40, '…'), vg_suppress_layer($reason), $want);
}
$eq('null 근거도 안전하게 미분류', vg_suppress_layer(null), 'other');

// ③ 미분류는 "근거 없음"이 아니라 "표를 못 따라간 것" 으로 보이게 한다(PASS 위장 금지).
$eq('미분류 라벨', vg_suppress_layer_meta('other')['label'], '근거 미분류');
$eq('알려진 겹은 자기 설명을 갖는다', vg_suppress_layer_meta('version')['desc'] !== '', true);

if ($fail > 0) { printf("suppression_test: %d건 실패\n", $fail); exit(1); }
echo "suppression_test: 전부 통과\n";
