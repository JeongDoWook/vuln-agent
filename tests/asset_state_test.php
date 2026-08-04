<?php
declare(strict_types=1);

require_once __DIR__ . '/../server/src/format.php';

$fail = 0;
$eq = static function (string $label, string $got, string $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, $want, $got);
        $fail++;
    }
};

$eq('스캔 전', vg_asset_state_key(false, 0, null, 43200), 'none');
$eq('poll 정상 + 오래된 수집', vg_asset_state_key(true, 0, 1000, 43200), 'ok');
$eq('poll 2분 지연', vg_asset_state_key(true, 2, 10, 43200), 'stale');
$eq('poll 6분 오프라인', vg_asset_state_key(true, 6, 10, 43200), 'offline');
$eq('구버전 12시간 주기 5시간 경과', vg_asset_state_key(true, null, 300, 43200), 'ok');
$eq('구버전 12시간 주기 19시간 경과', vg_asset_state_key(true, null, 1140, 43200), 'stale');

if ($fail > 0) { exit(1); }
echo "  ✓ 자산 연결 상태 단위 테스트\n";
