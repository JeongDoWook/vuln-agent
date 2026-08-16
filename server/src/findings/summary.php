<?php
declare(strict_types=1);

/**
 * findings/summary.php — 탭 위 공통 머리 두 줄: 판단 순서 도식 + 결론 배너.
 *
 *   탭 본문이 아니라 **세 탭이 같은 자리에 그리는 것**이라 탭 파일이 아니라 여기 있다.
 *   숫자는 각 탭이 이미 집계한 값만 받는다 — 새 쿼리를 만들지 않는다(그게 이 두 함수의 규칙).
 */

/* 이 화면이 무엇을 판단하는 자리인지를 도식 한 장으로 답한다 — 순서는 vg_signal_slots() 의
 *   네 축(노출→악용→등급→조치)과 같다. 같은 판단 순서를 화면마다 다른 순서로 그리지 않는다.
 *   숫자는 탭별 집계에서 이미 나온 값만 쓴다(새 쿼리 없음). CCE·노출 탭은 축이 다르므로
 *   각자의 순서를 그린다 — 없는 축을 빈 칸으로 세워 두지 않는다. */
/* 결론 배너 — 카드와 표는 값을 보여줄 뿐이라, "지금 이 탭에서 무엇이 몇 건인가"는
 *   사용자가 직접 세어야 했다. 그 한 줄을 탭 바로 아래 한 번만 세운다(role="status").
 *   수치는 각 탭이 이미 집계한 값만 쓴다 — 새 쿼리를 추가하지 않는다.
 *   기준이 둘이라는 걸 숨기지 않는다: 분포(등급·결과·범위)는 **대상 스캔 전체** 기준이고
 *   '현재 목록'만 필터가 반영된 수다. 그래서 note 에 기준을 적어 둔다. */
function vg_findings_verdict(string $type, int $total, int $scanCount, array $counts,
                             array $unsupBy, array $cceResultCounts, array $scopeCounts): void {
    $listStat = ['label' => '현재 목록 · 건', 'value' => number_format($total)];
    $note = '대상 자산 ' . number_format($scanCount) . '대 · 분포는 대상 스캔 전체 기준 · 현재 목록만 필터 반영';
    if ($type === 'cve') {
        $crit = (int) $counts['CRITICAL'];
        $high = (int) $counts['HIGH'];
        $unsup = 0;
        foreach ($unsupBy as $names) { $unsup += count($names); }
        $stats = [$listStat,
            ['label' => 'CRITICAL · 건', 'value' => number_format($crit), 'tone' => $crit > 0 ? 'crit' : 'ok'],
            ['label' => 'HIGH · 건',     'value' => number_format($high), 'tone' => $high > 0 ? 'warn' : 'ok']];
        if ($unsup > 0) {
            $stats[] = ['label' => '판정 불가 대상 · 개', 'value' => number_format($unsup), 'tone' => 'muted'];
        }
        if ($crit > 0) {
            $vTone = 'crit';
            $vHead = '현재 목록 ' . number_format($total) . '건 — CRITICAL ' . number_format($crit) . '건이 가장 먼저 조치할 대상입니다.';
        } elseif ($high > 0) {
            $vTone = 'warn';
            $vHead = '현재 목록 ' . number_format($total) . '건 — CRITICAL 은 없고 HIGH ' . number_format($high) . '건이 우선 대상입니다.';
        } elseif ($total > 0) {
            $vTone = 'warn';
            $vHead = '현재 목록 ' . number_format($total) . '건 — CRITICAL·HIGH 는 없습니다.';
        } else {
            // 0건을 "안전" 으로 읽히게 두지 않는다 — 판정 불가 대상이 있으면 톤부터 낮춘다.
            $vTone = $unsup > 0 ? 'muted' : 'ok';
            $vHead = $unsup > 0
                ? '현재 조건에 해당하는 취약점이 없습니다 — 다만 판정 불가 대상 ' . number_format($unsup) . '개가 있어 "안전"으로 읽을 수 없습니다.'
                : '현재 조건에 해당하는 취약점이 없습니다.';
        }
    } elseif ($type === 'cce') {
        $fail = (int) $cceResultCounts['FAIL'];
        $na   = (int) $cceResultCounts['NA'];
        $pass = (int) $cceResultCounts['PASS'];
        $stats = [$listStat,
            ['label' => '위반(FAIL) · 건',     'value' => number_format($fail), 'tone' => $fail > 0 ? 'crit' : 'ok'],
            ['label' => '판정 불가(NA) · 건',  'value' => number_format($na),   'tone' => $na > 0 ? 'muted' : 'ok'],
            ['label' => '양호(PASS) · 건',     'value' => number_format($pass), 'tone' => 'ok']];
        if ($fail > 0) {
            $vTone = 'crit';
            $vHead = '보안설정 위반 ' . number_format($fail) . '건이 확인됐습니다.';
        } elseif ($na > 0) {
            $vTone = 'warn';
            $vHead = '위반은 0건이지만 판정 불가(NA) ' . number_format($na) . '건이 남아 "준수"로 읽을 수 없습니다.';
        } elseif ($pass > 0) {
            $vTone = 'ok';
            $vHead = '점검한 ' . number_format($pass) . '건이 모두 양호합니다.';
        } else {
            $vTone = 'muted';
            $vHead = '아직 보안설정 점검 결과가 없습니다.';
        }
    } else {
        $ext = (int) ($scopeCounts['EXTERNAL'] ?? 0);
        $lan = (int) ($scopeCounts['LAN'] ?? 0);
        $expAll = array_sum(array_map('intval', $scopeCounts));
        // 범위 어휘는 vg_scope_label() 이 정본이다 — 여기서 다시 이름 짓지 않는다.
        $stats = [$listStat,
            ['label' => vg_scope_label('EXTERNAL') . ' · 건', 'value' => number_format($ext), 'tone' => $ext > 0 ? 'crit' : 'ok'],
            ['label' => vg_scope_label('LAN') . ' · 건',      'value' => number_format($lan), 'tone' => $lan > 0 ? 'warn' : 'ok']];
        if ($ext > 0) {
            $vTone = 'crit';
            $vHead = '외부에 노출된 리스너 ' . number_format($ext) . '건이 있습니다 — 가장 먼저 확인할 접점입니다.';
        } elseif ($lan > 0) {
            $vTone = 'warn';
            $vHead = '외부 노출은 없고 ' . vg_scope_label('LAN') . ' ' . number_format($lan) . '건이 있습니다.';
        } elseif ($expAll > 0) {
            $vTone = 'ok';
            $vHead = '외부·로컬 세그먼트에 노출된 리스너가 없습니다.';
        } else {
            $vTone = 'muted';
            $vHead = '아직 수집된 리스너가 없습니다.';
        }
    }
    vg_verdict($vTone, $vHead, $stats, $note);
}
