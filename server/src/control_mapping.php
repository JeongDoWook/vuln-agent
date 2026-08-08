<?php
declare(strict_types=1);

/**
 * control_mapping.php — CCE 점검 룰 ↔ 다중 컴플라이언스 기준(U-코드/ISMS-P/N2SF) 조회.
 *   매핑 데이터는 tb_control_mapping 이 정본이다(20260808105913_control_mapping.sql).
 *   화면은 "한 점검 결과가 어느 기준의 증적인가" 를 여기서만 물어본다 — cce.php 주석이나
 *   화면 문자열에 기준을 다시 적지 않는다(SSOT).
 */

require_once __DIR__ . '/db.php';

if (!function_exists('vg_control_frameworks')) {
    /**
     * 지원 기준 코드 → 화면 라벨(SSOT). 화이트리스트 검증에도 이 배열을 그대로 쓴다
     * (임의 문자열이 쿼리·출력에 흘러들지 않게).
     */
    function vg_control_frameworks(): array {
        return [
            'ISMS_P' => 'ISMS-P 기준',
            'KISA_U' => '기반시설 U-코드 기준',
            'N2SF'   => 'N2SF 기준',
        ];
    }

    /** GET 파라미터 → 유효한 기준 코드. 알 수 없는 값이면 기본값(ISMS-P). */
    function vg_control_framework_param(?string $raw): string {
        $fw = (string) $raw;
        return isset(vg_control_frameworks()[$fw]) ? $fw : 'ISMS_P';
    }

    /**
     * 룰코드 배열 → [rule_code][framework] = [['control_id'=>…, 'control_name'=>…], …].
     *   IN 절 배치 조회 1회 — 룰마다 물어보면 N+1 이 된다.
     *
     * @param string[] $ruleCodes
     * @return array<string, array<string, array<int, array{control_id: string, control_name: string}>>>
     */
    function vg_control_mapping_for(array $ruleCodes): array {
        $codes = [];
        foreach ($ruleCodes as $c) {
            $c = trim((string) $c);
            if ($c !== '') { $codes[$c] = true; }
        }
        if (!$codes) { return []; }
        $codes = array_keys($codes);

        $in = implode(',', array_fill(0, count($codes), '?'));
        $st = vg_pdo()->prepare(
            "SELECT rule_code, framework, control_id, control_name
               FROM tb_control_mapping
              WHERE is_deleted = 0 AND rule_code IN ($in)
              ORDER BY framework, control_id"
        );
        $st->execute($codes);

        $out = [];
        foreach ($st->fetchAll() as $r) {
            $out[(string) $r['rule_code']][(string) $r['framework']][] = [
                'control_id'   => (string) $r['control_id'],
                'control_name' => (string) $r['control_name'],
            ];
        }
        return $out;
    }
}
