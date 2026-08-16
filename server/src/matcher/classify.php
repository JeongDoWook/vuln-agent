<?php
declare(strict_types=1);

/**
 * matcher/classify.php — 런타임 노출 상태 → 등급(우선순위) 환산.
 *   "이 패키지가 지금 어떤 상태인가"(7종)를 정하고 그 상태 + KEV 로 CRITICAL~LOW 를 매긴다.
 *   억제 판정(무엇을 지울까)과는 축이 다르다 — 여기는 **남는 것의 순위**만 정한다.
 *   DB 를 모른다(순수 함수). 호출부: matcher/decide.php(vg_classify) · matcher/signals.php(vg_scope_rank).
 *
 * matcher.php 가 require 한다. 중복 로드 방어(function_exists)는 원본 그대로 유지한다 —
 *   로드 경로가 늘어난 만큼 오히려 더 필요하다.
 */

if (!function_exists('vg_scope_rank')) {
    // 노출 범위 위험도 (클수록 위험)
    function vg_scope_rank(?string $s): int {
        switch ($s) {
            case 'EXTERNAL': return 3;
            case 'BOUND':    return 2;
            // LAN: 링크로컬 멀티캐스트(mDNS/LLMNR/SSDP…) — 0.0.0.0 이지만 라우터를 못 넘어 같은
            //   세그먼트만 닿는다. 인터넷 노출(EXTERNAL)은 아니고 루프백(LOCAL)보다는 위험 → 중간.
            case 'LAN':      return 2;
            // FILTERED: 전체 인터페이스에 떠 있지만 방화벽이 그 포트를 막아 외부에서 못 닿는다.
            //   (에이전트가 firewalld/ufw 의 허용 포트와 대조해 판정) → LOCAL 과 같은 무게.
            case 'FILTERED':
            case 'LOCAL':    return 1;
            default:         return 0;
        }
    }

    // 런타임 상태 판정 + 등급 + 근거.
    //   상태 강도: EXTERNAL(외부노출) > LAN(로컬 세그먼트 노출) > FILTERED(방화벽 차단)
    //              > LISTENING(로컬리스닝) > RUNNING(실행중) > LOADED(사용중) > INSTALLED(설치만) — 7종.
    //   레벨: 설치1 / 로컬세그먼트·방화벽차단·실행·로드·로컬리스닝2 / 외부노출3, KEV 시 +1(최대 CRITICAL).
    //   반환: [status, severity, rationale]
    //   $pkgLoaded: 이 패키지가 "리스닝 중이 아닌" 실행 프로세스에 라이브러리로 로드됐는가(패키지 1개 기준 bool).
    //     호출부의 procLoadedPkgs(컨테이너별 로드 패키지 집합, 배열)와 이름이 겹치지 않도록 구분한다 —
    //     예전엔 둘 다 $procLoaded 라 배열/bool 이 이름만 보고 헷갈렸다.
    function vg_classify(?array $le, bool $running, bool $pkgLoaded, bool $inKev, string $pkg): array {
        if ($le && ($le['scope'] ?? '') === 'EXTERNAL') {
            $status = 'EXTERNAL'; $level = 3;
            $base = sprintf('외부노출(%s:%d 가 %s 사용)', $le['proc'] ?? '?', $le['port'] ?? 0, $pkg);
        } elseif ($le && ($le['scope'] ?? '') === 'LAN') {
            // 링크로컬 멀티캐스트(mDNS 등) — 인터넷엔 안 닿고 같은 세그먼트만. 외부노출보다 한 단계 아래.
            $status = 'LAN'; $level = 2;
            $base = sprintf('로컬 세그먼트 노출(%s:%d 가 %s 사용 — mDNS 등 멀티캐스트라 라우터를 넘지 않음)',
                            $le['proc'] ?? '?', $le['port'] ?? 0, $pkg);
        } elseif ($le && ($le['scope'] ?? '') === 'FILTERED') {
            // 전체 인터페이스 바인딩이지만 방화벽이 막고 있다 → 외부노출 아님.
            //   이 판정이 없으면 방화벽 뒤의 내부 서비스가 전부 HIGH/CRITICAL 로 뜬다(오탐).
            $status = 'FILTERED'; $level = 2;
            $base = sprintf('방화벽 차단(%s:%d — 리스닝이지만 외부 도달 불가)', $le['proc'] ?? '?', $le['port'] ?? 0);
        } elseif ($le) {
            $status = 'LISTENING'; $level = 2;
            $base = sprintf('로컬 리스닝(%s:%d, scope=%s)', $le['proc'] ?? '?', $le['port'] ?? 0, $le['scope'] ?? '-');
        } elseif ($running) {
            $status = 'RUNNING'; $level = 2;
            $base = '실행 중(포트 미개방)';
        } elseif ($pkgLoaded) {
            $status = 'LOADED'; $level = 2;
            $base = '사용 중(실행 프로세스가 라이브러리 로드)';
        } else {
            $status = 'INSTALLED'; $level = 1;
            $base = '설치만 됨(실행/로드 프로세스 없음)';
        }
        if ($inKev && $level < 4) {
            $level++;
        }
        $sev = [1 => 'LOW', 2 => 'MEDIUM', 3 => 'HIGH', 4 => 'CRITICAL'][$level];
        $why = $base . ($inKev ? ' · CISA KEV 등재' : '') . ' → ' . $sev;
        return [$status, $sev, $why];
    }
}
