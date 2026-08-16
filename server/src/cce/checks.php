<?php
declare(strict_types=1);

/**
 * cce/checks.php — 점검 39종을 도메인별 파일에 나눠 부르고 한 목록으로 잇는다.
 *
 * **호출 순서가 곧 결과 순서다.** 아래 순서는 분리 전 vg_cce_checks() 안의 순서 그대로다 —
 *   결과 순서가 tb_cce_finding 적재 순서이자 카탈로그(vg_cce_rules) 나열 순서라,
 *   도메인끼리 묶어 보기 좋게 재배열하면 화면 순서가 바뀐다(동작 변경). 그래서 SSH 점검이
 *   두 번(로그인 → 하드닝) 갈라져 불린다.
 *
 *   ※ cce.php 가 로드한다(그 파일의 중복 로드 가드 안에서).
 */

require_once __DIR__ . '/checks/ssh.php';
require_once __DIR__ . '/checks/accounts.php';
require_once __DIR__ . '/checks/system.php';
require_once __DIR__ . '/checks/timelog.php';
require_once __DIR__ . '/checks/crypto.php';

// 수집 JSON → 점검 결과 배열. 각 원소: [code,title,result,severity,evidence,rationale].
function vg_cce_checks(array $data): array {
    $sec  = $data['security'] ?? [];
    $usr  = $data['users']    ?? [];
    $meta = $data['meta']     ?? [];
    $isRoot = strtolower(trim((string) ($meta['running_as'] ?? ''))) === 'root';

    $sshEff = (string) ($usr['sshd_effective'] ?? '');
    $sshCfg = (string) ($usr['sshd_config']    ?? '');

    return array_merge(
        vg_cce_check_ssh_login($sshEff, $sshCfg),        // CCE-SSH-ROOT · CCE-SSH-PWAUTH
        vg_cce_check_uid0($usr),                         // CCE-ACC-UID0
        vg_cce_check_mac_firewall($sec, $isRoot),        // CCE-SEC-MODULE · CCE-SEC-FW
        // ══════════════════════════════════════════════════════════════════
        // KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 가이드」(U-XX) 항목
        //   CCE 는 CVE 처럼 받아올 피드가 없다 — MITRE/NIST CCE 사전은 2013년경 갱신이
        //   끊겼고, KISA·금융보안원 가이드는 PDF/HWP 문서로만 배포된다(API 없음).
        //   그래서 가이드 항목을 코드로 옮긴다. 각 판정은 근거값과 사유를 남긴다.
        // ══════════════════════════════════════════════════════════════════
        vg_cce_check_ssh_hardening($sshEff, $sshCfg),    // SSH 세부 5종 (U-01 계열 확장)
        vg_cce_check_file_perms($sec),                   // 파일 권한 9종 (U-07~U-12)
        vg_cce_check_password_policy($sec),              // 패스워드 정책 3종 (U-46~U-48) + UMASK (U-56)
        vg_cce_check_pam($sec),                          // 복잡도·계정 잠금 (U-02, U-03)
        vg_cce_check_account_lists($sec),                // 위반 목록형 4종 (U-04, U-52, 빈 패스워드, U-17)
        vg_cce_check_shell_env($sec),                    // root PATH(U-05) · 레거시 서비스 · TMOUT(U-54)
        // ══════════════════════════════════════════════════════════════════
        // 시간 동기화 · 로그 설정 · 암호화 (ISMS-P 2.9.6 / 2.9.4 / 2.7.1, N2SF 제5장 DT·EA-1)
        //   앞의 KISA U-XX 항목과 마찬가지로 판정 근거는 에이전트가 모은 원자료뿐이다.
        //   수집이 안 됐으면 PASS 가 아니라 NA — "못 봤다"를 "괜찮다"로 바꾸지 않는다.
        //   대응 기준은 주석으로만 남긴다(코드↔기준 매핑 테이블은 cce/catalog.php 소관).
        // ══════════════════════════════════════════════════════════════════
        vg_cce_check_time($sec),                         // CCE-TIME-SYNC · CCE-TIME-OFFSET
        vg_cce_check_logging($sec),                      // CCE-LOG-RETENTION · CCE-LOG-REMOTE
        vg_cce_check_crypto($sec, $sshEff, $sshCfg)      // SSH 알고리즘 · 디스크 암호화 · KCMVP
    );
}
