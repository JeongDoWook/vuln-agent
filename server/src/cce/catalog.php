<?php
declare(strict_types=1);

/**
 * cce/catalog.php — "우리가 무엇을 점검하는가"의 목록과, 그 항목이 인용하는 외부 근거(SSG 룰).
 *   판정은 하지 않는다 — 카탈로그는 판정 함수를 빈 수집값으로 한 번 돌려 메타만 뽑는다.
 *
 *   ※ cce.php 가 로드한다(그 파일의 중복 로드 가드 안에서).
 */

require_once __DIR__ . '/checks.php';   // vg_cce_checks — 카탈로그의 원천

/**
 * 우리 점검 코드 → **SCAP Security Guide(SSG) 룰 ID**.
 *
 * 왜 필요한가: 점검 항목의 "왜 중요한가 / 어느 기준에 근거하나" 를 우리가 지어내면 안 된다.
 *   SSG 는 오픈소스 룰셋이고 룰마다 CIS·NIST 800-53·STIG·PCI-DSS 참조와 근거를 갖는다.
 *   여기서 묶어 두면 화면이 그 기준을 그대로 인용할 수 있다(tb_compliance_rule).
 *
 * 매핑은 **추측하지 않았다** — SSG 룰 2,493개의 ID 를 실제로 검색해 대응하는 것만 적었다.
 *   대응하는 SSG 룰이 없는 항목(KISA 가이드 고유 등)은 여기 없다 → 화면에서 "자체 기준" 으로 뜬다.
 *   **빠진 칸은 미완성이 아니라 의도된 상태다. 비슷해 보인다고 채우면 안 된다.**
 *
 *   #519 에서 나머지 12개를 `tb_compliance_rule` 전수 대조했다(v0.1.81, 2,493룰).
 *   4개만 대응 룰이 있었고 8개는 **정말로 없어서** 자체 기준으로 남는다:
 *     · CCE-TIME-OFFSET  — SSG 는 maxpoll·RootDistanceMaxSec 같은 *설정값*만 본다.
 *                          실측 오차(chronyc offset)를 판정하는 룰은 없다.
 *     · CCE-LOG-RETENTION — 보존기간 룰은 auditd 전용(num_logs·max_log_file)뿐이고,
 *                          journald MaxRetentionSec/logrotate 보존일수 룰은 없다.
 *     · CCE-CRYPTO-KCMVP — SSG 의 검증 개념은 FIPS 140 이다. 국내 KCMVP 는 다른 제도라
 *                          FIPS 룰에 묶으면 없는 근거를 인용하게 된다.
 *     · CCE-SSH-PWAUTH   — PasswordAuthentication 을 다루는 룰이 없다.
 *                          sshd_enable_pubkey_auth 는 *다른 설정*이라 대체할 수 없다.
 *     · CCE-FILE-HOSTS/SERVICES/SYSLOG/XINETD — file_permissions_* 에 /etc/hosts·
 *                          /etc/services·/etc/rsyslog.conf·/etc/xinetd.conf 가 없다
 *                          (hosts.allow/deny 는 다른 파일, xinetd 는 제거·비활성 룰만 있다).
 */
function vg_cce_ssg_map(): array { return [
    // SSH (sshd -T 실효값으로 판정)
    'CCE-SSH-ROOT'      => 'sshd_disable_root_login',
    'CCE-SSH-EMPTYPW'   => 'sshd_disable_empty_passwords',
    'CCE-SSH-MAXAUTH'   => 'sshd_set_max_auth_tries',
    'CCE-SSH-X11'       => 'sshd_disable_x11_forwarding',
    'CCE-SSH-GRACE'     => 'sshd_set_login_grace_time',
    'CCE-SSH-IDLE'      => 'sshd_set_idle_timeout',
    // 계정
    'CCE-ACC-EMPTYPW'   => 'no_empty_passwords',
    'CCE-ACC-UID0'      => 'accounts_no_uid_except_zero',
    'CCE-ACC-DUPUID'    => 'no_duplicate_uids',
    'CCE-ACC-SHADOW'    => 'accounts_password_all_shadowed',
    // 패스워드 정책
    'CCE-PW-MINLEN'     => 'accounts_password_minlen_login_defs',
    'CCE-PW-MAXDAYS'    => 'accounts_maximum_age_login_defs',
    'CCE-PW-MINDAYS'    => 'accounts_minimum_age_login_defs',
    'CCE-PW-QUALITY'    => 'accounts_password_pam_pwquality_enabled',
    'CCE-PW-LOCKOUT'    => 'accounts_passwords_pam_faillock_deny',
    // 파일 권한
    'CCE-FILE-PASSWD'   => 'file_permissions_etc_passwd',
    'CCE-FILE-SHADOW'   => 'file_permissions_etc_shadow',
    'CCE-FILE-GROUP'    => 'file_permissions_etc_group',
    'CCE-FILE-GSHADOW'  => 'file_permissions_etc_gshadow',
    'CCE-FILE-CRONTAB'  => 'file_permissions_crontab',
    // 시스템
    'CCE-UMASK'         => 'accounts_umask_etc_login_defs',
    'CCE-SESSION-TMOUT' => 'accounts_tmout',
    'CCE-ROOT-PATH'     => 'root_path_default',
    'CCE-RHOSTS'        => 'no_rsh_trust_files',
    'CCE-SVC-LEGACY'    => 'service_telnetd_disabled',
    'CCE-SEC-MODULE'    => 'selinux_state',
    'CCE-SEC-FW'        => 'service_firewalld_enabled',
    // 시간 동기화 — 룰 ID 는 chrony 네임스페이스지만 제목·근거가 서비스 중립이다
    //   ("Synchronize internal information system clocks" / 로그 상관분석 근거).
    //   우리 점검도 chrony·ntpd·timesyncd 를 가리지 않고 동기화 여부만 본다.
    'CCE-TIME-SYNC'         => 'chronyd_sync_clock',
    // 로그·암호화
    'CCE-LOG-REMOTE'        => 'rsyslog_remote_loghost',
    'CCE-CRYPTO-DISK'       => 'encrypt_partitions',
    // Ciphers/MACs/Kex 를 한 항목에서 함께 보지만, 대표 룰은 CBC 취약성을 다루는 이것이다
    //   (sshd_use_strong_macs·sshd_use_strong_kex 도 있으나 매핑은 코드당 1개다).
    'CCE-CRYPTO-SSH-CIPHER' => 'sshd_use_strong_ciphers',
]; }

/**
 * 점검 룰 카탈로그 — [코드 => ['title'=>…, 'severity'=>…, 'ssg_rule_id'=>…|null]].
 *   cce-rules.php(CCE 카탈로그)가 "우리가 무엇을 점검하는가" 를 목록으로 보여줄 때 쓴다.
 *
 * 왜 목록을 따로 안 적나: 코드·제목·심각도를 화면이나 새 테이블에 복사하면 판정 로직과
 *   반드시 어긋난다(항목을 하나 고치면 두 곳을 고쳐야 한다). 그래서 판정 함수를
 *   **빈 수집값**으로 한 번 돌려 그 결과에서 메타만 뽑는다 — cce/checks/** 가 SSOT 로 남는다.
 *   수집값이 없으면 결과는 NA(설정 부재를 위반으로 보는 항목은 FAIL)로 떨어지지만,
 *   코드·제목·심각도는 어느 분기로 가든 항목마다 하나로 고정돼 있어 그대로 쓸 수 있다.
 *   판정 결과(3번째 값)는 여기서 버린다 — 카탈로그는 실제 판정을 말하지 않는다.
 *
 * @return array<string, array{title: string, severity: string, ssg_rule_id: ?string}>
 */
function vg_cce_rules(): array {
    static $rules = null;
    if ($rules !== null) { return $rules; }

    $ssg = vg_cce_ssg_map();
    $out = [];
    foreach (vg_cce_checks([]) as [$code, $title, , $severity]) {
        $out[$code] = [
            'title'       => $title,
            'severity'    => $severity,
            'ssg_rule_id' => $ssg[$code] ?? null,
        ];
    }
    return $rules = $out;
}
