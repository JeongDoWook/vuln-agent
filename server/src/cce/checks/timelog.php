<?php
declare(strict_types=1);

/**
 * cce/checks/timelog.php — 시간 동기화 · 로그 설정 점검(ISMS-P 2.9.6 / 2.9.4).
 *   앞의 KISA U-XX 항목과 마찬가지로 판정 근거는 에이전트가 모은 원자료뿐이다.
 *   수집이 안 됐으면 PASS 가 아니라 NA — "못 봤다"를 "괜찮다"로 바꾸지 않는다.
 *   대응 기준은 주석으로만 남긴다(코드↔기준 매핑 테이블은 cce/catalog.php 소관).
 *
 *   시간과 로그를 한 파일에 둔 이유: 타임스탬프가 틀어지면 아래 모든 로그 증적의 증거력이
 *   함께 무너진다 — 두 항목은 같은 증적의 앞뒤다.
 *
 *   ※ cce/checks.php 가 로드하고 호출한다. 각 함수는 [코드,제목,결과,위험도,근거값,사유] 행 배열을
 *     돌려주고, 그 순서가 곧 vg_cce_checks() 결과의 순서다(순서를 바꾸지 않는다).
 */

require_once __DIR__ . '/../parse.php';   // vg_cce_time_offset · vg_cce_timespan_sec · 임계 상수

/** CCE-TIME-SYNC · CCE-TIME-OFFSET — 시간 동기화 상태와 실측 오차 (ISMS-P 2.9.6). */
function vg_cce_check_time(array $sec): array {
    $out = [];

    // ── CCE-TIME-SYNC : 시간 동기화 (ISMS-P 2.9.6) ──
    //   타임스탬프가 틀어지면 아래 모든 로그 증적의 증거력이 함께 무너진다.
    $tSync  = (string) ($sec['time_sync']     ?? '');
    $tTrack = (string) ($sec['time_tracking'] ?? '');
    $tSvc   = (string) ($sec['time_services'] ?? '');
    $activeSvc = [];
    foreach (preg_split('/\r?\n/', $tSvc) as $line) {
        if (preg_match('/^(\S+)=active$/', trim($line), $m)) { $activeSvc[] = $m[1]; }
    }
    $synced = null;   // true=동기화됨 / false=아님 / null=모름
    if (preg_match('/NTPSynchronized=(yes|no)/i', $tSync, $m)) {
        $synced = strtolower($m[1]) === 'yes';
    } elseif (preg_match('/System clock synchronized:\s*(yes|no)/i', $tSync, $m)) {
        $synced = strtolower($m[1]) === 'yes';
    } elseif (preg_match('/Leap status\s*:\s*(\S+)/i', $tTrack, $m)) {
        $synced = strcasecmp(trim($m[1]), 'Normal') === 0;
    }
    $svcEv = $activeSvc ? '활성 서비스: ' . implode(', ', $activeSvc) : '활성 서비스 없음';
    if ($synced === null) {
        $out[] = ['CCE-TIME-SYNC', '시간 동기화 상태 (ISMS-P 2.9.6)', 'NA', 'MEDIUM',
            $tSvc !== '' ? $svcEv : null,
            '시간 동기화 여부를 수집하지 못함(timedatectl·chronyc 없음).'];
    } else {
        $out[] = ['CCE-TIME-SYNC', '시간 동기화 상태 (ISMS-P 2.9.6)', $synced ? 'PASS' : 'FAIL', 'MEDIUM',
            'synchronized=' . ($synced ? 'yes' : 'no') . ' / ' . $svcEv,
            $synced ? '시스템 시각이 NTP 와 동기화된 상태 — 로그 타임스탬프의 전제가 충족됨.'
                    : 'NTP 동기화가 되어 있지 않다 → 로그 타임스탬프를 신뢰할 수 없다. '
                      . 'chrony/systemd-timesyncd 등 동기화 서비스 활성 권고.'];
    }

    // ── CCE-TIME-OFFSET : 시각 오차 임계 (ISMS-P 2.9.6) ──
    $offset = vg_cce_time_offset($tTrack);
    if ($offset === null) {
        $out[] = ['CCE-TIME-OFFSET', '시각 오차 허용범위 (ISMS-P 2.9.6)', 'NA', 'MEDIUM', null,
            '시각 오차(offset)를 수집하지 못함(chronyc/ntpq 없음).'];
    } else {
        $fail = $offset > VG_CCE_TIME_OFFSET_MAX_SEC;
        $out[] = ['CCE-TIME-OFFSET', '시각 오차 허용범위 (ISMS-P 2.9.6)', $fail ? 'FAIL' : 'PASS', 'MEDIUM',
            sprintf('offset %.6f초', $offset),
            $fail ? sprintf('NTP 기준 시각 오차가 %.3f초로 임계(%.1f초)를 초과 → 로그 상관분석·감사 증적이 어긋난다.',
                            $offset, VG_CCE_TIME_OFFSET_MAX_SEC)
                  : sprintf('시각 오차가 임계(%.1f초) 이내.', VG_CCE_TIME_OFFSET_MAX_SEC)];
    }

    return $out;
}

/** CCE-LOG-RETENTION · CCE-LOG-REMOTE — 로그가 남는가, 남은 게 지워지지 않는가 (ISMS-P 2.9.4). */
function vg_cce_check_logging(array $sec): array {
    $out = [];

    // ── CCE-LOG-RETENTION : 로그 보존기간 설정 (ISMS-P 2.9.4) ──
    //   결함 사례 "중요 로그의 최대 크기를 불충분하게 설정해 보존기간 미충족" 대응.
    //   journald(MaxRetentionSec) 와 logrotate(전역 rotate×주기 / maxage) 중 **긴 쪽**을 본다 —
    //   둘은 대상이 다르고(저널 vs /var/log 파일), 하나라도 기준을 채우면 원문이 남는다.
    $jd = (string) ($sec['journald_conf']  ?? '');
    $lr = (string) ($sec['logrotate_conf'] ?? '');
    $retDays = null; $retSrc = [];
    if (preg_match('/MaxRetentionSec\s*=\s*(\S+)/i', $jd, $m)) {
        $s = vg_cce_timespan_sec($m[1]);
        if ($s !== null && $s > 0) { $retDays = $s / 86400.0; $retSrc[] = 'journald MaxRetentionSec=' . $m[1]; }
    }
    if ($lr !== '' && strcasecmp(trim($lr), 'NONE') !== 0) {
        $lrDays = null; $lrSrc = '';
        if (preg_match('/^maxage\s+(\d+)/mi', $lr, $m)) {
            $lrDays = (float) $m[1]; $lrSrc = 'logrotate maxage ' . $m[1];
        } elseif (preg_match('/^(daily|weekly|monthly|yearly)/mi', $lr, $mf)
               && preg_match('/^rotate\s+(\d+)/mi', $lr, $mr)) {
            $per = ['daily' => 1, 'weekly' => 7, 'monthly' => 30, 'yearly' => 365][strtolower($mf[1])];
            $lrDays = (float) ((int) $mr[1] * $per);
            $lrSrc  = sprintf('logrotate %s×rotate %d', strtolower($mf[1]), (int) $mr[1]);
        }
        if ($lrDays !== null && ($retDays === null || $lrDays > $retDays)) { $retDays = $lrDays; }
        if ($lrSrc !== '') { $retSrc[] = $lrSrc; }
    }
    if ($retDays === null) {
        $out[] = ['CCE-LOG-RETENTION', '로그 보존기간 설정 (ISMS-P 2.9.4)', 'NA', 'MEDIUM', null,
            'journald MaxRetentionSec 도 logrotate 전역 보존 설정도 확인되지 않아 보존기간을 계산할 수 없음'
            . '(설정 미기재이거나 파일을 읽지 못함).'];
    } else {
        $fail = $retDays < VG_CCE_LOG_RETENTION_DAYS;
        $out[] = ['CCE-LOG-RETENTION', '로그 보존기간 설정 (ISMS-P 2.9.4)', $fail ? 'FAIL' : 'PASS', 'MEDIUM',
            sprintf('%.0f일 (%s)', $retDays, implode(' / ', $retSrc)),
            $fail ? sprintf('보존기간이 약 %.0f일로 기준(%d일) 미만 → 사후 추적 시점에 로그가 이미 삭제된다.',
                            $retDays, VG_CCE_LOG_RETENTION_DAYS)
                  : sprintf('보존기간 약 %.0f일로 기준(%d일) 이상.', $retDays, VG_CCE_LOG_RETENTION_DAYS)];
    }

    // ── CCE-LOG-REMOTE : 원격 로그 전송 (ISMS-P 2.9.4) ──
    //   결함 사례 "서버 로그를 백업하지 않아 임의 삭제 가능" 대응. 침해 시 로컬 로그는 지워진다.
    $rsr = $sec['rsyslog_remote'] ?? null;
    $rsr = $rsr === null ? '' : trim((string) $rsr);
    if ($rsr === '') {
        $out[] = ['CCE-LOG-REMOTE', '원격 로그 전송 설정 (ISMS-P 2.9.4)', 'NA', 'MEDIUM', null,
            'rsyslog 설정을 읽지 못함(미설치이거나 권한 부족).'];
    } elseif (strcasecmp($rsr, 'NONE') === 0) {
        $out[] = ['CCE-LOG-REMOTE', '원격 로그 전송 설정 (ISMS-P 2.9.4)', 'FAIL', 'MEDIUM',
            '전송 설정 없음',
            '로그가 이 서버에만 남는다 → 침해 시 삭제·위변조를 막을 수 없다. 원격 로그 서버 전송(@/@@/omfwd) 권고.'];
    } else {
        $out[] = ['CCE-LOG-REMOTE', '원격 로그 전송 설정 (ISMS-P 2.9.4)', 'PASS', 'MEDIUM',
            mb_strimwidth(str_replace("\n", ' | ', $rsr), 0, 200, '…'),
            '원격 로그 서버로 전송하도록 설정됨 — 로컬 삭제만으로는 증적이 사라지지 않는다.'];
    }

    return $out;
}
