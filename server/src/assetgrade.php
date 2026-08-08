<?php
declare(strict_types=1);

/**
 * assetgrade.php — 자산 중요도·N2SF 보안등급(C/S/O)의 어휘와 **초안 제안 규칙**.
 *
 * 이 파일이 지키는 경계는 하나다 — **판정은 사람이, 초안은 시스템이.**
 *   등급 판정 기준은 「정보공개법」 제9조 비공개 대상정보의 호 매핑이고, 업무정보 등급 확정은
 *   기관의 법적 처분이라 시스템이 대신할 수 없다. 그래서 이 파일의 제안 함수는
 *   tb_host.grade(확정값)를 **절대 쓰지 않는다** — grade_suggested/grade_suggested_reason
 *   에만 쓴다. 확정은 host.php 의 관리자 폼이 사람 손으로만 한다.
 *
 * 규칙의 근거는 원문이 직접 준 두 줄뿐이다(억지 제안 금지 — 확신이 없으면 아무것도 제안하지 않는다):
 *   · "기타: 로그 및 임시백업 등"이 명시적 S  → 로그 수신·백업 처리 역할이면 S 후보
 *   · 외부에 열린 자산                        → O 영역 후보
 * 「개인정보 패턴 탐지 → S」는 이 제품이 개인정보를 수집하지 않으므로 구현 대상이 아니다.
 */

/** N2SF 등급 어휘. 화면 라벨·검증 허용값의 단일 출처(하드코딩 분류표를 늘리지 않는다). */
const VG_ASSET_GRADES = [
    'C' => 'C · 기밀',
    'S' => 'S · 민감',
    'O' => 'O · 공개',
];

/**
 * 등급의 보호수준 순위(높을수록 강한 보호). 여러 업무정보 등급이 한 정보시스템에 있으면
 * **가장 높은 등급을 승계**한다 — vg_asset_grade_max() 가 이 순위만 본다.
 */
const VG_ASSET_GRADE_RANK = ['O' => 1, 'S' => 2, 'C' => 3];

/** 자산 중요도 어휘(DB 는 ENUM('HIGH','MEDIUM','LOW'), 화면은 상/중/하). */
const VG_ASSET_CRITICALITY = ['HIGH' => '상', 'MEDIUM' => '중', 'LOW' => '하'];

/**
 * 원격 로그 수신 데몬 — 이 프로세스가 **포트를 열고 있으면** 다른 호스트의 로그를 받는다는 뜻이다.
 *   rsyslogd 자체는 거의 모든 리눅스에 떠 있으므로 "설치됨"만으로는 근거가 못 된다.
 *   포트를 여는 것(수신)까지 확인해야 "로그 처리 시스템"이라 말할 수 있다.
 */
const VG_ASSET_LOG_LISTENERS = ['rsyslogd', 'syslog-ng', 'syslogd'];

/**
 * 로그 수집기·백업 데몬 — 이름 자체가 역할을 특정하는 것만 넣는다.
 *   journald·cron 처럼 모든 호스트에 있는 것은 넣지 않는다(전 함대가 S 제안을 받게 된다).
 */
const VG_ASSET_LOGBACKUP_PROCS = [
    // 로그 수집·전송
    'fluentd', 'fluent-bit', 'logstash', 'filebeat', 'promtail',
    // 백업
    'bacula-fd', 'bacula-sd', 'bacula-dir', 'bareos-fd', 'bareos-sd', 'bareos-dir',
    'borg', 'restic', 'duplicity', 'rsnapshot', 'barman', 'amandad',
];

/**
 * 이 스캔의 수집 데이터만 보고 **초안 등급을 제안**한다. 확신이 없으면 제안하지 않는다.
 *
 * 우선순위: 로그·백업(S) > 외부노출(O). 둘 다 해당하면 보호수준이 높은 S 를 제안한다
 *   — 외부에 열려 있다는 사실이 "공개해도 되는 정보"를 뜻하지는 않기 때문이다.
 *
 * @return array{grade:string,reason:string}|null 제안이 없으면 null
 */
function vg_asset_grade_suggest(PDO $pdo, int $scanId): ?array
{
    // ① 로그 수신 — 로그 데몬이 포트를 열고 있는가(루프백만 여는 경우는 자기 호스트용이라 제외).
    $ph = implode(',', array_fill(0, count(VG_ASSET_LOG_LISTENERS), '?'));
    $st = $pdo->prepare(
        "SELECT proc, port FROM tb_exposure
          WHERE scan_id = ? AND scope <> 'LOCAL' AND proc IN ($ph)
          ORDER BY port LIMIT 1"
    );
    $st->execute(array_merge([$scanId], VG_ASSET_LOG_LISTENERS));
    $logListener = $st->fetch();
    if ($logListener !== false) {
        return [
            'grade'  => 'S',
            'reason' => '원격 로그 수신 추정 — ' . (string) $logListener['proc']
                      . ' 이(가) 포트 ' . (int) $logListener['port'] . ' 를 열고 있습니다.'
                      . ' (「정보공개법」 제9조 기타 "로그 및 임시백업 등" → S)',
        ];
    }

    // ② 로그 수집기·백업 데몬이 돌고 있는가.
    $ph = implode(',', array_fill(0, count(VG_ASSET_LOGBACKUP_PROCS), '?'));
    $st = $pdo->prepare(
        "SELECT comm FROM tb_process WHERE scan_id = ? AND comm IN ($ph) ORDER BY comm LIMIT 1"
    );
    $st->execute(array_merge([$scanId], VG_ASSET_LOGBACKUP_PROCS));
    $proc = $st->fetchColumn();
    if ($proc !== false) {
        return [
            'grade'  => 'S',
            'reason' => '로그·백업 처리 역할 추정 — 프로세스 ' . (string) $proc . ' 실행 중.'
                      . ' (「정보공개법」 제9조 기타 "로그 및 임시백업 등" → S)',
        ];
    }

    // ③ 외부 노출 — 인터넷에서 닿는 포트가 있으면 O 영역 후보.
    $st = $pdo->prepare(
        "SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ? AND scope = 'EXTERNAL'"
    );
    $st->execute([$scanId]);
    $ext = (int) $st->fetchColumn();
    if ($ext > 0) {
        return [
            'grade'  => 'O',
            'reason' => '외부 노출 포트 ' . $ext . '개 — 개방형(O) 영역 후보입니다.',
        ];
    }

    return null;   // 근거 없음 → 제안하지 않는다
}

/**
 * 제안값을 tb_host 에 반영한다. **확정값(grade)은 건드리지 않는다.**
 *   수집 때마다 불리므로 값이 같으면 UPDATE 자체를 하지 않는다.
 */
function vg_asset_grade_refresh(PDO $pdo, int $hostId, int $scanId): void
{
    $s = vg_asset_grade_suggest($pdo, $scanId);
    $grade  = $s['grade'] ?? null;
    $reason = $s === null ? null : mb_strimwidth($s['reason'], 0, 255, '');

    $st = $pdo->prepare(
        'UPDATE tb_host SET grade_suggested = ?, grade_suggested_reason = ?
          WHERE host_id = ?
            AND NOT (grade_suggested <=> ? AND grade_suggested_reason <=> ?)'
    );
    $st->execute([$grade, $reason, $hostId, $grade, $reason]);
}

/**
 * 정보시스템 등급 = 그 시스템에 포함된 업무정보 등급의 **최고값 승계**.
 *   리포트가 "표 2-9 가 완전한 결정 규칙이라 100% 자동 계산된다"고 한 부분이다. 표 원문의
 *   세부 조합까지는 확인하지 못했으므로, 여기서는 **단순 최고등급 승계**만 구현하고 근거 문구를
 *   함께 돌려준다(과설계 금지 — 규칙이 확인되면 이 함수 하나만 고치면 된다).
 *
 * @param string[] $grades 확정 등급 목록(빈 값·모르는 값은 무시)
 * @return array{grade:string,reason:string}|null 유효한 등급이 하나도 없으면 null
 */
function vg_asset_grade_max(array $grades): ?array
{
    $best = null;
    $count = 0;
    foreach ($grades as $g) {
        $g = (string) $g;
        if (!isset(VG_ASSET_GRADE_RANK[$g])) { continue; }
        $count++;
        if ($best === null || VG_ASSET_GRADE_RANK[$g] > VG_ASSET_GRADE_RANK[$best]) { $best = $g; }
    }
    if ($best === null) { return null; }

    return [
        'grade'  => $best,
        'reason' => '포함된 업무정보 등급 ' . $count . '건 중 최고등급 ' . $best . ' 를 승계했습니다.',
    ];
}

/** 등급 뱃지. 확정값과 제안값을 눈으로 구분해야 하므로 제안값은 '제안' 꼬리표를 단다. */
function vg_asset_grade_badge(?string $grade, bool $suggested = false, string $reason = ''): string
{
    $grade = (string) $grade;
    if (!isset(VG_ASSET_GRADES[$grade])) { return '<span class="why">–</span>'; }

    // 톤: 보호수준이 높을수록 강한 색(색 자체는 app.css 의 .tone-* 이 정한다).
    $tone = ['C' => 'crit', 'S' => 'high', 'O' => 'low'][$grade];
    $label = $suggested ? $grade . ' 제안' : VG_ASSET_GRADES[$grade];
    $title = $suggested
        ? '시스템 초안 제안(확정 아님) — ' . $reason
        : ($reason !== '' ? '확정 근거 — ' . $reason : '');

    return vg_badge($label, $suggested ? 'muted' : $tone, $title);
}
