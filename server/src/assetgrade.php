<?php
declare(strict_types=1);

/**
 * assetgrade.php — 자산 중요도·N2SF 보안등급(C/S/O)의 어휘와 **초안 제안 규칙**.
 *
 * 이 파일이 지키는 경계는 하나다 — **판정은 사람이, 초안은 시스템이.**
 *   등급 판정 기준은 「정보공개법」 제9조 비공개 대상정보의 호 매핑이고, 업무정보 등급 확정은
 *   기관의 법적 처분이라 시스템이 대신할 수 없다. 그래서 이 파일의 제안 함수는
 *   tb_host.grade(확정값)를 **절대 쓰지 않는다** — grade_suggested/grade_suggested_reason
 *   에만 쓴다. 확정은 사람이 고른 값으로만 하고, 그 처리는 vg_asset_grade_confirm() 한 곳이
 *   맡는다 — 호스트 상세(host.php)와 자산 목록의 일괄 확정(assets.php)이 같은 함수를 쓴다.
 *
 * 규칙의 근거는 원문이 직접 준 두 줄뿐이다(억지 제안 금지 — 확신이 없으면 아무것도 제안하지 않는다):
 *   · "기타: 로그 및 임시백업 등"이 명시적 S  → 로그 수신·백업 처리 역할이면 S 후보
 *   · 외부에 열린 자산                        → O 영역 후보
 * 「개인정보 패턴 탐지 → S」는 이 제품이 개인정보를 수집하지 않으므로 구현 대상이 아니다.
 */

require_once __DIR__ . '/audit.php';   // vg_log_activity — 등급 확정은 감사 대상이다

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
 * 원격에서 닿을 수 있거나 특정 비루프백 주소에 바인딩된 scope.
 * FILTERED 는 방화벽이 막은 소켓이고 LOCAL 은 루프백 전용이다. '-' 및 알 수 없는 미래 값도
 * 도달 가능하다고 추측하지 않는다.
 */
const VG_ASSET_REACHABLE_SCOPES = ['EXTERNAL', 'LAN', 'BOUND'];

/**
 * 로그·백업 프로세스 역할. 이름만으로 확정하지 않고 S 초안을 뒷받침하는 강도를 보존한다.
 * journald·cron 처럼 거의 모든 호스트에 있는 프로세스는 넣지 않는다.
 */
const VG_ASSET_LOGBACKUP_ROLES = [
    'server' => [
        'label' => '서버·저장소',
        'processes' => ['logstash', 'bacula-sd', 'bacula-dir', 'bareos-sd', 'bareos-dir', 'barman', 'amandad'],
    ],
    'forwarder' => [
        'label' => '전달자·클라이언트(검토)',
        'processes' => ['fluentd', 'fluent-bit', 'filebeat', 'promtail', 'bacula-fd', 'bareos-fd'],
    ],
    'transient' => [
        'label' => '일회성 도구(약함)',
        'processes' => ['borg', 'restic', 'duplicity', 'rsnapshot'],
    ],
];

/** 결정적인 짧은 근거를 만든다(DB 컬럼과 공개 반환값 모두 255자 이내). */
function vg_asset_grade_reason(array $parts): string
{
    return mb_strimwidth(implode(' ', $parts), 0, 255, '…');
}

/** 모든 일치 건수는 보존하되 대표 항목만 실어 뒤쪽 근거 범주가 잘리지 않게 한다. */
function vg_asset_grade_evidence(string $label, array $items, int $sampleSize = 1, ?int $total = null): string
{
    $sample = array_map(static function (string $item): string {
        return mb_strimwidth($item, 0, 48, '…');
    }, array_slice($items, 0, $sampleSize));
    $total = $total ?? count($items);
    $remaining = $total - count($sample);
    return $label . ' ' . $total . '건(' . implode(', ', $sample)
        . ($remaining > 0 ? ' 외 ' . $remaining . '건' : '') . ').';
}

/** 역할 구분 없이 로그·백업 프로세스 이름만 평평하게 편다(질의·해시 대상 목록). */
function vg_asset_logbackup_procs(): array
{
    return array_values(array_unique(array_merge(
        ...array_column(VG_ASSET_LOGBACKUP_ROLES, 'processes')
    )));
}

/**
 * 스냅샷 identity에 넣을 등급 분류 관련 프로세스 정규형.
 * 전체 프로세스를 해시하면 cron/ssh 같은 일시적 실행마다 무거운 새 스캔이 생긴다.
 */
function vg_asset_grade_relevant_process_rows(array $rows): array
{
    $procs = vg_asset_logbackup_procs();
    $out = [];
    foreach ($rows as $row) {
        // 제안 질의가 LOWER(comm) 로 맞추므로 identity 도 같은 기준이어야 한다 —
        //   'Filebeat' 가 제안엔 잡히는데 스냅샷엔 안 잡히면 그 프로세스의 기동·종료가
        //   재평가를 못 일으킨다.
        $comm = mb_strtolower((string) ($row[1] ?? ''));
        if (!in_array($comm, $procs, true)) { continue; }
        $key = implode('|', [$comm, (string) ($row[2] ?? ''), (string) ($row[3] ?? ''), (string) ($row[4] ?? '')]);
        $out[$key] = [$comm, (string) ($row[2] ?? ''), (string) ($row[3] ?? ''), (string) ($row[4] ?? '')];
    }
    ksort($out);
    return array_values($out);
}

/**
 * 이 스캔의 수집 데이터만 보고 **초안 등급을 제안**한다. 확신이 없으면 제안하지 않는다.
 *
 * 우선순위: 로그·백업(S) > 외부노출(O). 둘 다 해당하면 보호수준이 높은 S 를 제안한다
 *   — 외부에 열려 있다는 사실이 "공개해도 되는 정보"를 뜻하지는 않기 때문이다.
 *
 * source 는 이 제안을 **처음 뒷받침한** 근거의 종류다(우선순위대로 log_listener > process >
 *   external_exposure). 이력 기록이 "그 근거를 만든 수집 단계가 실제로 들어왔는가"를 판정해
 *   수집 누락과 근거 없음을 구분하는 데 쓴다 — 근거를 여러 개 모아도 판정에 필요한 단계는
 *   가장 먼저 성립한 근거의 단계다.
 *
 * @return array{grade:string,source:string,reason:string}|null 제안이 없으면 null
 */
function vg_asset_grade_suggest(PDO $pdo, int $scanId): ?array
{
    $sEvidence = [];
    $sSource = null;

    // ① 로그 수신 — 저장소 의미론에서 실제 비루프백 도달 가능성이 있는 scope 만 채택한다.
    $ph = implode(',', array_fill(0, count(VG_ASSET_LOG_LISTENERS), '?'));
    $scopePh = implode(',', array_fill(0, count(VG_ASSET_REACHABLE_SCOPES), '?'));
    // BOUND는 에이전트가 '특정 IP'로 분류하지만 구형 수집물의 127/8 오분류도 중앙에서 방어한다.
    $listenerWhere = "scan_id = ? AND scope IN ($scopePh) AND proc IN ($ph)
          AND NOT (scope = 'BOUND' AND (bind_addr LIKE '127.%' OR bind_addr IN ('::1', '[::1]')))";
    $params = array_merge([$scanId], VG_ASSET_REACHABLE_SCOPES, VG_ASSET_LOG_LISTENERS);
    $st = $pdo->prepare(
        "SELECT COUNT(*) FROM (
           SELECT 1 FROM tb_exposure WHERE $listenerWhere
           GROUP BY proc, proto, bind_addr, port, scope
         ) AS listener_evidence"
    );
    $st->execute($params);
    $listenerCount = (int) $st->fetchColumn();
    if ($listenerCount > 0) {
        $st = $pdo->prepare(
            "SELECT proc, proto, bind_addr, port, scope FROM tb_exposure
          WHERE $listenerWhere
          GROUP BY proc, proto, bind_addr, port, scope
          ORDER BY proc, port, proto, bind_addr, scope
          LIMIT 1"
        );
        $st->execute($params);
        $listeners = $st->fetchAll(PDO::FETCH_ASSOC);
        $items = array_map(static function (array $r): string {
            return (string) $r['proc'] . ':' . (int) $r['port'] . '/' . (string) $r['proto']
                . '@' . (string) $r['bind_addr'] . '/' . (string) $r['scope'];
        }, $listeners);
        $sEvidence[] = vg_asset_grade_evidence('원격 로그 수신', $items, 1, $listenerCount);
        $sSource = 'log_listener';
    }

    // ② 역할별 프로세스 증거를 전부 모은다. 같은 comm 의 여러 PID는 설명에서 한 번만 센다.
    // 전달자·일회성 도구도 S '초안'의 검토 신호지만 라벨로 약도를 보존하며 법적 확정은 하지 않는다.
    $allProcs = vg_asset_logbackup_procs();
    $ph = implode(',', array_fill(0, count($allProcs), '?'));
    $st = $pdo->prepare(
        "SELECT DISTINCT LOWER(comm) AS comm FROM tb_process
          WHERE scan_id = ? AND LOWER(comm) IN ($ph) ORDER BY comm"
    );
    $st->execute(array_merge([$scanId], $allProcs));
    $running = $st->fetchAll(PDO::FETCH_COLUMN);
    foreach (VG_ASSET_LOGBACKUP_ROLES as $role) {
        $names = $role['processes'];
        $matched = array_values(array_intersect($names, $running));
        sort($matched, SORT_STRING);
        if (!$matched) { continue; }
        $sEvidence[] = vg_asset_grade_evidence($role['label'], $matched);
        $sSource = $sSource ?? 'process';
    }

    // ③ 외부 노출 — 인터넷에서 닿는 포트가 있으면 O 영역 후보.
    $st = $pdo->prepare(
        "SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ? AND scope = 'EXTERNAL'"
    );
    $st->execute([$scanId]);
    $ext = (int) $st->fetchColumn();
    $oEvidence = $ext > 0 ? 'O 외부노출 ' . $ext . '개.' : null;

    if ($sEvidence) {
        if ($oEvidence !== null) { array_splice($sEvidence, 1, 0, [$oEvidence]); }
        array_unshift($sEvidence, 'S 초안(사람 확인 전 미확정).');
        return [
            'grade'  => 'S',
            'source' => (string) $sSource,
            'reason' => vg_asset_grade_reason($sEvidence),
        ];
    }

    if ($ext > 0) {
        return [
            'grade'  => 'O',
            'source' => 'external_exposure',
            'reason' => vg_asset_grade_reason([$oEvidence, '사람 확인 전에는 확정되지 않습니다.']),
        ];
    }

    return null;   // 근거 없음 → 제안하지 않는다
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

/**
 * 자산 등급 **확정** — 사람의 판정을 tb_host 에 쓴다. 제안값(grade_suggested)은 건드리지 않는다.
 *
 *   호스트 상세(host.php)와 자산 목록의 일괄 확정(assets.php)이 **같은 함수**를 쓴다. 두 벌이면
 *   화면마다 검증과 감사기록이 갈린다 — 확정은 감사 증적이라 갈리면 안 된다.
 *   인가(admin)는 호출부가 이미 확인한 뒤 부른다(인가는 화면이 아니라 서버측에서 정해진다).
 *
 * @param string      $grade       '' 이면 확정 해제(승인 이력도 함께 지운다)
 * @param string|null $criticality '' 이면 미지정으로 지움, null 이면 **그대로 둔다**(일괄 확정용)
 * @return string 확정한 호스트의 fqdn
 * @throws RuntimeException 어휘에 없는 값이거나 호스트를 찾지 못했을 때
 */
function vg_asset_grade_confirm(
    PDO $pdo,
    int $hostId,
    string $grade,
    ?string $criticality,
    string $reason,
    ?int $userId,
    bool $invalidateStructuredReview = true
): string {
    if ($grade !== '' && !isset(VG_ASSET_GRADES[$grade])) {
        throw new RuntimeException('알 수 없는 등급입니다.');
    }
    if ($criticality !== null && $criticality !== '' && !isset(VG_ASSET_CRITICALITY[$criticality])) {
        throw new RuntimeException('알 수 없는 중요도입니다.');
    }
    $reason = mb_strimwidth(trim($reason), 0, 255, '');

    $st = $pdo->prepare('SELECT fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $fqdn = $st->fetchColumn();
    if ($fqdn === false) {
        throw new RuntimeException('호스트를 찾을 수 없습니다.');
    }

    // 등급을 비우면 "확정 해제" — 승인 이력도 함께 지운다(확정이 없는데 확정자가 남아 있으면
    //   감사 때 누가 무엇을 승인했는지 읽을 수 없다). 해제 사실 자체는 아래 감사로그가 남긴다.
    $isClear = $grade === '';
    $set = [];
    $args = [];
    if ($criticality !== null) {           // null 은 "이번 조작에서 중요도는 안 건드린다"
        $set[] = 'criticality = ?';
        $args[] = $criticality !== '' ? $criticality : null;
    }
    $set[] = 'grade = ?';          $args[] = $isClear ? null : $grade;
    $set[] = 'grade_reason = ?';   $args[] = ($isClear || $reason === '') ? null : $reason;
    $set[] = 'approved_by = ?';    $args[] = $isClear ? null : $userId;
    $set[] = 'approved_at = ' . ($isClear ? 'NULL' : 'NOW()');
    $set[] = 'grade_version = grade_version + 1';
    $args[] = $hostId;

    $st = $pdo->prepare(
        'UPDATE tb_host SET ' . implode(', ', $set) . ' WHERE host_id = ? AND is_deleted = 0'
    );
    $st->execute($args);

    // 일괄 확정은 호스트별 구조화 근거를 복제하거나 지우지 않고 "재검토 필요"로 무효화한다.
    // 단일 호스트 경로는 같은 트랜잭션에서 새 검토 정보를 저장하며 이 표식을 다시 0으로 만든다.
    if ($invalidateStructuredReview) {
        $st = $pdo->prepare('UPDATE tb_asset_grade_review SET is_stale = 1, review_version = review_version + 1 WHERE host_id = ?');
        $st->execute([$hostId]);
    }

    $critLabel = ($criticality !== null && $criticality !== '')
        ? ' (중요도 ' . VG_ASSET_CRITICALITY[$criticality] . ')' : '';
    vg_log_activity(
        $pdo, 'HOST', $hostId, 'host_set_grade',
        $isClear
            ? "자산 등급 확정 해제: $fqdn"
            : "자산 등급 확정: $fqdn → $grade" . $critLabel,
        // 확정 근거 원문은 업무·법률 문서 내용을 포함할 수 있어 감사로그에 복제하지 않는다.
        // DB의 grade_reason 호환성은 유지하고, 로그에는 근거 입력 여부만 남긴다.
        ['grade' => $isClear ? null : $grade, 'criticality' => ($criticality ?: null),
         'reason' => (!$isClear && $reason !== '') ? '[REDACTED]' : null,
         'reason_present' => !$isClear && $reason !== ''],
        strict: true
    );

    return (string) $fqdn;
}

/**
 * 등급 범례 한 줄("C · 기밀 / S · 민감 / O · 공개").
 *   화면에 C/S/O 라는 글자만 뜨면 처음 보는 사람은 뜻을 알 수 없다. 어휘를 화면마다 다시 적지 않도록
 *   VG_ASSET_GRADES 에서 만들어 쓴다(하드코딩 분류표를 늘리지 않는다).
 */
function vg_asset_grade_legend(): string
{
    return implode(' / ', VG_ASSET_GRADES);
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
