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

/**
 * 프로세스 이름으로 읽는 **역할 신호**(로그·백업 외). 이름만 보는 약한 근거라 여기서 나오는 것도
 *   전부 `S` **초안**일 뿐이고, 확정은 사람이 한다 — 이 파일 첫머리의 경계와 같다.
 *
 *   왜 C 를 자동 제안하지 않나: C(기밀)는 「정보공개법」 제9조 비공개 대상정보에 해당한다는
 *   **법적 판단**이라, "slapd 가 떠 있다" 같은 관측으로는 성립하지 않는다. 대신 자격증명·비밀을
 *   보관하는 역할은 `note` 로 "C 검토 대상" 임을 사람에게 알리고, 제안 등급 자체는 S 에 둔다
 *   (억지 제안 금지 — 확신이 없으면 올리지 않는다).
 *
 *   source 는 'process' 하나로 둔다. 이 값은 이력이 "수집 누락 vs 근거 없음" 을 가르는 데 쓰는
 *   **수집 단계 식별자**이고(assetgrade_history.php), 이 신호들의 단계는 전부 runtime_processes 다.
 *   근거 종류를 더 잘게 쪼개면 그 판정만 흐려진다.
 */
const VG_ASSET_DATA_ROLES = [
    'datastore' => [
        'label' => '업무 데이터 저장소',
        'note'  => '업무정보를 실제로 보관하는 자산입니다. 저장 중인 정보의 등급을 따라가야 합니다.',
        'processes' => [
            'mysqld', 'mariadbd', 'postgres', 'mongod', 'redis-server', 'db2sysc', 'sqlservr',
            'oracle', 'clickhouse-serv', 'influxd', 'cassandra', 'elasticsearch', 'etcd',
        ],
    ],
    'identity' => [
        'label' => '인증·비밀 관리(C 검토)',
        'note'  => '자격증명·비밀을 보관하거나 발급하는 자산입니다. C(기밀) 해당 여부는 사람이 판단해야 합니다.',
        'processes' => [
            'slapd', 'ns-slapd', 'krb5kdc', 'kadmind', 'vault', 'keycloak', 'ipa-server',
            'freeradius', 'radiusd', 'stepca',
        ],
    ],
];

/**
 * 보호수준 판단을 뒷받침하는 **보조 신호**가 볼 CCE 코드 접두. 암호화·로그 통제의 FAIL 은
 *   "이 자산이 지금 그 수준의 보호를 하고 있지 않다"는 사실이라 등급 확정 회의에 필요한 재료다.
 *   접두로 두는 이유는 cce.php 가 코드 체계(CCE-CRYPTO-*, CCE-LOG-*)로 이미 묶어 두었기 때문이다.
 */
const VG_ASSET_PROTECTION_CCE_PREFIXES = ['CCE-CRYPTO-', 'CCE-LOG-'];

/**
 * 계정 인벤토리를 "검토 신호"로 볼 임계값. 이 수를 넘으면 사람이 한 번 봐야 한다는 뜻이지,
 *   등급이 올라간다는 뜻이 아니다(보조 신호는 등급도 source 도 만들지 않는다).
 */
const VG_ASSET_ACCOUNT_REVIEW_MIN = 5;
const VG_ASSET_SUDOER_REVIEW_MIN  = 3;

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
 * 등급 제안이 보는 **모든** 프로세스 이름(로그·백업 + 데이터 저장소 + 인증·비밀).
 *   제안 질의와 스냅샷 identity 가 **같은 목록**을 봐야 한다 — 목록이 갈리면 새 신호에 해당하는
 *   프로세스가 뜨고 꺼져도 재평가가 안 걸린다(기존 identity 주석과 같은 사고).
 */
function vg_asset_grade_watch_procs(): array
{
    return array_values(array_unique(array_merge(
        vg_asset_logbackup_procs(),
        ...array_column(VG_ASSET_DATA_ROLES, 'processes')
    )));
}

/**
 * 스냅샷 identity에 넣을 등급 분류 관련 프로세스 정규형.
 * 전체 프로세스를 해시하면 cron/ssh 같은 일시적 실행마다 무거운 새 스캔이 생긴다.
 */
function vg_asset_grade_relevant_process_rows(array $rows): array
{
    $procs = vg_asset_grade_watch_procs();
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
 * 이 스캔의 수집 데이터에서 **등급 판단 신호를 전부** 모은다. 제안(아래 vg_asset_grade_suggest)과
 *   화면의 근거 칩(host.php 자산 등급 카드)이 **같은 출처**를 보게 하는 자리다 — 화면이 근거를
 *   따로 조립하면 "제안은 S 인데 칩은 다른 얘기" 가 된다.
 *
 *   kind 는 두 종류다.
 *     primary : 등급을 만드는 신호(grade·source 를 갖는다).
 *     review  : 등급을 만들지 **않는** 보조 신호(사람이 확정할 때 볼 재료). 이 신호만 있으면
 *               제안은 여전히 없다 — 근거 없이 등급을 찍지 않는다는 원칙 그대로다.
 *
 * @return list<array{key:string,kind:string,grade:?string,source:?string,label:string,tone:string,count:int,evidence:string,note:string}>
 */
function vg_asset_grade_signals(PDO $pdo, int $scanId): array
{
    $signals = [];

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
        $signals[] = [
            'key' => 'log_listener', 'kind' => 'primary', 'grade' => 'S', 'source' => 'log_listener',
            'label' => '원격 로그 수신', 'tone' => 'high', 'count' => $listenerCount,
            'evidence' => vg_asset_grade_evidence('원격 로그 수신', $items, 1, $listenerCount),
            'note' => '다른 호스트의 로그를 받는 자산입니다 — 「기타: 로그 및 임시백업 등」이 명시적 S 입니다.',
        ];
    }

    // ② 역할별 프로세스 증거를 전부 모은다. 같은 comm 의 여러 PID는 설명에서 한 번만 센다.
    // 전달자·일회성 도구도 S '초안'의 검토 신호지만 라벨로 약도를 보존하며 법적 확정은 하지 않는다.
    //   로그·백업과 데이터·인증 역할을 **한 질의로** 읽는다(같은 테이블·같은 스캔 — 쿼리를 나눌 이유가 없다).
    $allProcs = vg_asset_grade_watch_procs();
    $ph = implode(',', array_fill(0, count($allProcs), '?'));
    $st = $pdo->prepare(
        "SELECT DISTINCT LOWER(comm) AS comm FROM tb_process
          WHERE scan_id = ? AND LOWER(comm) IN ($ph) ORDER BY comm"
    );
    $st->execute(array_merge([$scanId], $allProcs));
    $running = $st->fetchAll(PDO::FETCH_COLUMN);
    foreach (VG_ASSET_LOGBACKUP_ROLES as $roleKey => $role) {
        $names = $role['processes'];
        $matched = array_values(array_intersect($names, $running));
        sort($matched, SORT_STRING);
        if (!$matched) { continue; }
        $signals[] = [
            'key' => 'logbackup_' . $roleKey, 'kind' => 'primary', 'grade' => 'S', 'source' => 'process',
            'label' => $role['label'], 'tone' => 'med', 'count' => count($matched),
            'evidence' => vg_asset_grade_evidence($role['label'], $matched),
            'note' => '로그·백업을 처리하는 프로세스입니다. 이름만 본 약한 근거라 초안에만 씁니다.',
        ];
    }
    // ②-b 이미 수집해 둔 프로세스로 읽는 나머지 역할(데이터 저장소 · 인증/비밀 관리).
    //   새로 수집하는 항목이 없다 — 같은 tb_process 를 다르게 읽을 뿐이다.
    foreach (VG_ASSET_DATA_ROLES as $roleKey => $role) {
        $matched = array_values(array_intersect($role['processes'], $running));
        sort($matched, SORT_STRING);
        if (!$matched) { continue; }
        $signals[] = [
            'key' => 'role_' . $roleKey, 'kind' => 'primary', 'grade' => 'S', 'source' => 'process',
            'label' => $role['label'], 'tone' => 'high', 'count' => count($matched),
            'evidence' => vg_asset_grade_evidence($role['label'], $matched),
            'note' => $role['note'],
        ];
    }

    // ③ 외부 노출 — 인터넷에서 닿는 포트가 있으면 O 영역 후보.
    $st = $pdo->prepare(
        "SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ? AND scope = 'EXTERNAL'"
    );
    $st->execute([$scanId]);
    $ext = (int) $st->fetchColumn();
    if ($ext > 0) {
        $signals[] = [
            'key' => 'external_exposure', 'kind' => 'primary', 'grade' => 'O', 'source' => 'external_exposure',
            'label' => '외부 노출', 'tone' => 'crit', 'count' => $ext,
            'evidence' => 'O 외부노출 ' . $ext . '개.',
            'note' => '인터넷에서 닿는 포트가 있습니다. 열려 있다는 사실이 "공개해도 되는 정보"를 뜻하지는 않습니다.',
        ];
    }

    // ④ 보조 신호 — 등급을 만들지 않는다. 사람이 확정 회의에서 볼 재료만 모은다.
    //   전부 이미 수집된 표를 세는 값싼 COUNT 다(새 수집 항목을 만들지 않는다).
    $st = $pdo->prepare(
        'SELECT COUNT(*) AS people, SUM(is_sudoer = 1) AS sudoers
           FROM tb_host_account WHERE scan_id = ? AND is_deleted = 0 AND is_system = 0'
    );
    $st->execute([$scanId]);
    $acc = $st->fetchAll(PDO::FETCH_ASSOC)[0] ?? [];
    $people  = (int) ($acc['people'] ?? 0);
    $sudoers = (int) ($acc['sudoers'] ?? 0);
    if ($people >= VG_ASSET_ACCOUNT_REVIEW_MIN || $sudoers >= VG_ASSET_SUDOER_REVIEW_MIN) {
        $signals[] = [
            'key' => 'accounts', 'kind' => 'review', 'grade' => null, 'source' => null,
            'label' => '계정 인벤토리', 'tone' => 'muted', 'count' => $people,
            'evidence' => '사람 계정 ' . $people . '명(sudo ' . $sudoers . '명).',
            'note' => '사람이 여럿 붙는 자산입니다 — 접근통제 범위를 등급과 함께 검토하세요.',
        ];
    }

    $ccePh = implode(' OR ', array_fill(0, count(VG_ASSET_PROTECTION_CCE_PREFIXES), 'code LIKE ?'));
    $cceArgs = [$scanId];
    foreach (VG_ASSET_PROTECTION_CCE_PREFIXES as $prefix) { $cceArgs[] = $prefix . '%'; }
    $st = $pdo->prepare(
        "SELECT COUNT(*) FROM tb_cce_finding
          WHERE scan_id = ? AND result = 'FAIL' AND ($ccePh)"
    );
    $st->execute($cceArgs);
    $cceFail = (int) $st->fetchColumn();
    if ($cceFail > 0) {
        $signals[] = [
            'key' => 'protection_cce', 'kind' => 'review', 'grade' => null, 'source' => null,
            'label' => '암호화·로그 통제 미흡', 'tone' => 'warn', 'count' => $cceFail,
            'evidence' => '암호화·로그 통제 FAIL ' . $cceFail . '건.',
            'note' => '지금 보호수준이 등급에 못 미칠 수 있습니다(FAIL 이 등급을 낮추는 근거는 아닙니다).',
        ];
    }

    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_container WHERE scan_id = ? AND is_deleted = 0');
    $st->execute([$scanId]);
    $ctr = (int) $st->fetchColumn();
    if ($ctr > 0) {
        $signals[] = [
            'key' => 'containers', 'kind' => 'review', 'grade' => null, 'source' => null,
            'label' => '컨테이너 워크로드', 'tone' => 'muted', 'count' => $ctr,
            'evidence' => '컨테이너 ' . $ctr . '개.',
            'note' => '여러 워크로드가 한 자산에 올라 있습니다 — 정보시스템 등급은 최고등급을 승계합니다.',
        ];
    }

    return $signals;
}

/**
 * 이 스캔의 수집 데이터만 보고 **초안 등급을 제안**한다. 확신이 없으면 제안하지 않는다.
 *
 * 우선순위: S 근거(로그·백업 / 데이터 저장소 / 인증·비밀) > 외부노출(O). 둘 다 해당하면
 *   보호수준이 높은 S 를 제안한다 — 외부에 열려 있다는 사실이 "공개해도 되는 정보"를
 *   뜻하지는 않기 때문이다. **C 는 자동으로 제안하지 않는다**(VG_ASSET_DATA_ROLES 주석 참고).
 *
 * source 는 이 제안을 **처음 뒷받침한** 근거의 종류다(우선순위대로 log_listener > process >
 *   external_exposure). 이력 기록이 "그 근거를 만든 수집 단계가 실제로 들어왔는가"를 판정해
 *   수집 누락과 근거 없음을 구분하는 데 쓴다 — 근거를 여러 개 모아도 판정에 필요한 단계는
 *   가장 먼저 성립한 근거의 단계다. 보조 신호(kind=review)는 source 를 만들지 않는다:
 *   그 신호만 있는 자산은 여전히 "근거 없음" 이지 "판정 불가" 가 아니다.
 *
 * @return array{grade:string,source:string,reason:string}|null 제안이 없으면 null
 */
function vg_asset_grade_suggest(PDO $pdo, int $scanId): ?array
{
    $signals = vg_asset_grade_signals($pdo, $scanId);

    $sEvidence = [];
    $sSource = null;
    $oEvidence = null;
    $review = [];
    foreach ($signals as $sig) {
        if ($sig['kind'] === 'review') { $review[] = $sig['evidence']; continue; }
        if ($sig['grade'] === 'S') {
            $sEvidence[] = $sig['evidence'];
            $sSource = $sSource ?? (string) $sig['source'];
        } elseif ($sig['grade'] === 'O') {
            $oEvidence = $sig['evidence'];
        }
    }

    if ($sEvidence) {
        // 보조 신호는 **맨 뒤**에 붙인다 — 255자 상한에 잘리더라도 등급을 만든 근거가 먼저 남는다.
        $sEvidence = array_merge($sEvidence, $review);
        if ($oEvidence !== null) { array_splice($sEvidence, 1, 0, [$oEvidence]); }
        array_unshift($sEvidence, 'S 초안(사람 확인 전 미확정).');
        return [
            'grade'  => 'S',
            'source' => (string) $sSource,
            'reason' => vg_asset_grade_reason($sEvidence),
        ];
    }

    if ($oEvidence !== null) {
        return [
            'grade'  => 'O',
            'source' => 'external_exposure',
            'reason' => vg_asset_grade_reason(
                array_merge([$oEvidence, '사람 확인 전에는 확정되지 않습니다.'], $review)
            ),
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
