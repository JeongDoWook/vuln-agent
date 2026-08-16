<?php
declare(strict_types=1);

/**
 * assetgrade/signal_defs.php — 등급 **초안 제안이 무엇을 근거로 보는가**(신호 정의)와,
 *   그 근거 문자열·프로세스 목록을 만드는 헬퍼.
 *   여기 있는 것은 전부 "무엇을 신호로 칠지" 의 정의뿐이다 — 실제 수집은 signals.php,
 *   등급 판정은 suggest.php 가 한다.
 */

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
