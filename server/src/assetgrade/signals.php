<?php
declare(strict_types=1);

/**
 * assetgrade/signals.php — 한 스캔의 수집 데이터에서 등급 판단 **신호를 모은다**(조회층).
 *   무엇을 신호로 칠지는 signal_defs.php 가 정의하고, 모은 신호로 등급을 제안하는 것은
 *   suggest.php 다 — 이 파일은 DB 를 읽어 신호 목록을 만드는 일만 한다.
 */

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
