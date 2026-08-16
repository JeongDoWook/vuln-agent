<?php
declare(strict_types=1);

/**
 * assetgrade/confirm.php — 자산 등급 **확정**(사람의 판정을 tb_host 에 쓰는 유일한 경로).
 *   호스트 상세(host.php)와 자산 목록 일괄 확정(assets.php)이 **같은 함수**를 쓴다.
 *   두 벌이면 화면마다 검증과 감사기록이 갈리는데, 확정은 감사 증적이라 갈리면 안 된다.
 */

require_once __DIR__ . '/../audit.php';   // vg_log_activity — 등급 확정은 감사 대상이다

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
