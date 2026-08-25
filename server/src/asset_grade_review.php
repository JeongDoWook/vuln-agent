<?php
declare(strict_types=1);

/**
 * C/S/O 확정에 필요한 구조화 검토 정보.
 *
 * 정보공개법 제9조 해당 호는 사람의 판단 근거 중 하나일 뿐 법률이 C/S/O를 정의하지 않는다.
 * 자유서술 확정 근거의 SSOT는 기존 tb_host.grade_reason 으로 유지한다.
 */

require_once __DIR__ . '/assetgrade.php';

const VG_ASSET_REVIEW_ARTICLE9_ITEMS = [
    '1' => '제1호', '2' => '제2호', '3' => '제3호', '4' => '제4호',
    '5' => '제5호', '6' => '제6호', '7' => '제7호', '8' => '제8호',
    'NONE' => '해당 없음',
];
const VG_ASSET_REVIEW_PUBLICATION_STATES = [
    'PUBLIC' => '외부 공개', 'PARTIAL' => '일부 공개', 'NOT_PUBLIC' => '외부 비공개',
];
const VG_ASSET_REVIEW_TEXT_LIMITS = [
    'article9_reference' => 255,
    'business_category' => 100,
    'data_category' => 100,
    'owning_department' => 120,
    'review_reference' => 255,
];

function vg_asset_grade_review_input_string(array $input, string $field): string
{
    $value = $input[$field] ?? '';
    if (!is_string($value) && !is_int($value)) {
        throw new RuntimeException("잘못된 검토 정보 형식입니다: {$field}");
    }
    return trim((string) $value);
}

/** @return array<string, string|null> */
function vg_asset_grade_review_validate(array $input): array
{
    $item = vg_asset_grade_review_input_string($input, 'article9_item');
    if ($item !== '' && !isset(VG_ASSET_REVIEW_ARTICLE9_ITEMS[$item])) {
        throw new RuntimeException('알 수 없는 정보공개법 제9조 항목입니다.');
    }

    $publication = vg_asset_grade_review_input_string($input, 'external_publication_state');
    if ($publication !== '' && !isset(VG_ASSET_REVIEW_PUBLICATION_STATES[$publication])) {
        throw new RuntimeException('알 수 없는 외부 공개 상태입니다.');
    }

    $review = [
        'article9_item' => $item === '' ? null : $item,
        'external_publication_state' => $publication === '' ? null : $publication,
    ];
    foreach (VG_ASSET_REVIEW_TEXT_LIMITS as $field => $limit) {
        $value = vg_asset_grade_review_input_string($input, $field);
        if (mb_strlen($value) > $limit) {
            throw new RuntimeException("검토 정보가 너무 깁니다: {$field}");
        }
        $review[$field] = $value === '' ? null : $value;
    }

    $date = vg_asset_grade_review_input_string($input, 'next_review_date');
    if ($date !== '') {
        $parsed = DateTimeImmutable::createFromFormat('!Y-m-d', $date);
        $errors = DateTimeImmutable::getLastErrors();
        if ($parsed === false || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
            || $parsed->format('Y-m-d') !== $date) {
            throw new RuntimeException('재검토일은 올바른 날짜여야 합니다.');
        }
        $today = new DateTimeImmutable('today');
        if ($parsed < $today || $parsed > $today->modify('+10 years')) {
            throw new RuntimeException('재검토일은 오늘부터 10년 이내여야 합니다.');
        }
    }
    $review['next_review_date'] = $date === '' ? null : $date;
    return $review;
}

/** @return list<string> */
function vg_asset_grade_review_missing(array $review): array
{
    $labels = [
        'article9_item' => '정보공개법 제9조 해당 호',
        'article9_reference' => '조문·판단 참조',
        'business_category' => '업무 유형',
        'data_category' => '데이터 유형',
        'owning_department' => '소유 부서',
        'external_publication_state' => '외부 공개 상태',
        'review_reference' => '검토 문서·티켓',
        'next_review_date' => '다음 검토일',
    ];
    $missing = [];
    foreach ($labels as $field => $label) {
        if (($review[$field] ?? null) === null || trim((string) $review[$field]) === '') {
            $missing[] = $label;
        }
    }
    return $missing;
}

function vg_asset_grade_review_overdue(array $review, ?DateTimeImmutable $today = null): bool
{
    $date = (string) ($review['next_review_date'] ?? '');
    if ($date === '') { return false; }
    $parsed = DateTimeImmutable::createFromFormat('!Y-m-d', $date);
    return $parsed !== false && $parsed < ($today ?? new DateTimeImmutable('today'));
}

function vg_asset_grade_review_load(PDO $pdo, int $hostId, bool $forUpdate = false): array
{
    $st = $pdo->prepare('SELECT * FROM tb_asset_grade_review WHERE host_id = ?' . ($forUpdate ? ' FOR UPDATE' : ''));
    $st->execute([$hostId]);
    $row = $st->fetch();
    return $row === false ? [] : $row;
}

function vg_asset_grade_review_save(
    PDO $pdo,
    int $hostId,
    array $review,
    int $expectedVersion,
    ?int $userId,
    ?string $subject = null
): void
{
    $previous = vg_asset_grade_review_load($pdo, $hostId, true);
    $currentVersion = (int) ($previous['review_version'] ?? 0);
    if ($currentVersion !== $expectedVersion) {
        throw new RuntimeException('다른 관리자가 검토 정보를 변경했습니다. 화면을 새로고침한 뒤 다시 확인하세요.');
    }
    $fields = array_keys(VG_ASSET_REVIEW_TEXT_LIMITS);
    array_splice($fields, 0, 0, ['article9_item']);
    $fields[] = 'external_publication_state';
    $fields[] = 'next_review_date';
    $columns = implode(', ', $fields);
    $updates = implode(', ', array_map(static fn(string $f): string => "$f = VALUES($f)", $fields));
    $values = array_map(static fn(string $f) => $review[$f] ?? null, $fields);

    $st = $pdo->prepare(
        "INSERT INTO tb_asset_grade_review (host_id, $columns, is_stale, review_version, reviewed_by, reviewed_at)
         VALUES (?, " . implode(', ', array_fill(0, count($fields), '?')) . ", 0, 1, ?, NOW())
         ON DUPLICATE KEY UPDATE $updates, is_stale = 0, review_version = review_version + 1,
                                 reviewed_by = VALUES(reviewed_by), reviewed_at = NOW()"
    );
    $st->execute(array_merge([$hostId], $values, [$userId]));

    // 문서/티켓 참조와 자유서술 내용은 감사로그에 넣지 않는다. 완성도와 변경 사실만 기록한다.
    $missing = vg_asset_grade_review_missing($review);
    $changedFields = [];
    $presenceChanges = [];
    foreach ($fields as $field) {
        $before = $previous[$field] ?? null;
        $after = $review[$field] ?? null;
        if ($before !== $after) {
            $changedFields[] = $field;
            if (($before === null) !== ($after === null)) {
                $presenceChanges[$field] = $after === null ? 'cleared' : 'added';
            }
        }
    }
    vg_log_activity($pdo, 'HOST', $hostId, 'host_grade_review_save', '자산 등급 검토 정보 저장', [
        'completed_fields' => count(VG_ASSET_REVIEW_TEXT_LIMITS) + 3 - count($missing),
        'missing_fields' => $missing,
        'changed_fields' => $changedFields,
        'presence_changes' => $presenceChanges,
    ], $userId, subject: $subject, action: 'UPDATE', strict: true);
}

/**
 * 등급과 구조화 검토 정보를 검증 후 한 트랜잭션으로 확정한다.
 *
 * @param bool $preserveOnly true면 $input 의 9개 검토 필드는 이번에 사람이 입력한 값이
 *   아니라 폼에 입력칸이 없어 DB의 기존값을 그대로 승계하는 것이다(host/grade.php 는 이
 *   9개 칸을 걷어냈다). 이 경우 validate() 로 다시 검증하지 않는다 — 재검토일 같은
 *   "오늘 이후" 제약을 이미 지난 기존값에 다시 들이대면 재검토일이 지난 자산은 등급을
 *   영원히 못 바꾸게 된다. save() 도 호출하지 않는다 — 9개 항목을 아무도 다시 보지
 *   않았는데 reviewed_by/reviewed_at/is_stale 이 지금 시각으로 갱신되면 안 된다.
 *   등급 확정 해제($grade === '')는 사람이 명시적으로 고른 조작이라 $preserveOnly 와
 *   무관하게 그대로 삭제한다.
 */
function vg_asset_grade_review_confirm(
    PDO $pdo,
    int $hostId,
    string $grade,
    ?string $criticality,
    string $reason,
    array $input,
    ?int $userId,
    bool $preserveOnly = false
): string {
    $isClear = $grade === '';
    $review = ($isClear || $preserveOnly) ? [] : vg_asset_grade_review_validate($input);
    $versionRaw = array_key_exists('review_version', $input)
        ? vg_asset_grade_review_input_string($input, 'review_version') : '0';
    if (!ctype_digit($versionRaw) || strlen($versionRaw) > 20) {
        throw new RuntimeException('잘못된 검토 버전입니다.');
    }
    $expectedVersion = (int) $versionRaw;
    $gradeVersionRaw = vg_asset_grade_review_input_string($input, 'grade_version');
    if (!ctype_digit($gradeVersionRaw) || strlen($gradeVersionRaw) > 20) {
        throw new RuntimeException('잘못된 등급 확정 버전입니다.');
    }
    $expectedGradeVersion = (int) $gradeVersionRaw;
    $ownsTransaction = !$pdo->inTransaction();
    if ($ownsTransaction) { $pdo->beginTransaction(); }
    try {
        // 구조화 행이 아직 없는 호스트도 같은 초의 bulk 확정과 충돌을 검출하도록 카운터를 잠근다.
        $st = $pdo->prepare('SELECT grade_version FROM tb_host WHERE host_id = ? AND is_deleted = 0 FOR UPDATE');
        $st->execute([$hostId]);
        $gradeVersion = $st->fetchColumn();
        if ($gradeVersion === false) { throw new RuntimeException('호스트를 찾을 수 없습니다.'); }
        if ((int) $gradeVersion !== $expectedGradeVersion) {
            throw new RuntimeException('다른 관리자가 자산 등급을 변경했습니다. 화면을 새로고침한 뒤 다시 확인하세요.');
        }
        $fqdn = vg_asset_grade_confirm($pdo, $hostId, $grade, $criticality, $reason, $userId, false);
        if ($isClear) {
            // 모든 확정 경로가 host → review 순으로 잠가 bulk 확정과의 교착을 피한다.
            // 버전 충돌이면 아래 예외가 앞선 host 변경까지 함께 롤백한다.
            $previous = vg_asset_grade_review_load($pdo, $hostId, true);
            if ((int) ($previous['review_version'] ?? 0) !== $expectedVersion) {
                throw new RuntimeException('다른 관리자가 검토 정보를 변경했습니다. 화면을 새로고침한 뒤 다시 확인하세요.');
            }
            $st = $pdo->prepare('DELETE FROM tb_asset_grade_review WHERE host_id = ?');
            $st->execute([$hostId]);
            $reviewFields = array_merge(['article9_item'], array_keys(VG_ASSET_REVIEW_TEXT_LIMITS),
                ['external_publication_state', 'next_review_date']);
            $clearedFields = array_values(array_filter($reviewFields,
                static fn(string $field): bool => ($previous[$field] ?? null) !== null));
            vg_log_activity($pdo, 'HOST', $hostId, 'host_grade_review_clear', '자산 등급 검토 정보 삭제', [
                'structured_review_cleared' => true,
                'row_existed' => $previous !== [],
                'previous_completed_fields' => count($clearedFields),
                'cleared_fields' => $clearedFields,
            ], $userId, subject: $fqdn, action: 'DELETE', strict: true);
        } elseif (!$preserveOnly) {
            vg_asset_grade_review_save($pdo, $hostId, $review, $expectedVersion, $userId, $fqdn);
        }
        if ($ownsTransaction) { $pdo->commit(); }
        return $fqdn;
    } catch (Throwable $e) {
        if ($ownsTransaction && $pdo->inTransaction()) { $pdo->rollBack(); }
        throw $e;
    }
}
