<?php
declare(strict_types=1);

/**
 * assets/confirm_post.php — 자산 목록의 **등급 일괄 확정 POST 처리**.
 *   assets.php 가 GET 렌더보다 먼저·헤더 출력 전에 부른다 — 이 처리는 성공·실패 모두
 *   vg_redirect_flash() 로 끝나므로(PRG), 순서가 뒤로 밀리면 헤더가 이미 나간 뒤라 깨진다.
 *   검증·기록·감사로그는 여기서 다시 하지 않는다 — vg_asset_grade_confirm() 한 곳이 맡는다.
 */

/* 자산 등급 **일괄 확정** — 함대가 커지면 호스트를 한 대씩 열어 확정하는 건 현실적이지 않다.
 *   경계는 상세 화면과 같다:
 *     · 확정은 **사람이 고른 등급**으로만 한다 — "제안값 그대로 승인" 버튼은 두지 않는다.
 *       그 버튼이 있으면 사실상 시스템이 등급을 정한 것이 된다.
 *     · 검증·기록·감사로그는 host.php 와 같은 vg_asset_grade_confirm() 이 한다(증적이 갈리면 안 된다).
 *     · 일괄로는 **확정만** 한다. 해제는 되돌리기 어려운 조작이라 상세 화면에서 한 대씩 한다.
 *   POST 를 그대로 그리면 새로고침이 재전송되므로 PRG(303)로 돌린다. */
function vg_assets_handle_post(PDO $pdo): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        if (!vg_csrf_check($_POST['csrf'] ?? null)) {
            vg_redirect_flash(['assetErr' => '세션이 만료되었습니다.']);
        }
        // 인가는 클라이언트 숨김이 아니라 여기서 정해진다(폼이 안 보여도 POST 는 올 수 있다).
        if (!vg_has_role('admin')) {
            vg_redirect_flash(['assetErr' => '자산 등급을 확정할 권한이 없습니다.']);
        }
        $me = vg_current_user();
        $ids = array_values(array_unique(array_filter(
            array_map('intval', (array) ($_POST['host_ids'] ?? [])),
            static fn(int $id): bool => $id > 0
        )));
        $bulkGrade  = (string) ($_POST['grade'] ?? '');
        $bulkCrit   = (string) ($_POST['criticality'] ?? '');   // '' = 이번엔 중요도를 안 건드린다
        $bulkReason = (string) ($_POST['grade_reason'] ?? '');
        try {
            if (!$ids) { throw new RuntimeException('확정할 자산을 하나 이상 고르세요.'); }
            if ($bulkGrade === '') { throw new RuntimeException('확정할 등급을 고르세요.'); }
            // 한 페이지에서 고른 것만 오므로 정상 경로에선 못 넘는 수다. 조작된 POST 의 상한선.
            if (count($ids) > 500) { throw new RuntimeException('한 번에 확정할 수 있는 자산은 500대까지입니다.'); }

            // 한 건이라도 실패하면 전부 되돌린다 — "몇 대는 확정되고 몇 대는 아닌" 상태가 제일 나쁘다.
            $pdo->beginTransaction();
            foreach ($ids as $id) {
                vg_asset_grade_confirm(
                    $pdo, $id, $bulkGrade, $bulkCrit === '' ? null : $bulkCrit, $bulkReason, $me['id'] ?? null
                );
            }
            $pdo->commit();
            vg_redirect_flash([
                'assetMsg' => '자산 ' . count($ids) . '대의 등급을 ' . $bulkGrade . ' 로 확정했습니다.',
            ]);
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) { $pdo->rollBack(); }
            error_log('[assets] ' . $e->getMessage());
            // 사람이 고칠 수 있는 입력 오류는 그대로 보여주고, 그 밖의 내부 오류는 감춘다.
            vg_redirect_flash([
                'assetErr' => $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.',
            ]);
        }
    }
}
