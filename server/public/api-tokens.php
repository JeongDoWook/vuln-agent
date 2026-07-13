<?php
declare(strict_types=1);

/**
 * api-tokens.php — Export API 읽기 토큰 발급/폐기 (admin 전용).
 *   외부 시스템(예: AI 보고서 생성기)이 export.php 로 스캔 결과를 읽어갈 때 쓰는 토큰.
 *   발급 시 원문을 1회만 보여준다(DB 엔 해시만 저장). 폐기는 soft-delete → 즉시 무효.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/apitoken.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
vg_require_menu('apitokens');                 // admin 전용(코드에서 admin 만 true)

$pdo = vg_pdo();
$msg = null; $err = null; $newToken = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다.';
    } else {
        $action = $_POST['action'] ?? '';
        $me = vg_current_user();
        try {
            if ($action === 'create') {
                $label = trim((string) ($_POST['label'] ?? ''));
                if ($label === '') {
                    throw new RuntimeException('토큰 이름(용도)을 입력하세요.');
                }
                $r = vg_api_token_issue($pdo, mb_substr($label, 0, 100), $me['id'] ?? null);
                $newToken = $r['token'];   // 이 화면에서만 노출. 저장 안 함.
                vg_log_activity($pdo, 'API_TOKEN', null, 'token_issue', "토큰 발급: {$label}",
                    ['prefix' => $r['prefix']]);
                $msg = "토큰이 발급되었습니다. 아래 값을 지금 복사하세요 — 다시 볼 수 없습니다.";
            } elseif ($action === 'revoke') {
                $id = (int) ($_POST['id'] ?? 0);
                vg_soft_delete($pdo, 'tb_api_tokens', $id);
                vg_log_activity($pdo, 'API_TOKEN', $id, 'token_revoke', '토큰 폐기');
                $msg = '토큰을 폐기했습니다.';
            }
        } catch (Throwable $e) {
            $err = $e->getMessage();
        }
    }
}

$csrf = vg_csrf_token();

// 목록 페이지네이션 — 발급/폐기가 쌓이면 한 화면에 다 쏟지 않는다.
$perPage = vg_perpage();
$page    = max(1, (int) ($_GET['page'] ?? 1));
$total   = (int) $pdo->query('SELECT COUNT(*) FROM tb_api_tokens WHERE is_deleted = 0')->fetchColumn();
$offset  = ($page - 1) * $perPage;

$tokens = $pdo->query(
    "SELECT t.id, t.label, t.token_prefix, t.last_used_at, t.created_at, u.username AS created_by
       FROM tb_api_tokens t
       LEFT JOIN tb_users u ON u.id = t.created_by
      WHERE t.is_deleted = 0
      ORDER BY t.id DESC
      LIMIT $perPage OFFSET $offset"
)->fetchAll();

vg_header('API 토큰', 'apitokens');
?>
  <h1>API 토큰 <span class="hint">(<?= number_format($total) ?>개)</span></h1>
  <div class="sub">
    외부 시스템이 <code>/export.php</code> 로 스캔 결과(JSON/XML)를 읽어갈 때 쓰는 읽기 전용 토큰입니다.
    요청 헤더에 <code>X-API-Token: &lt;토큰&gt;</code> 로 넣습니다. 자세한 사용법은 <code>docs/export-api.md</code>.
  </div>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php if ($newToken !== null): ?>
    <div class="card card--accent">
      <div class="card__body">
        <strong>발급된 토큰 (한 번만 표시됨)</strong>
        <pre class="out selectable"><?= vg_h($newToken) ?></pre>
        <div class="why">이 값은 저장되지 않습니다. 지금 복사해 외부 시스템 설정에 넣으세요. 잃어버리면 새로 발급해야 합니다.</div>
      </div>
    </div>
  <?php endif; ?>

  <div class="card">
    <form method="post" class="toolbar">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="create">
      <input type="text" name="label" placeholder="토큰 용도 (예: AI 보고서 생성기)" maxlength="100" required>
      <button type="submit" class="btn btn--primary">토큰 발급</button>
    </form>
  </div>

  <?php
  vg_table(
      [
          ['label' => '용도'],
          ['label' => '토큰(앞자리)', 'width' => '12rem'],
          ['label' => '마지막 사용', 'width' => '11rem'],
          ['label' => '발급자', 'width' => '8rem'],
          ['label' => '발급일', 'width' => '11rem'],
          ['label' => '', 'width' => '5rem'],
      ],
      $tokens,
      [
          'empty' => [
              'icon'  => '🔑',
              'title' => '발급된 토큰이 없습니다.',
              'hint'  => '외부 시스템이 스캔 결과를 읽어가려면 토큰이 필요합니다. 위에서 발급하세요.',
          ],
          'cell'  => [
              0 => fn($t) => vg_h((string) $t['label']),
              1 => fn($t) => '<code>' . vg_h((string) $t['token_prefix']) . '…</code>',
              2 => fn($t) => $t['last_used_at']
                  ? '<span class="why">' . vg_h((string) $t['last_used_at']) . '</span>'
                  : '<span class="why">미사용</span>',
              3 => fn($t) => vg_h((string) ($t['created_by'] ?? '–')),
              4 => fn($t) => '<span class="why">' . vg_h((string) $t['created_at']) . '</span>',
              5 => fn($t) => '<form method="post" onsubmit="return confirm(\'이 토큰을 폐기할까요? 즉시 무효가 됩니다.\');">'
                  . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                  . '<input type="hidden" name="action" value="revoke">'
                  . '<input type="hidden" name="id" value="' . (int) $t['id'] . '">'
                  . '<button class="btn btn--sm btn--danger">폐기</button></form>',
          ],
      ]
  );
  vg_page_nav($total, $perPage, $page);
  ?>
<?php vg_footer();
