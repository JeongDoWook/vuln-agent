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

// 발급 실패 시 모달을 다시 열고 입력한 용도를 되살린다.
$issueFailed = false; $issueLabel = '';

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
            error_log('[api-tokens] ' . $e->getMessage());
            $err = '처리 중 오류가 발생했습니다.';
            if ($action === 'create') {
                $issueFailed = true;
                $issueLabel  = trim((string) ($_POST['label'] ?? ''));
            }
        }
    }
    // PRG — 결과를 세션에 넘기고 GET 으로 되돌린다. 여기서 바로 그리면 새로고침이
    // 발급 POST 를 재전송해 같은 용도의 토큰이 계속 쌓인다.
    vg_redirect_flash([
        'msg' => $msg, 'err' => $err, 'token' => $newToken,
        'failed' => $issueFailed, 'label' => $issueLabel,
    ]);
}

$f           = vg_flash_take();
$msg         = $f['msg']   ?? null;
$err         = $f['err']   ?? null;
$newToken    = $f['token'] ?? null;   // 리다이렉트 뒤 1회만 보여주고 세션에서 사라진다.
$issueFailed = (bool) ($f['failed'] ?? false);
$issueLabel  = (string) ($f['label'] ?? '');

$csrf = vg_csrf_token();

// 목록 검색·페이지네이션. 검색값은 바인딩하고 LIMIT/OFFSET 은 검증된 정수만 사용한다.
$q       = trim((string) ($_GET['q'] ?? ''));
$perPage = vg_perpage();
$page    = vg_page();
$where   = 't.is_deleted = 0';
$params  = [];
if ($q !== '') {
    $where .= ' AND (t.label LIKE ? OR t.token_prefix LIKE ?)';
    $like = '%' . $q . '%';
    $params = [$like, $like];
}
$count = $pdo->prepare("SELECT COUNT(*) FROM tb_api_tokens t WHERE $where");
$count->execute($params);
$total  = (int) $count->fetchColumn();
$offset = ($page - 1) * $perPage;

$list = $pdo->prepare(
    "SELECT t.id, t.label, t.token_prefix, t.last_used_at, t.created_at, u.username AS created_by
       FROM tb_api_tokens t
       LEFT JOIN tb_users u ON u.id = t.created_by
      WHERE $where
      ORDER BY t.id DESC
      LIMIT $perPage OFFSET $offset"
);
$list->execute($params);
$tokens = $list->fetchAll();

vg_header('API 토큰', 'apitokens');
?>
  <?php vg_page_title('API 토큰', 'API ACCESS', '', [
      'count' => $total, 'count_label' => '개',
      'actions' => vg_capture(static fn() => vg_modal_btn('issueToken', '+ 토큰 발급')),
  ]); ?>
  <div class="sub">
    외부 시스템이 <code>/export.php</code> 로 스캔 결과(JSON/XML)를 읽어갈 때 쓰는 읽기 전용 토큰입니다.
    요청 헤더에 <code>X-API-Token: &lt;토큰&gt;</code> 로 넣습니다. 자세한 사용법은 <code>docs/dev/export-api.md</code>.
  </div>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'value' => $q, 'placeholder' => '용도·토큰 앞자리 검색'],
  ]); ?>

  <?php if ($newToken !== null): ?>
    <div class="card card--accent">
      <div class="card__body">
        <strong>발급된 토큰 (한 번만 표시됨)</strong>
        <pre class="out selectable"><?= vg_h($newToken) ?></pre>
        <div class="actions"><?php vg_copy_btn($newToken, '토큰 복사'); ?></div>
        <div class="why">이 값은 저장되지 않습니다. 지금 복사해 외부 시스템 설정에 넣으세요. 잃어버리면 새로 발급해야 합니다.</div>
      </div>
    </div>
  <?php endif; ?>

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
          'empty' => $q !== '' ? [
              'icon' => '🔍', 'title' => '검색 결과가 없습니다.',
              'hint' => '용도나 토큰 앞자리를 다시 확인하세요.',
              'cta' => ['href' => '/api-tokens.php', 'label' => '검색 초기화'],
          ] : [
              'icon' => '🔑', 'title' => '발급된 토큰이 없습니다.',
              'hint' => '외부 시스템이 스캔 결과를 읽어가려면 토큰이 필요합니다. 위에서 발급하세요.',
          ],
          'cell'  => [
              0 => fn($t) => vg_h((string) $t['label']),
              1 => fn($t) => '<code>' . vg_h((string) $t['token_prefix']) . '…</code>',
              2 => fn($t) => $t['last_used_at']
                  ? '<span class="why">' . vg_h((string) $t['last_used_at']) . '</span>'
                  : '<span class="why">미사용</span>',
              3 => fn($t) => vg_h((string) ($t['created_by'] ?? '–')),
              4 => fn($t) => '<span class="why">' . vg_h((string) $t['created_at']) . '</span>',
              5 => fn($t) => '<form method="post" data-confirm="이 토큰을 폐기할까요? 즉시 무효가 됩니다.">'
                  . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                  . '<input type="hidden" name="action" value="revoke">'
                  . '<input type="hidden" name="id" value="' . (int) $t['id'] . '">'
                  . '<button class="btn btn--sm btn--danger">폐기</button></form>',
          ],
      ]
  );
  vg_page_nav($total, $perPage, $page);

  // 발급 폼은 가끔 쓰는 것 — 목록 위에 늘 펼쳐둘 이유가 없다. 실패하면 다시 연다.
  vg_modal_open('issueToken', 'API 토큰 발급', '', $issueFailed);
  ?>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="create">
      <label>토큰 용도</label>
      <input type="text" name="label" value="<?= vg_h($issueLabel) ?>"
             placeholder="예: AI 보고서 생성기" maxlength="100" required autocomplete="off">
      <div class="why">발급된 토큰 원문은 <strong>이 화면에서 한 번만</strong> 보여집니다(DB 엔 해시만 저장).</div>
      <?php vg_modal_foot('발급', ['loading' => '발급 중…']); ?>
    </form>
  <?php vg_modal_close(); ?>
<?php vg_footer();
