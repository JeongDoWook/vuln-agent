<?php
declare(strict_types=1);

/**
 * agent-tokens.php — 에이전트별 개별 수집 토큰 발급/폐기 (admin·operator).
 *   각 토큰은 발급 시 정한 호스트(fqdn)에 묶여, 그 호스트의 스캔만 갱신할 수 있다.
 *   침해된 대상이 남의 fqdn 을 위조하는 것을 ingest.php 가 막는다.
 *   발급 시 원문을 1회만 보여준다(DB 엔 해시만 저장). 폐기는 is_revoked → 즉시 무효.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/agenttoken.php';
require_once __DIR__ . '/../src/audit.php';        // vg_log_activity
require_once __DIR__ . '/../src/tokenexpiry.php';  // 유효기간 선택지·표시(API 키와 공용)
vg_require_menu('agenttokens');               // admin·operator

$pdo = vg_pdo();
$msg = null; $err = null; $newToken = null;

// 발급 실패 시 모달을 다시 열고 입력값을 되살린다.
$issueFailed = false; $issueFqdn = ''; $issueLabel = ''; $issueDays = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다.';
    } else {
        $action = $_POST['action'] ?? '';
        $me = vg_current_user();
        try {
            if ($action === 'create') {
                $fqdn  = trim((string) ($_POST['fqdn'] ?? ''));
                $label = trim((string) ($_POST['label'] ?? ''));
                if ($fqdn === '')  { throw new RuntimeException('바인딩할 호스트(fqdn)를 입력하세요.'); }
                if ($label === '') { $label = $fqdn . ' 수집 에이전트'; }   // 비우면 호스트명으로 기본값
                $days = vg_token_expiry_days_input($_POST['expires_days'] ?? 0);
                $r = vg_agent_token_issue($pdo, mb_substr($fqdn, 0, 255), mb_substr($label, 0, 100), $me['id'] ?? null, $days);
                $newToken = $r['token'];   // 이 화면에서만 노출. 저장 안 함.
                vg_log_activity($pdo, 'AGENT_TOKEN', null, 'agent_token_issue',
                    "에이전트 토큰 발급: {$fqdn}",
                    ['fqdn' => $fqdn, 'prefix' => $r['prefix'], 'auto_revoked' => $r['revoked'],
                     'expires_at' => $r['expires_at'] ?? '무기한'],
                    subject: $fqdn, action: 'CREATE');
                $expiryNote = $r['expires_at'] !== null ? "유효기간 {$r['expires_at']} 까지. " : '';
                $msg = $r['revoked'] > 0
                    ? "토큰이 발급되었습니다. {$expiryNote}같은 호스트의 기존 활성 토큰 {$r['revoked']}개는 자동 폐기되었습니다. 아래 값을 지금 복사하세요 — 다시 볼 수 없습니다."
                    : "토큰이 발급되었습니다. {$expiryNote}아래 값을 지금 복사하세요 — 다시 볼 수 없습니다.";
            } elseif ($action === 'revoke') {
                $id = (int) ($_POST['id'] ?? 0);
                vg_agent_token_revoke($pdo, $id);
                vg_log_activity($pdo, 'AGENT_TOKEN', $id, 'agent_token_revoke', '에이전트 토큰 폐기');
                $msg = '토큰을 폐기했습니다. 즉시 무효가 됩니다.';
            } elseif ($action === 'delete') {
                $id = (int) ($_POST['id'] ?? 0);
                vg_agent_token_delete($pdo, $id);   // 폐기된 것만 지워진다(아니면 예외)
                vg_log_activity($pdo, 'AGENT_TOKEN', $id, 'agent_token_delete', '에이전트 토큰 삭제(목록에서 제거)');
                $msg = '폐기된 토큰을 목록에서 지웠습니다. 이력은 활동 로그에 남습니다.';
            }
        } catch (Throwable $e) {
            error_log('[agent-tokens] ' . $e->getMessage());
            $err = '처리 중 오류가 발생했습니다.';
            if ($action === 'create') {
                $issueFailed = true;
                $issueFqdn   = trim((string) ($_POST['fqdn'] ?? ''));
                $issueLabel  = trim((string) ($_POST['label'] ?? ''));
                $issueDays   = (int) ($_POST['expires_days'] ?? 0);
            }
        }
    }
    // PRG — 결과를 세션에 넘기고 GET 으로 되돌린다. 여기서 바로 그리면 새로고침이
    // 발급 POST 를 재전송해, 방금 준 토큰을 자동 폐기하고 또 발급한다.
    vg_redirect_flash([
        'msg' => $msg, 'err' => $err, 'token' => $newToken,
        'failed' => $issueFailed, 'fqdn' => $issueFqdn, 'label' => $issueLabel, 'days' => $issueDays,
    ]);
}

$f           = vg_flash_take();
$msg         = $f['msg']    ?? null;
$err         = $f['err']    ?? null;
$newToken    = $f['token']  ?? null;   // 리다이렉트 뒤 1회만 보여주고 세션에서 사라진다.
$issueFailed = (bool) ($f['failed'] ?? false);
$issueFqdn   = (string) ($f['fqdn'] ?? '');
$issueLabel  = (string) ($f['label'] ?? '');
$issueDays   = (int) ($f['days'] ?? 0);

$csrf = vg_csrf_token();

// 목록 검색·페이지네이션. 검색값은 바인딩하고 LIMIT/OFFSET 은 검증된 정수만 사용한다.
$q       = trim((string) ($_GET['q'] ?? ''));
$perPage = vg_perpage();
$page    = vg_page();
$where   = 't.is_deleted = 0';
$params  = [];
if ($q !== '') {
    $where .= ' AND (t.host_fqdn LIKE ? OR t.label LIKE ? OR t.token_prefix LIKE ?)';
    $like = '%' . $q . '%';
    $params = [$like, $like, $like];
}
$count = $pdo->prepare("SELECT COUNT(*) FROM tb_agent_token t WHERE $where");
$count->execute($params);
$total  = (int) $count->fetchColumn();
$offset = ($page - 1) * $perPage;

$list = $pdo->prepare(
    "SELECT t.agent_token_id, t.host_fqdn, t.label, t.token_prefix, t.last_seen_at, t.is_revoked,
            t.created_at, t.expires_at, u.username AS created_by, h.host_id
       FROM tb_agent_token t
       LEFT JOIN tb_user u ON u.user_id = t.created_by
       LEFT JOIN tb_host h ON h.fqdn = t.host_fqdn AND h.is_deleted = 0
      WHERE $where
      ORDER BY t.agent_token_id DESC
      LIMIT $perPage OFFSET $offset"
);
$list->execute($params);
$tokens = $list->fetchAll();

// 발급 폼 prefill — 자산관리 등에서 ?fqdn=web01.example.com 로 넘어올 수 있게.
if ($issueFqdn === '') { $issueFqdn = trim((string) ($_GET['fqdn'] ?? '')); }

vg_header('에이전트 키', 'agenttokens');
?>
  <?php vg_page_title('에이전트 키', 'AGENT ACCESS', '호스트별 수집 인증 키를 발급하고 관리합니다.', [
      'count' => $total, 'count_label' => '개',
      'actions' => vg_capture(static fn() => vg_modal_btn('issueToken', '+ 토큰 발급')),
  ]); ?>
  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'value' => $q, 'placeholder' => '호스트·용도·토큰 앞자리 검색'],
  ]); ?>

  <?php if ($newToken !== null):
    // 설치는 대화형을 1순위로 안내한다 — 토큰을 --token 인자로 주면 셸 히스토리에 남는다.
    //   대화형(인자 없이 실행 → 숨김 프롬프트)은 히스토리·ps 어디에도 토큰이 남지 않는다.
    //   빠른 설치 명령은 자동화(무인) 편의를 위해 그대로 두되, 위험을 문구로 밝힌다.
    $scheme  = (($_SERVER['HTTPS'] ?? '') === 'on' || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') ? 'https' : 'http';
    $ingest  = $scheme . '://' . (string) ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/ingest.php';
    $install = 'sudo bash install-agent.sh --server ' . $ingest . ' --token ' . $newToken;
  ?>
    <div class="card card--accent">
      <div class="card__body">
        <strong>발급된 토큰 (한 번만 표시됨)</strong>
        <pre class="out selectable"><?= vg_h($newToken) ?></pre>
        <div class="actions">
          <?php vg_copy_btn($newToken, '토큰 복사'); ?>
          <?php vg_copy_btn($install, '빠른 설치 명령 복사'); ?>
        </div>
        <div class="why">대상 서버에서 <code>sudo bash install-agent.sh</code> 실행 후 숨김 프롬프트에 붙여넣는 방식을 권장합니다.
          빠른 설치 명령은 자동화용이며 토큰이 셸 히스토리에 남을 수 있습니다. 스크립트는 <a href="/assets.php">자산</a>에서 받습니다.</div>
      </div>
    </div>
  <?php endif; ?>

  <?php
  vg_table(
      [
          ['label' => '호스트(fqdn)'],
          ['label' => '용도'],
          ['label' => '토큰(앞자리)', 'width' => '12rem'],
          ['label' => '상태', 'width' => '6rem'],
          ['label' => '유효기간', 'width' => '13rem'],
          ['label' => '마지막 수신', 'width' => '11rem'],
          ['label' => '발급일', 'width' => '11rem'],
          ['label' => '', 'width' => '5rem', 'align' => 'right'],   // 폐기·삭제 버튼
      ],
      $tokens,
      [
          'empty' => $q !== '' ? [
              'icon' => '🔍', 'title' => '검색 결과가 없습니다.',
              'hint' => '호스트명·용도·토큰 앞자리를 다시 확인하세요.',
              'cta' => ['href' => '/agent-tokens.php', 'label' => '검색 초기화'],
          ] : [
              'icon' => '🔑', 'title' => '발급된 에이전트 토큰이 없습니다.',
              'hint' => '각 대상 서버마다 호스트 전용 토큰을 발급해 설치하세요. 위에서 발급합니다.',
          ],
          'cell'  => [
              0 => fn($t) => !empty($t['host_id'])
                  ? '<a href="/host.php?id=' . (int) $t['host_id'] . '"><code>' . vg_h((string) $t['host_fqdn']) . '</code></a>'
                  : '<code>' . vg_h((string) $t['host_fqdn']) . '</code>',
              1 => fn($t) => vg_h((string) $t['label'])
                  . '<div class="why">발급자 ' . vg_h((string) ($t['created_by'] ?? '–')) . '</div>',
              2 => fn($t) => '<code>' . vg_h((string) $t['token_prefix']) . '…</code>',
              // 폐기 > 만료 > 활성 순으로 판정 — 만료된 토큰이 '활성' 으로 보이면 안 된다.
              3 => fn($t) => (int) $t['is_revoked'] === 1
                  ? vg_badge('폐기됨', 'muted')
                  : (vg_token_is_expired($t['expires_at'] !== null ? (string) $t['expires_at'] : null)
                      ? vg_badge('만료됨', 'danger')
                      : vg_badge('활성', 'ok')),
              4 => fn($t) => vg_token_expiry_badge($t['expires_at'] !== null ? (string) $t['expires_at'] : null),
              5 => fn($t) => $t['last_seen_at']
                  ? '<span class="why">' . vg_h((string) $t['last_seen_at']) . '</span>'
                  : '<span class="why">미수신</span>',
              6 => fn($t) => '<span class="why">' . vg_h((string) $t['created_at']) . '</span>',
              // 활성이면 [폐기], 폐기된 것이면 [삭제] — 폐기·재발급을 반복해 쌓인 죽은 행을 치운다.
              7 => fn($t) => (int) $t['is_revoked'] === 1
                  ? '<form method="post" data-confirm="이 토큰을 목록에서 지울까요? 이미 폐기되어 무효인 토큰입니다.">'
                      . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                      . '<input type="hidden" name="action" value="delete">'
                      . '<input type="hidden" name="id" value="' . (int) $t['agent_token_id'] . '">'
                      . '<button class="btn btn--sm btn--danger">삭제</button></form>'
                  : '<form method="post" data-confirm="이 토큰을 폐기할까요? 해당 에이전트는 즉시 수신이 막힙니다.">'
                      . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                      . '<input type="hidden" name="action" value="revoke">'
                      . '<input type="hidden" name="id" value="' . (int) $t['agent_token_id'] . '">'
                      . '<button class="btn btn--sm btn--danger">폐기</button></form>',
          ],
      ]
  );
  vg_page_nav($total, $perPage, $page);

  // 발급 폼은 가끔 쓰는 것 — 버튼 뒤 모달로. 실패하면 다시 연다.
  vg_modal_open('issueToken', '에이전트 토큰 발급', '', $issueFailed);
  ?>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="create">
      <label>호스트 (fqdn)</label>
      <input type="text" name="fqdn" value="<?= vg_h($issueFqdn) ?>"
             placeholder="예: web01.example.com" maxlength="255" required autocomplete="off">
      <div class="why">이 호스트의 스캔만 갱신할 수 있습니다. 같은 호스트의 기존 활성 토큰은 자동 폐기됩니다.</div>
      <label>용도 (선택)</label>
      <input type="text" name="label" value="<?= vg_h($issueLabel) ?>"
             placeholder="비우면 호스트명으로 자동 지정" maxlength="100" autocomplete="off">
      <label>유효기간</label>
      <?= vg_token_expiry_select($issueDays) ?>
      <div class="why">만료 시 수집이 즉시 거부됩니다. 토큰 원문은 발급 직후 한 번만 표시됩니다.</div>
      <?php vg_modal_foot('발급', ['loading' => '발급 중…']); ?>
    </form>
  <?php vg_modal_close(); ?>
<?php vg_footer();
