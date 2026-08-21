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
  <?php vg_page_title('에이전트 키', 'AGENT ACCESS', [
      'count' => $total, 'count_label' => '개',
      'actions' => vg_capture(static fn() => vg_modal_btn('issueToken', '+ 토큰 발급')),
  ]); ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php /* 발급 직후 한 번만 뜨는 카드다 — 검색 툴바 아래에 두면 "지금 복사하세요" 라는 알림과
           실제 값 사이를 필터 줄이 갈라놓는다. 알림 바로 뒤에 붙인다. */ ?>
  <?php if ($newToken !== null):
    // 설치는 대화형을 1순위로 안내한다 — 토큰을 --token 인자로 주면 셸 히스토리에 남는다.
    //   대화형(인자 없이 실행 → 숨김 프롬프트)은 히스토리·ps 어디에도 토큰이 남지 않는다.
    //   빠른 설치 명령은 자동화(무인) 편의를 위해 그대로 두되, 위험을 문구로 밝힌다.
    $ingest  = vg_ingest_url();   // 계산은 format/links.php 가 소유한다(설치 안내와 같은 값).
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
        <?php /* 남길 값은 "빠른 설치 명령은 토큰이 셸 히스토리에 남는다" 는 보안 사실과 다음 단계 링크뿐이다. */ ?>
        <div class="why">빠른 설치 명령은 토큰이 셸 히스토리에 남는다 — 자동화가 아니면 <code>sudo bash install-agent.sh</code>
          의 숨김 프롬프트에 붙여넣는다. <a href="/assets.php#agentInstall">설치 안내 2단계(파일·CA)</a></div>
      </div>
    </div>
  <?php endif; ?>

  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'value' => $q, 'placeholder' => '호스트·용도·토큰 앞자리 검색'],
  ]); ?>

  <?php
  vg_table(
      [
          ['label' => '호스트(fqdn)', 'key' => 'host_fqdn'],
          ['label' => '용도', 'key' => 'label'],
          ['label' => '토큰(앞자리)', 'key' => 'token_prefix', 'width' => '12rem'],
          /* '상태'(폐기됨·만료됨·활성)와 '유효기간'(무기한·날짜·만료 임박·만료됨)은 **같은 두 값
             (is_revoked, expires_at)을 두 번 그린 열**이었다 — '만료됨' 은 아예 양쪽에 같이 떴다.
             운영 실측(tb_agent_token 26건)에서 **expires_at 이 100% NULL** 이라 '유효기간' 열은
             전 행이 '무기한' 한 글자였다(정보량 0). 한 칸으로 합치되 값은 하나도 안 버린다:
             폐기됨 / 만료됨(날짜) / 활성 + 만료 시각(무기한·날짜·임박)이 그대로 선다.
             열을 지우지 않고 합친 이유는, 유효기간을 걸어 발급하는 길이 살아 있기 때문이다
             (vg_token_expiry_select) — 그런 토큰이 생기면 이 칸이 날짜를 그대로 보여준다. */
          ['label' => '상태 · 유효기간', 'key' => 'is_revoked', 'width' => '15rem',
           'title' => '폐기·만료 여부와 만료 시각 — 무기한은 만료되지 않는 키입니다'],
          ['label' => '마지막 수신', 'key' => 'last_seen_at', 'width' => '11rem'],
          ['label' => '발급일', 'key' => 'created_at', 'width' => '11rem'],
          /* 조작부만 담는 열도 이름을 갖는다 — 빈 머리글은 화면에서 열이 하나 잘려 보이고,
             스크린리더는 이 칸을 읽을 때 딸려 읽을 열 이름이 없다(vg_table 이 th 를 그대로 비운다).
             '관리' 는 이 저장소의 액션 열 공통 이름이다(같은 뜻은 화면마다 같은 이름). */
          ['label' => '관리', 'key' => 'actions', 'width' => '5rem', 'align' => 'right'],   // 폐기·삭제 버튼
      ],
      $tokens,
      [
          'empty' => $q !== '' ? [
              'icon' => 'search', 'title' => '검색 결과가 없습니다.',
              'hint' => '호스트명·용도·토큰 앞자리를 다시 확인하세요.',
              'cta' => ['href' => '/agent-tokens.php', 'label' => '검색 초기화'],
          ] : [
              'icon' => 'key', 'title' => '발급된 에이전트 토큰이 없습니다.',
              'hint' => '각 대상 서버마다 호스트 전용 토큰을 발급해 설치하세요. 위에서 발급합니다.',
          ],
          'cell'  => [
              'host_fqdn' => fn($t) => !empty($t['host_id'])
                  ? '<a href="/host.php?id=' . (int) $t['host_id'] . '"><code>' . vg_h((string) $t['host_fqdn']) . '</code></a>'
                  : '<code>' . vg_h((string) $t['host_fqdn']) . '</code>',
              // 발급자를 모르는 토큰(스크립트 발급·옛 기록)은 '발급자 –' 로 채우지 않는다 —
              //   행마다 같은 자리표시가 서서 정작 아는 발급자를 못 알아보게 했다.
              'label' => function ($t) {
                  $by = trim((string) ($t['created_by'] ?? ''));
                  return vg_h((string) $t['label'])
                      . ($by !== '' ? '<div class="why">발급자 ' . vg_h($by) . '</div>' : '');
              },
              'token_prefix' => fn($t) => '<code>' . vg_h((string) $t['token_prefix']) . '…</code>',
              // 폐기 > 만료 > 활성 순으로 판정 — 만료된 토큰이 '활성' 으로 보이면 안 된다.
              //   만료는 그 자체로 "지금 못 쓴다" 라 '활성' 을 같이 세우지 않는다(합치기 전 두 열이
              //   '활성 아님'과 '만료됨'을 각각 말하던 자리다). 나머지는 활성 뱃지 + 만료 시각.
              'is_revoked' => function ($t) {
                  if ((int) $t['is_revoked'] === 1) {
                      return vg_badge('폐기됨', 'muted', '폐기된 토큰입니다 — 이 키로는 수집이 거부됩니다.');
                  }
                  $exp = $t['expires_at'] !== null ? (string) $t['expires_at'] : null;
                  if (vg_token_expiry_state($exp) === 'expired') { return vg_token_expiry_badge($exp); }
                  return vg_badge('활성', 'ok') . ' ' . vg_token_expiry_badge($exp);
              },
              'last_seen_at' => fn($t) => $t['last_seen_at']
                  ? '<span class="why">' . vg_h((string) $t['last_seen_at']) . '</span>'
                  : '<span class="why">미수신</span>',
              'created_at' => fn($t) => '<span class="why">' . vg_h((string) $t['created_at']) . '</span>',
              // 활성이면 [폐기], 폐기된 것이면 [삭제] — 폐기·재발급을 반복해 쌓인 죽은 행을 치운다.
              //   둘 다 색을 빼고(btn--ghost) 확인창으로 받는다 — 행마다 빨간 버튼이 반복되면
              //   목록에서 가장 강한 요소가 '되돌릴 수 없는 것' 이 된다.
              'actions' => fn($t) => (int) $t['is_revoked'] === 1
                  ? '<form method="post" data-confirm="이 토큰을 목록에서 지울까요? 이미 폐기되어 무효인 토큰입니다.">'
                      . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                      . '<input type="hidden" name="action" value="delete">'
                      . '<input type="hidden" name="id" value="' . (int) $t['agent_token_id'] . '">'
                      . '<button class="btn btn--xs btn--ghost">삭제</button></form>'
                  : '<form method="post" data-confirm="이 토큰을 폐기할까요? 해당 에이전트는 즉시 수신이 막힙니다.">'
                      . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                      . '<input type="hidden" name="action" value="revoke">'
                      . '<input type="hidden" name="id" value="' . (int) $t['agent_token_id'] . '">'
                      . '<button class="btn btn--xs btn--ghost">폐기</button></form>',
          ],
      ]
  );
  vg_page_nav($total, $perPage, $page);

  // 발급 폼은 가끔 쓰는 것 — 버튼 뒤 모달로. 실패하면 다시 연다.
  vg_modal_open('issueToken', '에이전트 토큰 발급', '', $issueFailed);
  ?>
    <form method="post" class="setting-form">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="create">
      <?php /* 호스트는 주소라 길고 안내문까지 달려 한 줄을 다 쓴다. 용도·유효기간은 짧아 2열. */ ?>
      <div class="form-grid">
      <label class="field form-grid__full" for="issue-fqdn">호스트 (fqdn)
        <input type="text" id="issue-fqdn" name="fqdn" value="<?= vg_h($issueFqdn) ?>"
               placeholder="예: web01.example.com" maxlength="255" required autocomplete="off">
        <span class="why">이 호스트 전용 · 같은 호스트의 기존 활성 토큰은 자동 폐기</span>
      </label>
      <label class="field" for="issue-label">용도 (선택)
        <input type="text" id="issue-label" name="label" value="<?= vg_h($issueLabel) ?>"
               placeholder="비우면 호스트명으로 자동 지정" maxlength="100" autocomplete="off">
      </label>
      <label class="field">유효기간
        <?= vg_token_expiry_select($issueDays) ?>
      </label>
      </div>
      <?php /* 같은 경고를 글로도 한 번 더 — 도식은 훑는 눈을 잡고, 이 배너가 "그래서 어떻게
               하라는 것인가"를 말한다. 알림(role=alert)이라 스크린리더에도 읽힌다. */
      vg_alert([
          'type'  => 'warn',
          'title' => '토큰 원문은 발급 직후 한 번만 표시됩니다',
          'hints' => ['창을 닫거나 새로고침하면 다시 볼 수 없습니다 — 지금 복사하세요. 만료 시 이 에이전트의 수집만 즉시 거부됩니다.'],
      ]); ?>
      <?php vg_modal_foot('발급', ['loading' => '발급 중…']); ?>
    </form>
  <?php vg_modal_close(); ?>
<?php vg_footer();
