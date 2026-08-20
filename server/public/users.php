<?php
declare(strict_types=1);

/**
 * users.php — 사용자 관리 (admin 전용). 목록 + 추가.
 *   역할변경·비번초기화·삭제는 상세 페이지(user.php?id=)에서 처리한다 — 여기는 조회 전용.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
vg_require_menu('users');

$pdo = vg_pdo();
$msg = null; $err = null;

/* 추가 모달을 다시 열어야 하는지 + 입력값 되살리기.
 * 추가에 실패했는데 모달이 닫혀 버리면 사용자는 뭐가 틀렸는지 못 보고 입력도 잃는다.
 * 비밀번호는 되살리지 않는다(폼에 평문으로 다시 심지 않는다). */
$addFailed = false; $addUsername = ''; $addRole = 'user';

// 저장 가능한 역할 3값(화이트리스트).
const VG_ROLES = ['user', 'operator', 'admin'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $me = vg_current_user();
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } elseif (($_POST['action'] ?? '') === 'add') {
        $u = trim((string) ($_POST['username'] ?? ''));
        $p = (string) ($_POST['password'] ?? '');
        $role = in_array($_POST['role'] ?? '', VG_ROLES, true) ? (string) $_POST['role'] : 'user';
        if ($u === '' || strlen($p) < 8) {
            $err = '아이디와 8자 이상 비밀번호를 입력하세요.';
        } else {
            try {
                $st = $pdo->prepare('INSERT INTO tb_user (username, password_hash, role) VALUES (?,?,?)');
                $st->execute([$u, password_hash($p, PASSWORD_DEFAULT), $role]);
                vg_log_activity($pdo, 'USER', (int) $pdo->lastInsertId(), 'user_add', "사용자 '$u' 추가", ['username' => $u, 'role' => $role],
                    subject: $u, action: 'CREATE');
                $msg = "사용자 '$u' 추가됨.";
            } catch (Throwable $e) {
                error_log('[users] ' . $e->getMessage());
                $err = '추가 실패(중복 아이디?).';
            }
        }
        if ($err !== null) {
            $addFailed = true; $addUsername = $u; $addRole = $role;
        }
    }
}

$me = vg_current_user();

// 사용자 검색·역할 필터·페이지네이션.
$q       = trim((string) ($_GET['q'] ?? ''));
$role    = in_array((string) ($_GET['role'] ?? ''), VG_ROLES, true) ? (string) $_GET['role'] : '';
$perPage = vg_perpage();
$page    = vg_page();
$where   = 'is_deleted = 0';
$params  = [];
if ($q !== '') { $where .= ' AND username LIKE ?'; $params[] = '%' . $q . '%'; }
if ($role !== '') { $where .= ' AND role = ?'; $params[] = $role; }
$count = $pdo->prepare("SELECT COUNT(*) FROM tb_user WHERE $where");
$count->execute($params);
$total  = (int) $count->fetchColumn();
$offset = ($page - 1) * $perPage;
$list = $pdo->prepare(
    "SELECT user_id, username, role, created_at, last_login
       FROM tb_user WHERE $where ORDER BY user_id
      LIMIT $perPage OFFSET $offset"
);
$list->execute($params);
$users = $list->fetchAll();
$csrf = vg_csrf_token();

vg_header('사용자', 'users');
?>
  <?php vg_page_title('사용자', 'ACCOUNTS', [
      'count' => $total, 'count_label' => '명',
      'actions' => vg_capture(static fn() => vg_modal_btn('addUser', '+ 사용자 추가')),
  ]); ?>
  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php
  $roleOptions = [];
  foreach (VG_ROLES as $roleCode) { $roleOptions[$roleCode] = vg_role_label($roleCode); }
  vg_toolbar([
      ['type' => 'select', 'name' => 'role', 'selected' => $role, 'empty_label' => '전체 역할', 'options' => $roleOptions],
      ['type' => 'search', 'name' => 'q', 'value' => $q, 'placeholder' => '아이디 검색'],
  ]);
  ?>

  <?php
  $meId = (int) ($me['id'] ?? 0);

  vg_table(
      [
          // 숫자 열은 우측정렬이 전 화면 규약이다(CVSS·EPSS·건수와 같다).
          ['label' => 'ID', 'align' => 'right', 'width' => '5rem'],
          ['label' => '아이디'],
          ['label' => '역할'],
          ['label' => '생성', 'nowrap' => true],
          ['label' => '마지막 로그인', 'nowrap' => true],
      ],
      $users,
      [
          'empty' => ($q !== '' || $role !== '') ? [
              'icon' => 'search', 'title' => '조건에 맞는 사용자가 없습니다.',
              'hint' => '아이디나 역할 필터를 바꿔 보세요.',
              'cta' => ['href' => '/users.php', 'label' => '필터 초기화'],
          ] : [
              'icon' => 'user', 'title' => '등록된 사용자가 없습니다.',
          ],
          'cell' => [
              0 => fn($u) => vg_h((string) $u['user_id']),
              1 => function ($u) use ($meId) {
                  $html = '<strong><a href="/user.php?id=' . (int) $u['user_id'] . '">' . vg_h($u['username']) . '</a></strong>';
                  if ((int) $u['user_id'] === $meId) { $html .= ' <span class="pill">본인</span>'; }
                  return $html;
              },
              2 => fn($u) => '<span class="pill">' . vg_h(vg_role_label($u['role'])) . '</span>',
              3 => fn($u) => '<span class="why">' . vg_h($u['created_at']) . '</span>',
              4 => fn($u) => '<span class="why">' . vg_h($u['last_login'] ?? '–') . '</span>',
          ],
      ]
  );
  vg_page_nav($total, $perPage, $page);
  ?>

  <?php
  // 추가 폼은 자주 쓰는 게 아니라 목록 아래 펼쳐둘 이유가 없다 → 버튼 뒤 모달로.
  // 추가에 실패했으면(중복 아이디·짧은 비번) 다시 열어 준다 — 안 그러면 뭐가 틀렸는지 못 보고 입력도 잃는다.
  vg_modal_open('addUser', '사용자 추가', '', $addFailed);
  /* 역할 3종의 접근 범위를 폼 위에 3칸 카드로 세운다. 예전엔 이 정보가 select 의
     옵션 문구('운영자 (피드)') 안에만 있어서, 목록을 펼치기 전에는 셋의 차이를 비교할 수
     없었다 — 고르기 전에 비교하는 값이라 폼 위에 펼쳐 둔다.
     역할 이름은 vg_role_label() 이 SSOT 다(여기서 다시 쓰지 않는다).
     .stat-grid 는 auto-fit 이라 좁은 화면에서 스스로 1~2칸으로 접힌다. */
  $roleScope = [
      'admin'    => '모든 화면과 설정 — 사용자·권한·판정 기준까지',
      'operator' => '탐지·자산·수집 운영 — 사용자·권한 설정은 제외',
      'user'     => '조회 전용 — 수집 실행이나 설정 변경은 불가',
  ];
  echo '<div class="stat-grid">';
  foreach (VG_ROLES as $roleCode) {
      /* 역할 하나에 설명이 둘이었다 — VG_ROLE_DESCRIPTIONS('조회')와 $roleScope('조회 전용 — …')가
       *   같은 말을 두 번 했다. 범위를 온전히 말하는 쪽만 남긴다. */
      echo '<div class="stat"><span class="stat__val">' . vg_h(vg_role_label($roleCode)) . '</span>'
         . '<span class="why">' . vg_h($roleScope[$roleCode] ?? '') . '</span></div>';
  }
  echo '</div>';
  ?>
    <?php /* 라벨-입력 짝은 .setting-form/.field 규약으로 묶는다(host.php·activity.php 와 동일). */ ?>
    <form method="post" class="setting-form">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="add">
      <?php /* 아이디·비밀번호는 짧아 나란히 두고, 역할 select 는 설명까지 들어가 한 줄을 다 쓴다. */ ?>
      <div class="form-grid">
      <label class="field" for="add-username">아이디
        <input type="text" id="add-username" name="username" value="<?= vg_h($addUsername) ?>" required autocomplete="off">
      </label>
      <label class="field" for="add-password">비밀번호 <span class="why">(8자 이상)</span>
        <input type="password" id="add-password" name="password" required autocomplete="new-password">
      </label>
      <label class="field form-grid__full" for="add-role">역할
        <select id="add-role" name="role">
          <?php foreach (VG_ROLES as $v): ?>
            <option value="<?= vg_h($v) ?>"<?= $addRole === $v ? ' selected' : '' ?>><?= vg_h(vg_role_label($v) . ' (' . VG_ROLE_DESCRIPTIONS[$v] . ')') ?></option>
          <?php endforeach; ?>
        </select>
      </label>
      </div>
      <?php vg_modal_foot('추가'); ?>
    </form>
  <?php vg_modal_close(); ?>
<?php vg_footer();
