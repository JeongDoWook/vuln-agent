<?php
declare(strict_types=1);

/**
 * user.php — 사용자 상세(admin 전용). ?id=<user_id> 1명의 프로필 + 관리 액션 + 활동 로그.
 *   역할변경·비번초기화·삭제는 지금까지 users.php 목록 안에 있었으나, 여기로 옮겼다
 *   (자기 자신 예외 규칙은 그대로 유지). 삭제 성공 시엔 이 사용자를 더는 보여줄 수 없으므로
 *   users.php 목록으로 리다이렉트한다. 그 외(역할변경·초기화)는 이 페이지에 그대로 남아
 *   결과를 보여준다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
vg_require_menu('users');

// 저장 가능한 역할 3값(화이트리스트) — users.php 와 동일.
const VG_ROLES = ['user', 'operator', 'admin'];

// 최근 활동 로그 표시 건수.
$userActivityLimit = vg_ui_detail_preview_limit();

$pdo = vg_pdo();
$msg = null; $err = null;
$id = (int) ($_GET['id'] ?? 0);
$me = vg_current_user();
$meId = (int) ($me['id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } elseif (($_POST['action'] ?? '') === 'role') {
        $role = in_array($_POST['role'] ?? '', VG_ROLES, true) ? (string) $_POST['role'] : '';
        if ($id === $meId) {
            $err = '자기 자신의 역할은 변경할 수 없습니다.';
        } elseif ($role === '') {
            $err = '유효하지 않은 역할입니다.';
        } else {
            $pdo->prepare('UPDATE tb_users SET role = ? WHERE id = ?')->execute([$role, $id]);
            vg_log_activity($pdo, 'USER', $id, 'user_role', '역할 변경', ['role' => $role]);
            $msg = '역할이 변경되었습니다.';
        }
    } elseif (($_POST['action'] ?? '') === 'reset') {
        $p = (string) ($_POST['password'] ?? '');
        if (strlen($p) < 8) {
            $err = '초기화 비밀번호는 8자 이상이어야 합니다.';
        } else {
            $pdo->prepare('UPDATE tb_users SET password_hash = ? WHERE id = ?')
                ->execute([password_hash($p, PASSWORD_DEFAULT), $id]);
            vg_log_activity($pdo, 'USER', $id, 'user_pw_reset', '비밀번호 초기화');
            $msg = '비밀번호가 초기화되었습니다.';
        }
    } elseif (($_POST['action'] ?? '') === 'unlock') {
        $pdo->prepare('UPDATE tb_users SET failed_login_count = 0, locked_until = NULL WHERE id = ?')->execute([$id]);
        vg_log_activity($pdo, 'USER', $id, 'account_unlock', '계정 잠금 해제');
        $msg = '계정 잠금이 해제되었습니다.';
    } elseif (($_POST['action'] ?? '') === 'delete') {
        if ($id === $meId) {
            $err = '자기 자신은 삭제할 수 없습니다.';
        } else {
            vg_soft_delete($pdo, 'tb_users', $id);
            vg_log_activity($pdo, 'USER', $id, 'user_delete', '사용자 삭제');
            // 삭제된 사용자는 더는 이 페이지에서 보여줄 게 없다 — 목록으로 돌아간다.
            header('Location: /users.php');
            exit;
        }
    }
}

$st = $pdo->prepare('SELECT id, username, role, created_at, last_login, locked_until FROM tb_users WHERE id = ? AND is_deleted = 0');
$st->execute([$id]);
$user = $st->fetch() ?: null;
$isLocked = $user && $user['locked_until'] !== null && strtotime((string) $user['locked_until']) > time();

$activity = [];
if ($user) {
    $st = $pdo->prepare(
        'SELECT created_at, activity_type, actor_type, user_name, message, ip_address
           FROM tb_activity_log WHERE scope = ? AND scope_id = ? AND is_deleted = 0
          ORDER BY id DESC LIMIT ' . $userActivityLimit
    );
    $st->execute(['USER', $id]);
    $activity = $st->fetchAll();
}

$csrf = vg_csrf_token();

vg_header($user['username'] ?? '사용자', 'users');
?>
<?php if (!$user): ?>
  <div class="card">
    <?php vg_empty([
        'icon'  => '📭',
        'title' => '사용자를 찾을 수 없습니다.',
        'cta'   => ['href' => '/users.php', 'label' => '← 사용자 목록'],
    ]); ?>
  </div>
<?php else:
    $isSelf = $id === $meId;
?>
  <?php
  $meta = [
      vg_h(vg_role_label($user['role'])),
      '생성 ' . vg_h($user['created_at']),
      '최근 로그인 ' . vg_h($user['last_login'] ?? '–'),
  ];
  if ($isLocked) {
      $meta[] = '<span class="badge tone-crit">🔒 잠김 — ' . vg_h((string) $user['locked_until']) . '까지</span>';
  }
  $meta[] = '<a href="/users.php">← 사용자 목록</a>';
  vg_hero(vg_h($user['username']) . ($isSelf ? ' <span class="why">(본인)</span>' : ''), $meta, null, 'ok', '계정 상태', 'USER DETAIL');
  ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <div class="card">
    <strong>계정 관리</strong>
    <span class="why">— 역할 변경 · 비밀번호 초기화 · 삭제. 자기 자신은 역할변경·삭제를 할 수 없습니다.</span>
    <div class="card__body">
      <div class="actions actions--stack">
        <?php if ($isLocked): ?>
          <form method="post" data-confirm="이 계정의 잠금을 해제할까요? 실패 카운트도 함께 초기화됩니다.">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="unlock">
            <label>계정 잠금</label>
            <button class="btn btn--sm btn--warn">잠금 해제</button>
          </form>
        <?php endif; ?>

        <?php if (!$isSelf): ?>
          <form method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="role">
            <label>역할 변경</label>
            <select name="role">
              <?php
              $cur = $user['role'] === 'viewer' ? 'user' : (string) $user['role'];
              foreach (VG_ROLES as $v):
              ?>
                <option value="<?= vg_h($v) ?>"<?= $cur === $v ? ' selected' : '' ?>><?= vg_h(vg_role_label($v)) ?></option>
              <?php endforeach; ?>
            </select>
            <button class="btn btn--sm btn--ghost">역할 변경</button>
          </form>
        <?php else: ?>
          <span class="why">역할 변경: 자기 자신은 변경할 수 없습니다.</span>
        <?php endif; ?>

        <form method="post" data-confirm="이 사용자의 비밀번호를 초기화할까요? 아래 입력한 새 비밀번호로 즉시 바뀌며, 기존 비밀번호로는 더는 로그인할 수 없습니다.">
          <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
          <input type="hidden" name="action" value="reset">
          <label>비밀번호 초기화</label>
          <input type="password" name="password" placeholder="새 비번(8자+)" required>
          <button class="btn btn--sm btn--warn">초기화</button>
        </form>

        <?php if (!$isSelf): ?>
          <form method="post" data-confirm="이 사용자를 삭제할까요? 계정이 즉시 비활성화되어 로그인할 수 없게 되고 사용자 목록에서도 사라집니다. 이 사용자의 활동 이력은 감사로그에 그대로 남습니다.">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="delete">
            <label>삭제</label>
            <button class="btn btn--sm btn--danger">사용자 삭제</button>
          </form>
        <?php else: ?>
          <span class="why">삭제: 자기 자신은 삭제할 수 없습니다.</span>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <div class="card mt-lg">
    <strong>최근 활동</strong>
    <span class="why">— 이 사용자와 관련된 감사 로그(최근 <?= $userActivityLimit ?>건) ·
      <a href="/activity.php?q=<?= urlencode($user['username']) ?>">전체 감사로그에서 보기 →</a></span>
    <div class="card__body">
      <?php
      $activityLabels = vg_activity_type_labels();
      vg_table(
          [
              ['label' => '시각', 'width' => '140px', 'nowrap' => true],
              ['label' => '액션', 'width' => '150px', 'nowrap' => true],
              ['label' => '내용'],
              ['label' => '행위자', 'width' => '110px', 'nowrap' => true],
              ['label' => '출처 IP', 'width' => '110px', 'nowrap' => true],
          ],
          $activity,
          [
              'card' => false,
              'empty' => [
                  'icon'  => '📋',
                  'title' => '기록된 활동이 없습니다.',
              ],
              'cell' => [
                  0 => static fn (array $r): string => vg_h(str_replace('T', ' ', substr((string) $r['created_at'], 0, 19))),
                  1 => static function (array $r) use ($activityLabels): string {
                      $code = (string) $r['activity_type'];
                      $label = $activityLabels[$code] ?? $code;
                      return vg_h($label) . '<div class="why" title="' . vg_h($code) . '">' . vg_h($code) . '</div>';
                  },
                  2 => static function (array $r): string {
                      $msg = trim((string) ($r['message'] ?? ''));
                      return $msg !== '' ? vg_h($msg) : '<span class="why">—</span>';
                  },
                  3 => static function (array $r): string {
                      $who = !empty($r['user_name'])
                          ? (string) $r['user_name']
                          : (((string) ($r['actor_type'] ?? '')) === 'SYSTEM' ? '시스템' : '사용자');
                      return vg_h($who);
                  },
                  4 => static function (array $r): string {
                      $ip = trim((string) ($r['ip_address'] ?? ''));
                      return $ip !== '' ? vg_h($ip) : '<span class="why">—</span>';
                  },
              ],
          ]
      );
      ?>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
