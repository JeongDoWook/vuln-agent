<?php
declare(strict_types=1);

/**
 * permissions.php — 역할별 메뉴 접근권한 설정 (admin 전용).
 *   매트릭스 UI: 행=메뉴, 열=운영자/사용자 체크박스. 관리자 열은 "항상 허용"으로 잠금.
 *   저장 시 tb_role_permissions 를 upsert 하고 감사로그를 남긴다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
vg_require_menu('permissions');

$pdo = vg_pdo();
$msg = null; $err = null;

// 매트릭스에서 토글 가능한 역할·메뉴.
//   permissions 메뉴는 admin 전용 성격이라 매트릭스에서 제외(코드에서 admin 만 true).
const VG_PERM_ROLES = ['operator', 'user'];
$menus = vg_menus();
unset($menus['permissions']);   // 권한설정 행은 표시하지 않음

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } else {
        try {
            $posted = $_POST['perm'] ?? [];   // perm[role][menu] = '1'
            $up = $pdo->prepare(
                'INSERT INTO tb_role_permissions (role, menu_code, allowed)
                 VALUES (?,?,?)
                 ON DUPLICATE KEY UPDATE allowed = VALUES(allowed), is_deleted = 0, deleted_at = NULL'
            );
            foreach (VG_PERM_ROLES as $role) {
                foreach (array_keys($menus) as $code) {
                    $allowed = !empty($posted[$role][$code]) ? 1 : 0;
                    $up->execute([$role, $code, $allowed]);
                }
            }
            vg_log_activity($pdo, 'PERMISSION', null, 'permission_update', '역할별 메뉴 접근권한 변경', $posted);
            $msg = '권한이 저장되었습니다.';
        } catch (Throwable $e) {
            $err = '저장 실패: ' . $e->getMessage();
        }
    }
}

// 현재 권한 로드 → $cur[role][menu] = bool
$cur = [];
foreach ($pdo->query('SELECT role, menu_code, allowed FROM tb_role_permissions WHERE is_deleted = 0')->fetchAll() as $r) {
    $cur[(string) $r['role']][(string) $r['menu_code']] = (int) $r['allowed'] === 1;
}

$csrf = vg_csrf_token();
vg_header('권한설정', 'permissions');
?>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
    <div class="page-head">
      <h1>역할별 메뉴 접근권한</h1>
      <div class="toolbar"><button type="submit" class="btn btn--primary" data-loading="저장 중…">저장</button></div>
    </div>
    <div class="sub">admin 전용 · 운영자·사용자가 접근할 수 있는 메뉴를 체크로 설정 · 관리자는 항상 전체 허용</div>

    <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

    <div class="card">
      <table class="matrix">
        <thead><tr>
          <th>메뉴</th>
          <th class="col-role">관리자</th>
          <th class="col-role">운영자</th>
          <th class="col-role">사용자</th>
        </tr></thead>
        <tbody>
        <?php foreach ($menus as $code => $label): ?>
          <tr>
            <td><strong><?= vg_h($label) ?></strong> <code><?= vg_h($code) ?></code></td>
            <td title="관리자는 항상 전체 허용"><span class="pill">✔ 항상</span></td>
            <?php foreach (VG_PERM_ROLES as $role): ?>
              <td class="col-role">
                <label>
                  <input type="checkbox" name="perm[<?= vg_h($role) ?>][<?= vg_h($code) ?>]" value="1"
                         <?= !empty($cur[$role][$code]) ? 'checked' : '' ?>>
                </label>
              </td>
            <?php endforeach; ?>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <div class="mt-lg"><button type="submit" class="btn btn--primary" data-loading="저장 중…">저장</button></div>
  </form>

  <div class="card">
    <div class="sub">
      · <strong>권한설정</strong> 메뉴 자체는 관리자 전용이라 목록에서 제외됩니다.<br>
      · 관리자 계정은 어떤 설정과 무관하게 모든 메뉴에 접근합니다(잠금방지).
    </div>
  </div>
<?php vg_footer();
