<?php
declare(strict_types=1);

/**
 * permissions.php — 역할별 메뉴 접근권한 설정 (admin 전용).
 *   매트릭스 UI: 행=메뉴, 열=운영자/사용자 체크박스. 관리자 열은 "항상 허용"으로 잠금.
 *   저장 시 tb_role_permission 을 upsert 하고 감사로그를 남긴다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
vg_require_menu('permissions');

$pdo = vg_pdo();
$msg = null; $err = null;

// 매트릭스에서 토글 가능한 역할·메뉴.
//   admin 전용 메뉴는 여기서만 뺀다 — vg_menus() 에는 남겨야 nav.php 의 'perm' 코드와
//   일치해서 "보이는데 403" 링크가 안 생긴다(메뉴코드 정본은 vg_menus()).
const VG_PERM_ROLES = ['operator', 'user'];
$menus = vg_menus();
unset($menus['permissions']);   // 권한설정: admin 전용(코드에서 admin 만 true)
unset($menus['apitokens']);     // Export API 토큰 발급: admin 전용(코드에서 admin 만 true)
unset($menus['settings']);      // 운영 설정: admin 전용(판정 기준값을 바꾸는 화면)

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } else {
        try {
            $posted = $_POST['perm'] ?? [];   // perm[role][menu] = '1'
            $up = $pdo->prepare(
                'INSERT INTO tb_role_permission (role, menu_code, allowed)
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
            error_log('[permissions] ' . $e->getMessage());
            $err = '저장 실패.';
        }
    }
}

// 현재 권한 로드 → $cur[role][menu] = bool
$cur = [];
foreach ($pdo->query('SELECT role, menu_code, allowed FROM tb_role_permission WHERE is_deleted = 0')->fetchAll() as $r) {
    $cur[(string) $r['role']][(string) $r['menu_code']] = (int) $r['allowed'] === 1;
}

$csrf = vg_csrf_token();
vg_header('권한', 'permissions');
?>
  <form method="post" class="permission-form">
    <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
    <?php vg_page_title('권한', 'ACCESS', '역할별 메뉴 접근 범위를 설정합니다.', [
        'actions' => '<button type="submit" class="btn btn--primary" data-loading="저장 중…">저장</button>',
    ]); ?>
    <div class="sub">admin 전용 · 운영자·사용자가 접근할 수 있는 메뉴를 체크로 설정 · 관리자는 항상 전체 허용</div>

    <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

    <?php
      $permissionRows = [];
      foreach ($menus as $code => $label) { $permissionRows[] = ['code' => $code, 'label' => $label]; }
      vg_table([
          ['label' => '메뉴', 'key' => 'label', 'class' => 'permission-menu'],
          ['label' => '관리자', 'align' => 'center', 'class' => 'permission-role'],
          ['label' => '운영자', 'align' => 'center', 'class' => 'permission-role'],
          ['label' => '사용자', 'align' => 'center', 'class' => 'permission-role'],
      ], $permissionRows, [
          'class' => 'matrix',
          'cell' => [
              0 => static fn($row) => '<strong>' . vg_h($row['label']) . '</strong> <code>' . vg_h($row['code']) . '</code>',
              1 => static fn() => vg_badge('✔ 항상', 'ok'),
              2 => static fn($row) => '<label class="check-cell"><input type="checkbox" name="perm[operator][' . vg_h($row['code']) . ']" value="1"' . (!empty($cur['operator'][$row['code']]) ? ' checked' : '') . '><span class="sr-only">운영자 ' . vg_h($row['label']) . ' 접근 허용</span></label>',
              3 => static fn($row) => '<label class="check-cell"><input type="checkbox" name="perm[user][' . vg_h($row['code']) . ']" value="1"' . (!empty($cur['user'][$row['code']]) ? ' checked' : '') . '><span class="sr-only">사용자 ' . vg_h($row['label']) . ' 접근 허용</span></label>',
          ],
      ]);
    ?>
  </form>

  <div class="card permission-note">
    <div class="sub">
      · <strong>권한설정</strong> 메뉴 자체는 관리자 전용이라 목록에서 제외됩니다.<br>
      · 관리자 계정은 어떤 설정과 무관하게 모든 메뉴에 접근합니다(잠금방지).
    </div>
  </div>
<?php vg_footer();
