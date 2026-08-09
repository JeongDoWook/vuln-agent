<?php
declare(strict_types=1);

/**
 * settings.php — 전역 운영 설정(tb_setting) 편집 (admin 전용).
 *   판정 기준값처럼 조직마다 달라지는 값만 다룬다. 표 + 인라인 입력 한 폼으로 최소화한다
 *   (permissions.php 매트릭스와 같은 구조 — 저장 버튼 하나로 전부 upsert).
 *   항목 목록·검증 범위는 vg_setting_defs() 가 정본이라 여기엔 문구를 다시 적지 않는다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';    // vg_log_activity
require_once __DIR__ . '/../src/setting.php';  // vg_setting_defs
vg_require_menu('settings');

$pdo = vg_pdo();
$defs = vg_setting_defs();
$msg = null; $err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } else {
        try {
            $posted = $_POST['setting'] ?? [];
            $changed = [];
            $rejected = [];
            $up = $pdo->prepare(
                'INSERT INTO tb_setting (setting_key, setting_value, description)
                 VALUES (?,?,?)
                 ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), is_deleted = 0, deleted_at = NULL'
            );
            foreach ($defs as $key => $def) {
                if (!array_key_exists($key, $posted)) { continue; }
                $raw = trim((string) $posted[$key]);
                $int = filter_var($raw, FILTER_VALIDATE_INT);
                if ($int === false || $int < (int) $def['min'] || $int > (int) $def['max']) {
                    $rejected[] = sprintf('%s — %d~%d 사이의 정수만 가능합니다.', $def['label'], $def['min'], $def['max']);
                    continue;
                }
                $up->execute([$key, (string) $int, (string) $def['desc']]);
                $changed[$key] = $int;
            }
            if ($changed) {
                // 무엇을 얼마로 바꿨는지까지 남긴다 — 판정 기준이 바뀌면 과거 판정 결과의
                //   해석이 달라지므로, 나중에 "왜 그때는 준수였나"를 이 로그로 되짚는다.
                vg_log_activity($pdo, 'SETTING', null, 'setting_update', '운영 설정 변경', $changed);
                $msg = count($changed) . '개 설정을 저장했습니다.';
            }
            if ($rejected) {
                $err = implode(' / ', $rejected);
            } elseif (!$changed) {
                $msg = '변경된 값이 없습니다.';
            }
        } catch (Throwable $e) {
            error_log('[settings] ' . $e->getMessage());
            $err = '저장 실패.';
        }
    }
}

// 현재 값 로드. POST 직후에도 방금 저장한 값이 보이도록 여기서 다시 읽는다
//   (vg_settings_all() 은 요청당 캐시라 저장 전 값을 들고 있을 수 있다).
$cur = [];
$tableMissing = false;
try {
    foreach ($pdo->query('SELECT setting_key, setting_value FROM tb_setting WHERE is_deleted = 0')->fetchAll() as $r) {
        $cur[(string) $r['setting_key']] = (string) $r['setting_value'];
    }
} catch (Throwable $e) {
    error_log('[settings] ' . $e->getMessage());
    $tableMissing = true;
}

$csrf = vg_csrf_token();
vg_header('설정', 'settings');
?>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
    <?php vg_page_title('설정', 'SETTINGS', '조직 기준에 맞춰 판정 기준값과 세션 만료 정책을 조정합니다.', [
        'actions' => '<button type="submit" class="btn btn--primary" data-loading="저장 중…">저장</button>',
    ]); ?>
    <div class="sub">admin 전용 · 비워 두면 기본값으로 동작 · 변경은 감사 로그에 남습니다 · 세션 만료는 다음 요청부터 적용됩니다</div>

    <?php
    vg_alert($msg, 'ok');
    vg_alert($err);
    if ($tableMissing) {
        vg_alert('설정 테이블을 읽을 수 없습니다. 마이그레이션 적용 여부를 확인하세요(기본값으로 판정 중).', 'warn');
    }

    $rows = [];
    foreach ($defs as $key => $def) { $rows[] = ['key' => $key] + $def; }
    vg_table([
        ['label' => '항목', 'width' => '32%'],
        ['label' => '값', 'width' => '10rem'],
        ['label' => '설명'],
    ], $rows, [
        'cell' => [
            0 => static fn($r) => '<strong>' . vg_h((string) $r['label']) . '</strong> <code class="why">' . vg_h((string) $r['key']) . '</code>',
            // 입력 스타일은 app.css 의 input[type=number] 가 이미 갖는다 — 클래스를 새로 만들지 않는다.
            1 => static fn($r) => '<input type="number" name="setting[' . vg_h((string) $r['key']) . ']"'
                . ' value="' . vg_h((string) ($cur[$r['key']] ?? '')) . '"'
                . ' min="' . (int) $r['min'] . '" max="' . (int) $r['max'] . '" step="1"'
                . ' aria-label="' . vg_h((string) $r['label']) . '">',
            2 => static fn($r) => '<span class="why">' . vg_h((string) $r['desc'])
                . ' (' . (int) $r['min'] . '~' . (int) $r['max'] . ')</span>',
        ],
    ]);
    ?>
  </form>
<?php vg_footer();
