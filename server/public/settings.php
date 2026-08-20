<?php
declare(strict_types=1);

/**
 * settings.php — 전역 운영 설정(tb_setting) 편집 (admin 전용).
 *   판정 기준값처럼 조직마다 달라지는 값만 다룬다. 폼 하나 · 저장 버튼 하나로 전부 upsert 한다
 *   (permissions.php 매트릭스와 같은 구조).
 *
 *   화면은 vg_setting_groups() 순서대로 카드를 그리고, 각 카드는 자기 그룹의 항목만 담는다 —
 *   예전엔 성격이 전혀 다른 값(조치 기한 · 세션 정책 · 계정 판정)이 표 3열에 통째로 섞여 있어
 *   무엇을 만지는지 눈에 안 들어왔다. 항목 문구·범위·묶음은 vg_setting_defs()/vg_setting_groups()
 *   가 정본이라 여기엔 다시 적지 않는다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';    // vg_log_activity
require_once __DIR__ . '/../src/setting.php';  // vg_setting_defs / vg_setting_groups / vg_setting_default
// 기본값 상수(VG_COMPLIANCE_*·VG_ACCOUNT_STALE_LOGIN_DAYS)를 가진 파일. vg_setting_default() 가
//   그 상수에서 기본값을 읽으므로 이 화면에서만 로드한다 — setting.php 는 모든 요청이 거치는
//   경로라 거기서 require 하면 값 하나 때문에 판정 로직 전체를 요청마다 끌어오게 된다.
//   (세션 상수는 auth.php 가 이미 정의했다.)
require_once __DIR__ . '/../src/compliance.php';
// AI 보고서 기본값 상수(VG_REPORT_*). 같은 이유로 이 화면에서만 로드한다.
require_once __DIR__ . '/../src/report_job.php';
vg_require_menu('settings');

$pdo = vg_pdo();
$defs = vg_setting_defs();
$msg = null; $err = null;
$fieldErr = [];   // 키 => 그 입력 아래에 붙일 오류 문구
$posted = [];     // 거절된 입력은 사용자가 친 값을 그대로 되돌려준다(고칠 수 있게)

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } else {
        try {
            $posted = is_array($_POST['setting'] ?? null) ? $_POST['setting'] : [];
            $changed = [];
            $up = $pdo->prepare(
                'INSERT INTO tb_setting (setting_key, setting_value, description)
                 VALUES (?,?,?)
                 ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), is_deleted = 0, deleted_at = NULL'
            );
            foreach ($defs as $key => $def) {
                if (!array_key_exists($key, $posted)) { continue; }
                $raw = trim((string) $posted[$key]);
                if (vg_setting_is_int($key)) {
                    $int = filter_var($raw, FILTER_VALIDATE_INT);
                    if ($int === false || $int < (int) $def['min'] || $int > (int) $def['max']) {
                        // 문제가 난 입력 자체에 붙인다 — 상단에 문구만 모아 두면 항목이 아홉 개일 때
                        //   어느 칸을 고쳐야 하는지 눈으로 되짚어야 했다.
                        $fieldErr[$key] = sprintf('%d~%d 사이의 정수만 가능합니다.', (int) $def['min'], (int) $def['max']);
                        continue;
                    }
                    $value = (string) $int;
                    $logged = $int;
                } else {
                    // 주소 항목(type=url). 여기서 거르는 값이 그대로 서버측 HTTP 호출의
                    //   목적지가 되므로, 스킴을 http/https 로 못박고 경로·질의는 붙이지 못하게 한다
                    //   (base URL 자리다 — 뒤에 '/jobs/' 를 우리가 붙인다).
                    $err2 = vg_setting_url_error($raw, (int) $def['max']);
                    if ($err2 !== null) { $fieldErr[$key] = $err2; continue; }
                    $value = rtrim($raw, '/');
                    $logged = $value;
                }
                $up->execute([$key, $value, (string) $def['desc']]);
                $changed[$key] = $logged;
            }
            if ($changed) {
                // 무엇을 얼마로 바꿨는지까지 남긴다 — 판정 기준이 바뀌면 과거 판정 결과의
                //   해석이 달라지므로, 나중에 "왜 그때는 준수였나"를 이 로그로 되짚는다.
                vg_log_activity($pdo, 'SETTING', null, 'setting_update', '운영 설정 변경', $changed);
                $msg = count($changed) . '개 설정을 저장했습니다.';
            }
            if ($fieldErr) {
                $err = count($fieldErr) . '개 항목을 저장하지 못했습니다. 아래 표시된 입력을 확인하세요.';
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

// 그룹별로 항목을 담는다. 정의에 group 이 없거나 모르는 값이면 첫 그룹에 넣는다 —
//   항목이 어느 카드에도 안 잡혀 화면에서 조용히 사라지는 일은 없어야 한다.
$groups = vg_setting_groups();
$byGroup = array_fill_keys(array_keys($groups), []);
$firstGroup = (string) array_key_first($groups);
foreach ($defs as $key => $def) {
    $g = (string) ($def['group'] ?? '');
    if (!isset($byGroup[$g])) { $g = $firstGroup; }
    $byGroup[$g][$key] = $def;
}

$csrf = vg_csrf_token();
vg_header('설정', 'settings');
?>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
    <?php vg_page_title('설정', 'SETTINGS', [
        'actions' => '<button type="submit" class="btn btn--sm btn--primary" data-loading="저장 중…">저장</button>',
    ]); ?>

    <?php
    vg_alert($msg, 'ok');
    vg_alert($err);
    if ($tableMissing) {
        vg_alert('설정 테이블을 읽을 수 없습니다. 마이그레이션 적용 여부를 확인하세요(기본값으로 판정 중).', 'warn');
    }

    foreach ($groups as $gkey => $group):
        if (!$byGroup[$gkey]) { continue; } ?>
      <section class="card">
        <strong><?= vg_h((string) $group['label']) ?></strong>
        <div class="card__body setting-form setting-form--grid">
          <?php foreach ($byGroup[$gkey] as $key => $def):
              $id  = 'set-' . str_replace('.', '-', $key);
              // 정수든 주소든 화면은 문자열 하나를 그린다 — 기본값도 같은 모양으로 받는다.
              $def_val = vg_setting_default_str($key);
              $isInt = vg_setting_is_int($key);
              // 저장된 값이 없으면 실제로 쓰이는 값(기본값)을 채운다 — 빈 칸으로 두면
              //   저장 버튼 한 번에 전 항목이 "정수만 가능합니다"로 거절된다.
              $val = $cur[$key] ?? ($def_val !== null ? $def_val : '');
              if (isset($fieldErr[$key])) { $val = trim((string) ($posted[$key] ?? '')); }
              $isErr = isset($fieldErr[$key]);
              $showDefault = $def_val !== null && $val !== $def_val;
          ?>
            <label class="field<?= $isErr ? ' field--err' : '' ?>" for="<?= vg_h($id) ?>">
              <?= vg_h((string) $def['label']) ?>
              <?php if ($isInt): ?>
                <input type="number" id="<?= vg_h($id) ?>" name="setting[<?= vg_h($key) ?>]"
                       value="<?= vg_h($val) ?>"
                       min="<?= (int) $def['min'] ?>" max="<?= (int) $def['max'] ?>" step="1"
                       aria-describedby="<?= vg_h($id) ?>-why"<?= $isErr ? ' aria-invalid="true"' : '' ?>>
              <?php else: ?>
                <input type="url" id="<?= vg_h($id) ?>" name="setting[<?= vg_h($key) ?>]"
                       value="<?= vg_h($val) ?>" maxlength="<?= (int) $def['max'] ?>"
                       aria-describedby="<?= vg_h($id) ?>-why"<?= $isErr ? ' aria-invalid="true"' : '' ?>>
              <?php endif; ?>
              <span class="why" id="<?= vg_h($id) ?>-why">
                <?= vg_h((string) $def['desc']) ?>
                <?= $isInt ? ' (' . (int) $def['min'] . '~' . (int) $def['max'] . ')' : '' ?>
              </span>
              <?php if ($showDefault): ?>
                <span class="field__default">기본값 <?= vg_h((string) $def_val) ?></span>
              <?php endif; ?>
              <?php if ($isErr): ?>
                <span class="field__err" role="alert"><?= vg_h($fieldErr[$key]) ?></span>
              <?php endif; ?>
            </label>
          <?php endforeach; ?>
        </div>
      </section>
    <?php endforeach; ?>
  </form>
<?php vg_footer();
