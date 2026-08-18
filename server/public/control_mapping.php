<?php
declare(strict_types=1);

/**
 * control_mapping.php — 보안설정 점검(CCE) 결과를 "기준"으로 바꿔 끼워 보는 화면. 로그인 필요.
 *   ?fw=ISMS_P|KISA_U|N2SF  ·  ?page=N/?per_page=N
 *
 * 통제 하나의 상세는 control.php 가 갖는다 — 이 파일은 목록만(SRP). 예전 `?control=` 드릴다운
 *   URL 은 아래에서 그 주소로 302 한다(링크만 갈아끼우면 이미 공유·북마크된 주소가 목록으로
 *   되돌아가 "눌렀는데 아무 일도 안 일어난다"가 된다).
 *
 * 왜 새 화면인가: compliance_rules.php/compliance_rule.php 는 SSG(SCAP) 룰 카탈로그이지 CCE
 *   점검 결과 목록이 아니고, compliance.php 는 통제 3종을 자동판정하는 화면이다(판정 로직은
 *   건드리지 않는다). "같은 점검 결과를 U-코드·ISMS-P·N2SF 로 바꿔 본다" 는 목적은 어느 쪽에도
 *   없어서, tb_control_mapping 을 읽어 기준별로 그룹핑만 하는 화면을 따로 둔다.
 *   판정은 하지 않는다 — 이 화면은 "이 통제에 걸린 점검 결과가 몇 건인가" 만 센다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';           // vg_log_activity
require_once __DIR__ . '/../src/control_mapping.php'; // vg_control_frameworks, vg_control_framework_param
// 인가 게이트. 이게 없어서 **비로그인 상태로도 200 + CCE 점검 결과 전량**이 나갔다(실측:
//   빈 쿠키로 curl 하면 다른 화면은 302 login 인데 여기만 200). 상세인 control.php 는 처음부터
//   갖고 있었다 — 목록만 빠져 있었다. 같은 데이터를 여는 두 URL 은 같은 게이트를 지나야 한다.
vg_require_menu('compliance');

$err = null;
$fw = vg_control_framework_param($_GET['fw'] ?? null);   // 화이트리스트 검증(SSOT)
$frameworks = vg_control_frameworks();

// 옛 드릴다운 URL 호환 — 상세는 control.php 로 이관했다.
$legacyControl = trim((string) ($_GET['control'] ?? ''));
if ($legacyControl !== '') {
    header('Location: /control.php?fw=' . urlencode($fw) . '&control=' . urlencode($legacyControl), true, 302);
    exit;
}

// U-코드는 이 화면이 답하지 않는다. 여기는 **매핑된 통제**만 나열해서 위반이 있는 21개만
//   보였고, kisa-u.php 는 가이드 전체 72개를 분모로 놓아 미점검 51개와 커버리지까지 답한다
//   — 뒤가 앞을 포함한다. 같은 질문에 두 화면이 따로 답하는 상태를 남기지 않으려고 U-코드는
//   kisa-u.php 하나로 모으고, 이미 공유·북마크된 이 주소는 302 로 그리로 보낸다(칩만 지우면
//   "눌렀는데 아무 일도 안 일어난다"가 된다 — 옛 ?control= 을 이관할 때와 같은 이유).
if ($fw === 'KISA_U') {
    header('Location: /kisa-u.php', true, 302);
    exit;
}

$rows = [];            // 매핑된 통제 전체(점검 결과 없는 통제 포함)
$total = 0;            // 페이지네이션 대상 총건수
$mappedRules = 0;      // 이 기준에 매핑된 CCE 룰 수
$findingTotal = 0;     // 이 기준으로 묶인 점검 결과 총건수
$failTotal = 0;        // 그중 FAIL 총건수(기준 전체 — 페이지가 아니다)
$failControls = 0;     // FAIL 이 하나라도 있는 통제 수
$noResultControls = 0; // 매핑은 있으나 점검 결과가 0건인 통제 수
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();
    vg_log_activity($pdo, 'PAGE', null, 'view_control_mapping', '통제 기준 매핑 조회 · ' . $fw);
    session_write_close();   // 인가·감사로그 이후 집계 전 세션락 해제(compliance.php 선례)

    // 호스트별 최신 스캔의 CCE 결과만 본다 — 지난 스캔까지 세면 같은 위반이 중복 집계된다.
    $baseSql =
        "FROM tb_cce_finding cf
           JOIN " . vg_latest_scan_subq() . " t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
           JOIN tb_control_mapping m ON m.rule_code = cf.code AND m.framework = ? AND m.is_deleted = 0
          WHERE cf.is_deleted = 0";

    $mappedRules = (int) (function () use ($pdo, $fw) {
        $st = $pdo->prepare(
            'SELECT COUNT(DISTINCT rule_code) FROM tb_control_mapping WHERE framework = ? AND is_deleted = 0'
        );
        $st->execute([$fw]);
        return $st->fetchColumn();
    })();

    $st = $pdo->prepare("SELECT COUNT(*) $baseSql");
    $st->execute([$fw]);
    $findingTotal = (int) $st->fetchColumn();

    // ── 실제 점검 결과를 기준의 통제 ID 로 그룹핑 ──
    $groupSql =
        "SELECT m.control_id, m.control_name,
                COUNT(*) AS finding_cnt,
                SUM(cf.result = 'FAIL') AS fail_cnt,
                SUM(cf.result = 'PASS') AS pass_cnt,
                SUM(cf.result = 'NA')   AS na_cnt,
                COUNT(DISTINCT cf.code) AS rule_cnt,
                GROUP_CONCAT(DISTINCT cf.code ORDER BY cf.code SEPARATOR ', ') AS codes
         $baseSql
          GROUP BY m.control_id, m.control_name";

    $st = $pdo->prepare($groupSql);
    $st->execute([$fw]);
    $findingsByControl = [];
    foreach ($st->fetchAll() as $r) {
        $findingsByControl[(string) $r['control_id']] = $r;
    }

    // 매핑된 통제를 하나의 목록으로 만든다. 예전에는 결과가 있는 통제와 없는 통제를 표/카드로
    //   갈라 같은 통제를 찾는 동선이 두 벌이었다. 매핑 정본을 기준으로 합치고, 결과가 없으면
    //   명시적인 "점검 결과 없음" 상태를 붙인다(0건 준수로 보이지 않게).
    $st = $pdo->prepare(
        "SELECT control_id, control_name, COUNT(DISTINCT rule_code) AS mapped_rule_cnt,
                GROUP_CONCAT(DISTINCT rule_code ORDER BY rule_code SEPARATOR ', ') AS codes
           FROM tb_control_mapping
          WHERE framework = ? AND is_deleted = 0
          GROUP BY control_id, control_name"
    );
    $st->execute([$fw]);
    $allRows = [];
    foreach ($st->fetchAll() as $mapped) {
        $observed = $findingsByControl[(string) $mapped['control_id']] ?? [];
        $allRows[] = array_merge($mapped, [
            'finding_cnt' => (int) ($observed['finding_cnt'] ?? 0),
            'fail_cnt'    => (int) ($observed['fail_cnt'] ?? 0),
            'pass_cnt'    => (int) ($observed['pass_cnt'] ?? 0),
            'na_cnt'      => (int) ($observed['na_cnt'] ?? 0),
        ]);
    }
    usort($allRows, static fn(array $a, array $b): int =>
        ((int) $b['fail_cnt'] <=> (int) $a['fail_cnt'])
        ?: strnatcasecmp((string) $a['control_id'], (string) $b['control_id'])
    );
    $total = count($allRows);
    // 결론 집계 — 페이지가 아니라 **기준 전체** 기준이다(1페이지만 세면 "위반 0" 이 거짓이 된다).
    //   판정이 아니라 집계다: 이 화면은 위반 건수를 세기만 하고 준수/미준수를 말하지 않는다.
    foreach ($allRows as $r) {
        $failTotal += (int) $r['fail_cnt'];
        if ((int) $r['fail_cnt'] > 0) { $failControls++; }
        if ((int) $r['finding_cnt'] === 0) { $noResultControls++; }
    }
    $offset = ($page - 1) * $perPage;
    $rows = array_slice($allRows, $offset, $perPage);
} catch (Throwable $e) {
    error_log('[control_mapping] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('통제 기준 매핑', 'control_mapping');
?>
  <?php // 제목은 계열 이름만 — 어느 화면인지는 바로 아래 서브탭이 말한다(compliance.php 와 같은 규약). ?>
  <?php vg_page_title('컴플라이언스', 'CONTROL MAPPING', ['count' => $total]); ?>
  <?php // 컴플라이언스 계열 서브탭(정의는 nav.php 한 곳) — 저쪽 화면과 같은 줄을 그린다.
        //   판정하지 않는다는 사실은 위 부제가 이미 말한다. ?>
  <?php vg_compliance_subtabs('control'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <div class="tabs">
    <?php // U-코드 칩은 없다 — 위 서브탭 '기반시설 U-코드' 가 그 기준의 정본 화면이다. ?>
    <?php foreach ($frameworks as $code => $label): ?>
      <?php if ($code === 'KISA_U') { continue; } ?>
      <a class="pill<?= $code === $fw ? ' pill--on' : '' ?>"
         href="/control_mapping.php?fw=<?= urlencode($code) ?>"><?= vg_h($label) ?></a>
    <?php endforeach; ?>
  </div>
  <p class="why">기반시설 U-코드는 위 <a href="/kisa-u.php">기반시설 U-코드</a> 탭이 정본입니다.
    거기는 가이드 전체 항목을 분모로 놓아 미점검 항목까지 보입니다.</p>

  <?php
  // 결론을 앞에 세운다(compliance.php 와 같은 원칙) — 예전엔 "매핑된 점검 항목 / 점검 결과"
  //   두 숫자뿐이라, 표를 다 훑기 전엔 이 기준에서 무엇이 걸렸는지 알 수 없었다.
  //   단위를 라벨에 붙인다: 건(점검 결과)과 종(통제 가짓수)이 한 줄에 섞여 있다.
  ?>
  <div class="cards cards--grid">
    <div class="kpi kpi--sm tone-crit"><b><?= number_format($failTotal) ?></b><span>위반(FAIL) · 건</span></div>
    <div class="kpi kpi--sm tone-high"><b><?= number_format($failControls) ?></b><span>위반 있는 통제 · 종</span></div>
    <div class="kpi kpi--sm tone-muted"><b><?= number_format($noResultControls) ?></b><span>점검 결과 없음 · 종</span></div>
    <div class="kpi kpi--sm"><b><?= number_format($mappedRules) ?></b><span>매핑된 점검 항목 · 개</span></div>
    <div class="kpi kpi--sm"><b><?= number_format($findingTotal) ?></b><span>최신 스캔 점검 결과 · 건</span></div>
  </div>
<?php /* 같은 말이 부제에 이미 있다 — 여기서 한 번 더 적지 않는다(부제가 정본). */ ?>

  <?php
  // 통제 ID·통제명 모두 상세로 들어가는 링크다 — "누르면 들어간다"가 요구사항이라
  //   누르는 면적을 ID 한 조각으로 좁혀 두지 않는다.
  $detailHref = fn(array $r): string => '/control.php?fw=' . urlencode($fw)
      . '&amp;control=' . urlencode((string) $r['control_id']);
  vg_table(
      [
          ['label' => '통제 ID', 'width' => '9rem', 'class' => 'col-id'],
          ['label' => '통제명'],
          ['label' => '매핑 점검 항목', 'width' => '20%'],
          // 'PASS n · NA n · n건' 이 9rem 에서 두 줄로 접혔다 — 한 줄에 들어오게 넓힌다.
          //   11rem 도 세 자리 수가 겹치면 여전히 접혀서(실측 'PASS 176 · NA 484 · 740건') 13rem.
          ['label' => '결과', 'width' => '13rem'],
          ['label' => '위반', 'width' => '6rem', 'align' => 'right'],
      ],
      $rows,
      [
          'empty' => [
              'icon'  => '🧭',
              'title' => '이 기준에 매핑된 통제가 없습니다.',
              'hint'  => '근거가 확인된 통제 매핑이 등록되면 이 목록에 표시됩니다.',
          ],
          'cell' => [
              0 => fn($r) => '<a href="' . $detailHref($r) . '">'
                           . '<code class="why">' . vg_h((string) $r['control_id']) . '</code></a>',
              1 => fn($r) => '<a class="control-name" href="' . $detailHref($r) . '">'
                           . vg_h((string) $r['control_name']) . '</a>',
              2 => fn($r) => '<span class="why">' . number_format((int) $r['mapped_rule_cnt']) . '개 · '
                           . vg_trunc((string) ($r['codes'] ?? ''), 52) . '</span>',
              3 => function ($r) {
                  if ((int) $r['finding_cnt'] === 0) { return vg_badge('점검 결과 없음', 'muted'); }
                  $cnt  = (int) $r['finding_cnt'];
                  $fail = (int) $r['fail_cnt'];
                  $why  = 'PASS ' . number_format((int) $r['pass_cnt'])
                        . ' · 판정 불가 ' . number_format((int) $r['na_cnt'])
                        . ' · 전체 ' . number_format($cnt) . '건';
                  // 위반 비율 게이지 — 숫자 세 개만으로는 "FAIL 12" 가 12/13 인지 12/740 인지
                  //   한눈에 안 잡힌다(분모가 글자에 묻힌다). meter 는 ok 톤이 없어 low 로 떨군다.
                  $tone = $fail > 0 ? 'crit' : ((int) $r['na_cnt'] > 0 ? 'med' : 'low');
                  return '<span class="why">' . vg_h($why) . '</span>'
                      . vg_meter($tone, $fail / $cnt * 100, 'FAIL ' . number_format($fail) . ' / ' . $why);
              },
              4 => function ($r) {
                  if ((int) $r['finding_cnt'] === 0) { return '<span class="why">–</span>'; }
                  $fail = (int) $r['fail_cnt'];
                  $tone = $fail > 0 ? 'crit' : ((int) $r['na_cnt'] > 0 ? 'med' : 'ok');
                  return vg_badge(number_format($fail) . '건', $tone);
              },
          ],
      ]
  );
  // 결과 범례는 걷었다 — 네 상태를 '결과' 칸이 이미 **글자로** 말한다('점검 결과 없음'
  //   뱃지 / 'PASS n · 판정 불가 n · 전체 n건'). 옆 '위반' 칸의 색은 그 글자를 되풀이하는
  //   두 번째 표기라, 범례를 지우면서 잃는 사실이 없다.
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

<?php endif; ?>
<?php vg_footer();
