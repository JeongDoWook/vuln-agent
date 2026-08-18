<?php
declare(strict_types=1);

/**
 * kisa-u.php — 「주요정보통신기반시설 기술적 취약점 분석·평가」 U-코드 커버리지. 로그인 필요.
 *   ?state=covered|uncovered  ·  ?category=계정관리…  ·  ?page=N/?per_page=N
 *
 * control_mapping.php 와 방향이 반대다. 저기는 **우리가 매핑한 통제**만 나열하므로
 *   "우리가 점검하지 않는 U-코드" 는 화면에 존재조차 하지 않는다(tb_control_mapping 은
 *   rule_code 가 NOT NULL 이라 행 자체가 없다). 그래서 "기반시설 기준으로 몇 %를 덮나" 를
 *   답할 수 없었다. 여기서는 tb_control_catalog(가이드 전 항목)를 **분모**로 놓고
 *   tb_control_mapping 을 왼쪽 조인해 덮이지 않은 항목까지 세어 보여준다.
 *
 * 빈 칸이 드러나는 것이 이 화면의 값이다 — 미점검 항목을 숨기거나 준수로 보이게 하지 않는다.
 *   카탈로그 정본은 db/migrations/20260818221235_kisa_u_catalog.sql(출처·판 명시),
 *   매핑 정본은 tb_control_mapping 이다. 이 화면은 둘 다 조회만 한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';           // vg_log_activity
require_once __DIR__ . '/../src/control_mapping.php'; // vg_control_frameworks (기준 라벨 SSOT)
// 같은 컴플라이언스 데이터를 여는 화면이라 control_mapping.php 와 같은 게이트를 쓴다.
//   새 menu_code 를 만들면 권한 마이그레이션이 따로 필요해진다(YAGNI).
vg_require_menu('compliance');

const VG_KISA_U_FW = 'KISA_U';

/** 가이드 위험도(상/중/하) → 톤 어휘. 색을 새로 만들지 않고 기존 어휘에 얹는다. */
function vg_kisa_u_sev_tone(string $sev): string {
    return ['상' => 'crit', '중' => 'high', '하' => 'med'][$sev] ?? 'muted';
}


$err = null;
$rows = [];
$total = 0;            // 필터 적용 후 목록 총건수(페이지네이션 대상)
$catalogTotal = 0;     // 가이드 전체 항목 수 — 커버리지의 분모
$coveredTotal = 0;     // 그중 우리 점검이 매핑된 항목 수 — 분자
$categories = [];      // 분류 필터 선택지(카탈로그가 가진 값으로만 만든다)
$page = vg_page();
$perPage = vg_perpage();

// 필터 — 화이트리스트로만 통과시킨다(임의 문자열이 쿼리·출력에 흘러들지 않게).
$stateLabels = ['covered' => '점검함', 'uncovered' => '미점검'];
$state = (string) ($_GET['state'] ?? '');
if (!isset($stateLabels[$state])) { $state = ''; }
$category = trim((string) ($_GET['category'] ?? ''));

try {
    $pdo = vg_pdo();
    vg_log_activity($pdo, 'PAGE', null, 'view_kisa_u_coverage', 'U-코드 커버리지 조회');
    session_write_close();   // 인가·감사로그 이후 집계 전 세션락 해제(control_mapping.php 선례)

    // 분류 선택지는 카탈로그가 실제로 가진 값에서 뽑는다 — 화면에 분류표를 새로 박지 않는다.
    $st = $pdo->prepare(
        // 가이드가 항목을 늘어놓은 차례대로 고른다(sort_order 의 최솟값) — 가나다순으로 세우면
        //   '계정관리 → 파일및디렉토리관리 → 서비스관리 → 패치관리 → 로그관리' 라는 가이드의
        //   장 순서가 깨진다. DISTINCT + ORDER BY 는 ONLY_FULL_GROUP_BY 에서 막히므로 GROUP BY 다.
        'SELECT category FROM tb_control_catalog
          WHERE framework = ? AND is_deleted = 0 AND category IS NOT NULL
          GROUP BY category ORDER BY MIN(sort_order)'
    );
    $st->execute([VG_KISA_U_FW]);
    foreach ($st->fetchAll() as $r) { $categories[(string) $r['category']] = (string) $r['category']; }
    if ($category !== '' && !isset($categories[$category])) { $category = ''; }

    // 매핑된 U-코드(분자). 카탈로그에 없는 control_id 가 매핑에 있어도 분자에 세지 않는다 —
    //   분모에 없는 것을 분자에 넣으면 커버리지가 100% 를 넘는다.
    $mapSubq =
        "(SELECT control_id,
                 COUNT(DISTINCT rule_code) AS mapped_rule_cnt,
                 GROUP_CONCAT(DISTINCT rule_code ORDER BY rule_code SEPARATOR ',') AS codes
            FROM tb_control_mapping
           WHERE framework = ? AND is_deleted = 0
           GROUP BY control_id) m";

    // 커버리지는 **필터와 무관하게** 기준 전체로 센다(1페이지·1분류만 세면 거짓이 된다).
    $st = $pdo->prepare(
        "SELECT COUNT(*) AS total, SUM(m.control_id IS NOT NULL) AS covered
           FROM tb_control_catalog c
           LEFT JOIN $mapSubq ON m.control_id = c.control_id
          WHERE c.framework = ? AND c.is_deleted = 0"
    );
    $st->execute([VG_KISA_U_FW, VG_KISA_U_FW]);
    $sum = $st->fetch() ?: [];
    $catalogTotal = (int) ($sum['total'] ?? 0);
    $coveredTotal = (int) ($sum['covered'] ?? 0);

    // ── 목록 ──
    $where = 'c.framework = ? AND c.is_deleted = 0';
    $args = [VG_KISA_U_FW, VG_KISA_U_FW];      // 서브쿼리의 framework 가 먼저 바인딩된다
    if ($state === 'covered')   { $where .= ' AND m.control_id IS NOT NULL'; }
    if ($state === 'uncovered') { $where .= ' AND m.control_id IS NULL'; }
    if ($category !== '')       { $where .= ' AND c.category = ?'; $args[] = $category; }

    $baseSql = "FROM tb_control_catalog c LEFT JOIN $mapSubq ON m.control_id = c.control_id WHERE $where";

    $st = $pdo->prepare("SELECT COUNT(*) $baseSql");
    $st->execute($args);
    $total = (int) $st->fetchColumn();

    $offset = max(0, ($page - 1) * $perPage);
    $st = $pdo->prepare(
        "SELECT c.control_id, c.control_name, c.category, c.severity,
                m.mapped_rule_cnt, m.codes
         $baseSql
          ORDER BY c.sort_order
          LIMIT $perPage OFFSET $offset"     // 정수 캐스팅된 값(vg_page/vg_perpage) — 바인딩 불가한 자리
    );
    $st->execute($args);
    $rows = $st->fetchAll();

    // 매핑된 항목의 현재 판정 — 호스트별 최신 스캔의 CCE 결과만 본다(control_mapping.php 와 같은
    //   기준). 지난 스캔까지 세면 같은 위반이 중복 집계된다. 목록과 별도 조회 1회로 끝낸다(N+1 금지).
    $st = $pdo->prepare(
        "SELECT m.control_id,
                COUNT(*) AS finding_cnt,
                SUM(cf.result = 'FAIL') AS fail_cnt,
                SUM(cf.result = 'PASS') AS pass_cnt,
                SUM(cf.result = 'NA')   AS na_cnt
           FROM tb_cce_finding cf
           JOIN " . vg_latest_scan_subq() . " t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
           JOIN tb_control_mapping m ON m.rule_code = cf.code AND m.framework = ? AND m.is_deleted = 0
          WHERE cf.is_deleted = 0
          GROUP BY m.control_id"
    );
    $st->execute([VG_KISA_U_FW]);
    $verdicts = [];
    foreach ($st->fetchAll() as $r) { $verdicts[(string) $r['control_id']] = $r; }
} catch (Throwable $e) {
    error_log('[kisa-u] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
    $verdicts = [];
}

$uncoveredTotal = $catalogTotal - $coveredTotal;
$coveragePct = $catalogTotal > 0 ? $coveredTotal / $catalogTotal * 100 : 0.0;

vg_header('기반시설 U-코드 커버리지', 'control_mapping');
?>
  <?php vg_page_title('컴플라이언스', 'KISA U COVERAGE', ['count' => $total]); ?>
  <?php vg_compliance_subtabs('kisa_u'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php
  // 결론을 앞에 세운다 — 분모(가이드 전체)·분자(우리가 덮는 항목)·그 차이인 미점검.
  //   미점검을 회색으로 죽이지 않는다. 이 화면의 값은 빈 칸이 보이는 것이다.
  vg_kpi_strip([
      ['value' => number_format($coveredTotal),   'label' => '점검하는 항목 · 개', 'tone' => 'ok'],
      ['value' => number_format($uncoveredTotal), 'label' => '미점검 항목 · 개',   'tone' => 'high',
       'href'  => '/kisa-u.php?state=uncovered'],
      ['value' => number_format($catalogTotal),   'label' => '가이드 전체 항목 · 개'],
      ['value' => number_format($coveragePct, 1) . '%', 'label' => '커버리지',
       'tone'  => $coveragePct >= 50 ? 'ok' : 'med'],
  ]);

  vg_toolbar([
      ['type' => 'select', 'name' => 'state',    'options' => $stateLabels, 'selected' => $state,
       'empty_label' => '전체'],
      ['type' => 'select', 'name' => 'category', 'options' => $categories,  'selected' => $category,
       'empty_label' => '전체 분류'],
  ]);

  // 판정 칸 — 매핑이 없으면 '미점검', 매핑은 있는데 결과가 없으면 '점검 결과 없음'.
  //   둘은 다른 상태다: 앞은 우리가 점검 자체를 안 만든 것이고, 뒤는 아직 안 돌았거나
  //   해당 호스트가 없는 것이다. 하나로 뭉치면 미점검 규모가 가려진다.
  $verdictCell = function (array $r) use ($verdicts): string {
      if ($r['mapped_rule_cnt'] === null) { return vg_badge('미점검', 'high'); }
      $v = $verdicts[(string) $r['control_id']] ?? null;
      if ($v === null || (int) $v['finding_cnt'] === 0) { return vg_badge('점검 결과 없음', 'muted'); }
      $cnt  = (int) $v['finding_cnt'];
      $fail = (int) $v['fail_cnt'];
      $tone = $fail > 0 ? 'crit' : ((int) $v['na_cnt'] > 0 ? 'med' : 'ok');
      // 0 인 항목은 적지 않는다 — 신호는 FAIL 하나뿐인데 모든 행이 'PASS 0 · 판정 불가 0' 으로
      //   채워져 정작 읽어야 할 값을 덮었다. 전체 건수는 호스트 수라 행마다 같은 값이 반복되므로
      //   본문에서 빼고 미터 툴팁이 갖는다(근거를 지우는 게 아니라 접는다). cce-rules.php 와 같은 어휘.
      $parts = [];
      if ((int) $v['pass_cnt'] > 0) { $parts[] = 'PASS ' . number_format((int) $v['pass_cnt']); }
      if ((int) $v['na_cnt'] > 0)   { $parts[] = '판정 불가 ' . number_format((int) $v['na_cnt']); }
      $why = implode(' · ', $parts);
      // meter 에는 ok 톤이 없다(app.css) → low 로 떨군다. 0% 라 색은 안 보인다.
      return vg_badge('FAIL ' . number_format($fail), $tone)
          . ($why === '' ? '' : '<br><span class="why">' . vg_h($why) . '</span>')
          . vg_meter($tone === 'ok' ? 'low' : $tone, $cnt > 0 ? $fail / $cnt * 100 : 0.0,
                     'FAIL ' . number_format($fail) . ' / 점검 ' . number_format($cnt) . '건');
  };

  vg_table(
      [
          ['label' => 'U-코드', 'width' => '6rem', 'class' => 'col-id'],
          ['label' => '항목명'],
          ['label' => '분류', 'width' => '10rem'],
          ['label' => '위험도', 'width' => '5rem', 'align' => 'center'],
          ['label' => '우리 점검', 'width' => '22%'],
          ['label' => '판정', 'width' => '16rem'],
      ],
      $rows,
      [
          'empty' => [
              'icon'  => '🧭',
              'title' => '조건에 맞는 항목이 없습니다.',
              'hint'  => '분류·상태 필터를 바꿔 보세요.',
          ],
          'cell' => [
              0 => fn($r) => '<code class="why">' . vg_h((string) $r['control_id']) . '</code>',
              // 명칭을 확인하지 못한 항목은 비워 둔다 — 자리표시 문구로 채우면 확인된 것처럼 읽힌다.
              1 => fn($r) => $r['control_name'] !== null && $r['control_name'] !== ''
                  ? vg_h((string) $r['control_name']) : '',
              2 => fn($r) => $r['category'] !== null ? '<span class="why">' . vg_h((string) $r['category']) . '</span>' : '',
              3 => fn($r) => $r['severity'] !== null ? vg_badge((string) $r['severity'], vg_kisa_u_sev_tone((string) $r['severity'])) : '',
              4 => function ($r) {
                  if ($r['mapped_rule_cnt'] === null) { return ''; }
                  $links = [];
                  foreach (explode(',', (string) $r['codes']) as $code) {
                      $code = trim($code);
                      if ($code === '') { continue; }
                      $links[] = '<a href="/cce-rule.php?code=' . urlencode($code) . '">'
                               . '<code class="why">' . vg_h($code) . '</code></a>';
                  }
                  return implode(' ', $links);
              },
              5 => $verdictCell,
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();

