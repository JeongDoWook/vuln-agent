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
require_once __DIR__ . '/../src/compliance/policy.php'; // vg_compliance_status — 판정 어휘 SSOT
// 같은 컴플라이언스 데이터를 여는 화면이라 control_mapping.php 와 같은 게이트를 쓴다.
//   새 menu_code 를 만들면 권한 마이그레이션이 따로 필요해진다(YAGNI).
vg_require_menu('compliance');

const VG_KISA_U_FW = 'KISA_U';

/* 가이드 위험도(상/중/하)를 톤으로 옮기던 vg_kisa_u_sev_tone() 은 지웠다 — 색은 가이드
 *   위험도가 아니라 **우리 점검의 미준수 비율**이 정하고(그게 이 화면이 답하는 질문이다),
 *   위험도 값 자체는 상세(control.php)가 갖는다. 색 축이 둘이면 무엇을 보는지 흐려진다. */


$err = null;
$rows = [];
$total = 0;            // 필터 적용 후 목록 총건수(페이지네이션 대상)
$catalogTotal = 0;     // 가이드 전체 항목 수 — 커버리지의 분모
$coveredTotal = 0;     // 그중 우리 점검이 매핑된 항목 수 — 분자
$categories = [];      // 분류 필터 선택지(카탈로그가 가진 값으로만 만든다)

// 필터 — 화이트리스트로만 통과시킨다(임의 문자열이 쿼리·출력에 흘러들지 않게).
$stateLabels = ['covered' => '점검함', 'uncovered' => '미점검'];
$state = (string) ($_GET['state'] ?? '');
if (!isset($stateLabels[$state])) { $state = ''; }
$category = trim((string) ($_GET['category'] ?? ''));

try {
    $pdo = vg_pdo();
    session_write_close();   // 집계 전 세션락 해제(control_mapping.php 선례)

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

    // 페이지네이션이 없다 — 이 화면은 72개를 **한 화면에 전부** 놓는 것이 목적이다(그래야
    //   커버리지의 빈 칸이 보인다). 예전엔 1/8 페이지로 쪼개져 "몇 %를 덮나" 를 보려면 8번을
    //   넘겨야 했다. 점검하는 21개는 표로, 미점검 51개는 접힘(<details>)으로 들어간다.
    //   무한정 커질 목록이 아니라서 상한 없이 읽는다: 이 카탈로그는 가이드 한 판(2021.03)의
    //   고정 항목(72종)이고, 늘어나는 건 개정판이 나올 때뿐이다(그때도 판을 섞지 않는다 —
    //   db/migrations/20260818221235_kisa_u_catalog.sql 의 출처·판 주석이 정본).
    $st = $pdo->prepare(
        "SELECT c.control_id, c.control_name, c.category, c.severity,
                m.mapped_rule_cnt, m.codes
         $baseSql
          ORDER BY c.sort_order"
    );
    $st->execute($args);
    $rows = $st->fetchAll();

    // 매핑된 항목의 현재 판정 — 호스트별 최신 수집의 CCE 결과만 본다(control_mapping.php 와 같은
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

    // 쿼리 성공 이후에 남긴다 — 필터 값 때문에 실패한 요청이 정상 조회로 기록되지 않게.
    $logDetail = 'U-코드 커버리지 조회';
    if ($state !== '')    { $logDetail .= ' · state=' . $state; }
    if ($category !== '') { $logDetail .= ' · category=' . $category; }
    vg_log_activity($pdo, 'PAGE', null, 'view_kisa_u_coverage', $logDetail);
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
  ?>
  <?php
  /* 타일 히트맵을 **표 + 접힘**으로 바꿨다. 72개 중 51개(71%)가 미점검이라 히트맵은 화면
   *   대부분이 빈 회색 타일이 됐다 — 빈 칸을 보이게 하려던 장치가 정작 **점검하는 21개를**
   *   가려 버렸다. 그래서 판정 근거가 있는 21개만 표로 세우고(FAIL·PASS·판정 불가·미준수율을
   *   나란히 비교할 수 있는 형태), 미점검 51개는 접어 둔다.
   *   빈 칸을 숨기는 게 아니다: 접힌 채로도 **개수가 요약줄에 항상 보이고** 위 지표 4칸이
   *   커버리지 29.2%를 계속 말한다. 펼치면 코드·항목명·분류가 그대로 나온다.
   *
   * 표 어휘(열 구성·0 은 안 적는다·미터 톤)는 control_mapping.php 의 통제 기준 매핑 표에서
   *   가져왔다 — 같은 성격의 화면이 둘로 갈리면 안 된다.
   *
   * 코드·항목명은 2021.03 판 번호 체계 그대로다. 개정판은 번호가 다르므로 렌더를 바꾸면서
   *   "최신" 으로 고치지 않는다(판을 섞으면 매핑된 21종과 어긋난다). */

  // 점검하는 항목과 미점검 항목은 답할 수 있는 것이 다르다(전자는 판정, 후자는 이름뿐) —
  //   같은 표에 섞으면 열의 3/4 이 '–' 로 채워진다. 렌더 직전에 한 번만 가른다.
  $covered = [];
  $uncovered = [];
  foreach ($rows as $r) {
      if ($r['mapped_rule_cnt'] !== null) { $covered[] = $r; } else { $uncovered[] = $r; }
  }

  $detailHref = static fn(array $r): string => '/control.php?fw=' . urlencode(VG_KISA_U_FW)
      . '&control=' . urlencode((string) $r['control_id']);
  $policy = vg_compliance_policy();
  // 판정 어휘는 control_mapping.php·control.php 와 같은 함수로 뽑는다(SSOT) — 0건을 준수로
  //   찍지 않는다는 원칙이 미준수율 미터의 톤에 그대로 적용된다.
  $vOf = static fn(array $r): ?array => $verdicts[(string) $r['control_id']] ?? null;
  ?>
  <?php if (!$rows): ?>
    <div class="card">
      <?php vg_empty([
          'icon'  => 'search',
          'title' => '조건에 맞는 항목이 없습니다.',
          'hint'  => '분류·상태 필터를 바꿔 보세요.',
      ]); ?>
    </div>
  <?php else: ?>
  <?php
  vg_table(
      [
          ['label' => '코드',   'width' => '7rem', 'class' => 'col-id', 'nowrap' => true],
          ['label' => '항목명'],
          ['label' => '분류',   'width' => '12%', 'nowrap' => true],
          ['label' => 'FAIL',   'align' => 'right', 'width' => '5rem', 'nowrap' => true],
          ['label' => 'PASS',   'align' => 'right', 'width' => '5rem', 'nowrap' => true],
          ['label' => '판정 불가', 'align' => 'right', 'width' => '6rem', 'nowrap' => true,
           'title' => '점검을 돌렸지만 판정할 수 없었던 건수(NA)'],
          ['label' => '미준수율', 'width' => '14%',
           'title' => 'FAIL ÷ 최신 수집 점검 결과. 판정이 아니라 집계다.'],
      ],
      $covered,
      [
          'card'  => false,
          'empty' => [
              'icon'  => 'chart',
              'title' => '이 조건에 점검하는 항목이 없습니다.',
              'hint'  => '아래 미점검 목록에 남은 항목이 있습니다.',
          ],
          'cell' => [
              // 코드·항목명 둘 다에 링크를 건다 — 누르는 면적을 코드 한 조각으로 좁혀 두지
              //   않는다(control_mapping.php 와 같은 규약).
              0 => static fn(array $r): string => '<a href="' . vg_h($detailHref($r)) . '"><code>'
                  . vg_h((string) $r['control_id']) . '</code></a>',
              1 => static fn(array $r): string => '<a class="body-link" href="' . vg_h($detailHref($r)) . '">'
                  . vg_h((string) $r['control_name']) . '</a>',
              2 => static fn(array $r): string => vg_h((string) ($r['category'] ?? '')),
              // 0 은 적지 않는다 — 신호는 FAIL 하나뿐인데 모든 행이 '0' 으로 채워지면 정작
              //   읽어야 할 값을 덮는다(control_mapping.php·cce-rules.php 와 같은 어휘).
              3 => static function (array $r) use ($vOf): string {
                  $v = $vOf($r);
                  if ($v === null) { return '<span class="why">–</span>'; }
                  return '<b>' . number_format((int) $v['fail_cnt']) . '</b>';
              },
              4 => static function (array $r) use ($vOf): string {
                  $v = $vOf($r);
                  if ($v === null || (int) $v['pass_cnt'] === 0) { return '<span class="why">–</span>'; }
                  return number_format((int) $v['pass_cnt']);
              },
              5 => static function (array $r) use ($vOf): string {
                  $v = $vOf($r);
                  if ($v === null || (int) $v['na_cnt'] === 0) { return '<span class="why">–</span>'; }
                  return number_format((int) $v['na_cnt']);
              },
              // meter 에는 ok 톤이 없다(app.css) → low 로 떨군다. 0% 라 색은 안 보인다.
              6 => static function (array $r) use ($vOf, $policy): string {
                  $v = $vOf($r);
                  $cnt = $v !== null ? (int) $v['finding_cnt'] : 0;
                  if ($cnt === 0) { return '<span class="why">점검 결과 없음</span>'; }
                  $fail = (int) $v['fail_cnt'];
                  $tone = vg_compliance_status($fail, (int) $v['na_cnt'] > 0, $policy['partial_max'])['tone'];
                  return vg_meter($tone === 'ok' ? 'low' : $tone, $fail / $cnt * 100,
                                  'FAIL ' . number_format($fail) . ' / 전체 ' . number_format($cnt) . '건')
                       . '<span class="why">' . number_format($fail / $cnt * 100, 1) . '%</span>';
              },
          ],
      ]
  );
  ?>

  <?php if ($uncovered): ?>
  <div class="card">
    <strong>미점검 항목</strong>
    <span class="why"> · 대응 점검(CCE 규칙)이 매핑되지 않아 판정 근거가 없습니다</span>
    <div class="card__body">
      <?php /* 접혀 있어도 개수는 요약줄에 항상 남는다 — 이 숫자가 커버리지의 근거라 숨기면
               위 지표 4칸과 말이 어긋난다. 펼치면 답할 수 있는 것(코드·항목명·분류)만 나온다. */ ?>
      <details>
        <summary>미점검 <?= number_format(count($uncovered)) ?>개 보기
          <?= vg_badge(number_format(count($uncovered)), 'high') ?></summary>
        <?php
        vg_table(
            [
                ['label' => '코드',   'width' => '7rem', 'class' => 'col-id', 'nowrap' => true],
                ['label' => '항목명'],
                ['label' => '분류',   'width' => '14%', 'nowrap' => true],
            ],
            $uncovered,
            [
                'card' => false,
                'cell' => [
                    0 => static fn(array $r): string => '<code>' . vg_h((string) $r['control_id']) . '</code>',
                    1 => static fn(array $r): string => vg_h((string) $r['control_name']),
                    2 => static fn(array $r): string => vg_h((string) ($r['category'] ?? '')),
                ],
            ]
        );
        ?>
      </details>
    </div>
  </div>
  <?php endif; ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();

