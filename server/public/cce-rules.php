<?php
declare(strict_types=1);

/**
 * cce-rules.php — CCE 카탈로그. "우리가 실제로 무엇을 점검하는가" 를 한 화면에 세운다. 로그인 필요.
 *   ?q=검색  ·  ?sev=HIGH|MEDIUM|LOW  ·  ?page=N/?per_page=N
 *
 * 이 자리에는 원래 SSG(SCAP Security Guide) 룰 카탈로그(compliance_rules.php, 약 2,493건)가
 *   있었다. 그건 우리가 판정하지 않는 외부 참조 데이터라, 사이드바에서 이 화면으로 바꿨다.
 *   SSG 카탈로그는 지우지 않는다 — 이 화면의 상세(cce-rule.php)가 참조 근거로 계속 링크한다.
 *
 * 목록의 정본은 DB 가 아니라 **판정 코드**다(server/src/cce.php 의 vg_cce_rules) — 항목을
 *   테이블로 복사하면 판정 로직과 어긋난다. 39개뿐이라 필터·정렬·페이지는 메모리에서 끝낸다
 *   (LIMIT/OFFSET 을 쓸 표가 없다). 무거운 건 판정 집계뿐이고 그건 GROUP BY 한 번이다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/cce.php';             // vg_cce_rules — 점검 룰 메타의 SSOT
require_once __DIR__ . '/../src/control_mapping.php'; // vg_control_mapping_for, vg_cce_rule_guides
vg_require_menu('catalog');   // 카탈로그 계열과 같은 메뉴코드(cves.php·packages.php 와 동일)

$err = null;
$rules = [];        // 화면에 뿌릴 행(필터·정렬 후 전체)
$rows = [];         // 그중 이 페이지 몫
$total = 0;         // 필터 결과 건수(페이지네이션 분모)
$ruleTotal = 0;     // 점검 항목 전체 수(필터 무관)
$checkedHosts = 0;  // 최신 스캔에 CCE 판정이 있는 자산 수
$sevOptions = ['HIGH' => 'HIGH', 'MEDIUM' => 'MEDIUM', 'LOW' => 'LOW'];

$q   = trim((string) ($_GET['q'] ?? ''));
$sev = trim((string) ($_GET['sev'] ?? ''));
if ($sev !== '' && !isset($sevOptions[$sev])) { $sev = ''; }
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();
    $catalog = vg_cce_rules();
    $ruleTotal = count($catalog);
    $codes = array_keys($catalog);

    // 판정 집계 — 호스트별 최신 스캔만 센다. 지난 스캔까지 세면 같은 위반이 중복 집계된다
    //   (control_mapping.php·control.php 와 같은 기준). 룰마다 물어보면 39번 왕복이라
    //   한 번의 GROUP BY 로 끝낸다.
    $st = $pdo->query(
        "SELECT cf.code,
                SUM(cf.result = 'FAIL') AS fail_cnt,
                SUM(cf.result = 'PASS') AS pass_cnt,
                SUM(cf.result = 'NA')   AS na_cnt
           FROM tb_cce_finding cf
           JOIN " . vg_latest_scan_subq() . " t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
          WHERE cf.is_deleted = 0
          GROUP BY cf.code"
    );
    $counts = [];
    foreach ($st->fetchAll() as $r) {
        $counts[(string) $r['code']] = [
            'FAIL' => (int) $r['fail_cnt'],
            'PASS' => (int) $r['pass_cnt'],
            'NA'   => (int) $r['na_cnt'],
        ];
    }

    $st = $pdo->query(
        "SELECT COUNT(DISTINCT t.host_id)
           FROM tb_cce_finding cf
           JOIN " . vg_latest_scan_subq() . " t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
          WHERE cf.is_deleted = 0"
    );
    $checkedHosts = (int) $st->fetchColumn();

    // 요약·기준 매핑도 각각 IN 절 한 번씩(N+1 금지) — 기존 헬퍼를 그대로 쓴다.
    $guides   = vg_cce_rule_guides($codes);
    $mappings = vg_control_mapping_for($codes);

    foreach ($catalog as $code => $meta) {
        $c = $counts[$code] ?? ['FAIL' => 0, 'PASS' => 0, 'NA' => 0];
        $mapped = $mappings[$code] ?? [];
        // 검색 대상에 기준 식별자(U-01·2.5.4·AP)까지 넣는다 — 감사 대응 중에는 점검 이름보다
        //   기준 번호로 찾는 일이 더 많다.
        $haystack = $code . ' ' . $meta['title'] . ' ' . ($guides[$code]['summary'] ?? '')
                  . ' ' . (string) $meta['ssg_rule_id'];
        foreach ($mapped as $fw => $items) {
            foreach ($items as $it) { $haystack .= ' ' . $fw . ' ' . $it['control_id'] . ' ' . $it['control_name']; }
        }

        $rules[] = [
            'code'        => $code,
            'title'       => $meta['title'],
            'severity'    => $meta['severity'],
            'ssg_rule_id' => $meta['ssg_rule_id'],
            'summary'     => $guides[$code]['summary'] ?? '',
            'mapping'     => $mapped,
            'fail_cnt'    => $c['FAIL'],
            'pass_cnt'    => $c['PASS'],
            'na_cnt'      => $c['NA'],
            'result_cnt'  => $c['FAIL'] + $c['PASS'] + $c['NA'],
            'haystack'    => $haystack,
        ];
    }

    if ($sev !== '') {
        $rules = array_values(array_filter($rules, fn(array $r): bool => $r['severity'] === $sev));
    }
    if ($q !== '') {
        $rules = array_values(array_filter(
            $rules,
            fn(array $r): bool => mb_stripos($r['haystack'], $q) !== false
        ));
    }

    // 위반이 많은 항목이 먼저, 그다음 심각도, 그다음 코드 — 매번 같은 순서가 나오게 고정한다.
    $sevRank = ['HIGH' => 0, 'MEDIUM' => 1, 'LOW' => 2];
    usort($rules, function (array $a, array $b) use ($sevRank): int {
        return [$b['fail_cnt'], $sevRank[$a['severity']] ?? 9, $a['code']]
           <=> [$a['fail_cnt'], $sevRank[$b['severity']] ?? 9, $b['code']];
    });

    $total = count($rules);
    if ($total > 0) { $page = min($page, (int) ceil($total / $perPage)); }
    $rows = array_slice($rules, ($page - 1) * $perPage, $perPage);
} catch (Throwable $e) {
    error_log('[cce_rules] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('CCE 카탈로그', 'cce_rules');
?>
  <?php vg_page_title(
      'CCE 카탈로그',
      'SECURITY CONFIG BASELINE',
      '우리가 직접 판정하는 보안설정 점검 항목 — 자산별 판정 결과는 탐지 결과에서',
      ['count' => $total]
  ); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <p class="sub">점검 항목 <?= number_format($ruleTotal) ?>개 · 최신 스캔 기준으로 판정된 자산
    <?= number_format($checkedHosts) ?>대입니다. 준수/미준수 판정은 하지 않습니다(판정은 컴플라이언스 매핑 화면).</p>
  <?php
  $frameworks = vg_control_frameworks();
  $fwShort    = vg_control_framework_short();

  vg_toolbar([
      ['type' => 'select', 'name' => 'sev', 'selected' => $sev, 'empty_label' => '전체 심각도',
       'options' => $sevOptions],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·항목명·기준(U-01·2.5.4) 검색', 'value' => $q],
  ]);

  $hasFilter = $q !== '' || $sev !== '';
  $detailHref = fn(array $r): string => '/cce-rule.php?code=' . urlencode((string) $r['code']);

  vg_table(
      [
          ['label' => 'CCE 코드', 'width' => '14%', 'class' => 'col-id'],
          ['label' => '점검 항목'],
          ['label' => '심각도', 'width' => '6.5rem'],
          ['label' => '무엇을 보는가'],
          ['label' => '기준 매핑', 'width' => '18%'],
          ['label' => '현재 판정', 'width' => '15%'],
      ],
      $rows,
      [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 점검 항목이 없습니다.',
                  'hint'  => '검색어나 심각도 필터를 확인해 보세요.',
                  'cta'   => ['href' => '/cce-rules.php', 'label' => '필터 초기화'],
              ]
              : [
                  'icon'  => '📋',
                  'title' => '점검 항목을 읽지 못했습니다.',
                  'hint'  => '점검 정의는 서버 코드가 갖고 있습니다 — 관리자에게 문의하세요.',
              ],
          'cell' => [
              0 => fn($r) => '<a href="' . vg_h($detailHref($r)) . '" title="' . vg_h((string) $r['code']) . '">'
                            . '<code class="why">' . vg_h((string) $r['code']) . '</code></a>',
              1 => fn($r) => '<a href="' . vg_h($detailHref($r)) . '">' . vg_h((string) $r['title']) . '</a>',
              2 => fn($r) => vg_badge((string) $r['severity'], vg_sev_tone((string) $r['severity'])),
              3 => fn($r) => '<span class="why">'
                            . ($r['summary'] !== '' ? vg_h((string) $r['summary']) : '설명 준비 중')
                            . '</span>',
              // 기준 문자열은 tb_control_mapping 이 정본이다 — 화면은 조회한 값만 찍는다.
              4 => function ($r) use ($frameworks, $fwShort) {
                  if (!$r['mapping']) { return '<span class="why">자체 기준</span>'; }
                  $out = [];
                  foreach ($r['mapping'] as $fw => $items) {
                      foreach ($items as $it) {
                          $label = ($fwShort[$fw] ?? $fw) . ' ' . $it['control_id'];
                          $out[] = '<a href="/control.php?fw=' . urlencode((string) $fw)
                                 . '&amp;control=' . urlencode((string) $it['control_id']) . '">'
                                 . vg_badge($label, 'muted',
                                            ($frameworks[$fw] ?? $fw) . ' · ' . $it['control_name'])
                                 . '</a>';
                      }
                  }
                  return implode(' ', $out);
              },
              5 => function ($r) {
                  if ((int) $r['result_cnt'] === 0) { return vg_badge('점검 결과 없음', 'muted'); }
                  $cnt  = (int) $r['result_cnt'];
                  $fail = (int) $r['fail_cnt'];
                  $tone = $fail > 0 ? 'crit' : ((int) $r['na_cnt'] > 0 ? 'med' : 'ok');
                  $why  = 'PASS ' . number_format((int) $r['pass_cnt'])
                        . ' · 판정 불가 ' . number_format((int) $r['na_cnt']);
                  // meter 에는 ok 톤이 없다(app.css) → low 로 떨군다. 0% 라 색은 안 보인다.
                  return vg_badge('FAIL ' . number_format($fail), $tone)
                       . '<br><span class="why">' . vg_h($why) . '</span>'
                       . vg_meter($tone === 'ok' ? 'low' : $tone, $fail / $cnt * 100,
                                  'FAIL ' . number_format($fail) . ' / 점검 ' . number_format($cnt) . '건');
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
