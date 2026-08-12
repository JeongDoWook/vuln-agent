<?php
declare(strict_types=1);

/**
 * compliance_rules.php — SSG(SCAP Security Guide) 룰 카탈로그 조회.
 *   vendor.php 가 "벤더가 이 CVE 를 뭐라 했나" 를 보여주듯, 이 페이지는 "SSG 가 이 보안설정
 *   항목을 뭐라 정의했나" 를 보여준다. tb_compliance_rule 은 지금 host.php 에서 그 호스트가
 *   실제 점검한 규칙만 조각으로 보여줄 뿐, 룰셋 전체(약 2,493개)를 검색·필터로 훑어보는
 *   화면이 없었다. 로그인 필요(취약점 메뉴 권한 재사용 — vendor.php·packages.php 와 같은 이유).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

/**
 * refs_json → "CIS 5.2.11 · NIST AC-17(a)" 형태. host.php 의 $refBadges 가 다루는 것과
 * 같은 참조 종류(CIS/NIST/STIG)만 고른다 — cis-csc 같은 상위 카테고리는 항목 번호가 아니라 생략.
 */
function vg_ssg_refs_line(string $refsJson): string {
    $refs = vg_json_col($refsJson);
    $parts = [];
    foreach ($refs as $k => $v) {
        $k = (string) $k;
        if (strncmp($k, 'cis@', 4) === 0) {
            $parts[] = 'CIS ' . $v;
        } elseif ($k === 'nist') {
            $parts[] = 'NIST ' . $v;
        } elseif (strncmp($k, 'stigid', 6) === 0) {
            $parts[] = 'STIG ' . $v;
        }
    }
    return $parts ? vg_h(implode(' · ', $parts)) : '<span class="why">–</span>';
}

$err = null; $rows = []; $total = 0; $sevOptions = [];

$q   = trim((string) ($_GET['q'] ?? ''));
$sev = trim((string) ($_GET['sev'] ?? ''));
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();

    $sevValues = $pdo->query(
        'SELECT DISTINCT severity FROM tb_compliance_rule WHERE is_deleted = 0 ORDER BY severity'
    )->fetchAll(PDO::FETCH_COLUMN);
    foreach ($sevValues as $v) { $sevOptions[$v] = mb_strtoupper($v); }
    if ($sev !== '' && !isset($sevOptions[$sev])) { $sev = ''; }

    $where = ['is_deleted = 0'];
    $params = [];
    if ($q !== '') {
        $like = '%' . addcslashes($q, '\\%_') . '%';
        $where[] = '(rule_id LIKE ? OR title LIKE ? OR rationale LIKE ? OR refs_json LIKE ?)';
        array_push($params, $like, $like, $like, $like);
    }
    if ($sev !== '') {
        $where[] = 'severity = ?';
        $params[] = $sev;
    }
    $whereSql = implode(' AND ', $where);

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_compliance_rule WHERE $whereSql");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;
    $stmt = $pdo->prepare(
        "SELECT rule_id, title, severity, rationale, refs_json FROM tb_compliance_rule
          WHERE $whereSql ORDER BY rule_id ASC LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
} catch (Throwable $e) {
    error_log('[compliance_rules] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('보안 설정 룰', 'compliance');
?>
  <?php vg_page_title('보안 설정 룰', 'SECURITY BASELINE', 'SSG·CIS·STIG 점검 항목 — 점검 결과는 탐지 결과에서', ['count' => $total]); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php
  vg_toolbar([
      ['type' => 'select', 'name' => 'sev', 'selected' => $sev, 'empty_label' => '전체 심각도',
       'options' => $sevOptions],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '룰 ID·제목·참조 검색', 'value' => $q],
  ]);

  $hasFilter = $q !== '' || $sev !== '';
  vg_table(
      [
          ['label' => '룰 ID', 'width' => '20%', 'class' => 'col-id'],
          ['label' => '제목'],
          // 심각도 뱃지는 고정 크기라 % 가 아니라 rem 이다(cves.php 와 같은 이유 — 870px 에서
          //   44.5px 가 옆 열을 덮었다). 값 69 + 칸 여백 32 = 101 → 6.5rem.
          ['label' => '심각도', 'width' => '6.5rem'],
          ['label' => '참조 기준', 'width' => '15%'],
          ['label' => '근거'],
      ],
      $rows,
      [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 룰이 없습니다.',
                  'hint'  => '검색어나 심각도 필터를 확인해 보세요.',
                  'cta'   => ['href' => '/compliance_rules.php', 'label' => '필터 초기화'],
              ]
              : array_filter([
                  'icon'  => '📋',
                  'title' => '아직 수집된 보안설정 룰이 없습니다.',
                  'hint'  => 'SSG(SCAP Security Guide) 커넥터가 한 번은 돌아야 합니다.',
                  'cta'   => vg_connectors_empty_cta(),
              ]),
          'cell' => [
              // 룰 ID 는 길다 — col-id 가 한 줄로 두고 넘치면 말줄임한다(전체 값은 title 로 남는다).
              0 => fn($r) => '<a href="/compliance_rule.php?rule=' . urlencode((string) $r['rule_id']) . '" title="' . vg_h((string) $r['rule_id']) . '">'
                            . '<code class="why">' . vg_h((string) $r['rule_id']) . '</code></a>',
              1 => fn($r) => '<a href="/compliance_rule.php?rule=' . urlencode((string) $r['rule_id']) . '">'
                            . vg_h((string) $r['title']) . '</a>',
              2 => function ($r) {
                  $s = mb_strtoupper((string) $r['severity']);
                  return vg_badge($s, vg_sev_tone($s));
              },
              3 => fn($r) => vg_ssg_refs_line((string) ($r['refs_json'] ?? '')),
              // SSG 원문 근거는 XHTML 조각이라 <tt>/<br> 같은 태그가 섞여 있다. 그대로 이스케이프하면
              //   화면에 "The <tt>/etc/sysconfig/sshd</tt> file …" 처럼 태그가 글자로 보인다(실측).
              //   태그를 먼저 걷어내고 자른다 — vg_trunc 가 남은 텍스트를 이스케이프한다.
              4 => fn($r) => vg_trunc(strip_tags((string) $r['rationale']), 96),
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
