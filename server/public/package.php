<?php
declare(strict_types=1);

/** 취약 영향 패키지 카탈로그의 패키지·생태계별 관련 CVE 상세. */
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';
vg_require_menu('findings');

$name = trim((string)($_GET['name'] ?? ''));
$ecosystem = trim((string)($_GET['eco'] ?? ''));
$err = null;
$summary = null;
$rows = [];
$total = 0;
$page = vg_page();
$perPage = vg_perpage();

if ($name === '') {
    $err = '패키지명이 필요합니다.';
} else {
    try {
        $pdo = vg_pdo();
        // asset-packages.php 가 링크에 넣는 eco 는 vg_osv_ecosystem() 의 짧은 형태('Ubuntu:24.04')인데
        //   tb_package_summary.ecosystem 은 OSV 원본 접미사가 붙어 저장될 수 있다('Ubuntu:24.04:LTS').
        //   정확일치 대신 매처와 같은 기준(vg_eco_matches, distro.php:234)의 접두 일치로 실제 저장값을 찾는다.
        $st = $pdo->prepare(
            'SELECT package_name,ecosystem,cve_cnt,max_epss,fix_cnt,max_fixed
               FROM tb_package_summary WHERE package_name=?'
        );
        $st->execute([$name]);
        $summary = null;
        // eco 파라미터가 없는 요청까지 vg_eco_matches() 의 "정보 없음→통과" 규칙에 걸리면
        //   같은 패키지명의 아무 생태계 행이나 집히므로, 값이 있을 때만 매칭을 시도한다.
        if ($ecosystem !== '') {
            foreach ($st->fetchAll() as $row) {
                if (vg_eco_matches($row['ecosystem'] ?? null, $ecosystem, '')) {
                    $summary = $row;
                    break;
                }
            }
        }
        if ($summary === null) {
            $err = '패키지 정보를 찾을 수 없습니다.';
        } else {
            $ecosystem = (string) $summary['ecosystem'];
            $from = 'FROM tb_cve_affected_package a
                     JOIN tb_cve c ON c.cve_id=a.cve_id AND c.is_deleted=0';
            $where = 'a.is_deleted=0 AND a.package_name=? AND a.ecosystem=?';
            $params = [$name, $ecosystem];
            $st = $pdo->prepare("SELECT COUNT(*) $from WHERE $where");
            $st->execute($params);
            $total = (int)$st->fetchColumn();

            $offset = ($page - 1) * $perPage;
            $st = $pdo->prepare(
                "SELECT a.cve_id,a.fixed_version,c.summary,c.cvss,c.epss,c.epss_percentile,c.published,
                        (k.cve_id IS NOT NULL) is_kev
                   $from
                   LEFT JOIN tb_kev_catalog k ON k.cve_id=a.cve_id AND k.is_deleted=0
                  WHERE $where
                  ORDER BY c.cvss IS NULL,c.cvss DESC,c.epss DESC,a.cve_id DESC
                  LIMIT $perPage OFFSET $offset"
            );
            $st->execute($params);
            $rows = $st->fetchAll();
        }
    } catch (Throwable $e) {
        error_log('[package] ' . $e->getMessage());
        $err = '패키지 상세를 불러오는 중 오류가 발생했습니다.';
    }
}

vg_header($name !== '' ? $name : '패키지 상세', 'packages');
?>
  <?php if ($summary !== null): ?>
    <?php vg_page_title($name, '', '취약 영향 패키지 카탈로그의 관련 CVE와 수정 버전입니다.', [
        'count' => $total,
        'hint' => $ecosystem !== '' ? vg_h($ecosystem) : '생태계 미지정',
        'actions' => '<a class="btn btn--sm btn--ghost" href="/packages.php">패키지 목록</a>'
            . ' <a class="btn btn--sm btn--ghost" href="/asset-packages.php?q=' . urlencode($name)
            . '">설치된 자산 보기</a>',
    ]); ?>
    <div class="cards">
      <div class="kpi kpi--sm"><b><?= number_format($total) ?></b><span>관련 CVE</span></div>
      <div class="kpi kpi--sm"><b><?= number_format((int)$summary['fix_cnt']) ?></b><span>수정 버전 확인</span></div>
      <div class="kpi kpi--sm"><b><?= vg_h(number_format((float)($summary['max_epss'] ?? 0) * 100, 1)) ?>%</b><span>최고 EPSS</span></div>
    </div>
  <?php else: ?>
    <?php vg_page_title('패키지를 찾을 수 없습니다', '', $err ?? '존재하지 않는 패키지입니다.', [
        'actions' => '<a class="btn btn--sm btn--ghost" href="/packages.php">패키지 목록</a>',
    ]); ?>
  <?php endif; ?>

  <?php if ($summary !== null): ?>
    <?php vg_table(
        [
            ['label' => 'CVE', 'key' => 'cve_id', 'nowrap' => true],
            ['label' => '등급', 'key' => 'severity'],
            ['label' => 'CVSS', 'key' => 'cvss', 'align' => 'right'],
            ['label' => 'EPSS', 'key' => 'epss', 'align' => 'right'],
            ['label' => '수정 버전', 'key' => 'fixed_version'],
            ['label' => '요약', 'key' => 'summary'],
        ],
        $rows,
        [
            'empty' => ['icon' => '□', 'title' => '관련 CVE가 없습니다.'],
            'row_class' => fn($r) => vg_sev_row(strtoupper(vg_cvss_sev(
                $r['cvss'] === null ? null : (string)$r['cvss']
            ))),
            'cell' => [
                'cve_id' => function ($r) {
                    $out = '<a href="/cve.php?cve=' . urlencode((string)$r['cve_id']) . '">'
                        . vg_h((string)$r['cve_id']) . '</a>';
                    return $out . (!empty($r['is_kev']) ? ' ' . vg_badge('KEV', 'crit') : '');
                },
                'severity' => function ($r) {
                    $sev = vg_cvss_sev($r['cvss'] === null ? null : (string)$r['cvss']);
                    return $sev !== '' ? vg_sev_badge(strtoupper($sev)) : '<span class="why">–</span>';
                },
                'cvss' => fn($r) => $r['cvss'] !== null ? vg_h((string)$r['cvss']) : '<span class="why">–</span>',
                'epss' => fn($r) => vg_epss_cell($r['epss'], $r['epss_percentile']),
                'fixed_version' => fn($r) => !empty($r['fixed_version'])
                    ? '<span class="pill">' . vg_h((string)$r['fixed_version']) . ' 이상</span>'
                    : '<span class="why">수정 버전 미확인</span>',
                'summary' => fn($r) => !empty($r['summary'])
                    ? '<div class="clamp-2" title="' . vg_h((string)$r['summary']) . '">' . vg_h((string)$r['summary']) . '</div>'
                    : '<span class="why">–</span>',
            ],
        ]
    ); ?>
    <?php vg_page_nav($total, $perPage, $page); ?>
  <?php endif; ?>
<?php vg_footer();
