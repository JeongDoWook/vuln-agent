<?php
declare(strict_types=1);

/** 취약 영향 패키지 카탈로그의 패키지·생태계별 관련 CVE 상세. */
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';
require_once __DIR__ . '/../src/nofix.php';   // 벤더 미수정 집중 관측 — 조치가 패치가 아닌 경우
vg_require_menu('findings');

$name = trim((string)($_GET['name'] ?? ''));
$ecosystem = trim((string)($_GET['eco'] ?? ''));
$err = null;
$summary = null;
$rows = [];
$total = 0;
$page = vg_page();
$perPage = vg_perpage();
$nofixGroups = [];   // 이 패키지가 실제 자산에서 "벤더 미수정 집중" 으로 관측된 조합

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

            // 이 카탈로그 패키지가 실제 자산에서 "벤더 미수정 집중" 으로 관측되는가.
            //   카탈로그(전역 CVE 목록)와 달리 이건 호스트별 최신 스캔의 판정 결과다 —
            //   그래서 "고칠 수 있는가" 가 아니라 "고칠 수 없는 게 몰려 있는가" 를 본다.
            //   이 화면은 (패키지명 × 생태계) 단위라, 이름만 같고 배포판이 다른 자산의 관측은
            //   걸러낸다 — 안 그러면 데비안 페이지에 RHEL 호스트의 관측이 얹힌다.
            $scans = vg_nofix_latest_scans($pdo);
            $nofixGroups = vg_nofix_filter_eco(
                $pdo,
                vg_nofix_pkg_groups($pdo, array_keys($scans), $name, true),
                $scans,
                $ecosystem
            );
            foreach ($nofixGroups as $i => $g) {
                $nofixGroups[$i]['fqdn'] = $scans[(int) $g['scan_id']]['fqdn'] ?? '?';
            }
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

  <?php if ($nofixGroups): ?>
    <?php
    // 관측 + 권고. "EOL 이다" 라고 단정하지 않는다 — 우리가 아는 건 숫자뿐이다.
    $hints = ['이 패키지는 아래 자산에서 벤더 미수정 CVE 가 몰려 있습니다 — 패치를 기다려도 오지 않습니다.'];
    foreach ($nofixGroups as $g) {
        $hints[] = $g['fqdn'] . ' · ' . vg_nofix_reason($g);
    }
    $hints[] = 'EOL(지원 종료) 확정이 아니라 관측입니다. 조치는 패치가 아니라 제거 또는 대체 검토입니다.';
    vg_alert(['type' => 'warn', 'title' => '조치 = 패치 아님, 제거 또는 대체 검토', 'hints' => $hints]);
    ?>
    <p class="why"><?= vg_nofix_badge() ?>
      <a href="/nofix-packages.php?q=<?= urlencode($name) ?>">제거 권고 목록에서 보기 →</a></p>
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
