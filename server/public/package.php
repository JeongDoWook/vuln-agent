<?php
declare(strict_types=1);

/**
 * package.php — 취약 영향 패키지 카탈로그의 패키지·생태계별 관련 CVE 상세. 로그인 필요.
 *   ?name=<패키지명>&eco=<생태계>  ·  ?page=N/?per_page=N (관련 CVE)
 *
 * 화면 골격은 다른 상세 화면(control.php·cve.php)과 같다: 히어로 → 핵심 지표(stat-grid) →
 *   앵커 내비 → 섹션. 예전엔 이 화면만 vg_page_title + kpi 카드를 써서 상세 화면들 사이에서
 *   혼자 다른 모양이었다.
 */
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';
require_once __DIR__ . '/../src/nofix.php';   // 벤더 미수정 집중 관측 — 조치가 패치가 아닌 경우
vg_require_menu_any('catalog', 'findings');   // 패키지 상세: 패키지 카탈로그·탐지 결과에서 함께 열린다

$name = trim((string)($_GET['name'] ?? ''));
$ecosystem = trim((string)($_GET['eco'] ?? ''));
$err = null;
$summary = null;
$rows = [];
$total = 0;
$page = vg_page();
$perPage = vg_perpage();
$nofixGroups = [];   // 이 패키지가 실제 자산에서 "벤더 미수정 집중" 으로 관측된 조합
$kevTotal = 0;       // 관련 CVE 중 KEV 등재 건수

if ($name === '') {
    $err = '패키지명이 필요합니다.';
} else {
    try {
        $pdo = vg_pdo();
        // asset-packages.php 가 링크에 넣는 eco 는 vg_osv_ecosystem() 의 짧은 형태('Ubuntu:24.04')인데
        //   tb_package_summary.ecosystem 은 OSV 원본 접미사가 붙어 저장될 수 있다('Ubuntu:24.04:LTS').
        //   정확일치 대신 매처와 같은 기준(vg_eco_matches, distro.php:234)의 접두 일치로 실제 저장값을 찾는다.
        $st = $pdo->prepare(
            'SELECT package_name,ecosystem,cve_cnt,max_epss,fix_cnt,max_fixed,updated_at
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
            // 총건수와 KEV 등재 건수를 한 번에 — 상단 지표가 이 둘뿐이라 쿼리를 쪼개지 않는다.
            $st = $pdo->prepare(
                "SELECT COUNT(*) AS n, SUM(k.cve_id IS NOT NULL) AS kev_cnt
                 $from
                 LEFT JOIN tb_kev_catalog k ON k.cve_id=a.cve_id AND k.is_deleted=0
                 WHERE $where"
            );
            $st->execute($params);
            $agg = $st->fetch() ?: [];
            $total    = (int) ($agg['n'] ?? 0);
            $kevTotal = (int) ($agg['kev_cnt'] ?? 0);

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
                vg_nofix_attach_containers($pdo, vg_nofix_pkg_groups($pdo, array_keys($scans), $name, true)),
                $scans,
                $ecosystem
            );
            foreach ($nofixGroups as $i => $g) {
                $host = $scans[(int) $g['scan_id']] ?? [];
                $nofixGroups[$i]['host_id'] = (int) ($host['host_id'] ?? 0);
                $nofixGroups[$i]['fqdn'] = $host['fqdn'] ?? '?';
            }
        }
    } catch (Throwable $e) {
        error_log('[package] ' . $e->getMessage());
        $err = '패키지 상세를 불러오는 중 오류가 발생했습니다.';
    }
}

vg_header($name !== '' ? $name : '패키지 상세', 'packages');

if ($summary === null) {
    vg_page_title('패키지를 찾을 수 없습니다', '', [
        'actions' => '<a class="btn btn--sm btn--ghost" href="/packages.php">패키지 목록</a>',
    ]);
    // 조회가 실패한 것과 애초에 없는 것은 다르다 — 실패했을 때만 그 사실을 알린다(제목은 둘을 못 가른다).
    if ($err !== null) { vg_alert('오류 · ' . $err); }
    vg_footer();
    return;
}

$maxEpss = (float) ($summary['max_epss'] ?? 0);
vg_hero(
    vg_h($name),
    [
        $ecosystem !== '' ? vg_h($ecosystem) : '생태계 미지정',
        '<a href="/packages.php">← 패키지 목록</a>',
        '<a href="/asset-packages.php?q=' . urlencode($name) . '">설치된 자산 보기</a>',
    ],
    number_format($maxEpss * 100, 1) . '%',
    vg_epss_tone($maxEpss),
    '최고 EPSS(악용확률)',
    'PACKAGE DETAIL'
);
?>

<?php
?>

<div class="card">
  <strong>핵심 지표</strong>
  <div class="card__body stat-grid">
    <div class="stat">
      <span class="stat__val"><?= number_format($total) ?>건</span>
      <div class="why">관련 CVE</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= $kevTotal > 0 ? vg_badge(number_format($kevTotal) . '건', 'crit', '실제 악용이 확인된 취약점(CISA KEV)') : vg_badge('없음', 'muted') ?></span>
      <div class="why">KEV 등재</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= number_format((int) $summary['fix_cnt']) ?>건</span>
      <div class="why">수정 버전 확인<?= $total > 0 ? ' · ' . number_format((int) $summary['fix_cnt'] / max(1, $total) * 100, 0) . '%' : '' ?></div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= !empty($summary['max_fixed'])
          ? '<span class="pill">' . vg_h((string) $summary['max_fixed']) . ' 이상</span>'
          : '<span class="why">미확인</span>' ?></span>
      <div class="why">가장 높은 수정 버전</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= $ecosystem !== '' ? vg_h($ecosystem) : '<span class="why">미지정</span>' ?></span>
      <div class="why">생태계</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= vg_h((string) $summary['updated_at']) ?></span>
      <div class="why">집계 갱신</div>
    </div>
  </div>
</div>

<nav class="subtabs subtabs--sticky">
  <?php if ($nofixGroups): ?><a href="#nofix">벤더 미수정 관측<span class="n"><?= number_format(count($nofixGroups)) ?></span></a><?php endif; ?>
  <a href="#cves">관련 CVE<span class="n"><?= number_format($total) ?></span></a>
</nav>

<?php if ($nofixGroups): ?>
<section id="nofix">
  <?php
  /* 배너를 두지 않는다 — 같은 말("제거·대체 검토 · EOL 확정이 아닌 관측")을 바로 아래
   *   카드 머리의 vg_nofix_badge() 가 라벨과 title 로 이미 하고 있었다(같은 화면에 두 번). */
  ?>
  <div class="card">
    <strong>벤더 미수정이 몰린 자산</strong>
    <span class="why"><?= vg_nofix_badge() ?></span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '자산'],
            ['label' => '위치'],
            ['label' => '미수정 / 전체', 'align' => 'right', 'width' => '9rem'],
            ['label' => 'KEV', 'align' => 'right', 'width' => '5rem'],
            ['label' => '최고 등급', 'width' => '7rem'],
            ['label' => '런타임 상태', 'width' => '8rem'],
        ],
        $nofixGroups,
        [
            'card' => false,
            'cell' => [
                0 => fn($g) => !empty($g['host_id'])
                    ? '<a href="/host.php?id=' . (int) $g['host_id'] . '">' . vg_h((string) $g['fqdn']) . '</a>'
                    : vg_h((string) $g['fqdn']),
                // 같은 호스트의 호스트 자신·컨테이너가 나란히 오면 fqdn 만으론 구분이 안 된다.
                1 => fn($g) => !empty($g['container_cid'])
                    ? '<span class="why">컨테이너 ' . vg_h((string) $g['container_cid']) . '</span>'
                    : '<span class="why">호스트</span>',
                2 => fn($g) => number_format((int) $g['nofix_cnt']) . '<span class="why"> / '
                    . number_format((int) $g['cve_cnt']) . '</span>',
                3 => fn($g) => ((int) ($g['kev_cnt'] ?? 0)) > 0
                    ? vg_badge(number_format((int) $g['kev_cnt']), 'crit')
                    : '<span class="why">–</span>',
                4 => fn($g) => !empty($g['severity'])
                    ? vg_sev_badge((string) $g['severity'])
                    : '<span class="why">–</span>',
                5 => fn($g) => !empty($g['runtime_status'])
                    ? vg_status_badge((string) $g['runtime_status'])
                    : '<span class="why">–</span>',
            ],
        ]
    );
    ?>
      <p class="why mt"><a href="/nofix-packages.php?q=<?= urlencode($name) ?>">제거 권고 목록에서 보기 →</a></p>
    </div>
  </div>
</section>
<?php endif; ?>

<section id="cves">
  <div class="card">
    <strong>관련 CVE</strong>
    <?php /* 표의 등급 뱃지는 CVSS 에서 파생된 색이다 — 색의 뜻을 표 바로 위에 세운다.
             점수가 없으면 등급이 '없는' 게 아니라 아직 안 매겨진 것이다(cves.php 와 같은 어휘). */ ?>
    <?php vg_legend(array_merge(
        array_map(
            fn(string $s): array => ['label' => $s, 'tone' => vg_sev_tone($s)],
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        ),
        [['label' => '– · 점수 미수집', 'tone' => 'muted']]
    ), ['inline' => true, 'caption' => '심각도']); ?>
    <div class="card__body">
    <?php vg_table(
        [
            ['label' => 'CVE', 'key' => 'cve_id', 'nowrap' => true],
            ['label' => '등급', 'key' => 'severity', 'width' => '6rem'],
            ['label' => 'CVSS', 'key' => 'cvss', 'align' => 'right', 'width' => '5rem'],
            ['label' => 'EPSS', 'key' => 'epss', 'align' => 'right', 'width' => '8rem'],
            ['label' => '공개일', 'key' => 'published', 'nowrap' => true, 'width' => '8rem'],
            ['label' => '수정 버전', 'key' => 'fixed_version'],
            ['label' => '요약', 'key' => 'summary'],
        ],
        $rows,
        [
            'card'  => false,
            'empty' => ['icon' => 'cve', 'title' => '관련 CVE가 없습니다.'],
            'row_class' => fn($r) => vg_sev_row(strtoupper(vg_cvss_sev(
                $r['cvss'] === null ? null : (string)$r['cvss']
            ))),
            'cell' => [
                'cve_id' => function ($r) {
                    $out = '<a href="/cve.php?cve=' . urlencode((string)$r['cve_id']) . '">'
                        . vg_h((string)$r['cve_id']) . '</a>';
                    return $out . (!empty($r['is_kev']) ? ' ' . vg_badge('KEV', 'crit', '악용이 확인된 취약점 — CISA KEV 등재') : '');
                },
                'severity' => function ($r) {
                    $sev = vg_cvss_sev($r['cvss'] === null ? null : (string)$r['cvss']);
                    return $sev !== '' ? vg_sev_badge(strtoupper($sev)) : '<span class="why">–</span>';
                },
                'cvss' => fn($r) => $r['cvss'] !== null ? vg_h((string)$r['cvss']) : '<span class="why">–</span>',
                'epss' => fn($r) => vg_epss_cell($r['epss'], $r['epss_percentile']),
                'published' => fn($r) => !empty($r['published'])
                    ? '<span class="why">' . vg_h((string) $r['published']) . '</span>'
                    : '<span class="why">–</span>',
                'fixed_version' => fn($r) => !empty($r['fixed_version'])
                    ? '<span class="pill">' . vg_h((string)$r['fixed_version']) . ' 이상</span>'
                    : '<span class="why">수정 버전 미확인</span>',
                // 본문성 링크 — .body-link 로 통일한다(cves.php 요약 열과 같은 자리·같은 규약).
                //   .clamp-2 만으로도 지금은 본문 색이 나오지만, 그건 잘림 처리의 부수효과일 뿐이라
                //   "이건 본문 링크다" 는 뜻을 클래스로 남긴다.
                'summary' => fn($r) => !empty($r['summary'])
                    ? '<a class="clamp-2 body-link" href="/cve.php?cve=' . urlencode((string) $r['cve_id']) . '">'
                        . vg_h((string) $r['summary']) . '</a>'
                    : '<span class="why">–</span>',
            ],
        ]
    ); ?>
    <?php if ($rows) { vg_page_nav($total, $perPage, $page); } ?>
    </div>
  </div>
</section>
<?php vg_footer();
