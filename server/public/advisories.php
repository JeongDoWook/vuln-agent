<?php
declare(strict_types=1);

/**
 * advisories.php — 국내 보안공지(KISA 보호나라). 로그인 필요.
 *   해외 도구가 안 하는 국내 특화 피드. 피드 커넥터(kisa)가 수집.
 *   검색(q: 제목/CVE) + 페이지네이션.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('advisories');

$err = null; $rows = []; $total = 0;
$q = trim((string) ($_GET['q'] ?? ''));
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();

    $where = 'is_deleted = 0';
    $params = [];
    if ($q !== '') {
        // 본문까지 검색 대상(수집된 건에 한함). 2천여 행이라 LIKE 스캔으로 충분.
        // CVE 검색은 cve_ids CSV 대신 정규화된 junction(tb_advisory_cve)을 본다.
        $where .= ' AND (title LIKE ? OR content LIKE ? OR EXISTS (
            SELECT 1 FROM tb_advisory_cve ac
             WHERE ac.advisory_id = tb_advisory.advisory_id AND ac.is_deleted = 0 AND ac.cve_id LIKE ?
        ))';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_advisory WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        "SELECT advisory_id, source, title, url, published
         FROM tb_advisory
         WHERE $where
         ORDER BY published DESC, advisory_id DESC
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    // 관련 CVE 는 정션에서 배치 조회(N+1 방지) — advisory_id 로 묶어 각 행에 붙인다.
    $assetsByAdvisory = [];   // advisory_id => ['hostCount'=>int, 'rows'=>array, 'total'=>int]
    if ($rows) {
        $ids = array_column($rows, 'advisory_id');
        $in  = implode(',', array_fill(0, count($ids), '?'));
        $cst = $pdo->prepare(
            "SELECT advisory_id, cve_id FROM tb_advisory_cve
             WHERE advisory_id IN ($in) AND is_deleted = 0 ORDER BY cve_id"
        );
        $cst->execute($ids);
        $byAdvisory = [];
        foreach ($cst->fetchAll(PDO::FETCH_ASSOC) as $c) {
            $byAdvisory[(int) $c['advisory_id']][] = $c['cve_id'];
        }
        foreach ($rows as &$row) {
            $row['cve_id_list'] = $byAdvisory[(int) $row['advisory_id']] ?? [];
        }
        unset($row);

        // 영향 자산 배지 — 이 페이지에 걸린 전체 cve_id 집합을 한 번에 조회해(N+1 방지)
        //   각 공지의 cve 목록으로 역매핑한다. 호스트는 항상 "최신 스캔" 기준(host.php/cve.php 와 동일).
        $allCves = [];
        foreach ($byAdvisory as $cveList) {
            foreach ($cveList as $cv) { $allCves[$cv] = true; }
        }
        $allCves = array_keys($allCves);
        if ($allCves) {
            $cin = implode(',', array_fill(0, count($allCves), '?'));
            $fst = $pdo->prepare(
                "SELECT f.cve_id, f.package_name, f.installed_version, f.severity, h.host_id, h.fqdn
                   FROM tb_finding f
                   JOIN tb_scan s ON s.scan_id = f.scan_id
                   JOIN " . vg_latest_scan_subq() . " latest
                     ON latest.host_id = s.host_id AND latest.mid = s.scan_id
                   JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                  WHERE f.cve_id IN ($cin) AND f.is_deleted = 0
                  ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), h.fqdn"
            );
            $fst->execute($allCves);
            $findingsByCve = [];
            foreach ($fst->fetchAll(PDO::FETCH_ASSOC) as $f) {
                $findingsByCve[$f['cve_id']][] = $f;
            }

            $detailLimit = vg_ui_advisory_asset_limit();
            foreach ($rows as $row) {
                $aid = (int) $row['advisory_id'];
                $hostIds = [];
                $detail = [];
                foreach ($row['cve_id_list'] as $cv) {
                    foreach ($findingsByCve[$cv] ?? [] as $f) {
                        $hostIds[(int) $f['host_id']] = true;
                        $detail[] = $f;
                    }
                }
                $assetsByAdvisory[$aid] = [
                    'hostCount' => count($hostIds),
                    'rows'      => array_slice($detail, 0, $detailLimit),
                    'total'     => count($detail),
                ];
            }
        }
    }
} catch (Throwable $e) {
    error_log('[advisories] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('보안 공지', 'advisories');
?>
  <?php // 건수는 다른 목록 화면과 같은 자리에 둔다 — 여기만 없어서 페이지네이션까지 내려가야 보였다. ?>
  <?php vg_page_title('보안 공지', 'KISA', '국내 보안공지와 관련 CVE를 확인합니다.', ['count' => $total]); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php vg_toolbar([
      // 실제 검색 범위는 제목·본문·CVE 셋 다인데 placeholder 가 둘만 말해서, 빈 결과 안내가
      //   "본문도 검색합니다" 를 뒤늦게 알려주고 있었다 — 입력칸에서 먼저 밝힌다.
      ['type' => 'search', 'name' => 'q', 'placeholder' => '제목·본문·CVE 검색', 'value' => $q],
  ]); ?>

  <?php
  vg_table(
      [
          ['label' => '발행일', 'nowrap' => true, 'width' => '9%'],
          ['label' => '제목'],
          ['label' => '관련 CVE', 'width' => '30%'],
          ['label' => '영향 자산', 'nowrap' => true, 'width' => '10%'],
      ],
      $rows,
      [
          'empty' => $q !== ''
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 공지가 없습니다.',
                  'hint'  => '다른 검색어를 써 보세요.',
                  'cta'   => ['href' => '/advisories.php', 'label' => '검색 초기화'],
              ]
              : array_filter([
                  'icon'  => '🇰🇷',
                  'title' => '아직 수집된 공지가 없습니다.',
                  'hint'  => 'KISA 보안공지 커넥터를 실행하면 여기에 쌓입니다.',
                  'cta'   => vg_connectors_empty_cta(),
              ]),
          'cell' => [
              0 => fn($r) => '<span class="why">' . vg_h($r['published'] ?? '–') . '</span>',
              // 제목을 누르면 상세로. 원문은 상세 안의 [원문 열기] 버튼에서 연다.
              1 => fn($r) => '<a href="/advisory.php?id=' . (int) $r['advisory_id'] . '">' . vg_trunc($r['title']) . '</a>',
              // CVE 를 수십 개 달고 오는 공지가 있다(예: 월간 브라우저 패치).
              // 전부 알약으로 깔면 행이 터지므로 앞 4개만 보이고 나머지는 "+N" 으로 접는다.
              2 => function ($r) {
                  $ids = $r['cve_id_list'] ?? [];
                  if (!$ids) { return '<span class="why">–</span>'; }

                  $shown = array_slice($ids, 0, 4);
                  $rest  = count($ids) - count($shown);

                  $html = '';
                  foreach ($shown as $cv) {
                      $html .= '<a class="pill" href="/cve.php?cve=' . urlencode($cv) . '">' . vg_h($cv) . '</a> ';
                  }
                  if ($rest > 0) {
                      // 나머지는 상세에서 전부 본다. title 로 원문 목록을 남겨 둔다.
                      $html .= '<a class="pill" href="/advisory.php?id=' . (int) $r['advisory_id'] . '"'
                             . ' title="' . vg_h(implode(', ', array_slice($ids, 4))) . '">+' . $rest . '</a>';
                  }
                  return $html;
              },
              // 배지 값 = 이 공지의 CVE 들과 매칭되는 distinct 호스트 수(컨테이너 포함).
              //   1건 이상이면 클릭 가능한 배지로 상세(호스트·패키지·버전·CVE·심각도)를 모달에 채운다.
              3 => function ($r) use ($assetsByAdvisory) {
                  $aid = (int) $r['advisory_id'];
                  $a = $assetsByAdvisory[$aid] ?? ['hostCount' => 0, 'rows' => [], 'total' => 0];
                  if ($a['hostCount'] <= 0) {
                      return '<span class="badge tone-muted">해당 자산 없음</span>';
                  }
                  $payload = [
                      'title' => $r['title'],
                      'rows'  => array_map(static function ($f) {
                          return [
                              'host_fqdn' => (string) $f['fqdn'],
                              'host_url'  => '/host.php?id=' . (int) $f['host_id'],
                              'package'   => (string) $f['package_name'],
                              'installed' => (string) ($f['installed_version'] ?? '–'),
                              'cve'       => (string) $f['cve_id'],
                              'cve_url'   => '/cve.php?cve=' . urlencode((string) $f['cve_id']),
                              'severity'  => (string) $f['severity'],
                          ];
                      }, $a['rows']),
                      'total' => $a['total'],
                  ];
                  $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                  return '<span class="badge tone-warn" data-advisory-assets="' . vg_h((string) $json) . '"'
                       . ' tabindex="0" role="button" aria-label="영향 자산 ' . (int) $a['hostCount'] . '대 상세 보기">'
                       . number_format($a['hostCount']) . '대</span>';
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <?php
  vg_modal_open('advisoryAssetsModal', '영향 자산', 'modal--wide');
  ?>
    <p class="why" data-advisory-assets-title></p>
    <div class="card__body" data-advisory-assets-body></div>
    <p class="why" data-advisory-assets-more></p>
  <?php
  vg_modal_foot(null, ['cancel' => '닫기']);
  vg_modal_close();
  ?>
<?php endif; ?>
<?php vg_footer();
