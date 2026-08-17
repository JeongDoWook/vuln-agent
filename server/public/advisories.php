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

/** '영향 자산' 칸의 툴팁에 넣을 자산 이름 수. 나머지는 "외 N대" 로 접고 전체는 모달이 갖는다. */
const VG_ADVISORY_TIP_NAMES = 8;

$err = null; $rows = []; $total = 0;
$q = trim((string) ($_GET['q'] ?? ''));
/* 기본 조회는 **내 자산에 영향 있는 공지**다.
 *   전체를 기본으로 두면(예전) 목록 2,756건 중 자산에 걸리는 건 3건이라 '영향 자산' 칸이
 *   화면 가득 '없음' 으로 채워졌다 — 참조 자료지 업무 화면이 아니었다. 전체를 보는 길은
 *   없애지 않고 칩으로 남긴다(수집 자체가 됐는지 확인하는 경로라 지우면 안 된다).
 */
$scope = (string) ($_GET['scope'] ?? 'mine');
if (!in_array($scope, ['mine', 'all'], true)) { $scope = 'mine'; }
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();

    $where = 'is_deleted = 0';
    $params = [];

    /* '내 자산 영향' = 이 공지의 CVE 중 하나라도 **최신 스캔 기준** 판정에 잡힌 것.
     *
     * EXISTS 상관 서브쿼리로 매 공지 행마다 확인하지 않는다 — 영향 있는 advisory_id 집합을
     * 한 번에 구해 값으로 펼쳐 넣는다(실측 dev: 이 한 쿼리 131ms, 상관 서브쿼리는 공지 수만큼
     * 반복된다). tb_advisory_cve(작은 표)에서 출발해 idx_find_cve(cve_id)로 들어가는 방향이라
     * tb_finding 42만 행을 통째로 훑지 않는다.
     */
    if ($scope === 'mine') {
        $mineIds = $pdo->query(
            'SELECT DISTINCT ac.advisory_id
               FROM tb_advisory_cve ac
               JOIN tb_finding f ON f.cve_id = ac.cve_id AND f.is_deleted = 0
               JOIN tb_scan s ON s.scan_id = f.scan_id
               JOIN ' . vg_latest_scan_subq() . ' latest
                 ON latest.host_id = s.host_id AND latest.mid = s.scan_id
               JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
              WHERE ac.is_deleted = 0'
        )->fetchAll(PDO::FETCH_COLUMN);
        if ($mineIds) {
            $where .= ' AND advisory_id IN (' . implode(',', array_map('intval', $mineIds)) . ')';
        } else {
            // 한 건도 없으면 "전부 보여주기" 로 흘러가지 않게 명시적으로 0건을 만든다.
            $where .= ' AND 1 = 0';
        }
    }
    if ($q !== '') {
        // 본문까지 검색 대상(수집된 건에 한함). 2천여 행이라 LIKE 스캔으로 충분.
        // CVE 검색은 정규화된 junction(tb_advisory_cve)을 본다 — 인덱스가 걸린 유일한 정본.
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
                        // 이름은 host_id 로 묶어 담는다 — 같은 호스트가 CVE 수만큼 반복된다.
                        $hostIds[(int) $f['host_id']] = (string) $f['fqdn'];
                        $detail[] = $f;
                    }
                }
                $assetsByAdvisory[$aid] = [
                    'hostCount' => count($hostIds),
                    'names'     => array_values($hostIds),
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
  <?php // 건수는 다른 목록 화면과 같은 자리에 둔다 — 여기만 없어서 페이지네이션까지 내려가야 보였다.
        //   건수는 **지금 필터 기준**이다(예전엔 필터와 무관하게 늘 전체 2,756건이었다). ?>
  <?php /* 범위(전체/내 자산)는 바로 아래 칩이 말한다 — 부제로 한 번 더 적지 않는다. */ ?>
  <?php vg_page_title('보안 공지', 'KISA', '', ['count' => $total]); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php // 범위 칩 — cves.php 의 필터 프리셋(.tabs/.pill)과 같은 컴포넌트. 페이지 번호는 항상 지운다. ?>
  <div class="tabs">
    <?php foreach (['mine' => '내 자산 영향', 'all' => '전체 공지'] as $key => $label): ?>
      <a class="pill<?= $scope === $key ? ' pill--on' : '' ?>"
         href="<?= vg_h(vg_qs(['scope' => $key, 'page' => null])) ?>"><?= vg_h($label) ?></a>
    <?php endforeach; ?>
  </div>

  <?php vg_toolbar([
      // 칩으로 고른 범위는 검색 폼 필드가 아니라, 폼 제출 시 사라지지 않도록 hidden 으로 함께 싣는다.
      ['type' => 'hidden', 'name' => 'scope', 'value' => $scope],
      // 실제 검색 범위는 제목·본문·CVE 셋 다인데 placeholder 가 둘만 말해서, 빈 결과 안내가
      //   "본문도 검색합니다" 를 뒤늦게 알려주고 있었다 — 입력칸에서 먼저 밝힌다.
      ['type' => 'search', 'name' => 'q', 'placeholder' => '제목·본문·CVE 검색', 'value' => $q],
  ]); ?>

  <?php
  vg_table(
      [
          // 날짜는 길이가 고정(YYYY-MM-DD)이라 % 가 아니라 rem 으로 준다 — 9% 는 첫 칸의 넉넉한
          //   왼쪽 여백(1.4rem)까지 빼고 나면 61px 밖에 안 남아 '2026-08…' 로 잘렸다(실측 69px 필요).
          //   cves.php 의 '공개일' 열이 같은 이유로 rem 을 쓴다.
          ['label' => '발행일', 'nowrap' => true, 'width' => '7rem'],
          ['label' => '제목'],
          ['label' => '관련 CVE', 'width' => '30%'],
          // '내 자산 영향' 에서는 이 칸이 문장('없음')이 아니라 **자산 이름**이라 폭이 더 필요하다.
          ['label' => '영향 자산', 'width' => $scope === 'mine' ? '18%' : '10%',
              'nowrap' => $scope !== 'mine'],
      ],
      $rows,
      [
          'empty' => $q !== ''
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 공지가 없습니다.',
                  'hint'  => '다른 검색어를 써 보세요.',
                  'cta'   => ['href' => '/advisories.php?scope=' . $scope, 'label' => '검색 초기화'],
              ]
              : ($scope === 'mine'
              ? [
                  // 0건이 "공지가 없다" 로 읽히면 안 된다 — 여기서 0 은 **내 자산에 걸리는 게 없다** 는 뜻이다.
                  'icon'  => '✅',
                  'title' => '내 자산에 영향 있는 공지가 없습니다.',
                  'hint'  => '수집된 공지 자체는 [전체 공지] 칩에서 볼 수 있습니다.',
                  'cta'   => ['href' => vg_qs(['scope' => 'all', 'page' => null]), 'label' => '전체 공지 보기'],
              ]
              : array_filter([
                  'icon'  => '🇰🇷',
                  'title' => '아직 수집된 공지가 없습니다.',
                  'hint'  => 'KISA 보안공지 커넥터를 실행하면 여기에 쌓입니다.',
                  'cta'   => vg_connectors_empty_cta(),
              ])),
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
                      // 나머지는 상세에서 전부 본다. 긴 CVE 목록을 툴팁에 다시 숨기지 않는다.
                      $html .= '<a class="pill" href="/advisory.php?id=' . (int) $r['advisory_id']
                             . '#cves">+' . $rest . ' · 전체</a>';
                  }
                  return $html;
              },
              // 배지 값 = 이 공지의 CVE 들과 매칭되는 distinct 호스트 수(컨테이너 포함).
              //   1건 이상이면 클릭 가능한 배지로 상세(호스트·패키지·버전·CVE·심각도)를 모달에 채운다.
              3 => function ($r) use ($assetsByAdvisory, $scope) {
                  $aid = (int) $r['advisory_id'];
                  $a = $assetsByAdvisory[$aid] ?? ['hostCount' => 0, 'rows' => [], 'total' => 0, 'names' => []];
                  if ($a['hostCount'] <= 0) {
                      // '해당 자산 없음'(6글자 뱃지)은 10% 칸에 안 들어가 nowrap 말줄임에 잘렸다 —
                      //   뱃지는 잘리면 어휘가 깨져서 못 읽는다. 짧게 쓰고 뜻은 title 로 남긴다.
                      return vg_badge('없음', 'muted', '이 공지의 CVE 와 매칭되는 자산이 최신 스캔 기준으로 없습니다');
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
                      'detail_url' => '/advisory.php?id=' . $aid . '#assets',
                  ];
                  $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                  /* '내 자산 영향' 필터에서는 이 칸을 **자산 이름**으로 채운다. 그 필터의 모든 행이
                   *   1대 이상이라 'N대' 만 반복되면 칸이 아무것도 구분해 주지 않는다 — 어느 자산인지가
                   *   여기서 알고 싶은 값이다. 이름이 여럿이면 첫 이름 + '외 N대'(칸을 넘기지 않는 선).
                   *   전체 공지 필터는 지금까지처럼 대수만 — 거기서는 '몇 대나 걸리나' 가 먼저다. */
                  $label = number_format($a['hostCount']) . '대';
                  if ($scope === 'mine' && $a['names']) {
                      $label = $a['names'][0]
                             . ($a['hostCount'] > 1 ? ' 외 ' . number_format($a['hostCount'] - 1) . '대' : '');
                  }
                  // title 은 마우스를 올렸을 때 뜨는 한 덩어리 텍스트다 — 이름을 전부 넣으면
                  //   자산이 많은 공지에서 화면을 덮는다(실측 dev 70대). 앞 몇 개만 넣고 나머지는
                  //   수로 말한다. 전체 목록은 배지를 눌러 여는 모달이 갖는다.
                  $tipNames = array_slice($a['names'], 0, VG_ADVISORY_TIP_NAMES);
                  $tipRest  = count($a['names']) - count($tipNames);
                  $tip = implode(', ', $tipNames) . ($tipRest > 0 ? ' 외 ' . number_format($tipRest) . '대' : '');
                  return '<span class="badge tone-warn" data-advisory-assets="' . vg_h((string) $json) . '"'
                       . ' tabindex="0" role="button" aria-label="영향 자산 ' . (int) $a['hostCount'] . '대 상세 보기"'
                       . ' title="' . vg_h($tip) . '">'
                       . vg_h($label) . '</span>';
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
