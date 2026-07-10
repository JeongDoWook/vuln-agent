<?php
declare(strict_types=1);

/**
 * findings.php — 매처 판정 결과(우선순위 취약점). 로그인 필요.
 *   기본  : 전 호스트의 "각 호스트 최신 스캔" 을 통합해서 보여준다(호스트 컬럼 표시).
 *   ?host=N     : 그 호스트의 최신 스캔만.
 *   ?scan_id=N  : 특정 스캔 하나만(대시보드·호스트 상세에서 넘어오는 링크). 이때만 부제에 scan# 표시.
 *   검색(q)/등급(sev)/상태(st) 필터 + 페이지네이션.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

$sevOptions = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
$stOptions  = ['EXTERNAL', 'LISTENING', 'RUNNING', 'LOADED', 'INSTALLED'];

$err = null; $scan = null; $rows = []; $total = 0; $perPage = vg_perpage();
$scanIds = []; $hostOptions = [];
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];

$q   = trim((string) ($_GET['q'] ?? ''));
$sev = (string) ($_GET['sev'] ?? '');
$st  = (string) ($_GET['st'] ?? '');
if (!in_array($sev, $sevOptions, true)) { $sev = ''; }
if (!in_array($st, $stOptions, true)) { $st = ''; }
$page   = max(1, (int) ($_GET['page'] ?? 1));
$hostId = (int) ($_GET['host'] ?? 0);
$scanId = (int) ($_GET['scan_id'] ?? 0);

try {
    $pdo = vg_pdo();

    // 호스트별 최신 스캔 (삭제된 호스트 제외) — 통합 뷰의 대상 스캔 집합.
    $hosts = $pdo->query(
        'SELECT h.id AS host_id, h.fqdn, MAX(s.id) AS scan_id
           FROM tb_hosts h JOIN tb_scans s ON s.host_id = h.id
          WHERE h.is_deleted = 0
          GROUP BY h.id, h.fqdn
          ORDER BY h.fqdn'
    )->fetchAll();
    foreach ($hosts as $h) { $hostOptions[(int) $h['host_id']] = (string) $h['fqdn']; }

    if ($scanId > 0) {
        // 단일 스캔 모드 — 어느 호스트의 어느 시점인지 부제에 명시해야 한다.
        $stmt = $pdo->prepare(
            'SELECT s.id, s.collected_at, h.fqdn FROM tb_scans s JOIN tb_hosts h ON h.id = s.host_id WHERE s.id = ?'
        );
        $stmt->execute([$scanId]);
        $scan = $stmt->fetch() ?: null;
        if ($scan) { $scanIds = [(int) $scan['id']]; }
    } else {
        if (!isset($hostOptions[$hostId])) { $hostId = 0; }   // 없는 호스트면 전체로
        foreach ($hosts as $h) {
            if ($hostId === 0 || (int) $h['host_id'] === $hostId) { $scanIds[] = (int) $h['scan_id']; }
        }
    }

    if ($scanIds) {
        $in = implode(',', array_fill(0, count($scanIds), '?'));

        // KPI 는 필터 무관 — 대상 스캔 전체 기준
        $stmt = $pdo->prepare("SELECT severity, COUNT(*) c FROM tb_findings WHERE scan_id IN ($in) GROUP BY severity");
        $stmt->execute($scanIds);
        foreach ($stmt->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        // 필터 WHERE 조립 (COUNT 와 목록 쿼리에 동일하게 사용)
        $where  = "f.scan_id IN ($in)";
        $params = $scanIds;
        if ($q !== '') {
            $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
            $params[] = '%' . $q . '%';
            $params[] = '%' . $q . '%';
        }
        if ($sev !== '') {
            $where .= ' AND f.severity = ?';
            $params[] = $sev;
        }
        if ($st !== '') {
            $where .= ' AND f.runtime_status = ?';
            $params[] = $st;
        }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_findings f WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();

        $offset = ($page - 1) * $perPage;

        $stmt = $pdo->prepare(
            "SELECT f.*, h.id AS host_id, h.fqdn, c.summary, c.epss, c.epss_percentile,
                (SELECT a.fixed_version FROM tb_cve_affected_packages a
                 WHERE a.cve_id = f.cve_id AND a.package_name = f.package_name
                   AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version
             FROM tb_findings f
             JOIN tb_scans s ON s.id = f.scan_id
             JOIN tb_hosts h ON h.id = s.host_id
             LEFT JOIN tb_cves c ON c.cve_id = f.cve_id
             WHERE $where
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cvss DESC, h.fqdn
             LIMIT $perPage OFFSET $offset"
        );
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header('취약점', 'findings');
?>
  <h1>취약점 우선순위 <span class="hint">(매처 결과)</span></h1>
  <div class="sub">
    <?php if ($scan): ?>
      호스트 <strong><?= vg_h($scan['fqdn']) ?></strong> · scan #<?= (int) $scan['id'] ?> · <?= vg_h($scan['collected_at']) ?>
      · <a href="/findings.php">전체 호스트 보기 →</a>
    <?php elseif ($scanId > 0): ?>
      스캔 #<?= $scanId ?> 을(를) 찾을 수 없습니다. · <a href="/findings.php">전체 호스트 보기 →</a>
    <?php elseif ($hostId > 0): ?>
      호스트 <strong><?= vg_h($hostOptions[$hostId]) ?></strong> · 최신 스캔 기준
      · <a href="/findings.php">전체 호스트 보기 →</a>
    <?php elseif ($hostOptions): ?>
      전체 호스트 <?= count($hostOptions) ?>대 · 각 호스트의 최신 스캔 기준
    <?php else: ?>스캔 없음<?php endif; ?>
  </div>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <a href="<?= vg_h(vg_qs(['sev' => $sev === $s ? '' : $s, 'page' => 1])) ?>"
         class="kpi tone-<?= vg_sev_tone($s) ?><?= $sev === $s ? ' is-selected' : '' ?>">
        <b><?= (int) $counts[$s] ?></b><span><?= $s ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  // 단일 스캔 모드에선 scan_id 를 유지하고, 통합 모드에선 호스트 선택 드롭다운을 준다.
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  vg_toolbar(array_merge($toolbar, [
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'sev', 'empty_label' => '전체 등급', 'selected' => $sev,
          'options' => array_combine($sevOptions, $sevOptions)],
      ['type' => 'select', 'name' => 'st', 'empty_label' => '전체 상태', 'selected' => $st,
          'options' => array_combine($stOptions, array_map('vg_status_label', $stOptions))],
  ]));

  // 호스트 컬럼은 통합 모드에서만. 단일 스캔 모드는 부제가 이미 호스트를 밝힌다.
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn']];
  $headers = array_merge($headers, [
      ['label' => '등급', 'key' => 'severity'],
      ['label' => '상태', 'key' => 'runtime_status'],
      ['label' => 'CVE', 'key' => 'cve_id'],
      ['label' => '패키지', 'key' => 'package_name'],
      ['label' => '버전', 'key' => 'installed_version'],
      ['label' => 'CVSS', 'key' => 'cvss'],
      ['label' => 'EPSS', 'key' => 'epss'],
      ['label' => 'KEV', 'key' => 'in_kev'],
      ['label' => '근거 (왜 위험한가)', 'key' => 'rationale'],
      ['label' => '조치', 'key' => 'fix'],
  ]);

  vg_table(
      $headers,
      $rows,
      [
          'empty' => '조건에 맞는 판정 결과가 없습니다.',
          'cell' => [
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
              'severity'       => fn($r) => vg_sev_badge((string) $r['severity']),
              'runtime_status' => fn($r) => vg_status_badge($r['runtime_status']),
              'cve_id' => function ($r) {
                  $html = '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a></strong>';
                  if ($r['summary']) { $html .= '<div class="why">' . vg_trunc($r['summary']) . '</div>'; }
                  return $html;
              },
              'package_name'      => fn($r) => vg_h($r['package_name']),
              'installed_version' => fn($r) => '<code>' . vg_h($r['installed_version']) . '</code>',
              'cvss'      => fn($r) => $r['cvss'] !== null ? vg_h((string) $r['cvss']) : '-',
              'epss'      => fn($r) => vg_epss_cell($r['epss'], $r['epss_percentile']),
              'in_kev'    => fn($r) => $r['in_kev'] ? '✔' : '',
              'rationale' => fn($r) => '<span class="why">' . vg_trunc($r['rationale']) . '</span>',
              'fix'       => fn($r) => !empty($r['fixed_version']) ? '<span class="pill">' . vg_h($r['fixed_version']) . ' 이상</span>' : '<span class="why">패치 확인</span>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
