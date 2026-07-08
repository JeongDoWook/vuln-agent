<?php
declare(strict_types=1);

/**
 * findings.php — 매처 판정 결과(우선순위 취약점). 로그인 필요.
 *   ?scan_id=N, 없으면 최신 스캔. 검색(q)/등급(sev)/상태(st) 필터 + 페이지네이션.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();

const VG_PER_PAGE = 50;
$sevOptions = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
$stOptions  = ['EXTERNAL', 'LISTENING', 'RUNNING', 'LOADED', 'INSTALLED'];

$err = null; $scan = null; $rows = []; $total = 0;
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];

$q   = trim((string) ($_GET['q'] ?? ''));
$sev = (string) ($_GET['sev'] ?? '');
$st  = (string) ($_GET['st'] ?? '');
if (!in_array($sev, $sevOptions, true)) { $sev = ''; }
if (!in_array($st, $stOptions, true)) { $st = ''; }
$page = max(1, (int) ($_GET['page'] ?? 1));

try {
    $pdo = vg_pdo();
    if (isset($_GET['scan_id'])) {
        $scanId = (int) $_GET['scan_id'];
    } else {
        $scanId = (int) ($pdo->query('SELECT id FROM scans ORDER BY received_at DESC LIMIT 1')->fetchColumn() ?: 0);
    }
    if ($scanId > 0) {
        $stmt = $pdo->prepare('SELECT s.*, h.fqdn FROM scans s JOIN hosts h ON h.id = s.host_id WHERE s.id = ?');
        $stmt->execute([$scanId]);
        $scan = $stmt->fetch() ?: null;

        // KPI 는 필터 무관 전체 스캔 기준
        $stmt = $pdo->prepare('SELECT severity, COUNT(*) c FROM findings WHERE scan_id = ? GROUP BY severity');
        $stmt->execute([$scanId]);
        foreach ($stmt->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        // 필터 WHERE 조립 (COUNT 와 목록 쿼리에 동일하게 사용)
        $where = 'f.scan_id = ?';
        $params = [$scanId];
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

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM findings f WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();

        $perPage = VG_PER_PAGE;
        $offset = ($page - 1) * $perPage;

        $stmt = $pdo->prepare(
            "SELECT f.*, c.summary, c.epss,
                (SELECT a.fixed_version FROM cve_affected_packages a
                 WHERE a.cve_id = f.cve_id AND a.package_name = f.package_name
                   AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version
             FROM findings f LEFT JOIN cves c ON c.cve_id = f.cve_id
             WHERE $where
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cvss DESC
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
  <h1>취약점 우선순위 <span style="font-size:.8rem;color:#8b93a1;">(매처 결과)</span></h1>
  <div class="sub">
    <?php if ($scan): ?>
      호스트 <strong><?= vg_h($scan['fqdn']) ?></strong> · scan #<?= (int) $scan['id'] ?> · <?= vg_h($scan['collected_at']) ?>
    <?php else: ?>스캔 없음<?php endif; ?>
  </div>

<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php else: ?>
  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <a href="<?= vg_h(vg_qs(['sev' => $sev === $s ? '' : $s, 'page' => 1])) ?>"
         class="kpi" style="background:<?= vg_sev_color($s) ?>;color:#fff;<?= $sev === $s ? 'outline:2px solid #fff;' : '' ?>">
        <b><?= (int) $counts[$s] ?></b><span><?= $s ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <form class="toolbar" method="get">
    <?php if ($scan): ?><input type="hidden" name="scan_id" value="<?= (int) $scan['id'] ?>"><?php endif; ?>
    <input type="search" name="q" placeholder="CVE 또는 패키지명 검색" value="<?= vg_h($q) ?>">
    <select name="sev">
      <option value="">전체 등급</option>
      <?php foreach ($sevOptions as $s): ?>
        <option value="<?= $s ?>" <?= $sev === $s ? 'selected' : '' ?>><?= $s ?></option>
      <?php endforeach; ?>
    </select>
    <select name="st">
      <option value="">전체 상태</option>
      <?php foreach ($stOptions as $s): ?>
        <option value="<?= $s ?>" <?= $st === $s ? 'selected' : '' ?>><?= vg_h(vg_status_label($s)) ?></option>
      <?php endforeach; ?>
    </select>
    <button type="submit" class="btn-sm"><?= '검색' ?></button>
    <?php if ($q !== '' || $sev !== '' || $st !== ''): ?>
      <a class="btn-sm" href="<?= vg_h(vg_qs(['q' => null, 'sev' => null, 'st' => null, 'page' => null])) ?>">초기화</a>
    <?php endif; ?>
  </form>

  <?php if (!$rows): ?>
    <div class="card"><div class="empty">조건에 맞는 판정 결과가 없습니다.</div></div>
  <?php else: ?>
  <div class="card">
    <table>
      <thead><tr>
        <th>등급</th><th>상태</th><th>CVE</th><th>패키지</th><th>버전</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>근거 (왜 위험한가)</th><th>조치</th>
      </tr></thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><span class="badge" style="background:<?= vg_sev_color($r['severity']) ?>;"><?= vg_h($r['severity']) ?></span></td>
          <td><span class="badge" style="background:<?= vg_status_color($r['runtime_status']) ?>;"><?= vg_h(vg_status_label($r['runtime_status'])) ?></span></td>
          <td><strong><a href="/cve.php?cve=<?= urlencode($r['cve_id']) ?>"><?= vg_h($r['cve_id']) ?></a></strong>
            <?php if ($r['summary']): ?><div class="why"><?= vg_trunc($r['summary']) ?></div><?php endif; ?>
          </td>
          <td><?= vg_h($r['package_name']) ?></td>
          <td><code><?= vg_h($r['installed_version']) ?></code></td>
          <td><?= $r['cvss'] !== null ? vg_h((string) $r['cvss']) : '-' ?></td>
          <td><?= $r['epss'] !== null ? vg_h(number_format((float) $r['epss'] * 100, 1)) . '%' : '-' ?></td>
          <td><?= $r['in_kev'] ? '✔' : '' ?></td>
          <td class="why"><?= vg_trunc($r['rationale']) ?></td>
          <td class="why"><?= !empty($r['fixed_version']) ? '<span class="pill">' . vg_h($r['fixed_version']) . ' 이상</span>' : '패치 확인' ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php vg_page_nav($total, VG_PER_PAGE, $page); ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
