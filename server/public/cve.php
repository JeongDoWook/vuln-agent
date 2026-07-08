<?php
declare(strict_types=1);

/**
 * cve.php — CVE 상세페이지. 로그인 필요.
 *   ?cve=CVE-XXXX-XXXXX. 요약/영향 패키지/발견 위치(최신 스캔 기준)를 보여준다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();

$err = null; $cveId = ''; $cve = null; $kev = null; $affected = []; $locations = [];
try {
    $raw = (string) ($_GET['cve'] ?? '');
    if (!preg_match('/^CVE-\d{4}-\d+$/i', $raw)) {
        $err = '잘못된 CVE 형식입니다.';
    } else {
        $cveId = strtoupper($raw);
        $pdo = vg_pdo();

        $stmt = $pdo->prepare('SELECT * FROM cves WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $cve = $stmt->fetch() ?: null;

        $stmt = $pdo->prepare('SELECT * FROM kev_catalog WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $kev = $stmt->fetch() ?: null;

        $stmt = $pdo->prepare('SELECT ecosystem, package_name, fixed_version FROM cve_affected_packages WHERE cve_id = ? ORDER BY ecosystem, package_name');
        $stmt->execute([$cveId]);
        $affected = $stmt->fetchAll();

        // 호스트별 최신 스캔 기준으로 이 CVE 가 발견된 위치
        $stmt = $pdo->prepare(
            "SELECT h.id AS host_id, h.fqdn, f.severity, f.runtime_status, f.package_name, f.installed_version, s.collected_at
             FROM findings f
             JOIN scans s ON s.id = f.scan_id
             JOIN hosts h ON h.id = s.host_id
             JOIN (SELECT host_id, MAX(id) AS max_id FROM scans GROUP BY host_id) latest
               ON latest.host_id = s.host_id AND latest.max_id = s.id
             WHERE f.cve_id = ?
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), h.fqdn"
        );
        $stmt->execute([$cveId]);
        $locations = $stmt->fetchAll();
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header($cveId !== '' ? $cveId : 'CVE', 'findings');
?>
  <div class="sub"><a href="/findings.php">← 취약점</a></div>

<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php else: ?>
  <h1>
    <?= vg_h($cveId) ?>
    <?php if ($kev): ?><span class="badge" style="background:#da3633;">KEV</span><?php endif; ?>
  </h1>
  <div class="sub">
    CVSS <?= $cve && $cve['cvss'] !== null ? vg_h((string) $cve['cvss']) : '-' ?> ·
    EPSS <?= $cve && $cve['epss'] !== null ? vg_h(number_format((float) $cve['epss'] * 100, 1)) . '%' : '-' ?> ·
    공개일 <?= $cve && $cve['published'] !== null ? vg_h((string) $cve['published']) : '-' ?>
  </div>

  <div class="card">
    <strong>요약</strong>
    <p class="why" style="margin:.6rem 0 0;white-space:pre-wrap;"><?= $cve && $cve['summary'] ? vg_h($cve['summary']) : '해당 없음' ?></p>
  </div>

  <div class="card">
    <strong>영향 패키지</strong>
    <table style="margin-top:.6rem;">
      <thead><tr><th>생태계</th><th>패키지</th><th>수정 버전</th></tr></thead>
      <tbody>
      <?php if (!$affected): ?><tr><td colspan="3" class="empty">해당 없음</td></tr><?php endif; ?>
      <?php foreach ($affected as $a): ?>
        <tr>
          <td><?= vg_h($a['ecosystem']) ?></td>
          <td><?= vg_h($a['package_name']) ?></td>
          <td><?= !empty($a['fixed_version']) ? '<span class="pill">' . vg_h($a['fixed_version']) . ' 이상</span>' : '-' ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <div class="card">
    <strong>이 CVE가 발견된 위치</strong> <span class="why">— 호스트별 최신 스캔 기준</span>
    <table style="margin-top:.6rem;">
      <thead><tr><th>호스트</th><th>등급</th><th>상태</th><th>패키지</th><th>설치 버전</th><th>수집일</th></tr></thead>
      <tbody>
      <?php if (!$locations): ?><tr><td colspan="6" class="empty">해당 없음</td></tr><?php endif; ?>
      <?php foreach ($locations as $l): ?>
        <tr>
          <td><a href="/host.php?id=<?= (int) $l['host_id'] ?>"><?= vg_h($l['fqdn']) ?></a></td>
          <td><span class="badge" style="background:<?= vg_sev_color($l['severity']) ?>;"><?= vg_h($l['severity']) ?></span></td>
          <td><span class="badge" style="background:<?= vg_status_color($l['runtime_status']) ?>;"><?= vg_h(vg_status_label($l['runtime_status'])) ?></span></td>
          <td><?= vg_h($l['package_name']) ?></td>
          <td><code><?= vg_h($l['installed_version']) ?></code></td>
          <td class="why"><?= vg_h($l['collected_at']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
<?php endif; ?>
<?php vg_footer();
