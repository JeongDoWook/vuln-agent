<?php
declare(strict_types=1);

/**
 * cve.php — CVE 상세페이지. 로그인 필요.
 *   ?cve=CVE-XXXX-XXXXX. 요약/영향 패키지/발견 위치(최신 스캔 기준)를 보여준다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

$err = null; $cveId = ''; $cve = null; $kev = null; $affected = []; $locations = [];
$locTotal = 0; $page = max(1, (int) ($_GET['page'] ?? 1)); $perPage = vg_perpage();
try {
    $raw = (string) ($_GET['cve'] ?? '');
    if (!preg_match('/^CVE-\d{4}-\d+$/i', $raw)) {
        $err = '잘못된 CVE 형식입니다.';
    } else {
        $cveId = strtoupper($raw);
        $pdo = vg_pdo();

        $stmt = $pdo->prepare('SELECT * FROM tb_cves WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $cve = $stmt->fetch() ?: null;

        $stmt = $pdo->prepare('SELECT * FROM tb_kev_catalog WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $kev = $stmt->fetch() ?: null;

        $stmt = $pdo->prepare('SELECT ecosystem, package_name, fixed_version FROM tb_cve_affected_packages WHERE cve_id = ? ORDER BY ecosystem, package_name');
        $stmt->execute([$cveId]);
        $affected = $stmt->fetchAll();

        // 호스트별 최신 스캔 기준으로 이 CVE 가 발견된 위치(호스트 수만큼 늘어 페이지네이션)
        $locSql =
            "FROM tb_findings f
             JOIN tb_scans s ON s.id = f.scan_id
             JOIN tb_hosts h ON h.id = s.host_id
             JOIN (SELECT host_id, MAX(id) AS max_id FROM tb_scans GROUP BY host_id) latest
               ON latest.host_id = s.host_id AND latest.max_id = s.id
             WHERE f.cve_id = ?";
        $stmt = $pdo->prepare("SELECT COUNT(*) $locSql");
        $stmt->execute([$cveId]);
        $locTotal = (int) $stmt->fetchColumn();

        $offset = ($page - 1) * $perPage;
        $stmt = $pdo->prepare(
            "SELECT h.id AS host_id, h.fqdn, f.severity, f.runtime_status, f.package_name, f.installed_version, s.collected_at
             $locSql
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), h.fqdn
             LIMIT $perPage OFFSET $offset"
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
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <h1>
    <?= vg_h($cveId) ?>
    <?php if ($kev): ?><?= vg_badge('KEV', 'crit') ?><?php endif; ?>
  </h1>
  <div class="sub">
    CVSS <?= $cve && $cve['cvss'] !== null ? vg_h((string) $cve['cvss']) : '-' ?> ·
    EPSS <?= $cve ? vg_epss_cell($cve['epss'], $cve['epss_percentile']) : '-' ?> ·
    공개일 <?= $cve && $cve['published'] !== null ? vg_h((string) $cve['published']) : '-' ?>
  </div>

  <div class="card">
    <strong>요약</strong>
    <p class="why prose"><?= $cve && $cve['summary'] ? vg_h($cve['summary']) : '해당 없음' ?></p>
  </div>

  <div class="card">
    <strong>영향 패키지</strong>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '생태계', 'key' => 'ecosystem'],
            ['label' => '패키지', 'key' => 'package_name'],
            ['label' => '수정 버전'],
        ],
        $affected,
        [
            'card' => false,
            'empty' => '해당 없음',
            'cell' => [
                2 => fn($a) => !empty($a['fixed_version']) ? '<span class="pill">' . vg_h($a['fixed_version']) . ' 이상</span>' : '-',
            ],
        ]
    );
    ?>
    </div>
  </div>

  <div class="card">
    <strong>이 CVE가 발견된 위치</strong> <span class="why">— 호스트별 최신 스캔 기준</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '호스트'],
            ['label' => '등급', 'key' => 'severity'],
            ['label' => '상태', 'key' => 'runtime_status'],
            ['label' => '패키지', 'key' => 'package_name'],
            ['label' => '설치 버전'],
            ['label' => '수집일', 'nowrap' => true],
        ],
        $locations,
        [
            'card' => false,
            'empty' => '해당 없음',
            'cell' => [
                0 => fn($l) => '<a href="/host.php?id=' . (int) $l['host_id'] . '">' . vg_h($l['fqdn']) . '</a>',
                'severity'       => fn($l) => vg_sev_badge((string) $l['severity']),
                'runtime_status' => fn($l) => vg_status_badge($l['runtime_status']),
                4 => fn($l) => '<code>' . vg_h($l['installed_version']) . '</code>',
                5 => fn($l) => '<span class="why">' . vg_h($l['collected_at']) . '</span>',
            ],
        ]
    );
    if ($locations) { vg_page_nav($locTotal, $perPage, $page); }
    ?>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
