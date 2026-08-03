<?php
declare(strict_types=1);

/**
 * finding_history.php — 특정 (호스트, 컨테이너, CVE, 패키지) 조합의 스캔별 이력 타임라인. 로그인 필요.
 *   ?id=<host_id>&cid=<container_id, 0=호스트 자신>&cve=<cve_id>&pkg=<package_name>
 *
 * host.php 의 "스캔" 탭은 스캔별 심각도 분포만, changes.php 는 최근 스캔 2개 비교만 보여준다.
 * 이 페이지가 그 사이 빈틈 — 하나의 (호스트,CVE,패키지) 조합을 호스트의 전체 스캔 이력에 걸쳐
 * 이어 보여준다. host.php 취약점 탭의 각 행에서 "이력" 링크로 들어온다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';       // vg_log_activity
require_once __DIR__ . '/../src/finding_history.php';
vg_require_menu('findings');

$err = null; $host = null; $rows = [];
$hostId = (int) ($_GET['id'] ?? 0);
$containerId = (int) ($_GET['cid'] ?? 0);
$cveId = trim((string) ($_GET['cve'] ?? ''));
$packageName = trim((string) ($_GET['pkg'] ?? ''));

try {
    $pdo = vg_pdo();

    $st = $pdo->prepare('SELECT host_id, fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    $containerName = null;
    if ($host && $cveId !== '' && $packageName !== '') {
        if ($containerId > 0) {
            $st = $pdo->prepare('SELECT cid FROM tb_container WHERE container_id = ? AND is_deleted = 0');
            $st->execute([$containerId]);
            $c = $st->fetchColumn();
            $containerName = $c !== false ? (string) $c : null;
        }

        // 인프라 민감정보(설치 패키지 이력)의 스캔별 열람 — 감사로그 대상(CLAUDE.md 원칙 7).
        vg_log_activity(
            $pdo, 'HOST', $hostId, 'view_finding_history',
            $cveId . ' / ' . $packageName . ($containerId > 0 ? " (container #{$containerId})" : '')
        );

        $rows = vg_finding_history($pdo, $hostId, $containerId, $cveId, $packageName);
    }
} catch (Throwable $e) {
    error_log('[finding_history] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

$statusLabel = [
    'FOUND'        => '발견',
    'SUPPRESSED'   => '억제됨',
    'NO_CONTAINER' => '컨테이너 없음',
    'PACKAGE_ONLY' => '해당없음(패키지 있음)',
    'NONE'         => '해당없음',
];

vg_header($cveId !== '' ? $cveId . ' 이력' : '취약점 이력', 'assets');
?>
<?php if ($err !== null): ?>
  <?php vg_page_title('취약점 이력', 'FINDING HISTORY', '이력을 불러오지 못했습니다.'); ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif (!$host): ?>
  <?php vg_page_title('호스트를 찾을 수 없습니다', 'FINDING HISTORY'); ?>
  <div class="card"><?php vg_empty(['icon' => '🖥️', 'title' => '요청한 호스트 정보가 없습니다.', 'cta' => ['href' => '/', 'label' => '← 대시보드']]); ?></div>
<?php elseif ($cveId === '' || $packageName === ''): ?>
  <?php vg_page_title('취약점 이력', 'FINDING HISTORY'); ?>
  <div class="card"><?php vg_empty(['icon' => '⚠️', 'title' => 'CVE·패키지 정보가 없습니다.', 'hint' => 'host.php 취약점 탭의 "이력" 링크로 들어와 주세요.']); ?></div>
<?php else: ?>
  <?php
  $meta = [
      vg_h($packageName),
      $containerId > 0 ? '컨테이너 ' . vg_h($containerName ?? ('#' . $containerId)) : '호스트 자신',
      '<a href="/host.php?id=' . (int) $hostId . '">' . vg_h($host['fqdn']) . '</a>',
  ];
  vg_hero(vg_h($cveId), $meta, null, 'muted', '스캔별 이력', 'FINDING HISTORY');
  ?>
  <div class="card">
    <strong>스캔별 상태 타임라인</strong>
    <span class="why">— 이 호스트의 전체 스캔(<?= count($rows) ?>건)에 걸친 발견/억제/해당없음 변화</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '스캔', 'key' => 'scan_id'],
            ['label' => '수집시각', 'key' => 'collected_at'],
            ['label' => '상태'],
            ['label' => '버전'],
            ['label' => '근거'],
        ],
        $rows,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '🕘',
                'title' => '스캔 이력이 없습니다.',
            ],
            'cell' => [
                'scan_id'      => fn($r) => '<a href="/findings.php?scan_id=' . (int) $r['scan_id'] . '">#' . (int) $r['scan_id'] . '</a>',
                'collected_at' => fn($r) => $r['collected_at'] !== null ? vg_h((string) $r['collected_at']) : '<span class="why">–</span>',
                2 => function ($r) use ($statusLabel) {
                    $tone = $r['status'] === 'FOUND' ? vg_sev_tone((string) $r['severity'])
                          : ($r['status'] === 'SUPPRESSED' ? 'warn' : 'muted');
                    return vg_badge($statusLabel[$r['status']] ?? $r['status'], $tone);
                },
                3 => fn($r) => $r['version'] !== null ? '<span class="why">' . vg_h((string) $r['version']) . '</span>' : '<span class="why">–</span>',
                4 => fn($r) => $r['reason'] !== null ? '<span class="why">' . vg_h((string) $r['reason']) . '</span>' : '<span class="why">–</span>',
            ],
        ]
    );
    ?>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
