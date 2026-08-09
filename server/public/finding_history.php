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
require_once __DIR__ . '/../src/remediation_note.php';   // 미조치 사유 + 승인자(최소 필드)
vg_require_menu('findings');

/**
 * 컨테이너 PK → 컨테이너 이름. 0 이면 호스트 자신('').
 *   메모의 자연키는 이름이다 — container_id 는 스캔마다 새로 발급돼 스캔 간 비교가 안 된다.
 */
function vg_fh_container_name(PDO $pdo, int $containerId): string {
    if ($containerId <= 0) { return ''; }
    $st = $pdo->prepare('SELECT cid FROM tb_container WHERE container_id = ? AND is_deleted = 0');
    $st->execute([$containerId]);
    $c = $st->fetchColumn();
    return $c !== false ? (string) $c : '';
}

// --- 미조치 사유 저장/철회 POST — GET 렌더보다 먼저(헤더 출력 전) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $noteMsg = null; $noteErr = null;
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $noteErr = '세션이 만료되었습니다. 다시 시도해 주세요.';
    } elseif (!vg_has_role('admin', 'operator')) {
        // 조회 권한만 있는 사용자가 승인 이력을 남길 수는 없다(승인자는 자동 기록되는 값이다).
        http_response_code(403);
        echo 'forbidden';
        exit;
    } else {
        $pHostId = (int) ($_POST['id'] ?? 0);
        $pCtrId  = (int) ($_POST['cid'] ?? 0);
        $pCve    = trim((string) ($_POST['cve'] ?? ''));
        $pPkg    = trim((string) ($_POST['pkg'] ?? ''));
        $action  = (string) ($_POST['action'] ?? '');
        try {
            $pdo = vg_pdo();
            if ($pHostId <= 0 || $pCve === '' || $pPkg === '') {
                throw new RuntimeException('대상 취약점 정보가 없습니다.');
            }
            $pCid = vg_fh_container_name($pdo, $pCtrId);
            $me   = vg_current_user();

            if ($action === 'note_save') {
                $reason = trim((string) ($_POST['reason'] ?? ''));
                if ($reason === '') {
                    throw new RuntimeException('미조치 사유를 입력하세요.');
                }
                $reason = mb_substr($reason, 0, VG_REMEDIATION_REASON_MAX);
                vg_remediation_note_save($pdo, $pHostId, $pCid, $pCve, $pPkg, $reason, $me['id'] ?? null);
                vg_log_activity(
                    $pdo, 'HOST', $pHostId, 'remediation_note_save',
                    "미조치 사유 등록: {$pCve} / {$pPkg}" . ($pCid !== '' ? " (컨테이너 {$pCid})" : ''),
                    ['cve' => $pCve, 'package' => $pPkg, 'cid' => $pCid, 'reason' => $reason]
                );
                $noteMsg = '미조치 사유를 저장했습니다. 승인자·승인일시가 함께 기록됩니다.';
            } elseif ($action === 'note_revoke') {
                vg_remediation_note_revoke($pdo, $pHostId, $pCid, $pCve, $pPkg);
                vg_log_activity(
                    $pdo, 'HOST', $pHostId, 'remediation_note_revoke',
                    "미조치 사유 철회: {$pCve} / {$pPkg}" . ($pCid !== '' ? " (컨테이너 {$pCid})" : ''),
                    ['cve' => $pCve, 'package' => $pPkg, 'cid' => $pCid]
                );
                $noteMsg = '미조치 사유를 철회했습니다.';
            }
        } catch (Throwable $e) {
            error_log('[remediation-note] ' . $e->getMessage());
            $noteErr = $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.';
        }
    }
    vg_redirect_flash(['noteMsg' => $noteMsg, 'noteErr' => $noteErr]);
}
$noteFlash = vg_flash_take();
$noteMsg = $noteFlash['noteMsg'] ?? null;
$noteErr = $noteFlash['noteErr'] ?? null;
$csrf = vg_csrf_token();

$err = null; $host = null; $rows = []; $total = 0; $summary = null; $current = null;
$note = null;
$hostId = (int) ($_GET['id'] ?? 0);
$containerId = (int) ($_GET['cid'] ?? 0);
$cveId = trim((string) ($_GET['cve'] ?? ''));
$packageName = trim((string) ($_GET['pkg'] ?? ''));
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();

    $st = $pdo->prepare('SELECT host_id, fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    $containerName = null;
    if ($host && $cveId !== '' && $packageName !== '') {
        if ($containerId > 0) {
            $c = vg_fh_container_name($pdo, $containerId);
            $containerName = $c !== '' ? $c : null;
        }

        // 미조치 사유 메모(사람의 판단) — 억제(자동 판정)와는 별개로 자연키로 붙는다.
        $note = vg_remediation_note_get($pdo, $hostId, $containerName, $cveId, $packageName);

        // 인프라 민감정보(설치 패키지 이력)의 스캔별 열람 — 감사로그 대상(CLAUDE.md 원칙 7).
        vg_log_activity(
            $pdo, 'HOST', $hostId, 'view_finding_history',
            $cveId . ' / ' . $packageName . ($containerId > 0 ? " (container #{$containerId})" : '')
        );

        $total = vg_finding_history_count($pdo, $hostId);
        $rows = vg_finding_history($pdo, $hostId, $containerId, $cveId, $packageName, $perPage, ($page - 1) * $perPage);
        $summary = vg_finding_history_summary($pdo, $hostId, $containerId, $cveId, $packageName);
        // "현재 상태" 는 항상 최신 스캔(1건) 기준 — 조회 중인 페이지가 1페이지가 아니어도 동일해야 한다.
        $current = ($page === 1 && $rows) ? $rows[0] : (vg_finding_history($pdo, $hostId, $containerId, $cveId, $packageName, 1, 0)[0] ?? null);
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
  vg_alert($noteMsg, 'ok');
  vg_alert($noteErr);
  ?>
  <div class="card">
    <strong>현재 상태:</strong>
    <?php if ($note !== null): ?><?= vg_badge('미조치 사유 있음', 'info', '사람이 남긴 미조치 사유 메모가 있습니다 — 아래 참조') ?><?php endif; ?>
    <?= $current !== null ? vg_badge($statusLabel[$current['status']] ?? $current['status'], $current['status'] === 'FOUND' ? vg_sev_tone((string) $current['severity']) : ($current['status'] === 'SUPPRESSED' ? 'warn' : 'muted')) : '<span class="why">–</span>' ?>
    <span class="why">
      · 총 <?= number_format($total) ?>회 스캔 중 <?= number_format($summary['foundCount'] ?? 0) ?>회 발견됨
      · 최초 발견: <?= $summary && $summary['firstFoundAt'] !== null ? vg_h((string) $summary['firstFoundAt']) : '없음' ?>
    </span>
  </div>
  <div class="card">
    <strong>미조치 사유</strong>
    <span class="why">— 조치하지 않는 이유와 그 판단 주체·시점만 남깁니다.</span>
    <div class="card__body">
      <?php if ($note !== null): ?>
        <dl class="kv">
          <dt>사유</dt><dd><?= nl2br(vg_h((string) $note['reason'])) ?></dd>
          <dt>승인자</dt><dd><?= $note['approved_by_name'] !== null ? vg_h((string) $note['approved_by_name']) : '<span class="why">–</span>' ?></dd>
          <dt>승인일시</dt><dd><?= $note['approved_at'] !== null ? vg_h((string) $note['approved_at']) : '<span class="why">–</span>' ?></dd>
        </dl>
      <?php else: ?>
        <p class="why">등록된 미조치 사유가 없습니다.</p>
      <?php endif; ?>

      <?php if (vg_has_role('admin', 'operator')): ?>
        <form method="post">
          <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
          <input type="hidden" name="action" value="note_save">
          <input type="hidden" name="id" value="<?= (int) $hostId ?>">
          <input type="hidden" name="cid" value="<?= (int) $containerId ?>">
          <input type="hidden" name="cve" value="<?= vg_h($cveId) ?>">
          <input type="hidden" name="pkg" value="<?= vg_h($packageName) ?>">
          <label for="reason"><?= $note !== null ? '사유 수정' : '사유 입력' ?> (최대 <?= VG_REMEDIATION_REASON_MAX ?>자)</label>
          <textarea id="reason" name="reason" rows="3" required
                    maxlength="<?= VG_REMEDIATION_REASON_MAX ?>"
                    placeholder="예) 해당 서비스는 내부망 전용이고 벤더 수정본이 없어 다음 정기점검까지 보류합니다."><?= $note !== null ? vg_h((string) $note['reason']) : '' ?></textarea>
          <div class="actions">
            <button class="btn btn--sm btn--primary">저장</button>
            <span class="why">저장하면 승인자(<?= vg_h((string) (vg_current_user()['username'] ?? '-')) ?>)와 승인일시가 자동 기록됩니다.</span>
          </div>
        </form>
        <?php if ($note !== null): ?>
          <form method="post" data-confirm="이 미조치 사유를 철회할까요? 화면과 export 에서 사라집니다(감사로그에는 남습니다).">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="note_revoke">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <input type="hidden" name="cid" value="<?= (int) $containerId ?>">
            <input type="hidden" name="cve" value="<?= vg_h($cveId) ?>">
            <input type="hidden" name="pkg" value="<?= vg_h($packageName) ?>">
            <div class="actions"><button class="btn btn--sm btn--ghost">사유 철회</button></div>
          </form>
        <?php endif; ?>
      <?php else: ?>
        <p class="why">사유 등록은 관리자·운영자만 할 수 있습니다.</p>
      <?php endif; ?>
    </div>
  </div>

  <div class="card">
    <strong>스캔별 상태 타임라인</strong>
    <span class="why">— 최신 스캔부터, 이 페이지에 <?= count($rows) ?>건</span>
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
    <?php vg_page_nav($total, $perPage, $page); ?>
  </div>
<?php endif; ?>
<?php vg_footer();
