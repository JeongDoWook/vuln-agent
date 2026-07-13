<?php
declare(strict_types=1);

/**
 * assets.php — 자산(호스트) 관리. 로그인 + assets 메뉴 권한 필요.
 *   목록: 에이전트가 등록한 호스트 + 최신 수집 상태(정상/지연/오프라인/수집없음).
 *   삭제: admin·operator 만. 소프트삭제(is_deleted=1) 라 대시보드·취약점 집계에서 빠진다.
 *   스캔 이력은 호스트 상세(host.php)의 "스캔 이력" 카드에서 본다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
vg_require_menu('assets');

// 수집 지연 판정 기준(분). 에이전트 기본 스케줄이 매시간이라 3시간까지는 정상으로 본다.
const VG_STALE_MIN   = 180;        // 3시간 초과 → 지연
const VG_OFFLINE_MIN = 10080;      // 7일 초과 → 오프라인

$canDelete = vg_has_role('admin', 'operator');

$err = null; $msg = null; $rows = []; $total = 0; $sevByScan = [];
$q    = trim((string) ($_GET['q'] ?? ''));
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = vg_perpage();

$pdo = vg_pdo();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } elseif (!$canDelete) {
        $err = '자산을 삭제할 권한이 없습니다.';
    } else {
        try {
            $id = (int) ($_POST['id'] ?? 0);
            $st = $pdo->prepare('SELECT fqdn FROM tb_hosts WHERE id = ? AND is_deleted = 0');
            $st->execute([$id]);
            $fqdn = $st->fetchColumn();
            if ($fqdn === false) {
                $err = '호스트를 찾을 수 없습니다.';
            } else {
                vg_soft_delete($pdo, 'tb_hosts', $id);
                vg_log_activity($pdo, 'HOST', $id, 'host_delete', "자산 삭제: $fqdn");
                $msg = "자산 '$fqdn' 을(를) 삭제했습니다. 해당 호스트가 다시 수집을 보내면 재등록됩니다.";
            }
        } catch (Throwable $e) {
            $err = '삭제 실패: ' . $e->getMessage();
        }
    }
}

try {
    $where  = 'h.is_deleted = 0';
    $params = [];
    if ($q !== '') {
        $where .= ' AND h.fqdn LIKE ?';
        $params[] = '%' . $q . '%';
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_hosts h WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $offset = ($page - 1) * $perPage;

    // 호스트 + 최신 스캔(LEFT JOIN — 등록만 되고 아직 수집이 없는 호스트도 보여준다)
    $st = $pdo->prepare(
        "SELECT h.id, h.fqdn, h.os_id, h.os_version, h.first_seen,
                s.id AS scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) AS age_min,
                (SELECT COUNT(*) FROM tb_scans x WHERE x.host_id = h.id) AS scan_count
           FROM tb_hosts h
           LEFT JOIN tb_scans s ON s.id = (SELECT MAX(id) FROM tb_scans WHERE host_id = h.id)
          WHERE $where
          ORDER BY h.fqdn
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    // 이 페이지에 보이는 최신 스캔들의 심각도 카운트
    $ids = [];
    foreach ($rows as $r) { if ($r['scan_id'] !== null) { $ids[] = (int) $r['scan_id']; } }
    if ($ids) {
        $in = implode(',', array_fill(0, count($ids), '?'));
        $st = $pdo->prepare("SELECT scan_id, severity, COUNT(*) c FROM tb_findings WHERE scan_id IN ($in) GROUP BY scan_id, severity");
        $st->execute($ids);
        foreach ($st->fetchAll() as $f) { $sevByScan[(int) $f['scan_id']][$f['severity']] = (int) $f['c']; }
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

// 수집 상태 배지 — 최신 수집 경과시간(분)으로 판정. 스캔이 없으면 null.
function vg_asset_state($ageMin): string {
    if ($ageMin === null) { return vg_badge('수집없음', 'muted'); }
    $m = (int) $ageMin;
    if ($m > VG_OFFLINE_MIN) { return vg_badge('오프라인', 'crit'); }
    if ($m > VG_STALE_MIN)   { return vg_badge('지연', 'high'); }
    return vg_badge('정상', 'ok');
}

// 에이전트가 POST 할 수집 엔드포인트(현재 접속 주소 기준).
$https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
       || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
$ingest = ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/ingest.php';

$csrf = vg_csrf_token();
vg_header('자산관리', 'assets');
?>
  <h1>자산관리</h1>
  <div class="sub">에이전트가 등록한 호스트 · 최신 수집 상태와 취약점 요약 · 총 <?= number_format($total) ?>대</div>

  <?php vg_alert($msg, 'ok'); vg_alert($err !== null ? '오류 · ' . $err : null); ?>

  <?php
  vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '호스트명 검색', 'value' => $q],
  ]);

  $headers = [
      ['label' => '호스트', 'key' => 'fqdn'],
      ['label' => '상태', 'key' => 'state'],
      ['label' => 'OS', 'key' => 'os'],
      ['label' => '에이전트', 'key' => 'agent_version'],
      ['label' => '패키지', 'key' => 'package_count', 'align' => 'right'],
      ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right'],
      ['label' => '심각도', 'key' => 'sev'],
      ['label' => '최신 수집', 'key' => 'collected_at'],
      ['label' => '스캔', 'key' => 'scan_count', 'align' => 'right'],
  ];
  if ($canDelete) { $headers[] = ['label' => '', 'key' => 'act', 'align' => 'right']; }

  vg_table(
      $headers,
      $rows,
      [
          'empty' => $q !== '' ? '검색 결과가 없습니다.' : '등록된 자산이 없습니다. 아래 안내대로 에이전트를 설치하세요.',
          'cell' => [
              'fqdn'  => fn($r) => '<strong><a href="/host.php?id=' . (int) $r['id'] . '">' . vg_h($r['fqdn']) . '</a></strong>',
              'state' => fn($r) => vg_asset_state($r['age_min']),
              'os'            => fn($r) => vg_h(trim($r['os_id'] . ' ' . $r['os_version'])) ?: '<span class="why">–</span>',
              'agent_version' => fn($r) => $r['agent_version'] ? '<code>' . vg_h($r['agent_version']) . '</code>' : '<span class="why">–</span>',
              'package_count' => fn($r) => $r['scan_id'] !== null ? number_format((int) $r['package_count']) : '<span class="why">–</span>',
              'exposure_count'=> fn($r) => $r['scan_id'] !== null ? number_format((int) $r['exposure_count']) : '<span class="why">–</span>',
              // 뱃지를 누르면 그 호스트·등급의 취약점 목록으로.
              'sev' => fn($r) => vg_sev_counts(
                  $sevByScan[(int) $r['scan_id']] ?? [],
                  fn(string $s) => '/findings.php?host=' . (int) $r['id'] . '&sev=' . $s
              ),
              'collected_at' => fn($r) => $r['collected_at'] ? '<span class="why">' . vg_h($r['collected_at']) . '</span>' : '<span class="why">–</span>',
              'scan_count'   => fn($r) => (int) $r['scan_count'] > 0
                  ? '<a href="/host.php?id=' . (int) $r['id'] . '#scans">' . number_format((int) $r['scan_count']) . '회</a>'
                  : '<span class="why">0회</span>',
              'act' => fn($r) => '<form method="post" class="actions" onsubmit="return confirm(\'' . vg_h($r['fqdn']) . ' 자산을 삭제할까요? 수집 이력은 남고 목록·집계에서만 제외됩니다.\');">'
                  . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                  . '<input type="hidden" name="id" value="' . (int) $r['id'] . '">'
                  . '<button type="submit" class="btn btn--sm btn--danger">삭제</button></form>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <div class="card">
    <strong>에이전트 설치</strong>
    <span class="why">— 자산은 에이전트가 수집을 보내면 자동 등록된다. 중앙에서 대상 서버로 접속하지 않는다(아웃바운드 push).</span>
    <div class="card__body">
      <div class="why">대상 서버(Linux)의 <code>/opt/vuln-agent/</code> 에 스크립트 2개를 두고 한 번 실행. 인자 없이 실행하면 주소·토큰·주기를 물어본다.</div>
      <pre class="code">sudo mkdir -p /opt/vuln-agent && sudo cp ~/agent/*.sh /opt/vuln-agent/
cd /opt/vuln-agent
sudo bash install-agent.sh
  중앙 서버 주소 (예: ost-server.duckdns.org:8080): <?= vg_h($ingest) ?>

  전송 토큰 (입력은 화면에 보이지 않습니다): ********
  수집 주기 [hourly] (daily / '*:0/30'=30분마다):</pre>
      <div class="why">
        · 수집 엔드포인트: <code><?= vg_h($ingest) ?></code> — 대상 서버 → 중앙 아웃바운드 1개면 충분<br>
        · <code>sudo</code> 만 있으면 된다. <code>chmod</code>/<code>chown</code> 은 필요 없다(<code>bash &lt;파일&gt;</code> 로 실행하므로)<br>
        · 토큰은 보안상 화면에 표시하지 않는다. 중앙 서버의 <code>secrets/ingest_token.txt</code> 에서 확인<br>
        · 제거: <code>sudo bash install-agent.sh --uninstall</code><br>
        · 상태 <?= vg_badge('정상', 'ok') ?> = <?= VG_STALE_MIN / 60 ?>시간 이내 수집,
          <?= vg_badge('지연', 'high') ?> = <?= VG_STALE_MIN / 60 ?>시간~<?= VG_OFFLINE_MIN / 1440 ?>일,
          <?= vg_badge('오프라인', 'crit') ?> = <?= VG_OFFLINE_MIN / 1440 ?>일 초과
      </div>
    </div>
  </div>
<?php vg_footer();
