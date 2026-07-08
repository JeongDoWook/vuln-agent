<?php
declare(strict_types=1);

/**
 * host.php — 호스트 상세 (로그인 필요).
 *   ?id=<host_id> 의 최신 스캔: 요약 KPI + 런타임 노출 + 우선순위 취약점(조치 포함).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();

$err = null; $host = null; $scan = null; $exposures = []; $processes = []; $findings = [];
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
try {
    $pdo = vg_pdo();
    $hostId = (int) ($_GET['id'] ?? 0);
    $st = $pdo->prepare('SELECT * FROM hosts WHERE id = ?');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    if ($host) {
        $st = $pdo->prepare('SELECT * FROM scans WHERE host_id = ? ORDER BY id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }
    if ($scan) {
        $sid = (int) $scan['id'];
        $st = $pdo->prepare('SELECT proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs FROM exposures WHERE scan_id = ? ORDER BY FIELD(scope,\'EXTERNAL\',\'BOUND\',\'LOCAL\',\'-\'), port');
        $st->execute([$sid]);
        $exposures = $st->fetchAll();

        // 실행 프로세스 (실행중/사용중)
        $st = $pdo->prepare('SELECT pid, comm, username, exe_pkg, loaded_pkgs FROM processes WHERE scan_id = ? ORDER BY comm LIMIT 200');
        $st->execute([$sid]);
        $processes = $st->fetchAll();

        // 심각도 카운트
        $st = $pdo->prepare('SELECT severity, COUNT(*) c FROM findings WHERE scan_id = ? GROUP BY severity');
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        // 상위 취약점(CRITICAL/HIGH) + 조치
        $st = $pdo->prepare(
            "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale, c.epss,
                (SELECT a.fixed_version FROM cve_affected_packages a
                 WHERE a.cve_id=f.cve_id AND a.package_name=f.package_name AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version
             FROM findings f LEFT JOIN cves c ON c.cve_id = f.cve_id
             WHERE f.scan_id = ? AND f.severity IN ('CRITICAL','HIGH')
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH'), c.epss DESC, f.cve_id"
        );
        $st->execute([$sid]);
        $findings = $st->fetchAll();
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

$scopeColor = ['EXTERNAL'=>'#da3633','BOUND'=>'#9e6a03','LOCAL'=>'#6e7681'];

vg_header($host['fqdn'] ?? '호스트', 'dashboard');
?>
<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php elseif (!$host): ?>
  <div class="card"><div class="empty">호스트를 찾을 수 없습니다. <a href="/">← 대시보드</a></div></div>
<?php else: ?>
  <h1>🖥️ <?= vg_h($host['fqdn']) ?></h1>
  <div class="sub">
    <a href="/">← 대시보드</a> ·
    <?= vg_h($host['os_id']) ?> <?= vg_h($host['os_version']) ?>
    <?php if ($scan): ?> · 최신 수집 <?= vg_h($scan['collected_at']) ?> · 패키지 <?= (int) $scan['package_count'] ?>개<?php endif; ?>
  </div>

  <?php if (!$scan): ?>
    <div class="card"><div class="empty">아직 수집된 스캔이 없습니다.</div></div>
  <?php else: ?>
    <div class="cards">
      <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
        <div class="kpi" style="background:<?= vg_sev_color($s) ?>;color:#fff;"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
      <?php endforeach; ?>
      <div class="kpi big"><b><?= count($exposures) ?></b><span>노출 소켓</span></div>
    </div>

    <div class="card">
      <strong>런타임 노출</strong> <span class="why">— 어떤 프로세스가 무슨 포트를 열고 어떤 라이브러리를 로드했나</span>
      <table style="margin-top:.6rem;">
        <thead><tr><th>범위</th><th>프로세스</th><th>포트</th><th>실행패키지</th><th>로드한 패키지</th></tr></thead>
        <tbody>
        <?php if (!$exposures): ?><tr><td colspan="5" class="why">리스닝 소켓 없음(외부 노출면 없음).</td></tr><?php endif; ?>
        <?php foreach ($exposures as $e): ?>
          <tr>
            <td><span class="badge" style="background:<?= $scopeColor[$e['scope']] ?? '#6e7681' ?>;"><?= vg_h($e['scope']) ?></span></td>
            <td><?= vg_h($e['proc']) ?></td>
            <td><?= vg_h($e['proto']) ?>/<?= (int) $e['port'] ?></td>
            <td><?= vg_h($e['exe_pkg']) ?></td>
            <td class="why"><?= vg_h(mb_strimwidth((string) $e['loaded_pkgs'], 0, 60, '…')) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <div class="card">
      <strong>실행 프로세스</strong> <span class="why">— 실행 중인 프로그램과 소속 패키지(=실행중), 로드한 라이브러리(=사용중)</span>
      <table style="margin-top:.6rem;">
        <thead><tr><th>PID</th><th>프로세스</th><th>사용자</th><th>실행 패키지</th><th>로드한 패키지</th></tr></thead>
        <tbody>
        <?php if (!$processes): ?><tr><td colspan="5" class="why">실행 프로세스 데이터 없음(구버전 에이전트로 수집됨).</td></tr><?php endif; ?>
        <?php foreach ($processes as $pr): ?>
          <tr>
            <td class="why"><?= (int) $pr['pid'] ?></td>
            <td><?= vg_h($pr['comm']) ?></td>
            <td class="why"><?= vg_h($pr['username']) ?></td>
            <td><?= vg_h($pr['exe_pkg']) ?></td>
            <td class="why"><?= vg_h(mb_strimwidth((string) $pr['loaded_pkgs'], 0, 60, '…')) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH)</strong>
      <span class="why">— <a href="/findings.php?scan_id=<?= (int) $scan['id'] ?>">전체 취약점 보기 →</a></span>
      <table style="margin-top:.6rem;">
        <thead><tr><th>등급</th><th>상태</th><th>CVE</th><th>EPSS</th><th>패키지</th><th>근거</th><th>조치</th></tr></thead>
        <tbody>
        <?php if (!$findings): ?><tr><td colspan="7" class="why">CRITICAL·HIGH 없음(외부노출된 취약점이 없음).</td></tr><?php endif; ?>
        <?php foreach ($findings as $f): ?>
          <tr>
            <td><span class="badge" style="background:<?= vg_sev_color($f['severity']) ?>;"><?= vg_h($f['severity']) ?></span></td>
            <td><span class="badge" style="background:<?= vg_status_color($f['runtime_status']) ?>;"><?= vg_h(vg_status_label($f['runtime_status'])) ?></span></td>
            <td><strong><?= vg_h($f['cve_id']) ?></strong></td>
            <td><?= $f['epss'] !== null ? vg_h(number_format((float) $f['epss'] * 100, 1)) . '%' : '-' ?></td>
            <td><?= vg_h($f['package_name']) ?> <span class="why"><?= vg_h($f['installed_version']) ?></span></td>
            <td class="why"><?= vg_h($f['rationale']) ?></td>
            <td class="why"><?= !empty($f['fixed_version']) ? '<span class="pill">' . vg_h($f['fixed_version']) . ' 이상</span>' : '패치 확인' ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
