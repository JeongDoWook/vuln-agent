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
    $st = $pdo->prepare('SELECT * FROM tb_hosts WHERE id = ?');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    if ($host) {
        $st = $pdo->prepare('SELECT * FROM tb_scans WHERE host_id = ? ORDER BY id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }
    if ($scan) {
        $sid = (int) $scan['id'];
        $st = $pdo->prepare('SELECT proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs FROM tb_exposures WHERE scan_id = ? ORDER BY FIELD(scope,\'EXTERNAL\',\'BOUND\',\'LOCAL\',\'-\'), port');
        $st->execute([$sid]);
        $exposures = $st->fetchAll();

        // 실행 프로세스 (실행중/사용중)
        $st = $pdo->prepare('SELECT pid, comm, username, exe_pkg, loaded_pkgs FROM tb_processes WHERE scan_id = ? ORDER BY comm LIMIT 200');
        $st->execute([$sid]);
        $processes = $st->fetchAll();

        // 심각도 카운트
        $st = $pdo->prepare('SELECT severity, COUNT(*) c FROM tb_findings WHERE scan_id = ? GROUP BY severity');
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        // 상위 취약점(CRITICAL/HIGH) + 조치
        $st = $pdo->prepare(
            "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale, c.epss,
                (SELECT a.fixed_version FROM tb_cve_affected_packages a
                 WHERE a.cve_id=f.cve_id AND a.package_name=f.package_name AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version
             FROM tb_findings f LEFT JOIN tb_cves c ON c.cve_id = f.cve_id
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
      <div style="margin-top:.6rem;">
      <?php
      vg_table(
          [
              ['label' => '범위'],
              ['label' => '프로세스', 'key' => 'proc'],
              ['label' => '포트'],
              ['label' => '실행패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $exposures,
          [
              'card' => false,
              'empty' => '리스닝 소켓 없음(외부 노출면 없음).',
              'cell' => [
                  0 => fn($e) => '<span class="badge" style="background:' . ($scopeColor[$e['scope']] ?? '#6e7681') . ';">' . vg_h($e['scope']) . '</span>',
                  2 => fn($e) => vg_h($e['proto']) . '/' . (int) $e['port'],
                  4 => fn($e) => '<span class="why">' . vg_trunc($e['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>

    <div class="card">
      <strong>실행 프로세스</strong> <span class="why">— 실행 중인 프로그램과 소속 패키지(=실행중), 로드한 라이브러리(=사용중)</span>
      <div style="margin-top:.6rem;">
      <?php
      vg_table(
          [
              ['label' => 'PID'],
              ['label' => '프로세스', 'key' => 'comm'],
              ['label' => '사용자'],
              ['label' => '실행 패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $processes,
          [
              'card' => false,
              'empty' => '실행 프로세스 데이터 없음(구버전 에이전트로 수집됨).',
              'cell' => [
                  0 => fn($pr) => '<span class="why">' . (int) $pr['pid'] . '</span>',
                  2 => fn($pr) => '<span class="why">' . vg_h($pr['username']) . '</span>',
                  4 => fn($pr) => '<span class="why">' . vg_trunc($pr['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>

    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH)</strong>
      <span class="why">— <a href="/findings.php?scan_id=<?= (int) $scan['id'] ?>">전체 취약점 보기 →</a></span>
      <div style="margin-top:.6rem;">
      <?php
      vg_table(
          [
              ['label' => '등급', 'key' => 'severity'],
              ['label' => '상태', 'key' => 'runtime_status'],
              ['label' => 'CVE'],
              ['label' => 'EPSS'],
              ['label' => '패키지'],
              ['label' => '근거'],
              ['label' => '조치'],
          ],
          $findings,
          [
              'card' => false,
              'empty' => 'CRITICAL·HIGH 없음(외부노출된 취약점이 없음).',
              'cell' => [
                  'severity'       => fn($f) => '<span class="badge" style="background:' . vg_sev_color($f['severity']) . ';">' . vg_h($f['severity']) . '</span>',
                  'runtime_status' => fn($f) => '<span class="badge" style="background:' . vg_status_color($f['runtime_status']) . ';">' . vg_h(vg_status_label($f['runtime_status'])) . '</span>',
                  2 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode($f['cve_id']) . '">' . vg_h($f['cve_id']) . '</a></strong>',
                  3 => fn($f) => $f['epss'] !== null ? vg_h(number_format((float) $f['epss'] * 100, 1)) . '%' : '-',
                  4 => fn($f) => vg_h($f['package_name']) . ' <span class="why">' . vg_h($f['installed_version']) . '</span>',
                  5 => fn($f) => '<span class="why">' . vg_trunc($f['rationale']) . '</span>',
                  6 => fn($f) => !empty($f['fixed_version']) ? '<span class="pill">' . vg_h($f['fixed_version']) . ' 이상</span>' : '<span class="why">패치 확인</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
