<?php
declare(strict_types=1);

/**
 * host.php — 호스트 상세 (로그인 필요).
 *   ?id=<host_id> 의 최신 스캔: 요약 KPI + 런타임 노출 + 우선순위 취약점(조치 포함).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

$err = null; $host = null; $scan = null; $exposures = []; $processes = []; $findings = [];
$cce = []; $cceFail = 0; $suppressed = [];
$scans = []; $sevByScan = [];
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
try {
    $pdo = vg_pdo();
    $hostId = (int) ($_GET['id'] ?? 0);
    $st = $pdo->prepare('SELECT * FROM tb_hosts WHERE id = ? AND is_deleted = 0');
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

        // 보안설정 점검(CCE) — FAIL 먼저, 위험도순. NA/PASS 는 뒤로.
        $st = $pdo->prepare(
            "SELECT code, title, result, severity, evidence, rationale
               FROM tb_cce_findings WHERE scan_id = ?
              ORDER BY FIELD(result,'FAIL','NA','PASS'), FIELD(severity,'HIGH','MEDIUM','LOW'), code"
        );
        $st->execute([$sid]);
        $cce = $st->fetchAll();
        foreach ($cce as $c) { if ($c['result'] === 'FAIL') { $cceFail++; } }

        // 상위 취약점(CRITICAL/HIGH) + 조치
        $st = $pdo->prepare(
            "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale, c.epss, c.epss_percentile,
                (SELECT a.fixed_version FROM tb_cve_affected_packages a
                 WHERE a.cve_id=f.cve_id AND a.package_name=f.package_name AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version
             FROM tb_findings f LEFT JOIN tb_cves c ON c.cve_id = f.cve_id
             WHERE f.scan_id = ? AND f.severity IN ('CRITICAL','HIGH')
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH'), c.epss DESC, f.cve_id"
        );
        $st->execute([$sid]);
        $findings = $st->fetchAll();

        // 백포트로 억제된 취약점 (오탐 제거의 근거를 투명하게 보여줌)
        $st = $pdo->prepare(
            "SELECT cve_id, package_name, installed_version, base_severity, in_kev, suppress_reason
               FROM tb_suppressed_findings WHERE scan_id = ?
              ORDER BY FIELD(base_severity,'CRITICAL','HIGH','MEDIUM','LOW'), cve_id"
        );
        $st->execute([$sid]);
        $suppressed = $st->fetchAll();

        // 스캔 이력(최근 20회) + 회차별 심각도 카운트
        $st = $pdo->prepare(
            'SELECT id, collected_at, received_at, package_count, exposure_count, agent_version
               FROM tb_scans WHERE host_id = ? ORDER BY id DESC LIMIT 20'
        );
        $st->execute([$hostId]);
        $scans = $st->fetchAll();

        $ids = [];
        foreach ($scans as $s) { $ids[] = (int) $s['id']; }
        if ($ids) {
            $in = implode(',', array_fill(0, count($ids), '?'));
            $st = $pdo->prepare("SELECT scan_id, severity, COUNT(*) c FROM tb_findings WHERE scan_id IN ($in) GROUP BY scan_id, severity");
            $st->execute($ids);
            foreach ($st->fetchAll() as $f) { $sevByScan[(int) $f['scan_id']][$f['severity']] = (int) $f['c']; }
        }
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

// 노출 범위 → 뱃지 톤(색은 CSS 가 결정).
$scopeTone = ['EXTERNAL' => 'crit', 'BOUND' => 'med', 'LOCAL' => 'muted'];

vg_header($host['fqdn'] ?? '호스트', 'dashboard');
?>
<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif (!$host): ?>
  <div class="card"><div class="empty">호스트를 찾을 수 없습니다. <a href="/">← 대시보드</a></div></div>
<?php else: ?>
  <h1>🖥️ <?= vg_h($host['fqdn']) ?></h1>
  <div class="sub">
    <a href="/">← 대시보드</a> ·
    <?php if (vg_can('assets')): ?><a href="/assets.php">자산관리</a> · <?php endif; ?>
    <?= vg_h($host['os_id']) ?> <?= vg_h($host['os_version']) ?>
    <?php if ($scan): ?> · 최신 수집 <?= vg_h($scan['collected_at']) ?> · 패키지 <?= (int) $scan['package_count'] ?>개<?php endif; ?>
  </div>

  <?php if (!$scan): ?>
    <div class="card"><div class="empty">아직 수집된 스캔이 없습니다.</div></div>
  <?php else: ?>
    <div class="cards">
      <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
        <div class="kpi tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
      <?php endforeach; ?>
      <div class="kpi big"><b><?= count($exposures) ?></b><span>노출 소켓</span></div>
      <div class="kpi tone-<?= $cceFail > 0 ? 'high' : 'low' ?>"><b><?= (int) $cceFail ?></b><span>설정 취약</span></div>
      <?php if ($suppressed): ?><div class="kpi tone-muted"><b><?= count($suppressed) ?></b><span>백포트 억제</span></div><?php endif; ?>
    </div>

    <div class="card">
      <strong>런타임 노출</strong> <span class="why">— 어떤 프로세스가 무슨 포트를 열고 어떤 라이브러리를 로드했나</span>
      <div class="card__body">
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
                  0 => fn($e) => vg_badge((string) $e['scope'], $scopeTone[$e['scope']] ?? 'muted'),
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
      <div class="card__body">
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
      <strong>보안 설정 점검 (CCE)</strong>
      <span class="why">— 취약한 버전(CVE)이 아니라 잘못된 설정을 본다. NA 는 수집 못한 항목(비-root 실행 등)</span>
      <div class="card__body">
      <?php
      // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted.
      $cceBadge = function (array $r): string {
          $tone = $r['result'] === 'FAIL' ? vg_sev_tone($r['severity'])
                : ($r['result'] === 'PASS' ? 'low' : 'muted');
          return vg_badge($r['result'], $tone);
      };
      vg_table(
          [
              ['label' => '결과', 'key' => 'result'],
              ['label' => '점검 항목', 'key' => 'title'],
              ['label' => '코드', 'key' => 'code'],
              ['label' => '근거'],
              ['label' => '사유'],
          ],
          $cce,
          [
              'card' => false,
              'empty' => 'CCE 점검 데이터 없음(구버전 에이전트 또는 security/users 미수집).',
              'cell' => [
                  'result' => $cceBadge,
                  'code'   => fn($r) => '<code>' . vg_h($r['code']) . '</code>',
                  3 => fn($r) => '<span class="why">' . vg_trunc($r['evidence'], 40) . '</span>',
                  4 => fn($r) => '<span class="why">' . vg_trunc($r['rationale']) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>

    <?php if ($suppressed): ?>
    <div class="card">
      <strong>백포트로 억제된 취약점</strong>
      <span class="why">— 버전상 취약해 보였으나 배포판 changelog에 수정 기록(백포트)이 있어 실제 위험에서 제외한 건. 오탐 제거의 근거</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '원래등급', 'key' => 'base_severity'],
              ['label' => 'CVE'],
              ['label' => '패키지'],
              ['label' => '억제 근거'],
          ],
          $suppressed,
          [
              'card' => false,
              'empty' => '억제된 취약점 없음.',
              'cell' => [
                  'base_severity' => fn($r) => vg_sev_badge((string) $r['base_severity'])
                      . ((int) $r['in_kev'] === 1 ? ' ' . vg_badge('KEV', 'crit') : ''),
                  1 => fn($r) => '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a></strong>',
                  2 => fn($r) => vg_h($r['package_name']) . ' <span class="why">' . vg_h($r['installed_version']) . '</span>',
                  3 => fn($r) => '<span class="why">' . vg_trunc($r['suppress_reason'], 90) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php endif; ?>

    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH)</strong>
      <span class="why">— <a href="/findings.php?scan_id=<?= (int) $scan['id'] ?>">전체 취약점 보기 →</a></span>
      <div class="card__body">
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
                  'severity'       => fn($f) => vg_sev_badge((string) $f['severity']),
                  'runtime_status' => fn($f) => vg_status_badge($f['runtime_status']),
                  2 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode($f['cve_id']) . '">' . vg_h($f['cve_id']) . '</a></strong>',
                  3 => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
                  4 => fn($f) => vg_h($f['package_name']) . ' <span class="why">' . vg_h($f['installed_version']) . '</span>',
                  5 => fn($f) => '<span class="why">' . vg_trunc($f['rationale']) . '</span>',
                  6 => fn($f) => !empty($f['fixed_version']) ? '<span class="pill">' . vg_h($f['fixed_version']) . ' 이상</span>' : '<span class="why">패치 확인</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>

    <div class="card" id="scans">
      <strong>스캔 이력</strong> <span class="why">— 최근 20회. 회차를 눌러 그 시점의 취약점을 본다</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '스캔', 'key' => 'id'],
              ['label' => '수집시각', 'key' => 'collected_at'],
              ['label' => '수신시각', 'key' => 'received_at'],
              ['label' => '패키지', 'key' => 'package_count', 'align' => 'right'],
              ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right'],
              ['label' => '에이전트', 'key' => 'agent_version'],
              ['label' => '심각도', 'key' => 'sev'],
          ],
          $scans,
          [
              'card' => false,
              'empty' => '스캔 이력이 없습니다.',
              'cell' => [
                  'id'             => fn($s) => '<a href="/findings.php?scan_id=' . (int) $s['id'] . '">#' . (int) $s['id'] . '</a>',
                  'collected_at'   => fn($s) => vg_h($s['collected_at']),
                  'received_at'    => fn($s) => '<span class="why">' . vg_h($s['received_at']) . '</span>',
                  'package_count'  => fn($s) => number_format((int) $s['package_count']),
                  'exposure_count' => fn($s) => number_format((int) $s['exposure_count']),
                  'agent_version'  => fn($s) => $s['agent_version'] ? '<code>' . vg_h($s['agent_version']) . '</code>' : '<span class="why">–</span>',
                  'sev' => fn($s) => vg_sev_counts($sevByScan[(int) $s['id']] ?? []),
              ],
          ]
      );
      ?>
      </div>
    </div>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
