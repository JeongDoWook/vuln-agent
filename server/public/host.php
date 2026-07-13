<?php
declare(strict_types=1);

/**
 * host.php — 호스트 상세(자산 상세). 로그인 필요.
 *   ?id=<host_id> 의 최신 스캔을 하나의 자산 화면으로 보여준다.
 *   상단: 자산 식별 + 최고 위험도 히어로 + KPI.
 *   그 아래 섹션 탭(취약점 / 런타임 / 보안설정 / 억제 / 스캔이력) — 각 탭이 자기 데이터를
 *   서버 페이지네이션한다. ?tab= 이 활성 탭, ?page= 는 그 활성 탭에만 적용된다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';   // vg_distro_unsupported — 피드 미지원 배포판 경고
vg_require_menu('findings');

$err = null; $host = null; $scan = null; $scanAge = null;
$unsupContainers = [];   // 피드 미지원 배포판 컨테이너

// 재시작이 필요한 finding 중 **커널**인가 — 커널은 프로세스 재시작이 아니라 재부팅이 답이다.
function vg_needs_reboot(array $f): bool {
    return preg_match('/^(kernel|linux-image-|linux-headers-)/', (string) ($f['package_name'] ?? '')) === 1;
}
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$exposureCount = 0; $cceFail = 0; $suppressedCount = 0; $vulnTotal = 0; $scanTotal = 0;
$tab = 'vuln'; $page = 1; $perPage = vg_perpage(); $total = 0;
$rows = []; $exposures = []; $sevByScan = [];

try {
    $pdo = vg_pdo();
    $hostId = (int) ($_GET['id'] ?? 0);
    $st = $pdo->prepare('SELECT * FROM tb_hosts WHERE id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    if ($host) {
        $st = $pdo->prepare('SELECT *, TIMESTAMPDIFF(MINUTE, collected_at, NOW()) AS age_min
                               FROM tb_scans WHERE host_id = ? ORDER BY id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }

    if ($scan) {
        $sid = (int) $scan['id'];
        $scanAge = $scan['age_min'];

        // CVE 피드가 지원하지 않는 배포판의 컨테이너 — 이것들도 매칭이 0건이라 알려야 한다.
        $st = $pdo->prepare('SELECT cid, os_id, os_version FROM tb_containers WHERE scan_id = ?');
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $c) {
            $reason = vg_distro_unsupported($c['os_id'] ?? null, $c['os_version'] ?? null);
            if ($reason !== null) {
                $unsupContainers[] = ['cid' => (string) $c['cid'], 'reason' => $reason];
            }
        }

        // --- 히어로/KPI 집계 (탭과 무관한 값싼 COUNT) ---
        $st = $pdo->prepare('SELECT severity, COUNT(*) c FROM tb_findings WHERE scan_id = ? GROUP BY severity');
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_exposures WHERE scan_id = ?');
        $st->execute([$sid]); $exposureCount = (int) $st->fetchColumn();

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_findings WHERE scan_id = ? AND result = 'FAIL'");
        $st->execute([$sid]); $cceFail = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_suppressed_findings WHERE scan_id = ?');
        $st->execute([$sid]); $suppressedCount = (int) $st->fetchColumn();

        // 우선순위 취약점 = CRITICAL·HIGH + 재시작 필요(등급이 낮아도 숨기지 않는다).
        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_findings
                              WHERE scan_id = ? AND (severity IN ('CRITICAL','HIGH') OR needs_restart = 1)");
        $st->execute([$sid]); $vulnTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_scans WHERE host_id = ?');
        $st->execute([$hostId]); $scanTotal = (int) $st->fetchColumn();

        // --- 활성 탭 결정 (억제 탭은 건이 있을 때만 존재) ---
        $validTabs = ['vuln', 'runtime', 'cce'];
        if ($suppressedCount > 0) { $validTabs[] = 'suppressed'; }
        $validTabs[] = 'scans';
        $tab = (string) ($_GET['tab'] ?? 'vuln');
        if (!in_array($tab, $validTabs, true)) { $tab = 'vuln'; }

        $page   = max(1, (int) ($_GET['page'] ?? 1));
        $offset = ($page - 1) * $perPage;

        // --- 활성 탭 데이터만 조회(+페이지네이션) ---
        if ($tab === 'vuln') {
            // 재시작/재부팅 필요 건을 맨 위로 정렬한다. 이건 등급이 아니라 "놓치기 쉬움"의 문제다:
            //   노출도가 낮아 LOW 로 떨어지는 경우가 많은데, 정작 패치했다고 안심하는 바로 그
            //   항목이다. 등급순으로만 정렬하면 CVE 가 많은 호스트에선 페이지 뒤로 밀려 안 보인다
            //   (실측: 메인 DB 에서 커널 재부팅 건이 2페이지로 밀려 화면에서 사라졌다).
            $total = $vulnTotal;
            $st = $pdo->prepare(
                "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale,
                        f.needs_restart, c.epss, c.epss_percentile,
                    (SELECT a.fixed_version FROM tb_cve_affected_packages a
                     WHERE a.cve_id=f.cve_id AND a.package_name=f.package_name AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version
                 FROM tb_findings f LEFT JOIN tb_cves c ON c.cve_id = f.cve_id
                 WHERE f.scan_id = ? AND (f.severity IN ('CRITICAL','HIGH') OR f.needs_restart = 1)
                 ORDER BY f.needs_restart DESC,
                          FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id
                 LIMIT $perPage OFFSET $offset"
            );
            $st->execute([$sid]);
            $rows = $st->fetchAll();
        } elseif ($tab === 'runtime') {
            // 노출은 보통 소량이라 전부 보여주고, 프로세스는 많을 수 있어 페이지네이션한다
            // (이 탭의 ?page= 는 프로세스 표에 적용된다).
            $st = $pdo->prepare('SELECT proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs FROM tb_exposures WHERE scan_id = ?
                                  ORDER BY FIELD(scope,\'EXTERNAL\',\'BOUND\',\'FILTERED\',\'LOCAL\',\'-\'), port');
            $st->execute([$sid]);
            $exposures = $st->fetchAll();

            $total = $pdo->prepare('SELECT COUNT(*) FROM tb_processes WHERE scan_id = ?');
            $total->execute([$sid]); $total = (int) $total->fetchColumn();
            $st = $pdo->prepare("SELECT pid, comm, username, exe_pkg, loaded_pkgs FROM tb_processes
                                  WHERE scan_id = ? ORDER BY comm LIMIT $perPage OFFSET $offset");
            $st->execute([$sid]);
            $rows = $st->fetchAll();
        } elseif ($tab === 'cce') {
            $st = $pdo->prepare('SELECT COUNT(*) FROM tb_cce_findings WHERE scan_id = ?');
            $st->execute([$sid]); $total = (int) $st->fetchColumn();
            $st = $pdo->prepare(
                "SELECT code, title, result, severity, evidence, rationale
                   FROM tb_cce_findings WHERE scan_id = ?
                  ORDER BY FIELD(result,'FAIL','NA','PASS'), FIELD(severity,'HIGH','MEDIUM','LOW'), code
                  LIMIT $perPage OFFSET $offset"
            );
            $st->execute([$sid]);
            $rows = $st->fetchAll();
        } elseif ($tab === 'suppressed') {
            $total = $suppressedCount;
            $st = $pdo->prepare(
                "SELECT cve_id, package_name, installed_version, base_severity, in_kev, suppress_reason
                   FROM tb_suppressed_findings WHERE scan_id = ?
                  ORDER BY FIELD(base_severity,'CRITICAL','HIGH','MEDIUM','LOW'), cve_id
                  LIMIT $perPage OFFSET $offset"
            );
            $st->execute([$sid]);
            $rows = $st->fetchAll();
        } else { // scans
            $total = $scanTotal;
            $st = $pdo->prepare(
                "SELECT id, collected_at, received_at, package_count, exposure_count, agent_version
                   FROM tb_scans WHERE host_id = ? ORDER BY id DESC LIMIT $perPage OFFSET $offset"
            );
            $st->execute([$hostId]);
            $rows = $st->fetchAll();

            $ids = [];
            foreach ($rows as $s) { $ids[] = (int) $s['id']; }
            if ($ids) {
                $in = implode(',', array_fill(0, count($ids), '?'));
                $st = $pdo->prepare("SELECT scan_id, severity, COUNT(*) c FROM tb_findings WHERE scan_id IN ($in) GROUP BY scan_id, severity");
                $st->execute($ids);
                foreach ($st->fetchAll() as $f) { $sevByScan[(int) $f['scan_id']][$f['severity']] = (int) $f['c']; }
            }
        }
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

// 노출 범위 → 뱃지 톤(색은 CSS 가 결정).
//   FILTERED = 전체 인터페이스에 떠 있지만 방화벽이 막아 외부에서 못 닿는 포트.
$scopeTone = ['EXTERNAL' => 'crit', 'BOUND' => 'med', 'FILTERED' => 'muted', 'LOCAL' => 'muted'];

vg_header($host['fqdn'] ?? '호스트', 'dashboard');
?>
<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif (!$host): ?>
  <div class="card"><div class="empty">호스트를 찾을 수 없습니다. <a href="/">← 대시보드</a></div></div>
<?php elseif (!$scan): ?>
  <h1>🖥️ <?= vg_h($host['fqdn']) ?></h1>
  <div class="sub">
    <a href="/">← 대시보드</a> ·
    <?php if (vg_can('assets')): ?><a href="/assets.php">자산관리</a> · <?php endif; ?>
    <?= vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?>
  </div>
  <div class="card"><div class="empty">아직 수집된 스캔이 없습니다.</div></div>
<?php else:
    // 최고 위험도 → 히어로 톤. 하나도 없으면 '양호'(ok).
    $worst = null;
    foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s) { if ($counts[$s] > 0) { $worst = $s; break; } }
    $heroTone = $worst ? vg_sev_tone($worst) : 'ok';

    // 탭 정의(배열 순서 = 표시 순서). n 은 라벨 옆 숫자(null 이면 숨김).
    $tabDefs = [
        'vuln'    => ['label' => '취약점',    'n' => $vulnTotal],
        'runtime' => ['label' => '런타임',    'n' => null],
        'cce'     => ['label' => '보안 설정', 'n' => $cceFail],
    ];
    if ($suppressedCount > 0) { $tabDefs['suppressed'] = ['label' => '억제', 'n' => $suppressedCount]; }
    $tabDefs['scans'] = ['label' => '스캔 이력', 'n' => $scanTotal];
?>
  <?php
  $meta = [
      vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?: 'OS 미상',
      vg_asset_state($scanAge),
      '최신 수집 ' . vg_h($scan['collected_at']),
      '패키지 ' . number_format((int) $scan['package_count']) . '개',
      '<a href="/">대시보드</a>',
  ];
  if (vg_can('assets')) { $meta[] = '<a href="/assets.php">자산관리</a>'; }
  vg_hero('🖥️ ' . vg_h($host['fqdn']), $meta, $worst ?? '양호', $heroTone);

  // CVE 피드가 지원하지 않는 배포판이면 매칭 후보가 아예 없어 **취약점이 0건으로 뜬다.**
  //   운영자는 "안전하다"고 읽는다 — 침묵하는 미탐이라 반드시 화면에 알린다.
  $unsup = [];
  $u = vg_distro_unsupported($host['os_id'] ?? null, $host['os_version'] ?? null);
  if ($u !== null) { $unsup[] = '이 호스트 — ' . $u; }
  foreach ($unsupContainers as $c) {
      $unsup[] = '컨테이너 ' . $c['cid'] . ' — ' . $c['reason'];
  }
  if ($unsup) {
      echo '<div class="alert alert--err"><strong>취약점 매칭이 수행되지 않습니다</strong> — '
         . '아래 대상은 CVE 피드(OSV)가 지원하지 않는 배포판입니다. '
         . '취약점 0건은 "안전함"이 아니라 <strong>"판정 불가"</strong>입니다.<ul class="hint-list">';
      foreach ($unsup as $line) { echo '<li>' . vg_h($line) . '</li>'; }
      echo '</ul></div>';
  }
  ?>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
    <div class="kpi"><b><?= number_format($exposureCount) ?></b><span>노출 소켓</span></div>
    <div class="kpi tone-<?= $cceFail > 0 ? 'high' : 'ok' ?>"><b><?= (int) $cceFail ?></b><span>설정 취약</span></div>
    <?php if ($suppressedCount > 0): ?><div class="kpi tone-muted"><b><?= number_format($suppressedCount) ?></b><span>백포트 억제</span></div><?php endif; ?>
  </div>

  <?php vg_subtabs($tabDefs, $tab); ?>

  <?php if ($tab === 'vuln'): ?>
    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH + 재시작 필요)</strong>
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
          $rows,
          [
              'card' => false,
              'empty' => 'CRITICAL·HIGH 없음(외부노출된 취약점이 없음).',
              'row_class' => fn($f) => vg_sev_row((string) $f['severity']),
              'cell' => [
                  'severity'       => fn($f) => vg_sev_badge((string) $f['severity']),
                  'runtime_status' => fn($f) => vg_status_badge($f['runtime_status']),
                  2 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode($f['cve_id']) . '">' . vg_h($f['cve_id']) . '</a></strong>',
                  3 => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
                  // 커널은 재부팅해야 새 코드가 올라온다 — 프로세스 재시작으로는 안 고쳐진다.
                  4 => fn($f) => vg_h($f['package_name']) . ' <span class="why">' . vg_h($f['installed_version']) . '</span>'
                                 . (!empty($f['needs_restart'])
                                    ? ' ' . vg_badge(vg_needs_reboot($f) ? '재부팅 필요' : '재시작 필요', 'high')
                                    : ''),
                  5 => fn($f) => '<span class="why">' . vg_trunc($f['rationale']) . '</span>',
                  // 재시작/재부팅이 필요하면 조치는 "업그레이드"가 아니다(이미 패치돼 있다).
                  6 => fn($f) => !empty($f['needs_restart'])
                                 ? '<span class="pill">' . (vg_needs_reboot($f) ? '재부팅' : '프로세스 재시작') . '</span>'
                                 : (!empty($f['fixed_version']) ? '<span class="pill">' . vg_h($f['fixed_version']) . ' 이상</span>' : '<span class="why">패치 확인</span>'),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'runtime'): ?>
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
          $rows,
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
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'cce'): ?>
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
          $rows,
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
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'suppressed'): ?>
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
          $rows,
          [
              'card' => false,
              'empty' => '억제된 취약점 없음.',
              'row_class' => fn($r) => vg_sev_row((string) $r['base_severity']),
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
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php else: /* scans */ ?>
    <div class="card">
      <strong>스캔 이력</strong> <span class="why">— 회차를 눌러 그 시점의 취약점을 본다</span>
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
          $rows,
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
    <?php vg_page_nav($total, $perPage, $page); ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
