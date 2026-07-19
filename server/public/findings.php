<?php
declare(strict_types=1);

/**
 * findings.php — 매처 판정 결과(우선순위 취약점). 로그인 필요.
 *   기본  : 전 호스트의 "각 호스트 최신 스캔" 을 통합해서 보여준다(호스트 컬럼 표시).
 *   ?host=N     : 그 호스트의 최신 스캔만.
 *   ?scan_id=N  : 특정 스캔 하나만(대시보드·호스트 상세에서 넘어오는 링크). 이때만 부제에 scan# 표시.
 *   검색(q)/등급(sev)/상태(st) 필터 + 페이지네이션.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';   // vg_distro_unsupported — 피드 미지원 배포판 경고
vg_require_menu('findings');

$unsupHosts = [];   // 취약점 0건이 "안전"이 아니라 "판정 불가"인 대상(호스트 + 컨테이너)

$sevOptions = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
$stOptions  = ['EXTERNAL', 'FILTERED', 'LISTENING', 'RUNNING', 'LOADED', 'INSTALLED'];

$err = null; $scan = null; $rows = []; $total = 0; $perPage = vg_perpage();
$scanIds = []; $hostOptions = [];
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];

$q   = trim((string) ($_GET['q'] ?? ''));
$sev = (string) ($_GET['sev'] ?? '');
$st  = (string) ($_GET['st'] ?? '');
$fx  = (string) ($_GET['fx'] ?? '');
if (!in_array($sev, $sevOptions, true)) { $sev = ''; }
if (!in_array($st, $stOptions, true)) { $st = ''; }
// 조치 가능성: '' 전체 / action 조치 가능 / nofix 조치 불가(벤더가 수정본을 안 냈다)
//              / restart 재시작·재부팅만 하면 됨(패치는 이미 됐다 — 자산 상세에서 넘어온다)
if (!in_array($fx, ['action', 'nofix', 'restart'], true)) { $fx = ''; }
$page   = vg_page();
$hostId = (int) ($_GET['host'] ?? 0);
$scanId = (int) ($_GET['scan_id'] ?? 0);

try {
    $pdo = vg_pdo();

    // 호스트별 최신 스캔 (삭제된 호스트 제외) — 통합 뷰의 대상 스캔 집합.
    $hosts = $pdo->query(
        'SELECT h.id AS host_id, h.fqdn, h.os_id, h.os_version, t.mid AS scan_id
           FROM tb_hosts h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn'
    )->fetchAll();
    foreach ($hosts as $h) {
        $hostOptions[(int) $h['host_id']] = (string) $h['fqdn'];
        // 피드가 지원하지 않는 배포판은 매칭 후보가 없어 0건으로 뜬다 → 목록에 모아 경고한다.
        $reason = vg_distro_unsupported($h['os_id'] ?? null, $h['os_version'] ?? null);
        if ($reason !== null) { $unsupHosts[] = $h['fqdn'] . ' (' . $reason . ')'; }
    }

    // 컨테이너도 같은 이유로 0건이 된다 — 특히 **패키지 DB 가 없는 이미지**(Calico 등)는
    //   rhel 로 잡혀 "미지원 배포판" 경고에도 안 걸린 채 조용히 0건으로 지나갔다(운영 실측 9개).
    $ctrs = $pdo->query(
        'SELECT h.fqdn, c.cid, c.os_id, c.os_version, c.manager, c.pkg_count
           FROM tb_containers c
           JOIN tb_scans s ON s.id = c.scan_id
           JOIN tb_hosts h ON h.id = s.host_id
           JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn, c.cid'
    )->fetchAll();
    foreach ($ctrs as $c) {
        $reason = vg_container_unjudgeable(
            $c['os_id'] ?? null, $c['os_version'] ?? null,
            $c['manager'] ?? null, (int) ($c['pkg_count'] ?? 0)
        );
        if ($reason !== null) {
            $unsupHosts[] = $c['fqdn'] . ' · 컨테이너 ' . $c['cid'] . ' (' . $reason . ')';
        }
    }

    if ($scanId > 0) {
        // 단일 스캔 모드 — 어느 호스트의 어느 시점인지 부제에 명시해야 한다.
        $stmt = $pdo->prepare(
            'SELECT s.id, s.collected_at, h.fqdn FROM tb_scans s JOIN tb_hosts h ON h.id = s.host_id WHERE s.id = ?'
        );
        $stmt->execute([$scanId]);
        $scan = $stmt->fetch() ?: null;
        if ($scan) { $scanIds = [(int) $scan['id']]; }
    } else {
        if (!isset($hostOptions[$hostId])) { $hostId = 0; }   // 없는 호스트면 전체로
        foreach ($hosts as $h) {
            if ($hostId === 0 || (int) $h['host_id'] === $hostId) { $scanIds[] = (int) $h['scan_id']; }
        }
    }

    if ($scanIds) {
        $in = implode(',', array_fill(0, count($scanIds), '?'));

        // KPI 는 필터 무관 — 대상 스캔 전체 기준
        $stmt = $pdo->prepare("SELECT severity, COUNT(*) c FROM tb_findings WHERE scan_id IN ($in) GROUP BY severity");
        $stmt->execute($scanIds);
        foreach ($stmt->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        // 필터 WHERE 조립 (COUNT 와 목록 쿼리에 동일하게 사용)
        $where  = "f.scan_id IN ($in)";
        $params = $scanIds;
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
        // 조치 가능성 필터 — 벤더가 수정본을 안 낸 CVE(no_fix)는 "지금 할 수 있는 일이 없는" 것이다.
        //   기본은 전부 보여주되 **조치 가능한 것을 위로 올린다**(아래 ORDER BY).
        //   섞어서 등급순으로만 세우면 조치 불가 수백 건이 고칠 수 있는 몇 건을 덮어버린다.
        if ($fx === 'action')  { $where .= ' AND f.no_fix = 0'; }
        if ($fx === 'nofix')   { $where .= ' AND f.no_fix = 1'; }
        // 재시작·재부팅만 하면 되는 것 — 자산 상세의 "전체 보기" 가 여기로 온다.
        if ($fx === 'restart') { $where .= ' AND f.needs_restart = 1'; }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_findings f WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();

        $offset = ($page - 1) * $perPage;

        $stmt = $pdo->prepare(
            "SELECT f.*, h.id AS host_id, h.fqdn, c.summary, c.epss, c.epss_percentile, c.ref_urls_json,
                    ctr.cid AS container_cid, ctr.image AS container_image,
                " . VG_FIXED_VERSION_SUBQ . "
             FROM tb_findings f
             JOIN tb_scans s ON s.id = f.scan_id
             JOIN tb_hosts h ON h.id = s.host_id
             LEFT JOIN tb_containers ctr ON ctr.id = f.container_id
             LEFT JOIN tb_cves c ON c.cve_id = f.cve_id
             WHERE $where
             ORDER BY f.no_fix ASC, FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cvss DESC, h.fqdn
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
  <h1>취약점 우선순위 <span class="hint">(매처 결과)</span></h1>
  <div class="sub">
    <?php if ($scan): ?>
      호스트 <strong><?= vg_h($scan['fqdn']) ?></strong> · scan #<?= (int) $scan['id'] ?> · <?= vg_h($scan['collected_at']) ?>
      · <a href="/findings.php">전체 호스트 보기 →</a>
    <?php elseif ($scanId > 0): ?>
      스캔 #<?= $scanId ?> 을(를) 찾을 수 없습니다. · <a href="/findings.php">전체 호스트 보기 →</a>
    <?php elseif ($hostId > 0): ?>
      호스트 <strong><?= vg_h($hostOptions[$hostId]) ?></strong> · 최신 스캔 기준
      · <a href="/findings.php">전체 호스트 보기 →</a>
    <?php elseif ($hostOptions): ?>
      전체 호스트 <?= count($hostOptions) ?>대 · 각 호스트의 최신 스캔 기준
    <?php else: ?>스캔 없음<?php endif; ?>
  </div>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php if ($unsupHosts): ?>
    <div class="alert alert--err">
      <strong>일부 대상은 취약점 매칭이 수행되지 않습니다</strong> — 피드가 모르는 배포판이거나,
      패키지 DB 가 없어 무엇이 깔렸는지 알 수 없습니다.
      이 대상들의 취약점 0건은 "안전함"이 아니라 <strong>"판정 불가"</strong>입니다.
      <ul class="hint-list">
        <?php foreach ($unsupHosts as $line): ?><li><?= vg_h($line) ?></li><?php endforeach; ?>
      </ul>
    </div>
  <?php endif; ?>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <a href="<?= vg_h(vg_qs(['sev' => $sev === $s ? '' : $s, 'page' => 1])) ?>"
         class="kpi tone-<?= vg_sev_tone($s) ?><?= $sev === $s ? ' is-selected' : '' ?>">
        <b><?= (int) $counts[$s] ?></b><span><?= $s ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  // 단일 스캔 모드에선 scan_id 를 유지하고, 통합 모드에선 호스트 선택 드롭다운을 준다.
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  vg_toolbar(array_merge($toolbar, [
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'sev', 'empty_label' => '전체 등급', 'selected' => $sev,
          'options' => array_combine($sevOptions, $sevOptions)],
      ['type' => 'select', 'name' => 'st', 'empty_label' => '전체 상태', 'selected' => $st,
          'options' => array_combine($stOptions, array_map('vg_status_label', $stOptions))],
      // 조치 가능성 — 벤더가 수정본을 안 낸 CVE 를 걸러 보거나, 그것만 모아 볼 수 있다.
      ['type' => 'select', 'name' => 'fx', 'empty_label' => '전체(조치 가능성)', 'selected' => $fx,
          'options' => ['action' => '조치 가능', 'nofix' => '조치 불가(벤더 미수정)',
                        'restart' => '재시작·재부팅만 하면 됨']],
  ]));

  // 컬럼 11개는 가로 스크롤을 만들어서, 정작 제일 중요한 "조치" 가 화면 밖으로 밀려났었다.
  // 값을 버리는 게 아니라 관련된 것끼리 한 칸에 쌓는다(패키지+버전, CVSS+EPSS+KEV).
  // 호스트 컬럼은 통합 모드에서만 — 단일 스캔 모드는 부제가 이미 호스트를 밝힌다.
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn']];
  $headers = array_merge($headers, [
      ['label' => '등급',  'key' => 'severity',       'width' => '6rem',  'nowrap' => true],
      ['label' => '상태',  'key' => 'runtime_status', 'width' => '7rem',  'nowrap' => true],
      ['label' => 'CVE',   'key' => 'cve_id',         'width' => '15rem', 'nowrap' => true],
      ['label' => '패키지', 'key' => 'package_name',  'width' => '13rem'],
      ['label' => '위험도', 'key' => 'risk',          'width' => '7rem',  'nowrap' => true],
      ['label' => '근거 (왜 위험한가)', 'key' => 'rationale'],
      ['label' => '조치',  'key' => 'fix',            'width' => '11rem'],
  ]);

  vg_table(
      $headers,
      $rows,
      [
          'empty' => [
              'icon'  => '🔍',
              'title' => '조건에 맞는 판정 결과가 없습니다.',
              'hint'  => '검색어·등급·상태 필터를 넓혀 보세요.',
          ],
          'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
          'cell' => [
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
              'severity'       => fn($r) => vg_sev_badge((string) $r['severity']),
              'runtime_status' => fn($r) => vg_status_badge($r['runtime_status']),
              // CVE — 링크 + KEV 뱃지(별도 컬럼이던 '✔' 를 여기로).
              // CVE 요약(summary)은 뺐다. 근거와 나란히 두면 긴 텍스트 컬럼이 둘이라
              // 표가 화면을 넘겨서 정작 제일 중요한 '조치' 가 밖으로 밀려난다.
              // 요약은 일반적인 CVE 설명이라 상세 페이지에 있고, 근거는 이 제품만의 판정 이유다.
              // 마우스를 올리면 title 로 요약을 볼 수 있게만 남긴다.
              'cve_id' => function ($r) {
                  $t = $r['summary'] ? ' title="' . vg_h($r['summary']) . '"' : '';
                  $html = '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '"' . $t . '>'
                        . vg_h($r['cve_id']) . '</a></strong>';
                  if ($r['in_kev']) { $html .= ' ' . vg_badge('KEV', 'crit', '악용이 확인된 취약점 — CISA KEV 등재'); }
                  // 벤더가 수정본을 내지 않은 CVE — 패치로는 못 고친다(완화·격리·제거가 답).
                  if (!empty($r['no_fix'])) {
                      $html .= ' ' . vg_badge('조치 불가', 'info',
                          '벤더가 수정본을 내지 않았다(미수정·수정 보류·수정 안 함) — 패치가 존재하지 않는다');
                  }
                  return $html;
              },
              // 패키지 — 이름 + 설치 버전(아래줄).
              //   컨테이너 안의 취약점은 호스트 것과 조치 방법이 다르다(이미지 재빌드) → 구분해 보여준다.
              //   이미지는 버전 옆에 붙인다(칸을 새로 만들면 표가 다시 가로로 넘친다).
              'package_name' => fn($r) => vg_h($r['package_name'])
                  . (!empty($r['container_cid']) ? ' ' . vg_badge('컨테이너 ' . $r['container_cid'], 'med') : '')
                  . '<div class="why"><code>' . vg_h($r['installed_version']) . '</code>'
                  . (!empty($r['container_image']) ? ' · ' . vg_h((string) $r['container_image']) : '')
                  . '</div>',
              // 위험도 — CVSS(얼마나 심한가) + EPSS(실제로 악용될 확률). 다른 걸 재므로 같이 본다.
              //   백분위("상위 N%")는 여기선 뺀다 — 좁은 칸에서 4줄로 접힌다. 상세 페이지에 있다.
              'risk' => function ($r) {
                  $cvss = $r['cvss'] !== null
                      ? 'CVSS <strong>' . vg_h((string) $r['cvss']) . '</strong>'
                      : '<span class="why">CVSS –</span>';
                  $epss = $r['epss'] !== null && $r['epss'] !== ''
                      ? 'EPSS ' . vg_h(number_format((float) $r['epss'] * 100, 1)) . '%'
                      : 'EPSS –';
                  return $cvss . '<div class="why">' . $epss . '</div>';
              },
              'rationale' => fn($r) => '<span class="why">' . vg_trunc($r['rationale'], 80) . '</span>',
              'fix'       => fn($r) => vg_fix_cell($r['fixed_version'] ?? null, $r['ref_urls_json'] ?? null),
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
