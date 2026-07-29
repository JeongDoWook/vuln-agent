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

// 수집 지연 판정 기준(VG_STALE_MIN/VG_OFFLINE_MIN)과 vg_asset_state() 는 format.php 에 있다
// (호스트 상세 히어로와 공유).

$canDelete = vg_has_role('admin', 'operator');

$err = null; $msg = null; $rows = []; $total = 0; $sevByScan = [];
$stateCounts = ['ok' => 0, 'stale' => 0, 'offline' => 0, 'none' => 0];
$q     = trim((string) ($_GET['q'] ?? ''));
$state = trim((string) ($_GET['state'] ?? ''));
$page  = vg_page();
$perPage = vg_perpage();

// 수집 상태 어휘. vg_asset_state() 가 뱃지를 그리는 기준(VG_STALE_MIN/VG_OFFLINE_MIN)과 같아야 한다.
const VG_ASSET_STATES = ['ok' => '정상', 'stale' => '지연', 'offline' => '오프라인', 'none' => '수집없음'];
if (!isset(VG_ASSET_STATES[$state])) { $state = ''; }

/* 호스트 한 대의 수집 상태를 SQL 안에서 판정하는 식.
 * 목록 필터·KPI 집계가 같은 식을 써야 "지연 3대" 를 눌렀을 때 3대가 나온다. */
$stateExpr =
    "CASE WHEN s.scan_id IS NULL THEN 'none'
          WHEN TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) > " . VG_OFFLINE_MIN . " THEN 'offline'
          WHEN TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) > " . VG_STALE_MIN . " THEN 'stale'
          ELSE 'ok' END";

// 호스트 + 최신 스캔. LEFT JOIN 이라 등록만 되고 아직 수집이 없는 호스트도 남는다.
$fromSql = 'FROM tb_host h
            LEFT JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
            LEFT JOIN tb_scan s ON s.scan_id = t.mid';

$pdo = vg_pdo();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } elseif (!$canDelete) {
        $err = '자산을 삭제할 권한이 없습니다.';
    } else {
        try {
            $id = (int) ($_POST['id'] ?? 0);
            $st = $pdo->prepare('SELECT fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
            $st->execute([$id]);
            $fqdn = $st->fetchColumn();
            if ($fqdn === false) {
                $err = '호스트를 찾을 수 없습니다.';
            } else {
                vg_soft_delete($pdo, 'tb_host', $id);
                vg_log_activity($pdo, 'HOST', $id, 'host_delete', "자산 삭제: $fqdn");
                $msg = "자산 '$fqdn' 을(를) 삭제했습니다. 해당 호스트가 다시 수집을 보내면 재등록됩니다.";
            }
        } catch (Throwable $e) {
            error_log('[assets] delete ' . $e->getMessage());
            $err = '삭제 실패: 처리 중 오류가 발생했습니다.';
        }
    }
}

try {
    // KPI — 검색어·상태 필터와 무관하게 전체 기준(필터를 걸어도 전체 그림은 유지된다).
    $kpi = $pdo->query("SELECT $stateExpr AS st, COUNT(*) c $fromSql WHERE h.is_deleted = 0 GROUP BY st")->fetchAll();
    foreach ($kpi as $k) {
        if (isset($stateCounts[$k['st']])) { $stateCounts[$k['st']] = (int) $k['c']; }
    }

    $where  = 'h.is_deleted = 0';
    $params = [];
    if ($q !== '') {
        $where .= ' AND h.fqdn LIKE ?';
        $params[] = '%' . $q . '%';
    }
    if ($state !== '') {
        // KPI 와 같은 식을 쓴다 — 다른 식을 쓰면 "지연 3대" 를 눌렀는데 2대가 나오는 일이 생긴다.
        $where .= " AND $stateExpr = ?";
        $params[] = $state;
    }

    // COUNT 도 목록과 같은 FROM 을 써야 한다. 상태 필터가 최신 스캔(s)을 참조하기 때문이다.
    $st = $pdo->prepare("SELECT COUNT(*) $fromSql WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $st = $pdo->prepare(
        "SELECT h.host_id, h.fqdn, h.os_id, h.os_version, h.first_seen,
                s.scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                s.schedule, s.peak_rss_mb, s.cpu_seconds,
                TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) AS age_min,
                (SELECT COUNT(*) FROM tb_scan x WHERE x.host_id = h.host_id) AS scan_count
           $fromSql
          WHERE $where
          ORDER BY h.fqdn
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    // 이 페이지에 보이는 최신 스캔들의 심각도 카운트
    $ids = [];
    foreach ($rows as $r) { if ($r['scan_id'] !== null) { $ids[] = (int) $r['scan_id']; } }
    $sevByScan = vg_sev_by_scan_ids($pdo, $ids);

    // 함대에서 가장 높은 에이전트 버전 — 이보다 낮은 호스트는 옛 에이전트가 돌고 있다.
    //   중앙은 노드에 아무것도 내려보내지 않으므로(노드가 밀어 올리기만 한다) 에이전트를 고쳐도
    //   **각 노드에 다시 깔 때까지 옛 코드가 계속 돈다.** 실제로 master 가 2.1 로 몇 주를 돌았는데
    //   화면에 숫자만 있고 "이게 구버전" 이라는 신호가 없어 아무도 못 알아챘다.
    //   기준을 코드에 박지 않고 **관측된 최댓값**으로 잡는다 — 웹 컨테이너는 agent/ 를 마운트하지
    //   않으므로 저장소의 버전을 읽을 수 없고, 박아 두면 배포 때마다 두 곳을 고쳐야 한다.
    //   (버전은 '2.10' > '2.9' 라 문자열 비교로는 틀린다 → version_compare)
    $seen = $pdo->query(
        "SELECT DISTINCT agent_version FROM tb_scan
          WHERE agent_version IS NOT NULL AND agent_version <> '' AND is_deleted = 0"
    )->fetchAll(PDO::FETCH_COLUMN);
    $latestAgent = (string) array_reduce(
        $seen,
        static fn(?string $max, string $v) => ($max === null || version_compare($v, $max, '>')) ? $v : $max
    );
} catch (Throwable $e) {
    error_log('[assets] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

// 에이전트가 POST 할 수집 엔드포인트(현재 접속 주소 기준).
$https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
       || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
$ingest = ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/ingest.php';

$csrf = vg_csrf_token();
vg_header('자산관리', 'assets');
?>
  <?php
  // 상태 판정 기준은 본문에 늘어놓지 않고 툴팁으로 — 한 번 읽으면 그만인 정보다.
  $stateHelp = sprintf(
      '정상 = %d시간 이내 수집 · 지연 = %d시간~%d일 · 오프라인 = %d일 초과 · 수집없음 = 등록만 되고 스캔이 아직 없음',
      VG_STALE_MIN / 60, VG_STALE_MIN / 60, VG_OFFLINE_MIN / 1440, VG_OFFLINE_MIN / 1440
  );
  ?>
  <?php vg_page_title('자산 관리', 'ASSETS', '수집 상태와 운영 위험을 기준으로 관리 대상을 찾습니다.', [
      'suffix_html' => vg_help($stateHelp),
      'actions' => vg_capture(static fn() => vg_modal_btn('agentInstall', '에이전트 설치 안내', 'btn btn--sm btn--ghost')),
  ]); ?>
  <div class="sub">에이전트가 등록한 호스트 · 최신 수집 상태와 취약점 요약</div>

  <?php vg_alert($msg, 'ok'); vg_alert($err !== null ? '오류 · ' . $err : null); ?>

  <?php
  /* 수집 상태 KPI. 눌러서 그 상태만 거른다 — 예전엔 오프라인 자산을 찾으려면
   * 목록을 눈으로 훑는 수밖에 없었다. 이미 선택된 걸 다시 누르면 필터가 풀린다. */
  $stateTone = ['ok' => 'ok', 'stale' => 'high', 'offline' => 'crit', 'none' => 'muted'];
  $totalHosts = array_sum($stateCounts);
  ?>
  <div class="cards">
    <div class="kpi"><b><?= number_format($totalHosts) ?></b><span>전체 자산</span></div>
    <?php foreach (VG_ASSET_STATES as $key => $label): ?>
      <a class="kpi tone-<?= vg_h($stateTone[$key]) ?><?= $state === $key ? ' is-selected' : '' ?>"
         href="<?= vg_h(vg_qs(['state' => $state === $key ? '' : $key, 'page' => null])) ?>">
        <b><?= number_format($stateCounts[$key]) ?></b><span><?= vg_h($label) ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '호스트명 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'state', 'empty_label' => '전체 상태',
       'selected' => $state, 'options' => VG_ASSET_STATES],
  ]);

  // 폭 배분: 목록 표는 table-layout:fixed 다(app.css 의 '목록 화면' 구역). 숫자·짧은 값 열은
  //   내용 크기로 좁히고 호스트명에 폭을 몰아준다. 폭을 안 준 '심각도'(등급별 건수 뱃지)가
  //   남는 폭을 갖는다. 폭을 하나도 안 주면 fixed 가 12열을 똑같이 쪼개 호스트명이 잘게 접힌다.
  //   % 를 쓰는 이유는 findings.php 와 같다 — 합이 화면 폭과 무관하게 고정돼 가로 스크롤이 없다.
  $headers = [
      ['label' => '호스트', 'key' => 'fqdn', 'width' => '14%', 'class' => 'col-id'],
      ['label' => '상태', 'key' => 'state', 'width' => '6.5%'],
      ['label' => 'OS', 'key' => 'os', 'width' => '7.5%'],
      ['label' => '에이전트', 'key' => 'agent_version', 'width' => '7.5%'],
      ['label' => '주기', 'key' => 'schedule', 'width' => '5.5%'],
      ['label' => '리소스', 'key' => 'resource', 'align' => 'right', 'width' => '9.5%'],
      ['label' => '패키지', 'key' => 'package_count', 'align' => 'right', 'width' => '5.5%'],
      ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right', 'width' => '5%'],
      ['label' => '심각도', 'key' => 'sev'],
      ['label' => '최신 수집', 'key' => 'collected_at', 'width' => '12%', 'nowrap' => true],
      ['label' => '스캔', 'key' => 'scan_count', 'align' => 'right', 'width' => '5.5%'],
  ];
  if ($canDelete) { $headers[] = ['label' => '', 'key' => 'act', 'align' => 'right', 'width' => '9%']; }

  vg_table(
      $headers,
      $rows,
      [
          // 빈 이유가 셋이라 메시지도 셋 — "필터 때문에 빈 것" 과 "자산이 없는 것" 은 다른 상황이다.
          'empty' => ($q !== '' || $state !== '')
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 자산이 없습니다.',
                  'hint'  => '검색어나 상태 필터를 바꿔 보세요.',
                  'cta'   => ['href' => '/assets.php', 'label' => '필터 초기화'],
              ]
              : [
                  'icon'  => '🖥️',
                  'title' => '등록된 자산이 없습니다.',
                  'hint'  => '자산은 에이전트가 수집을 보내면 자동 등록됩니다. 아래 설치 안내를 따르세요.',
              ],
          'cell' => [
              // 칸을 넘치는 긴 FQDN 은 col-id 가 말줄임으로 접는다 — 전체 이름은 title 로 남긴다.
              'fqdn'  => fn($r) => '<strong><a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a></strong>',
              'state' => fn($r) => vg_asset_state($r['age_min']),
              'os'            => fn($r) => vg_h(trim($r['os_id'] . ' ' . $r['os_version'])) ?: '<span class="why">–</span>',
              // 구버전 뱃지: 이 호스트만 옛 에이전트가 돈다는 뜻이다(중앙은 노드에 내려보내지 않는다).
              //   갱신은 master 에서 `deploy/agent_push.sh <노드>` — 토큰·타이머는 건드리지 않는다.
              'agent_version' => function ($r) use ($latestAgent) {
                  if (!$r['agent_version']) { return '<span class="why">–</span>'; }
                  $v   = (string) $r['agent_version'];
                  $old = $latestAgent !== '' && version_compare($v, $latestAgent, '<');
                  return '<code>' . vg_h($v) . '</code>'
                       . ($old ? ' ' . vg_badge('구버전', 'med',
                             "함대 최신은 {$latestAgent} — master 에서 deploy/agent_push.sh 로 갱신하세요") : '');
              },
              // 수집 주기(에이전트 타이머). 중앙은 읽기전용으로 보여줄 뿐 — 바꾸는 건 master 에서
              //   `deploy/agent_schedule.sh <주기> <노드>`(SSH 팬아웃). 하향 채널을 두지 않으려는 설계.
              'schedule' => function ($r) {
                  $s = trim((string) ($r['schedule'] ?? ''));
                  if ($s === '') { return '<span class="why">–</span>'; }
                  $label = ['hourly' => '매시간', 'daily' => '하루 1회'][$s] ?? $s;
                  return '<code title="' . vg_h($s) . '">' . vg_h($label) . '</code>';
              },
              'resource' => fn($r) => $r['scan_id'] !== null
                  ? vg_resource_mem($r['peak_rss_mb']) . ' <span class="why">·</span> ' . vg_resource_cpu($r['cpu_seconds'])
                  : '<span class="why">–</span>',
              'package_count' => fn($r) => $r['scan_id'] !== null ? number_format((int) $r['package_count']) : '<span class="why">–</span>',
              'exposure_count'=> fn($r) => $r['scan_id'] !== null ? number_format((int) $r['exposure_count']) : '<span class="why">–</span>',
              // 뱃지를 누르면 그 호스트·등급의 취약점 목록으로.
              'sev' => fn($r) => vg_sev_counts(
                  $sevByScan[(int) $r['scan_id']] ?? [],
                  fn(string $s) => '/findings.php?host=' . (int) $r['host_id'] . '&sev=' . $s
              ),
              'collected_at' => fn($r) => $r['collected_at'] ? '<span class="why">' . vg_h($r['collected_at']) . '</span>' : '<span class="why">–</span>',
              'scan_count'   => fn($r) => (int) $r['scan_count'] > 0
                  ? '<a href="/host.php?id=' . (int) $r['host_id'] . '&tab=scans">' . number_format((int) $r['scan_count']) . '회</a>'
                  : '<span class="why">0회</span>',
              'act' => fn($r) => '<form method="post" class="actions" data-confirm="' . vg_h($r['fqdn']) . ' 자산을 삭제할까요? 수집 이력은 남고 목록·집계에서만 제외됩니다.">'
                  . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                  . '<input type="hidden" name="id" value="' . (int) $r['host_id'] . '">'
                  . '<button type="submit" class="btn btn--sm btn--danger">삭제</button></form>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <?php
  /* 설치 안내는 자산을 처음 붙일 때 한 번 보는 것이다. 목록 아래 늘 펼쳐두면
   * 매일 보는 화면이 그만큼 길어진다 → 버튼 뒤 모달로. */
  vg_modal_open('agentInstall', '에이전트 설치', 'modal--wide');
  ?>
    <div class="why">자산은 에이전트가 수집을 보내면 <strong>자동 등록</strong>됩니다.
      중앙에서 대상 서버로 접속하지 않습니다(아웃바운드 push).</div>

    <div class="why mt"><strong>1) 아래 세 파일을 받습니다</strong> — 레포 체크아웃이 필요 없습니다.
      버튼으로 받아 대상 서버로 옮깁니다.</div>

    <div class="mt">
      <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=install-agent.sh" download>⬇ install-agent.sh</a>
      <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=vuln-inventory-agent.sh" download>⬇ vuln-inventory-agent.sh</a>
      <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=caddy-root.crt" download>⬇ caddy-root.crt</a>
    </div>

    <pre class="code">scp install-agent.sh vuln-inventory-agent.sh caddy-root.crt 대상서버:~/</pre>

    <div class="why mt"><strong>2) 대상 서버(Linux)</strong>의 <code>/opt/vuln-agent/</code> 에 두고 한 번 실행합니다.
      인자 없이 실행하면 주소·토큰·주기를 물어봅니다.</div>

    <pre class="code">ssh 대상서버
sudo mkdir -p /opt/vuln-agent &amp;&amp; sudo cp ~/install-agent.sh ~/vuln-inventory-agent.sh ~/caddy-root.crt /opt/vuln-agent/
cd /opt/vuln-agent
sudo bash install-agent.sh
  중앙 서버 주소 (예: vulnagent.example.com:8080): <?= vg_h($ingest) ?>

  전송 토큰 (입력은 화면에 보이지 않습니다): ********
  수집 주기 [hourly] (daily / '*:0/30'=30분마다):</pre>

    <ul class="hint-list why">
      <li><code>caddy-root.crt</code> 는 자체서명 Caddy(HTTPS) 신뢰용입니다 — <code>install-agent.sh</code> 옆에 두면 설치 시 자동 등록됩니다(없으면 TLS 검증 실패). 이 파일은 배포마다 다르며, 없다고 뜨면 중앙 관리자가 아직 추출하지 않은 것입니다.</li>
      <li>수집 엔드포인트: <code class="selectable"><?= vg_h($ingest) ?></code> — 대상 서버 → 중앙 아웃바운드 1개면 충분합니다.</li>
      <li><code>sudo</code> 만 있으면 됩니다. <code>chmod</code>/<code>chown</code> 은 필요 없습니다(<code>bash &lt;파일&gt;</code> 로 실행하므로).</li>
      <li>토큰은 <a href="/agent-tokens.php">에이전트 토큰</a> 화면에서 이 호스트(fqdn)용으로 발급받아 넣습니다 —
        그 호스트만 갱신할 수 있어 위조를 막습니다. (구버전 공유 토큰은 <code>secrets/ingest_token.txt</code>, deprecated)</li>
      <li>제거: <code>sudo bash install-agent.sh --uninstall</code></li>
    </ul>
    <?php vg_modal_foot(null); ?>
  <?php vg_modal_close(); ?>
<?php vg_footer();
