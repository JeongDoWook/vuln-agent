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
vg_require_menu('assets');

// 연결 상태 판정 기준과 vg_asset_state() 는 format.php 에 있다(호스트 상세와 공유).

$err = null; $msg = null; $rows = []; $total = 0; $sevByScan = [];
$stateCounts = ['ok' => 0, 'stale' => 0, 'offline' => 0, 'none' => 0];
$q     = trim((string) ($_GET['q'] ?? ''));
$state = trim((string) ($_GET['state'] ?? ''));
$page  = vg_page();
$perPage = vg_perpage();

// 연결 상태 어휘. 최신 수집 시각은 별도 열에서 보여준다.
const VG_ASSET_STATES = ['ok' => '정상', 'stale' => '지연', 'offline' => '오프라인', 'none' => '수집없음'];
if (!isset(VG_ASSET_STATES[$state])) { $state = ''; }

/* 호스트 한 대의 연결 상태를 SQL 안에서 판정하는 식.
 * 목록 필터·KPI 집계가 같은 식을 써야 "지연 3대" 를 눌렀을 때 3대가 나온다. */
$legacyStaleMin = 'GREATEST(180, CEIL(h.poll_schedule_seconds / 60 * 1.5))';
$legacyOfflineMin = 'GREATEST(10080, CEIL(h.poll_schedule_seconds / 60 * 3))';
$stateExpr =
    "CASE WHEN s.scan_id IS NULL THEN 'none'
          WHEN agent_seen.last_seen_at IS NOT NULL
            AND TIMESTAMPDIFF(MINUTE, agent_seen.last_seen_at, NOW()) > " . VG_POLL_OFFLINE_MIN . " THEN 'offline'
          WHEN agent_seen.last_seen_at IS NOT NULL
            AND TIMESTAMPDIFF(MINUTE, agent_seen.last_seen_at, NOW()) > " . VG_POLL_STALE_MIN . " THEN 'stale'
          WHEN agent_seen.last_seen_at IS NOT NULL THEN 'ok'
          WHEN TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) > $legacyOfflineMin THEN 'offline'
          WHEN TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) > $legacyStaleMin THEN 'stale'
          ELSE 'ok' END";

// 호스트 + 최신 스캔. LEFT JOIN 이라 등록만 되고 아직 수집이 없는 호스트도 남는다.
$fromSql = 'FROM tb_host h
            LEFT JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
            LEFT JOIN tb_scan s ON s.scan_id = t.mid
            LEFT JOIN (
                SELECT host_fqdn, MAX(last_seen_at) AS last_seen_at
                  FROM tb_agent_token
                 WHERE is_revoked = 0 AND is_deleted = 0
                 GROUP BY host_fqdn
            ) agent_seen ON agent_seen.host_fqdn = h.fqdn';

$pdo = vg_pdo();

$assetFlash = vg_flash_take();
$msg = $assetFlash['assetMsg'] ?? null;

try {
    // KPI — 검색어·상태 필터와 무관하게 전체 기준(필터를 걸어도 전체 그림은 유지된다).
    $kpi = $pdo->query("SELECT $stateExpr AS st, COUNT(*) c $fromSql WHERE h.is_deleted = 0 GROUP BY st")->fetchAll();
    foreach ($kpi as $k) {
        if (isset($stateCounts[$k['st']])) { $stateCounts[$k['st']] = (int) $k['c']; }
    }

    $where  = 'h.is_deleted = 0';
    $params = [];
    if ($q !== '') {
        $where .= " AND (h.fqdn LIKE ? OR h.last_seen_ip LIKE ? OR EXISTS (
            SELECT 1 FROM tb_package search_pkg
             WHERE search_pkg.scan_id=s.scan_id AND search_pkg.is_deleted=0
               AND search_pkg.container_id=0 AND search_pkg.manager IN ('dpkg','rpm','apk')
               AND (search_pkg.name LIKE ? OR search_pkg.source_pkg LIKE ?)
        ))";
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
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
        "SELECT h.host_id, h.fqdn, h.os_id, h.os_version, h.last_seen_ip, h.first_seen,
                s.scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                h.poll_schedule_seconds,
                TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) AS age_min,
                TIMESTAMPDIFF(MINUTE, agent_seen.last_seen_at, NOW()) AS poll_age_min
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

vg_header('자산', 'assets');
?>
  <?php
  $stateHelp = '상태는 수집 주기가 아니라 10초 poll 통신 기준입니다. '
      . '1분 초과 시 지연, 5분 초과 시 오프라인이며 최신 수집 시각은 별도로 표시합니다.';
  ?>
  <?php vg_page_title('자산', 'ASSETS', '호스트별 수집 상태와 탐지 결과를 확인합니다.', [
      'suffix_html' => vg_help($stateHelp),
      'actions' => vg_capture(static function (): void {
          echo '<a class="btn btn--sm btn--ghost" href="/asset-packages.php">전체 설치 패키지</a>';
          vg_modal_btn('agentInstall', '에이전트 설치 안내', 'btn btn--sm btn--ghost');
      }),
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
    <div class="kpi kpi--sm"><b><?= number_format($totalHosts) ?></b><span>전체 자산</span></div>
    <?php foreach (VG_ASSET_STATES as $key => $label): ?>
      <a class="kpi kpi--sm tone-<?= vg_h($stateTone[$key]) ?><?= $state === $key ? ' is-selected' : '' ?>"
         href="<?= vg_h(vg_qs(['state' => $state === $key ? '' : $key, 'page' => null])) ?>">
        <b><?= number_format($stateCounts[$key]) ?></b><span><?= vg_h($label) ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '호스트명 또는 설치 패키지 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'state', 'empty_label' => '전체 상태',
       'selected' => $state, 'options' => VG_ASSET_STATES],
  ]);

  // 폭 배분: 목록 표는 table-layout:fixed 다(app.css 의 '목록 화면' 구역).
  //   단위를 두 가지로 나눠 쓴다 — 이 표가 표 모드로 처음 뜨는 1061px 에서 실측한 값이 기준이다.
  //   · 줄바꿈이 불가능한 고정 크기 값(뱃지·<code>·버튼)이 담기는 열은 rem 이다. % 로 주면 표가
  //     좁아질 때 그 값보다 좁아지는데, 값은 안 줄어드니 그대로 옆 열 위에 그려진다. 실제로
  //     '상태' 6.5%(1061px 에서 48px)가 오프라인 뱃지(65px)를 못 담아 OS 열을 32px 덮었고,
  //     '에이전트' 는 구버전 뱃지가 13px 덮었다(가로 스크롤은 안 생겨 #377 의 넘침 검사엔 안 잡혔다).
  //     필요한 폭 = 값의 폭 + 칸 여백(.6rem×2): 뱃지 65+19=84 → 5.5rem, 구버전 뱃지 53+19=72 → 5rem.
  //   · 접거나 잘라도 되는 텍스트 열(OS·리소스·수치·수집시각·심각도 건수)은 그대로 % 다.
  //   · 남는 폭은 호스트명이 갖는다(폭을 안 준 열). 예전엔 심각도가 남는 폭을 다 가져가
  //     1920px 에서 건수 뱃지 4개에 344px 를 썼다 — 그 폭은 잘려 나가던 식별자 쪽이 써야 한다.
  $headers = [
      ['label' => '호스트', 'key' => 'fqdn', 'class' => 'col-id', 'width' => '18%'],
      ['label' => '상태', 'key' => 'state', 'width' => '5.5rem'],
      ['label' => 'OS', 'key' => 'os', 'width' => '9%'],
      ['label' => 'IP', 'key' => 'ip', 'width' => '9%', 'nowrap' => true],
      ['label' => '에이전트', 'key' => 'agent_version', 'width' => '5rem'],
      ['label' => '패키지', 'key' => 'package_count', 'align' => 'right', 'width' => '5%'],
      ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right', 'width' => '4.5%'],
      ['label' => '심각도', 'key' => 'sev', 'width' => '16%'],
      ['label' => '최신 수집', 'key' => 'collected_at', 'width' => '12%', 'nowrap' => true],
  ];
  // 액션 열만 % 가 아니라 rem 이다. 삭제 버튼은 폭이 늘 같은 고정 크기 조작부라 비율로 줄 이유가 없고,
  //   비율로 주면 표가 좁아질 때 버튼보다 좁아진다 — 실제로 900px 에서 9%(=51px)가 68px 버튼을
  //   못 담아 카드를 16.7px 밀어냈다(가로 스크롤). 5rem 이면 어느 폭에서도 버튼이 들어간다.

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
              'state' => fn($r) => vg_asset_state(
                  $r['scan_id'] !== null,
                  $r['poll_age_min'],
                  $r['age_min'],
                  (int) $r['poll_schedule_seconds']
              ),
              'os'            => fn($r) => vg_h(trim($r['os_id'] . ' ' . $r['os_version'])) ?: '<span class="why">–</span>',
              'ip'            => fn($r) => !empty($r['last_seen_ip'])
                  ? '<code>' . vg_h((string) $r['last_seen_ip']) . '</code>'
                  : '<span class="why">–</span>',
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
              'package_count' => fn($r) => $r['scan_id'] !== null
                  ? '<a href="/host.php?id=' . (int)$r['host_id'] . '&amp;tab=packages">' . number_format((int)$r['package_count']) . '</a>'
                  : '<span class="why">–</span>',
              'exposure_count'=> fn($r) => $r['scan_id'] !== null
                  ? '<a href="/host.php?id=' . (int)$r['host_id'] . '&amp;tab=runtime">' . number_format((int)$r['exposure_count']) . '</a>'
                  : '<span class="why">–</span>',
              // 뱃지를 누르면 그 호스트·등급의 취약점 목록으로.
              'sev' => fn($r) => vg_sev_counts(
                  $sevByScan[(int) $r['scan_id']] ?? [],
                  fn(string $s) => '/findings.php?host=' . (int) $r['host_id'] . '&sev=' . $s
              ),
              'collected_at' => fn($r) => $r['collected_at'] ? '<span class="why">' . vg_h($r['collected_at']) . '</span>' : '<span class="why">–</span>',
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
        그 호스트만 갱신할 수 있어 다른 호스트로 위조하는 요청을 막습니다.</li>
      <li>제거: <code>sudo bash install-agent.sh --uninstall</code></li>
    </ul>
    <?php vg_modal_foot(null); ?>
  <?php vg_modal_close(); ?>
<?php vg_footer();
