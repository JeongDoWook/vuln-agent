<?php
declare(strict_types=1);

/**
 * segment-map.php — 세그먼트 맵. 자산 목록의 서브탭. 열람은 assets 메뉴 권한(discovery.php 와 같은 이유
 *   — 새 사이드바 메뉴를 만들면 menu_code 가 또 늘어난다).
 *
 *   이 화면이 답하는 질문: **"우리 망이 어떻게 생겼나."** — 방화벽/게이트웨이 아래 어떤 대역이
 *   있고, 그 대역에 어떤 자산이 있는가.
 *
 *   ★ A단계다. 에이전트가 이미 보내는 라우팅 테이블(net.routes → tb_host_route)로 되는
 *     것까지만 그린다. 실제 트래픽 엣지(서버→DB, 서버→웹 같은 연결선)는 에이전트가 연결
 *     상대를 수집해야 하는 B단계이고, 이 화면은 그 데이터가 없어 만들지 않는다 — 없는 것을
 *     그럴듯하게 채우면 틀린 그림을 사실처럼 보여주게 된다.
 *
 *   ★ 그리는 방식: **대역마다 성형(star) 토폴로지 SVG 한 장**이다. 예전엔 대역 아래에 자산을
 *     카드 격자로 깔았는데, 카드마다 미터 바·버튼이 붙어 세로로만 길어졌고 정작 이 화면이
 *     답해야 할 "무엇이 무엇에 매달려 있나" 라는 **구조**가 안 보였다. 게이트웨이를 한가운데
 *     두고 자산을 가지로 잇는 그림이 그 구조 자체다.
 *     좌표 계산은 PHP 가 하고 SVG 만 내보낸다 — 이 서버의 CSP 는 default-src 'self' 라
 *     인라인 <script> 를 못 쓴다(depgraph.php·vg_sev_donut() 과 같은 방식). 노드 박스·곡선
 *     엣지·왼쪽 악센트 바라는 어휘도 depgraph.php 의 트리에서 그대로 가져왔다 — 같은 제품에서
 *     그래프가 화면마다 다르게 생기면 안 된다. 그래프 라이브러리(d3 등)는 들이지 않는다(YAGNI/KISS).
 *
 *   ★ 에이전트 없는 발견 자산(tb_discovered_asset)도 같은 토폴로지에 올린다 — 그 IP 가 이
 *     대역의 CIDR 안에 들면 "관리 중이 아닌 자산"으로 표시한다. 대역 밖(알려진 CIDR에
 *     안 드는) 발견 IP 는 여기서 다루지 않는다 — 자산 탐색(discovery.php)이 이미 그 목록을 갖는다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
vg_require_menu('assets');

/** IPv4 가 CIDR 범위 안에 있는가. 대역이 알려진 라우팅 서브넷일 때만 쓴다(작은 개수). */
function vg_segment_ip_in_cidr(string $ip, string $cidr): bool
{
    $parts = explode('/', $cidr);
    if (count($parts) !== 2) { return false; }
    $base = ip2long($parts[0]);
    $ipLong = ip2long($ip);
    if ($base === false || $ipLong === false || !ctype_digit($parts[1])) { return false; }
    $bits = (int) $parts[1];
    if ($bits === 0) { return true; }
    if ($bits > 32) { return false; }
    $mask = -1 << (32 - $bits);
    return (($base & $mask) === ($ipLong & $mask));
}

/* ── 성형(star) 토폴로지의 배치 상수(SVG 논리좌표, px) ──────────────────────
 *   화면 코드에 숫자를 박지 않고 여기 한곳에서만 정한다(depgraph.php 의 VG_DEPTREE_* 와 같은 규약).
 *   값을 바꾸면 대역 그림 전체가 따라온다. */
const VG_SEGMAP_NODE_W    = 250;   // 자산 노드 박스 폭
const VG_SEGMAP_NODE_H    = 30;    // 자산 노드 박스 높이
const VG_SEGMAP_HUB_W     = 168;   // 게이트웨이(허브) 박스 폭
const VG_SEGMAP_HUB_H     = 52;    // 게이트웨이 박스 높이 — IP 와 대역을 두 줄로 담는다
const VG_SEGMAP_GAP_X     = 84;    // 허브와 자산 열 사이 = 엣지 곡선이 놓이는 폭
const VG_SEGMAP_GAP_Y     = 8;     // 자산 노드 사이 세로 간격
const VG_SEGMAP_PAD       = 12;    // SVG 바깥 여백
const VG_SEGMAP_CHAR_W    = 6.4;   // 12px 글자 한 칸의 근사폭 — 이름 말줄임 계산용
const VG_SEGMAP_META_W    = 46;    // 노드 오른쪽 칸(수치·상태 글자)의 폭
const VG_SEGMAP_NODES_MAX = 40;    // 대역 하나에 그리는 노드 상한(넘치면 숫자로 밝힌다)

/**
 * 성형 토폴로지 배치 — 게이트웨이를 왼쪽 한가운데 두고 자산을 오른쪽 한 열로 쌓는다.
 *   지금 데이터로 그릴 수 있는 구조가 "게이트웨이 하나 아래 호스트 여럿" 뿐이라(파일 머리말의
 *   A단계) 힘 기반 배치가 필요 없다 — 자식 수만 알면 좌표가 나온다. 허브의 y 는 가지 전체의
 *   가운데다(depgraph 의 tidy tree 가 부모를 자식들 가운데 두는 것과 같은 규칙).
 *   반환: ['nodes' => [['x','y'], …], 'hub' => ['x','y'], 'w' => SVG 폭, 'h' => SVG 높이]
 */
function vg_segmap_layout(int $count): array
{
    $n     = max(1, $count);
    $stack = $n * VG_SEGMAP_NODE_H + ($n - 1) * VG_SEGMAP_GAP_Y;
    $h     = max($stack, VG_SEGMAP_HUB_H) + VG_SEGMAP_PAD * 2;
    $top   = ($h - $stack) / 2;
    $nodeX = VG_SEGMAP_PAD + VG_SEGMAP_HUB_W + VG_SEGMAP_GAP_X;

    $nodes = [];
    for ($i = 0; $i < $count; $i++) {
        $nodes[] = [
            'x' => $nodeX,
            'y' => round($top + $i * (VG_SEGMAP_NODE_H + VG_SEGMAP_GAP_Y) + VG_SEGMAP_NODE_H / 2, 1),
        ];
    }
    return [
        'nodes' => $nodes,
        'hub'   => ['x' => VG_SEGMAP_PAD, 'y' => round($h / 2, 1)],
        'w'     => (int) (VG_SEGMAP_PAD * 2 + VG_SEGMAP_HUB_W + VG_SEGMAP_GAP_X + VG_SEGMAP_NODE_W),
        'h'     => (int) ceil($h),
    ];
}

$err = null;
$segments = [];       // cidr => {gateway_ip, hosts: [...], discovered: [...]}
$unmatchedHosts = [];  // 라우팅 정보가 아예 없는 호스트(에이전트가 net.routes 를 못 보냈거나 전부 가상 인터페이스)
$totalHosts = 0;

try {
    $pdo = vg_pdo();

    $totalHosts = (int) $pdo->query('SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0')->fetchColumn();

    // 직결 서브넷 + 그 서브넷에 속한 활성 호스트.
    $subnetRows = $pdo->query(
        "SELECT hr.cidr, h.host_id, h.fqdn
           FROM tb_host_route hr
           JOIN tb_host h ON h.host_id = hr.host_id AND h.is_deleted = 0
          WHERE hr.is_deleted = 0 AND hr.gateway_ip IS NULL
          ORDER BY hr.cidr, h.fqdn"
    )->fetchAll();

    foreach ($subnetRows as $r) {
        $cidr = (string) $r['cidr'];
        if (!isset($segments[$cidr])) {
            $segments[$cidr] = ['gateway_ip' => null, 'hosts' => [], 'discovered' => []];
        }
        $segments[$cidr]['hosts'][(int) $r['host_id']] = (string) $r['fqdn'];
    }

    // 호스트별 기본 게이트웨이 — 대역의 대표 게이트웨이는 그 대역 호스트들이 신고한 값 중
    //   가장 많이 나온 것으로 정한다(보통 전부 같다. DHCP 오설정 등으로 갈리면 다수결).
    $gatewayByHost = [];
    $gwRows = $pdo->query(
        'SELECT host_id, gateway_ip FROM tb_host_route WHERE is_deleted = 0 AND gateway_ip IS NOT NULL'
    )->fetchAll();
    foreach ($gwRows as $r) { $gatewayByHost[(int) $r['host_id']] = (string) $r['gateway_ip']; }

    foreach ($segments as $cidr => &$seg) {
        $votes = [];
        foreach (array_keys($seg['hosts']) as $hostId) {
            if (isset($gatewayByHost[$hostId])) {
                $votes[$gatewayByHost[$hostId]] = ($votes[$gatewayByHost[$hostId]] ?? 0) + 1;
            }
        }
        if ($votes) {
            arsort($votes);
            $seg['gateway_ip'] = (string) array_key_first($votes);
        }
    }
    unset($seg);

    // 라우팅 정보가 아예 없는 호스트 — "왜 게이트웨이를 못 찾았나"를 화면에 그대로 밝힌다.
    $unmatchedHosts = $pdo->query(
        "SELECT h.host_id, h.fqdn
           FROM tb_host h
          WHERE h.is_deleted = 0
            AND NOT EXISTS (
                SELECT 1 FROM tb_host_route hr
                 WHERE hr.host_id = h.host_id AND hr.is_deleted = 0 AND hr.gateway_ip IS NULL
            )
          ORDER BY h.fqdn"
    )->fetchAll();

    // 이 페이지에 실제로 올라간 호스트들의 최신 수집 · 심각도 · 외부노출 건수 — 한 번에 배치 조회(N+1 방지).
    $allHostIds = [];
    foreach ($segments as $seg) { $allHostIds = array_merge($allHostIds, array_keys($seg['hosts'])); }
    $allHostIds = array_values(array_unique($allHostIds));

    $scanByHost = [];   // host_id => scan_id
    if ($allHostIds) {
        $in = implode(',', array_fill(0, count($allHostIds), '?'));
        $st = $pdo->prepare(
            "SELECT t.host_id, t.mid AS scan_id
               FROM " . vg_latest_scan_subq() . " t
              WHERE t.host_id IN ($in)"
        );
        $st->execute($allHostIds);
        foreach ($st->fetchAll() as $r) { $scanByHost[(int) $r['host_id']] = (int) $r['scan_id']; }
    }
    $scanIds = array_values(array_unique(array_values($scanByHost)));
    $sevByScan = vg_sev_by_scan_ids($pdo, $scanIds);
    // 위험 분포 막대(vg_sev_bar)의 공통 척도는 더 이상 안 쓴다 — 노드 하나에 미터 바를 넣으면
    //   토폴로지가 다시 카드 격자가 된다. 노드가 담는 수치는 조치 대상 건수 하나뿐이다.

    // 외부노출(EXTERNAL) 건수도 배치로 — 호스트마다 따로 부르면 세그먼트 화면이 N+1 이 된다.
    $extByScan = [];
    if ($scanIds) {
        $in = implode(',', array_fill(0, count($scanIds), '?'));
        $st = $pdo->prepare(
            "SELECT scan_id, COUNT(*) c FROM tb_exposure WHERE scan_id IN ($in) AND scope = 'EXTERNAL' GROUP BY scan_id"
        );
        $st->execute($scanIds);
        foreach ($st->fetchAll() as $r) { $extByScan[(int) $r['scan_id']] = (int) $r['c']; }
    }

    // 에이전트 없는 발견 자산(known 은 이미 위 호스트로 그려지므로 제외) — 대역 CIDR 로 배치.
    $discoveredRows = $pdo->query(
        "SELECT ip, hostname, state FROM tb_discovered_asset
          WHERE is_deleted = 0 AND host_id IS NULL
          ORDER BY ip"
    )->fetchAll();
    foreach ($discoveredRows as $d) {
        foreach ($segments as $cidr => &$seg) {
            if (vg_segment_ip_in_cidr((string) $d['ip'], $cidr)) {
                $seg['discovered'][] = $d;
                break;   // 대역은 겹치지 않는다 — 첫 매칭 하나로 충분.
            }
        }
        unset($seg);
    }

    vg_log_activity($pdo, 'PAGE', null, 'view_segment_map', '세그먼트 맵 조회',
        ['segments' => count($segments), 'unmatched_hosts' => count($unmatchedHosts)], action: 'READ');
} catch (Throwable $e) {
    error_log('[segment-map] ' . $e->getMessage());
    $err = '세그먼트 맵을 불러오는 중 오류가 발생했습니다.';
}

$discoveryStateTone = ['new' => 'crit', 'known' => 'ok', 'ignored' => 'muted'];
$discoveryStateLabel = ['new' => '미관리', 'known' => '관리 중', 'ignored' => '제외'];

vg_header('세그먼트 맵', 'segment_map');
?>
  <?php vg_page_title('세그먼트 맵', '', [
      'suffix_html' => vg_help('라우팅 테이블(net.routes)로 그린 망 구조 — A단계: 게이트웨이·대역·소속 자산까지. 서버 간 실제 연결선은 다음 단계입니다.'),
  ]); ?>
  <?php vg_asset_subtabs('segment_map'); ?>
  <?php vg_alert($err !== null ? '오류 · ' . $err : null); ?>

  <?php if ($err === null): ?>
    <div class="cards">
      <div class="kpi kpi--sm"><b><?= number_format(count($segments)) ?></b><span>대역</span></div>
      <div class="kpi kpi--sm"><b><?= number_format($totalHosts - count($unmatchedHosts)) ?></b><span>대역에 배치된 자산</span></div>
      <div class="kpi kpi--sm<?= $unmatchedHosts ? ' tone-med' : '' ?>">
        <b><?= number_format(count($unmatchedHosts)) ?></b><span>게이트웨이 미확인</span>
      </div>
    </div>

    <?php if (!$segments): ?>
      <?php vg_empty([
          'icon' => 'search',
          'title' => '아직 그릴 수 있는 대역이 없습니다.',
          'cta' => ['href' => '/assets.php', 'label' => '자산 목록으로'],
      ]); ?>
    <?php else: ?>
      <?php
      /**
       * 노드 한 칸(SVG <a> 안의 rect·text) — 왼쪽 악센트 바 + 이름(왼쪽) + 핵심 수치 하나(오른쪽).
       *   depgraph.php 의 노드와 같은 어휘다(박스·악센트 바·알약). 옛 카드가 달고 있던 미터 바·
       *   '자산 상세 →' 버튼은 노드에서 뺐다 — 노드 자체가 링크라 버튼이 두 번 있을 이유가 없고,
       *   막대까지 넣으면 노드가 다시 카드가 된다. 칸에 안 들어가는 사실(외부노출·LOW·호스트명)은
       *   <title>(툴팁)로 넘긴다.
       *   좌표·크기는 SVG 속성이라 CSS 가 가질 수 없다. 색은 전부 class 로만 준다(app.css 소유).
       */
      $svgNode = static function (array $pos, array $it): string {
          $x   = (float) $pos['x'];
          $y   = (float) $pos['y'];
          $top = round($y - VG_SEGMAP_NODE_H / 2, 1);

          // 오른쪽 칸: 관리 중이면 조치 대상 건수 알약, 미관리면 상태 글자.
          $rightW = $it['value'] !== null
              ? max(26.0, strlen($it['value']) * 7.2 + 16)
              : (float) VG_SEGMAP_META_W;
          $avail = VG_SEGMAP_NODE_W - 12 - 8 - $rightW - 10;
          $name  = mb_strimwidth($it['label'], 0, max(4, (int) ($avail / VG_SEGMAP_CHAR_W)), '…');

          $svg = '<a href="' . vg_h($it['href']) . '" class="segmap__node">'
              . '<title>' . vg_h($it['title']) . '</title>'
              // 미관리 자산은 점선 테두리다 — 에이전트가 없어 안을 못 본다는 사실을 모양으로 말한다.
              . '<rect class="segmap__box' . ($it['managed'] ? '' : ' segmap__box--gap') . '"'
              . ' x="' . $x . '" y="' . $top . '" width="' . VG_SEGMAP_NODE_W . '" height="' . VG_SEGMAP_NODE_H . '" rx="7"/>'
              . '<rect class="segmap__accent tone-' . vg_h($it['tone']) . '"'
              . ' x="' . ($x + 1.5) . '" y="' . ($top + 4) . '" width="3.5" height="' . (VG_SEGMAP_NODE_H - 8) . '" rx="2"/>'
              . '<text class="segmap__name" x="' . ($x + 12) . '" y="' . $y . '">' . vg_h($name) . '</text>';

          if ($it['value'] !== null) {
              $px = round($x + VG_SEGMAP_NODE_W - 10 - $rightW, 1);
              $svg .= '<rect class="segmap__pill tone-' . vg_h($it['tone']) . '" x="' . $px . '"'
                  . ' y="' . round($y - 8, 1) . '" width="' . round($rightW, 1) . '" height="16" rx="8"/>'
                  . '<text class="segmap__pilltext tone-' . vg_h($it['tone']) . '"'
                  . ' x="' . round($px + $rightW / 2, 1) . '" y="' . $y . '">' . vg_h($it['value']) . '</text>';
          } else {
              $svg .= '<text class="segmap__meta" x="' . ($x + VG_SEGMAP_NODE_W - 10) . '" y="' . $y . '">'
                  . vg_h($it['meta']) . '</text>';
          }
          return $svg . '</a>';
      };
      ?>
      <?php foreach ($segments as $cidr => $seg): ?>
        <?php
        /* 한 대역의 가지 = 관리 중 자산 + 그 대역 CIDR 안에서 발견된 미관리 자산.
           노드는 관리 상태로 갈린다: 관리 중은 실선 + 최고 심각도 톤, 미관리는 점선 + 빨간 톤
           (자산 탐색 화면이 쓰던 어휘 그대로다 — 두 화면에서 같은 것이 같은 색이어야 한다). */
        $items = [];
        foreach ($seg['hosts'] as $hostId => $fqdn) {
            $scanId = $scanByHost[$hostId] ?? null;
            $sev    = $scanId !== null ? ($sevByScan[$scanId] ?? []) : [];
            $act    = vg_sev_actionable($sev);
            $worst  = null;
            foreach (VG_SEV_ACTIONABLE as $s) {
                if (($sev[$s] ?? 0) > 0) { $worst = $s; break; }
            }
            $ext = $scanId !== null ? ($extByScan[$scanId] ?? 0) : 0;
            $low = (int) ($sev['LOW'] ?? 0);

            $tip = [(string) $fqdn, '조치 대상 ' . number_format($act) . '건'];
            if ($low > 0) { $tip[] = 'LOW ' . number_format($low) . '건'; }
            if ($ext > 0) { $tip[] = '외부노출 ' . number_format($ext) . '건'; }
            if ($scanId === null) { $tip[] = '수집 이력 없음'; }

            $items[] = [
                'label'   => (string) $fqdn,
                'href'    => '/host.php?id=' . (int) $hostId,
                // 조치 대상이 없으면 초록(ok) — 회색으로 두면 '데이터 없음'과 구분이 안 된다.
                'tone'    => $worst !== null ? vg_sev_tone($worst) : 'ok',
                'value'   => number_format($act),
                'meta'    => '',
                'title'   => implode(' · ', $tip),
                'managed' => true,
            ];
        }
        foreach ($seg['discovered'] as $d) {
            $state = (string) $d['state'];
            $tip   = [(string) $d['ip'], $discoveryStateLabel[$state] ?? $state];
            $tip[] = !empty($d['hostname']) ? (string) $d['hostname'] : '호스트명 미상 · 에이전트 미설치';
            $items[] = [
                'label'   => (string) $d['ip'],
                'href'    => '/discovery.php',
                'tone'    => $discoveryStateTone[$state] ?? 'muted',
                'value'   => null,
                'meta'    => $discoveryStateLabel[$state] ?? $state,
                'title'   => implode(' · ', $tip),
                'managed' => false,
            ];
        }

        // 노드 상한 — 자산이 많은 대역에서 SVG 하나가 화면을 통째로 먹지 않게 자른다.
        //   자른 사실은 카드 머리에 숫자로 밝힌다(depgraph.php 의 노드 예산과 같은 처리).
        $skipped = max(0, count($items) - VG_SEGMAP_NODES_MAX);
        if ($skipped > 0) { $items = array_slice($items, 0, VG_SEGMAP_NODES_MAX); }
        $l = vg_segmap_layout(count($items));
        ?>
        <div class="card">
          <strong><?= vg_h($cidr) ?></strong>
          <span class="why">
            · 게이트웨이 <?= $seg['gateway_ip'] !== null ? '<code>' . vg_h($seg['gateway_ip']) . '</code>' : '미확인' ?>
            · 자산 <?= number_format(count($seg['hosts'])) ?>대
            <?= $seg['discovered'] ? ' · 미관리 발견 ' . number_format(count($seg['discovered'])) . '건' : '' ?>
          </span>
          <?php if ($skipped > 0): ?>
            <span class="why"><?= vg_badge('노드 상한(' . number_format(VG_SEGMAP_NODES_MAX) . '개)에서 잘림 · 미표시 '
                . number_format($skipped) . '개', 'warn') ?></span>
          <?php endif; ?>
          <div class="card__body">
            <div class="segmap">
              <svg class="segmap__svg" width="<?= $l['w'] ?>" height="<?= $l['h'] ?>"
                   viewBox="0 0 <?= $l['w'] ?> <?= $l['h'] ?>" role="img"
                   aria-label="<?= vg_h($cidr . ' 대역 토폴로지 · 노드 ' . count($items) . '개') ?>">
                <?php
                // 허브 → 자산: 두 열의 가운데를 제어점으로 잡은 3차 베지에(depgraph 의 엣지와 같다).
                $hx = VG_SEGMAP_PAD + VG_SEGMAP_HUB_W;
                $hy = $l['hub']['y'];
                foreach ($l['nodes'] as $pos) {
                    $mid = round(($hx + $pos['x']) / 2, 1);
                    echo '<path class="segmap__edge" d="M' . $hx . ',' . $hy . ' C' . $mid . ',' . $hy
                        . ' ' . $mid . ',' . $pos['y'] . ' ' . $pos['x'] . ',' . $pos['y'] . '"/>';
                }
                // 허브(대역의 기본 게이트웨이) — 이 대역이 무엇에 매달려 있는지가 그림의 중심이다.
                $hubTop = round($hy - VG_SEGMAP_HUB_H / 2, 1);
                $hubCx  = VG_SEGMAP_PAD + VG_SEGMAP_HUB_W / 2;
                echo '<rect class="segmap__hub' . ($seg['gateway_ip'] === null ? ' segmap__hub--gap' : '') . '"'
                    . ' x="' . VG_SEGMAP_PAD . '" y="' . $hubTop . '" width="' . VG_SEGMAP_HUB_W . '"'
                    . ' height="' . VG_SEGMAP_HUB_H . '" rx="9"/>';
                echo '<text class="segmap__hubip" x="' . $hubCx . '" y="' . round($hy - 8, 1) . '">'
                    . vg_h($seg['gateway_ip'] ?? '게이트웨이 미확인') . '</text>';
                echo '<text class="segmap__hubcidr" x="' . $hubCx . '" y="' . round($hy + 11, 1) . '">'
                    . vg_h($cidr) . '</text>';

                foreach ($l['nodes'] as $i => $pos) { echo $svgNode($pos, $items[$i]); }
                ?>
              </svg>
            </div>
            <?php if (!$items): ?>
              <span class="why">이 대역에 배치된 자산이 없습니다.</span>
            <?php endif; ?>
          </div>
        </div>
      <?php endforeach; ?>
      <?php
      // 노드 색이 무슨 뜻인지 그 자리에서 말한다 — 색만으로 식별하게 두지 않는다(vg_legend 규약).
      //   노드 안에도 숫자·상태 글자가 항상 찍혀 있어 색을 못 봐도 읽힌다.
      vg_legend([
          ['label' => 'CRITICAL', 'tone' => 'crit'],
          ['label' => 'HIGH',     'tone' => 'high'],
          ['label' => 'MEDIUM',   'tone' => 'med'],
          ['label' => '조치 대상 없음', 'tone' => 'ok'],
          ['label' => '미관리(에이전트 없음) · 점선 테두리', 'tone' => 'crit'],
      ], ['inline' => true, 'caption' => '노드 왼쪽 띠 = 최고 심각도 · 알약 숫자 = 조치 대상 건수']);
      ?>
    <?php endif; ?>

    <?php if ($unmatchedHosts): ?>
      <div class="card">
        <strong>게이트웨이 미확인 자산</strong>
        <span class="why"> · 라우팅 정보가 없어 대역에 배치할 수 없습니다</span>
        <div class="card__body">
          <ul class="hint-list">
            <?php foreach ($unmatchedHosts as $h): ?>
              <li><a href="/host.php?id=<?= (int) $h['host_id'] ?>"><?= vg_h((string) $h['fqdn']) ?></a></li>
            <?php endforeach; ?>
          </ul>
        </div>
      </div>
    <?php endif; ?>
  <?php endif; ?>
<?php vg_footer();
