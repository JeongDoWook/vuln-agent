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
 *   ★ 그리는 방식: 노드-링크 그래프가 아니라 **대역별 카드 묶음**을 골랐다. 지금 데이터로는
 *     "게이트웨이 하나 아래 호스트 여럿"인 성형(star) 구조뿐이라, 대역마다 카드 하나 세우고
 *     그 안에 호스트를 늘어놓는 것으로 구조가 다 읽힌다. 새 그래프 레이아웃 엔진(d3-force·
 *     cytoscape)을 들이는 대신 자산 상세의 컨테이너 계층(.ctree/.ctrcard, host/tabs/containers.php)을
 *     그대로 재사용한다 — "루트 하나 아래 카드 여럿"이라는 같은 모양이고, 이미 다크·라이트
 *     양쪽에서 검증된 토큰이라 새 CSS를 안 만들어도 된다(CLAUDE.md — app.css 토큰 추가 금지).
 *
 *   ★ 에이전트 없는 발견 자산(tb_discovered_asset)도 같은 카드 안에 올린다 — 그 IP 가 이
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

    // 이 페이지에 실제로 올라간 호스트들의 최신 스캔 · 심각도 · 외부노출 건수 — 한 번에 배치 조회(N+1 방지).
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
      <?php foreach ($segments as $cidr => $seg): ?>
        <div class="card">
          <strong><?= vg_h($cidr) ?></strong>
          <span class="why">
            · 게이트웨이 <?= $seg['gateway_ip'] !== null ? '<code>' . vg_h($seg['gateway_ip']) . '</code>' : '미확인' ?>
            · 자산 <?= number_format(count($seg['hosts'])) ?>대
            <?= $seg['discovered'] ? ' · 미관리 발견 ' . number_format(count($seg['discovered'])) . '건' : '' ?>
          </span>
          <div class="card__body">
            <div class="ctree">
              <div class="ctree__root">
                <span class="ctree__icon" aria-hidden="true">🛜</span>
                <div class="ctree__rootid">
                  <strong><?= $seg['gateway_ip'] !== null ? vg_h($seg['gateway_ip']) : '게이트웨이 미확인' ?></strong>
                  <span class="why">이 대역의 기본 게이트웨이</span>
                </div>
                <span class="badge tone-muted"><?= vg_h($cidr) ?></span>
              </div>
              <ul class="ctree__list">
                <?php foreach ($seg['hosts'] as $hostId => $fqdn):
                    $scanId = $scanByHost[$hostId] ?? null;
                    $sev = $scanId !== null ? ($sevByScan[$scanId] ?? []) : [];
                    $sevSum = array_sum($sev);
                    $worst = null;
                    foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s) {
                        if (($sev[$s] ?? 0) > 0) { $worst = $s; break; }
                    }
                    $extCount = $scanId !== null ? ($extByScan[$scanId] ?? 0) : 0;
                ?>
                  <li class="ctrcard tone-<?= $worst !== null ? vg_h(vg_sev_tone($worst)) : 'muted' ?>">
                    <div class="ctrcard__head">
                      <a class="ctrcard__name" href="/host.php?id=<?= (int) $hostId ?>"><?= vg_h($fqdn) ?></a>
                      <?php if ($extCount > 0): ?>
                        <div class="ctrcard__badges"><?= vg_badge('외부노출 ' . $extCount, 'high') ?></div>
                      <?php endif; ?>
                    </div>
                    <div class="ctrcard__risk">
                      <?php if ($sevSum > 0): ?>
                        <?= vg_sev_bar($sev) ?>
                      <?php else: ?>
                        <span class="why">판정된 취약점 없음</span>
                      <?php endif; ?>
                    </div>
                    <div class="links"><a href="/host.php?id=<?= (int) $hostId ?>">자산 상세 →</a></div>
                  </li>
                <?php endforeach; ?>
                <?php foreach ($seg['discovered'] as $d):
                    $state = (string) $d['state'];
                    $tone = $discoveryStateTone[$state] ?? 'muted';
                ?>
                  <li class="ctrcard tone-<?= vg_h($tone) ?>">
                    <div class="ctrcard__head">
                      <span class="ctrcard__name"><?= vg_h((string) $d['ip']) ?></span>
                      <div class="ctrcard__badges"><?= vg_badge($discoveryStateLabel[$state] ?? $state, $tone) ?></div>
                    </div>
                    <div class="ctrcard__facts">
                      <span><?= !empty($d['hostname']) ? vg_h((string) $d['hostname']) : '<span class="why">호스트명 미상 · 에이전트 미설치</span>' ?></span>
                    </div>
                    <div class="links"><a href="/discovery.php">자산 탐색에서 보기 →</a></div>
                  </li>
                <?php endforeach; ?>
              </ul>
            </div>
          </div>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>

    <?php if ($unmatchedHosts): ?>
      <div class="card">
        <strong>게이트웨이 미확인 자산</strong>
        <span class="why"> · 라우팅 정보가 없어 대역에 배치할 수 없습니다(에이전트가 net.routes 를 못 보냈거나, 인터페이스가 전부 가상입니다)</span>
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
