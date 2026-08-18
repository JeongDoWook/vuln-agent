<?php
declare(strict_types=1);

/**
 * discovery.php — 자산 탐색(섀도우 IT). 자산 목록의 서브탭. 열람은 assets 메뉴 권한.
 *   이 화면이 답하는 질문은 하나다: **"내가 모르는 자산이 몇 대인가."**
 *   에이전트를 설치한 서버만 아는 상태로는 담당자가 엑셀에서 빠뜨린 자산을 구조적으로 못 찾는다.
 *
 *   취약점 스캔과 **별개 파이프라인**이다(Nexpose·Nessus 의 Discovery/Vulnerability 분리와 같은 구도).
 *   두 파이프라인의 접점은 IP 대조 한 곳뿐 — tb_discovered_asset.host_id.
 *
 *   ★ 웹은 스캔을 직접 돌리지 않는다. 이 화면은 tb_discovery_run 에 status='pending' 행을
 *     만들기만 하고 집행은 `php bin/discover.php --pending` 이 한다(CLAUDE.md 원칙 6 —
 *     무거운 작업은 bin/ 으로). 화면은 status 를 읽어 보여준다.
 *
 *   인가 경계 두 단:
 *     · 대역 등록·수정·삭제 · 스캔 실행  → **admin** (남의 대역을 훑는 것은 관리 행위다)
 *     · 제외 표시·메모                   → **admin·operator** (매일 도는 분류 작업)
 *   화면에서 버튼을 감추는 건 인가가 아니다 — 판정은 아래 POST 처리부가 한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';                 // vg_log_activity · vg_soft_delete
require_once __DIR__ . '/../src/assets/modal_install.php';  // 에이전트 설치 안내(자산 목록과 같은 모달)
vg_require_menu('assets');

/* 발견 IP 의 상태 어휘 — tb_discovered_asset.state 의 ENUM 과 1:1. 표·KPI·필터가 이 하나만 본다.
 *   new 가 이 화면의 주인공이라 '미관리' 로 부른다(스키마의 'new' 는 사람 말로 옮기면 그 뜻이다). */
const VG_DISCOVERY_STATES = ['new' => '미관리', 'known' => '관리 중', 'ignored' => '제외'];
/* 톤(색 어휘)은 이 화면이 소유한다 — KPI 카드와 표 뱃지가 같은 값을 두 색으로 부르지 않게. */
const VG_DISCOVERY_TONES = ['new' => 'crit', 'known' => 'ok', 'ignored' => 'muted'];
/** 한 행에 펼치는 열린 포트 수. 넘으면 "+N" 으로 접는다 — 포트 40개짜리 행이 표를 무너뜨린다. */
const VG_DISCOVERY_PORTS_SHOWN = 6;

/** CIDR 표기(IPv4/IPv6 + 프리픽스)인가. 대역은 사람이 손으로 넣는 값이라 형식을 먼저 막는다. */
function vg_discovery_valid_cidr(string $cidr): bool
{
    $parts = explode('/', $cidr);
    if (count($parts) !== 2 || $parts[1] === '' || !ctype_digit($parts[1])) { return false; }
    $bits = (int) $parts[1];
    if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) { return $bits <= 32; }
    if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) { return $bits <= 128; }
    return false;
}

/**
 * 포트 목록을 정규화한다: "80, 443,8000-8100" → "80,443,8000-8100".
 *   빈 값이면 null(= 집행기의 기본 세트를 쓴다). 형식이 틀리면 RuntimeException —
 *   여기서 막지 않으면 집행기가 대역 하나를 통째로 못 돌고 나서야 알게 된다.
 */
function vg_discovery_normalize_ports(string $raw): ?string
{
    $raw = trim($raw);
    if ($raw === '') { return null; }
    $out = [];
    foreach (explode(',', $raw) as $tok) {
        $tok = trim($tok);
        if ($tok === '') { continue; }
        $range = explode('-', $tok);
        if (count($range) > 2) { throw new RuntimeException('포트 형식이 올바르지 않습니다: ' . $tok); }
        foreach ($range as $p) {
            if (!ctype_digit($p) || (int) $p < 1 || (int) $p > 65535) {
                throw new RuntimeException('포트 형식이 올바르지 않습니다: ' . $tok);
            }
        }
        if (count($range) === 2 && (int) $range[0] > (int) $range[1]) {
            throw new RuntimeException('포트 범위의 시작이 끝보다 큽니다: ' . $tok);
        }
        $out[] = count($range) === 2 ? ((int) $range[0]) . '-' . ((int) $range[1]) : (string) ((int) $range[0]);
    }
    if (!$out) { return null; }
    $joined = implode(',', $out);
    if (strlen($joined) > 1024) { throw new RuntimeException('포트 목록이 너무 깁니다(1024자).'); }
    return $joined;
}

$pdo = vg_pdo();

/* ── POST 처리 — GET 렌더보다 먼저·헤더 출력 전이어야 한다(전부 PRG 로 끝난다). ───────── */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        vg_redirect_flash(['err' => '세션이 만료되었습니다.']);
    }
    $action = (string) ($_POST['action'] ?? '');
    $me     = vg_current_user();
    $canManage = vg_has_role('admin');                 // 대역·스캔
    $canTriage = vg_has_role('admin', 'operator');     // 제외·메모
    try {
        if ($action === 'target_save') {
            if (!$canManage) { throw new RuntimeException('대역을 등록할 권한이 없습니다.'); }
            $id      = (int) ($_POST['discovery_target_id'] ?? 0);
            $cidr    = trim((string) ($_POST['cidr'] ?? ''));
            $label   = mb_substr(trim((string) ($_POST['label'] ?? '')), 0, 255);
            $ports   = vg_discovery_normalize_ports((string) ($_POST['ports'] ?? ''));
            $enabled = isset($_POST['enabled']) ? 1 : 0;
            if (!vg_discovery_valid_cidr($cidr)) {
                throw new RuntimeException('대역은 CIDR 표기여야 합니다(예: 10.3.142.0/24).');
            }
            /* uq_discovery_target_cidr 는 is_deleted 를 안 본다 — 지웠던 대역을 다시 등록하면
             *   그대로 걸린다. 그 행을 되살려 준다(사람이 보기엔 "다시 등록" 이 맞다). */
            $dup = $pdo->prepare('SELECT discovery_target_id, is_deleted FROM tb_discovery_target WHERE cidr = ?');
            $dup->execute([$cidr]);
            $existing = $dup->fetch();
            if ($existing && (int) $existing['discovery_target_id'] !== $id) {
                if ($id === 0 && (int) $existing['is_deleted'] === 1) {
                    $id = (int) $existing['discovery_target_id'];
                } else {
                    throw new RuntimeException('이미 등록된 대역입니다: ' . $cidr);
                }
            }
            if ($id > 0) {
                $st = $pdo->prepare(
                    'UPDATE tb_discovery_target
                        SET cidr = ?, ports = ?, label = ?, enabled = ?, is_deleted = 0, deleted_at = NULL
                      WHERE discovery_target_id = ?'
                );
                $st->execute([$cidr, $ports, $label !== '' ? $label : null, $enabled, $id]);
                $msg = '대역을 저장했습니다: ' . $cidr;
            } else {
                $st = $pdo->prepare(
                    'INSERT INTO tb_discovery_target (cidr, ports, label, enabled, created_by)
                     VALUES (?,?,?,?,?)'
                );
                $st->execute([$cidr, $ports, $label !== '' ? $label : null, $enabled, $me['id'] ?? null]);
                $id  = (int) $pdo->lastInsertId();
                $msg = '대역을 등록했습니다: ' . $cidr;
            }
            vg_log_activity($pdo, 'DISCOVERY_TARGET', $id, 'discovery_target_save',
                '자산 탐색 대역 저장: ' . $cidr,
                ['cidr' => $cidr, 'ports' => $ports, 'label' => $label, 'enabled' => $enabled],
                subject: $cidr, action: 'UPDATE');
            vg_redirect_flash(['msg' => $msg]);

        } elseif ($action === 'target_delete') {
            if (!$canManage) { throw new RuntimeException('대역을 삭제할 권한이 없습니다.'); }
            $id = (int) ($_POST['discovery_target_id'] ?? 0);
            $st = $pdo->prepare('SELECT cidr FROM tb_discovery_target WHERE discovery_target_id = ? AND is_deleted = 0');
            $st->execute([$id]);
            $cidr = (string) ($st->fetchColumn() ?: '');
            if ($cidr === '') { throw new RuntimeException('대역을 찾을 수 없습니다.'); }
            vg_soft_delete($pdo, 'tb_discovery_target', $id);
            vg_log_activity($pdo, 'DISCOVERY_TARGET', $id, 'discovery_target_delete',
                '자산 탐색 대역 삭제: ' . $cidr, ['cidr' => $cidr], subject: $cidr, action: 'DELETE');
            vg_redirect_flash(['msg' => '대역을 삭제했습니다: ' . $cidr . ' (발견 이력은 남습니다)']);

        } elseif ($action === 'scan') {
            if (!$canManage) { throw new RuntimeException('스캔을 실행할 권한이 없습니다.'); }
            $id = (int) ($_POST['discovery_target_id'] ?? 0);
            $st = $pdo->prepare(
                'SELECT cidr, enabled FROM tb_discovery_target WHERE discovery_target_id = ? AND is_deleted = 0'
            );
            $st->execute([$id]);
            $target = $st->fetch();
            if (!$target) { throw new RuntimeException('대역을 찾을 수 없습니다.'); }
            if ((int) $target['enabled'] !== 1) { throw new RuntimeException('사용 안 함으로 둔 대역은 스캔하지 않습니다.'); }
            /* 중복 실행 방지 — 버튼은 진행 중이면 이미 막혀 있지만, 두 사람이 동시에 눌렀거나
             *   조작된 POST 가 오면 여기서 걸린다(화면 숨김은 인가가 아니다와 같은 이유). */
            $busy = $pdo->prepare(
                "SELECT COUNT(*) FROM tb_discovery_run
                  WHERE discovery_target_id = ? AND is_deleted = 0 AND status IN ('pending','running')"
            );
            $busy->execute([$id]);
            if ((int) $busy->fetchColumn() > 0) {
                throw new RuntimeException('이미 대기 중이거나 진행 중인 스캔이 있습니다.');
            }
            $ins = $pdo->prepare(
                "INSERT INTO tb_discovery_run (discovery_target_id, status, created_by) VALUES (?, 'pending', ?)"
            );
            $ins->execute([$id, $me['id'] ?? null]);
            $runId = (int) $pdo->lastInsertId();
            /* "누가 어느 대역을 스캔했나" 는 이 기능에서 가장 중요한 기록이다. */
            vg_log_activity($pdo, 'DISCOVERY_RUN', $runId, 'discovery_scan_request',
                '자산 탐색 스캔 요청: ' . $target['cidr'],
                ['cidr' => $target['cidr'], 'discovery_target_id' => $id],
                subject: (string) $target['cidr'], action: 'EXECUTE');
            vg_redirect_flash(['msg' => '스캔을 대기열에 넣었습니다: ' . $target['cidr'] . ' (집행기가 순서대로 처리합니다)']);

        } elseif ($action === 'asset_triage') {
            if (!$canTriage) { throw new RuntimeException('발견 자산을 정리할 권한이 없습니다.'); }
            $id   = (int) ($_POST['discovered_asset_id'] ?? 0);
            $op   = (string) ($_POST['op'] ?? 'note');
            $note = mb_substr(trim((string) ($_POST['note'] ?? '')), 0, 500);
            $st = $pdo->prepare(
                'SELECT ip, state FROM tb_discovered_asset WHERE discovered_asset_id = ? AND is_deleted = 0'
            );
            $st->execute([$id]);
            $asset = $st->fetch();
            if (!$asset) { throw new RuntimeException('발견 자산을 찾을 수 없습니다.'); }
            if ($op === 'toggle') {
                /* 해제하면 자동 판정 자리로 되돌린다 — host_id 가 있으면 관리 중, 없으면 미관리.
                 *   반대로 ignored 는 사람이 정한 값이라 집행기의 자동 판정이 덮지 않는다(스키마 주석). */
                $sql = (string) $asset['state'] === 'ignored'
                    ? "UPDATE tb_discovered_asset
                          SET state = IF(host_id IS NULL, 'new', 'known'), note = ?
                        WHERE discovered_asset_id = ?"
                    : "UPDATE tb_discovered_asset SET state = 'ignored', note = ? WHERE discovered_asset_id = ?";
                $pdo->prepare($sql)->execute([$note !== '' ? $note : null, $id]);
                $msg = (string) $asset['state'] === 'ignored'
                    ? '제외를 해제했습니다: ' . $asset['ip']
                    : '제외로 표시했습니다: ' . $asset['ip'];
            } else {
                $pdo->prepare('UPDATE tb_discovered_asset SET note = ? WHERE discovered_asset_id = ?')
                    ->execute([$note !== '' ? $note : null, $id]);
                $msg = '메모를 저장했습니다: ' . $asset['ip'];
            }
            vg_log_activity($pdo, 'DISCOVERED_ASSET', $id, 'discovered_asset_triage', $msg,
                ['ip' => $asset['ip'], 'op' => $op], subject: (string) $asset['ip'], action: 'UPDATE');
            vg_redirect_flash(['msg' => $msg]);
        }
        vg_redirect_flash(['err' => '알 수 없는 요청입니다.']);
    } catch (Throwable $e) {
        error_log('[discovery] ' . $e->getMessage());
        // 사람이 고칠 수 있는 입력 오류만 그대로 보여주고, 그 밖의 내부 오류는 감춘다.
        vg_redirect_flash([
            'err' => $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.',
        ]);
    }
}

$flash = vg_flash_take();
$msg = $flash['msg'] ?? null;
$err = $flash['err'] ?? null;

/* ── 필터 ─────────────────────────────────────────────────────────────────── */
$q       = trim((string) ($_GET['q'] ?? ''));
$state   = trim((string) ($_GET['state'] ?? ''));
if (!isset(VG_DISCOVERY_STATES[$state])) { $state = ''; }
$targetId = (int) ($_GET['target'] ?? 0);
$editId   = (int) ($_GET['edit'] ?? 0);
$page     = vg_page();
$perPage  = vg_perpage();

$targets = [];
$targetOptions = [];
$stateCounts = ['new' => 0, 'known' => 0, 'ignored' => 0];
$rows = [];
$portsByAsset = [];
$total = 0;

try {
    /* 대역 + 그 대역의 **마지막 스캔**. 대역은 사람이 손으로 등록하는 것이라 수십 건 규모다
     *   — 상관 서브쿼리가 대역마다 한 번 도는 것이 조인 후 집계보다 단순하고 인덱스도 탄다
     *   (PK + idx_discovery_run_target_time). */
    $targets = $pdo->query(
        "SELECT t.discovery_target_id, t.cidr, t.ports, t.label, t.enabled,
                r.status, r.started_at, r.finished_at, r.ip_total, r.ip_alive,
                r.port_checked, r.open_total, r.elapsed_seconds, r.created_at AS run_created_at
           FROM tb_discovery_target t
           LEFT JOIN tb_discovery_run r ON r.discovery_run_id = (
                SELECT r2.discovery_run_id FROM tb_discovery_run r2
                 WHERE r2.discovery_target_id = t.discovery_target_id AND r2.is_deleted = 0
                 ORDER BY r2.discovery_run_id DESC LIMIT 1)
          WHERE t.is_deleted = 0
          ORDER BY t.cidr"
    )->fetchAll();
    foreach ($targets as $t) {
        $targetOptions[(string) $t['discovery_target_id']] =
            (string) $t['cidr'] . ($t['label'] !== null && $t['label'] !== '' ? ' · ' . $t['label'] : '');
    }
    if ($targetId > 0 && !isset($targetOptions[(string) $targetId])) { $targetId = 0; }

    // 상태별 건수(KPI). 대역을 고르면 idx_discovered_asset_state(discovery_target_id, state) 를 탄다.
    $where  = 'da.is_deleted = 0';
    $params = [];
    if ($targetId > 0) { $where .= ' AND da.discovery_target_id = ?'; $params[] = $targetId; }
    $st = $pdo->prepare("SELECT da.state, COUNT(*) AS n FROM tb_discovered_asset da WHERE $where GROUP BY da.state");
    $st->execute($params);
    foreach ($st->fetchAll() as $r) {
        if (isset($stateCounts[(string) $r['state']])) { $stateCounts[(string) $r['state']] = (int) $r['n']; }
    }

    // 목록 — 위 조건에 상태·IP 검색을 더한다.
    if ($state !== '') { $where .= ' AND da.state = ?'; $params[] = $state; }
    if ($q !== '')     { $where .= ' AND da.ip LIKE ?'; $params[] = '%' . $q . '%'; }

    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_discovered_asset da WHERE $where");
    $cnt->execute($params);
    $total  = (int) $cnt->fetchColumn();
    $offset = ($page - 1) * $perPage;

    /* 호스트·대역은 각각 한 번의 LEFT JOIN 으로 붙인다(행마다 다시 묻지 않는다 — N+1 금지).
     *   LIMIT/OFFSET 은 화이트리스트로 검증된 정수라 문자열로 넣어도 주입면이 없다. */
    $lst = $pdo->prepare(
        "SELECT da.discovered_asset_id, da.ip, da.state, da.note, da.first_seen, da.last_seen,
                da.host_id, da.last_run_id, h.fqdn, t.cidr
           FROM tb_discovered_asset da
           JOIN tb_discovery_target t ON t.discovery_target_id = da.discovery_target_id
           LEFT JOIN tb_host h ON h.host_id = da.host_id AND h.is_deleted = 0
          WHERE $where
          ORDER BY da.last_seen DESC, da.discovered_asset_id DESC
          LIMIT $perPage OFFSET $offset"
    );
    $lst->execute($params);
    $rows = $lst->fetchAll();

    /* 열린 포트 — **이 페이지에 뜬 자산만**, **그 자산의 마지막 run 것만** 한 번에 가져온다.
     *   행마다 조회하면 페이지당 쿼리가 50번 나간다. uq_discovered_port 의 선두 두 컬럼
     *   (discovered_asset_id, discovery_run_id)이 그대로 조건이라 인덱스를 탄다. */
    $ids = array_map(static fn($r): int => (int) $r['discovered_asset_id'], $rows);
    if ($ids) {
        $in = implode(',', array_fill(0, count($ids), '?'));
        $ps = $pdo->prepare(
            "SELECT dp.discovered_asset_id, dp.port, dp.proto
               FROM tb_discovered_port dp
               JOIN tb_discovered_asset da ON da.discovered_asset_id = dp.discovered_asset_id
                                          AND da.last_run_id = dp.discovery_run_id
              WHERE dp.is_deleted = 0 AND dp.discovered_asset_id IN ($in)
              ORDER BY dp.discovered_asset_id, dp.port"
        );
        $ps->execute($ids);
        foreach ($ps->fetchAll() as $p) {
            $portsByAsset[(int) $p['discovered_asset_id']][] = (int) $p['port'] . '/' . (string) $p['proto'];
        }
    }

    /* 열람 감사 — 발견 IP 목록은 "우리 대역에 무엇이 떠 있나" 라는 인프라 정보다.
     *   vg_header() 의 page_view 는 쿼리 값을 안 남기므로, 무엇을 걸러 봤는지는 여기서 남긴다. */
    vg_log_activity($pdo, 'PAGE', null, 'view_discovery', '자산 탐색 조회',
        ['target' => $targetId, 'state' => $state, 'q' => $q, 'matched' => $total], action: 'READ');
} catch (Throwable $e) {
    error_log('[discovery] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

$canManage = vg_has_role('admin');
$canTriage = vg_has_role('admin', 'operator');
$csrf = vg_csrf_token();

// 수정은 ?edit=<id> 로 연다 — 대역마다 모달을 하나씩 찍지 않고 폼 하나를 서버에서 채운다.
$editTarget = null;
foreach ($targets as $t) {
    if ((int) $t['discovery_target_id'] === $editId) { $editTarget = $t; break; }
}

// 에이전트 커버리지 — 제외한 자산은 분모에서 뺀다(프린터·스위치는 에이전트를 깔 대상이 아니다).
$managed  = $stateCounts['known'];
$shadow   = $stateCounts['new'];
$scope    = $managed + $shadow;
$coverage = $scope > 0 ? (int) round($managed * 100 / $scope) : 0;
$found    = $scope + $stateCounts['ignored'];

vg_header('자산 탐색', 'discovery');
?>
  <?php vg_page_title('자산 탐색', 'DISCOVERY', [
      'suffix_html' => vg_help('대역을 훑어 살아있는 IP 를 모읍니다. 취약점 스캔과는 별개 파이프라인입니다.'),
      'actions' => vg_capture(static function (): void {
          vg_modal_btn('agentInstall', '에이전트 설치 안내', 'btn btn--sm btn--ghost');
      }),
  ]); ?>
  <?php vg_asset_subtabs('discovery'); ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err !== null ? '오류 · ' . $err : null); ?>

  <?php /* KPI 를 누르면 그 상태만 거른다. 이미 선택된 걸 다시 누르면 풀린다(자산 목록과 같은 규칙). */ ?>
  <div class="cards">
    <div class="kpi kpi--sm"><b><?= number_format($found) ?></b><span>발견 자산</span></div>
    <?php foreach (VG_DISCOVERY_STATES as $key => $label): ?>
      <?php /* 0건이면 톤을 뺀다 — '미관리 0' 은 좋은 소식인데 강조 테두리가 붙으면 경고로 읽힌다. */ ?>
      <a class="kpi kpi--sm<?= $stateCounts[$key] > 0 ? ' tone-' . vg_h(VG_DISCOVERY_TONES[$key]) : '' ?><?= $state === $key ? ' is-selected' : '' ?>"
         href="<?= vg_h(vg_qs(['state' => $state === $key ? '' : $key, 'page' => null, 'edit' => null])) ?>">
        <b><?= number_format($stateCounts[$key]) ?></b><span><?= vg_h($label) ?></span>
      </a>
    <?php endforeach; ?>
    <div class="kpi kpi--sm" title="관리 중 ÷ (관리 중 + 미관리). 제외한 자산은 분모에서 뺀다.">
      <b><?= $scope > 0 ? $coverage . '%' : '–' ?></b><span>에이전트 커버리지</span>
    </div>
  </div>

  <?php /* ── 대역 · 스캔 ─────────────────────────────────────────────────── */ ?>
  <?php
  vg_table(
      [
          ['label' => '대역(CIDR)', 'width' => '12rem'],
          ['label' => '라벨'],
          ['label' => '포트', 'width' => '12rem'],
          ['label' => '사용', 'width' => '5rem'],
          ['label' => '마지막 스캔'],
          ['label' => '', 'width' => '13rem', 'align' => 'right'],
      ],
      $targets,
      [
          'empty' => $canManage ? [
              'icon' => 'search', 'title' => '등록된 대역이 없습니다.',
              'hint' => '훑을 대역을 등록하면 그 안의 살아있는 IP 를 모읍니다.',
          ] : [
              'icon' => 'search', 'title' => '등록된 대역이 없습니다.',
              'hint' => '대역 등록은 관리자만 할 수 있습니다.',
          ],
          'cell' => [
              0 => fn($t) => '<code>' . vg_h((string) $t['cidr']) . '</code>',
              1 => fn($t) => $t['label'] !== null && $t['label'] !== ''
                  ? vg_h((string) $t['label']) : '<span class="why">–</span>',
              2 => fn($t) => $t['ports'] !== null && $t['ports'] !== ''
                  ? '<code>' . vg_trunc((string) $t['ports'], 40) . '</code>'
                  : '<span class="why">기본 세트</span>',
              3 => fn($t) => (int) $t['enabled'] === 1 ? vg_badge('사용', 'ok') : vg_badge('중지', 'muted'),
              /* 마지막 스캔 — 얼마나 걸렸는지가 운영자에게 중요하다(대역을 더 넓힐지 판단한다).
               *   실패는 **일반화된 문구**만 낸다: error_text 원문에는 대상 주소·예외 원문이 섞인다. */
              4 => function ($t): string {
                  $status = (string) ($t['status'] ?? '');
                  if ($status === '') { return '<span class="why">스캔 이력 없음</span>'; }
                  if ($status === 'pending')  { return vg_badge('대기 중', 'med') . ' <span class="why">집행기 대기</span>'; }
                  if ($status === 'running')  { return vg_badge('진행 중', 'high')
                      . ' <span class="why">' . vg_h(substr((string) ($t['started_at'] ?? ''), 0, 16)) . ' 시작</span>'; }
                  if ($status === 'failed')   { return vg_badge('실패', 'crit')
                      . ' <span class="why">스캔이 실패했습니다. 서버 로그를 확인하세요.</span>'; }
                  $at = substr((string) ($t['finished_at'] ?? ''), 0, 16);
                  return vg_badge('완료', 'ok') . ' <span class="why">' . vg_h($at)
                      . ' · 응답 IP ' . number_format((int) $t['ip_alive']) . '/' . number_format((int) $t['ip_total'])
                      . ' · 포트 시도 ' . number_format((int) $t['port_checked'])
                      . ' · 열린 포트 ' . number_format((int) $t['open_total'])
                      . ($t['elapsed_seconds'] !== null ? ' · ' . vg_h((string) $t['elapsed_seconds']) . '초' : '')
                      . '</span>';
              },
              5 => function ($t) use ($canManage, $csrf): string {
                  if (!$canManage) { return ''; }
                  $id = (int) $t['discovery_target_id'];
                  $busy = in_array((string) ($t['status'] ?? ''), ['pending', 'running'], true);
                  $scan = $busy
                      ? '<button type="button" class="btn btn--xs btn--ghost" disabled'
                        . ' title="이미 대기 중이거나 진행 중입니다">지금 스캔</button>'
                      : '<form method="post"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                        . '<input type="hidden" name="action" value="scan">'
                        . '<input type="hidden" name="discovery_target_id" value="' . $id . '">'
                        . '<button class="btn btn--xs btn--primary" data-loading="요청 중…">지금 스캔</button></form>';
                  return '<div class="actions">' . $scan
                      . '<a class="btn btn--xs btn--ghost" href="' . vg_h(vg_qs(['edit' => $id])) . '">수정</a>'
                      . '<form method="post" data-confirm="이 대역을 삭제할까요? 지금까지 발견한 자산 이력은 남습니다.">'
                      . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                      . '<input type="hidden" name="action" value="target_delete">'
                      . '<input type="hidden" name="discovery_target_id" value="' . $id . '">'
                      . '<button class="btn btn--xs btn--ghost">삭제</button></form></div>';
              },
          ],
      ]
  );
  ?>

  <?php if ($canManage): ?>
    <div class="form-bar">
      <?php vg_modal_btn('discoveryTarget', '+ 대역 등록', 'btn btn--sm btn--primary'); ?>
    </div>
  <?php endif; ?>

  <?php /* ── 발견 자산 ────────────────────────────────────────────────────── */ ?>
  <?php vg_toolbar([
      ['type' => 'select', 'name' => 'state', 'empty_label' => '전체 상태',
       'selected' => $state, 'options' => VG_DISCOVERY_STATES],
      ...($targetOptions ? [['type' => 'select', 'name' => 'target', 'empty_label' => '전체 대역',
       'selected' => $targetId > 0 ? (string) $targetId : '', 'options' => $targetOptions]] : []),
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'IP 검색', 'value' => $q],
  ]); ?>

  <?php
  $filtered = ($q !== '' || $state !== '' || $targetId > 0);
  $headers = [
      ['label' => 'IP', 'width' => '10rem'],
      ['label' => '상태', 'width' => '6rem'],
      ['label' => '열린 포트'],
      ['label' => '최초 발견', 'width' => '9rem', 'nowrap' => true],
      ['label' => '최근 발견', 'width' => '9rem', 'nowrap' => true],
      ['label' => '연결된 자산', 'width' => '14rem'],
  ];
  $cells = [
      0 => fn($r) => '<code>' . vg_h((string) $r['ip']) . '</code>'
          . '<div class="why">' . vg_h((string) $r['cidr']) . '</div>',
      1 => fn($r) => vg_badge(
          VG_DISCOVERY_STATES[(string) $r['state']] ?? (string) $r['state'],
          VG_DISCOVERY_TONES[(string) $r['state']] ?? 'muted'
      ),
      2 => function ($r) use ($portsByAsset): string {
          $ports = $portsByAsset[(int) $r['discovered_asset_id']] ?? [];
          if (!$ports) { return '<span class="why">열린 포트 없음</span>'; }
          $shown = array_slice($ports, 0, VG_DISCOVERY_PORTS_SHOWN);
          $html  = '<code>' . vg_h(implode(' ', $shown)) . '</code>';
          $rest  = count($ports) - count($shown);
          if ($rest > 0) {
              $html .= ' <span class="why" title="' . vg_h(implode(' ', $ports)) . '">+' . $rest . '</span>';
          }
          return $html;
      },
      3 => fn($r) => '<span class="why">' . vg_h(substr((string) $r['first_seen'], 0, 16)) . '</span>',
      4 => fn($r) => '<span class="why">' . vg_h(substr((string) $r['last_seen'], 0, 16)) . '</span>',
      /* 이 열이 이 기능의 결론 동선이다 — 모르는 자산을 찾았으면 에이전트를 깔고 취약점
       *   스캔으로 넘어간다. 그래서 연결이 없을 때 막다른 칸이 아니라 설치 안내로 잇는다. */
      5 => function ($r): string {
          if ((int) ($r['host_id'] ?? 0) > 0 && $r['fqdn'] !== null) {
              return '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h((string) $r['fqdn']) . '</a>';
          }
          if ((string) $r['state'] === 'ignored') { return '<span class="why">제외됨</span>'; }
          return vg_capture(static function (): void {
              vg_modal_btn('agentInstall', '에이전트 설치 안내', 'btn btn--xs btn--ghost');
          });
      },
  ];
  if ($canTriage) {
      $headers[] = ['label' => '제외 · 메모', 'width' => '18rem', 'align' => 'right'];
      $cells[6] = function ($r) use ($csrf): string {
          $id = (int) $r['discovered_asset_id'];
          $isIgnored = (string) $r['state'] === 'ignored';
          return '<div class="actions"><form method="post">'
              . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
              . '<input type="hidden" name="action" value="asset_triage">'
              . '<input type="hidden" name="discovered_asset_id" value="' . $id . '">'
              . '<input type="text" name="note" maxlength="500" value="' . vg_h((string) ($r['note'] ?? ''))
              . '" placeholder="메모(프린터·스위치 등)" aria-label="메모">'
              . '<button name="op" value="note" class="btn btn--xs btn--ghost">저장</button>'
              . '<button name="op" value="toggle" class="btn btn--xs btn--ghost">'
              . ($isIgnored ? '제외 해제' : '제외') . '</button>'
              . '</form></div>';
      };
  }
  vg_table($headers, $rows, [
      'empty' => $filtered ? [
          'icon' => 'search', 'title' => '조건에 맞는 발견 자산이 없습니다.',
          'cta' => ['href' => '/discovery.php', 'label' => '필터 초기화'],
      ] : [
          'icon' => 'search', 'title' => '아직 발견된 자산이 없습니다.',
          'hint' => '대역을 등록하고 "지금 스캔" 을 누르면 집행기가 순서대로 훑습니다.',
      ],
      'cell' => $cells,
  ]);
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <?php if ($canManage): ?>
    <?php /* 등록·수정이 같은 폼이다. 수정은 ?edit=<id> 로 열리므로($editTarget) 그때는 열린 채로 뜬다. */ ?>
    <?php vg_modal_open('discoveryTarget', $editTarget !== null ? '대역 수정' : '대역 등록', '', $editTarget !== null); ?>
      <form method="post" class="setting-form" action="<?= vg_h(vg_qs(['edit' => null])) ?>">
        <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
        <input type="hidden" name="action" value="target_save">
        <input type="hidden" name="discovery_target_id" value="<?= (int) ($editTarget['discovery_target_id'] ?? 0) ?>">
        <div class="form-grid">
          <label class="field form-grid__full" for="discovery-cidr">대역 (CIDR)
            <input type="text" id="discovery-cidr" name="cidr" required maxlength="64" autocomplete="off"
                   placeholder="예: 10.3.142.0/24" value="<?= vg_h((string) ($editTarget['cidr'] ?? '')) ?>">
          </label>
          <label class="field" for="discovery-label">라벨 (선택)
            <input type="text" id="discovery-label" name="label" maxlength="255" autocomplete="off"
                   placeholder="예: 사무실 유선" value="<?= vg_h((string) ($editTarget['label'] ?? '')) ?>">
          </label>
          <label class="field" for="discovery-ports">포트 (선택)
            <input type="text" id="discovery-ports" name="ports" maxlength="1024" autocomplete="off"
                   placeholder="비우면 기본 세트" value="<?= vg_h((string) ($editTarget['ports'] ?? '')) ?>">
            <span class="why">콤마·범위로 지정: <code>22,80,443,8000-8100</code></span>
          </label>
          <?php /* 체크박스는 label.inline 이 가로로 세운다 — .field 는 세로 스택이라 글자가 위로 뜬다
                   (connectors 의 '활성' 체크박스가 같은 이유로 이 클래스를 쓴다). */ ?>
          <label class="inline form-grid__full" for="discovery-enabled">
            <input type="checkbox" id="discovery-enabled" name="enabled" value="1"
                   <?= $editTarget === null || (int) $editTarget['enabled'] === 1 ? 'checked' : '' ?>>
            사용
          </label>
        </div>
        <?php vg_modal_foot('저장', ['loading' => '저장 중…']); ?>
      </form>
    <?php vg_modal_close(); ?>
  <?php endif; ?>

  <?php vg_assets_render_install_modal(vg_ingest_url()); ?>
<?php vg_footer();
