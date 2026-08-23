<?php
declare(strict_types=1);

/**
 * discovery.php — 자산 탐색(섀도우 IT). 자산 목록의 서브탭. 열람은 assets 메뉴 권한.
 *   이 화면이 답하는 질문은 하나다: **"내가 모르는 자산이 몇 대인가."**
 *   에이전트를 설치한 서버만 아는 상태로는 담당자가 엑셀에서 빠뜨린 자산을 구조적으로 못 찾는다.
 *
 *   취약점 수집과 **별개 파이프라인**이다(Nexpose·Nessus 의 Discovery/Vulnerability 분리와 같은 구도).
 *   두 파이프라인의 접점은 IP 대조 한 곳뿐 — tb_discovered_asset.host_id.
 *
 *   ★ 웹은 대역 탐색을 직접 돌리지 않는다. 이 화면은 tb_discovery_run 에 status='pending' 행을
 *     만들기만 하고, 집행은 스케줄러 틱(bin/scheduler.php, 1분마다)이 한다 — 대역 전체를 훑는
 *     무거운 작업이라 웹 요청을 막지 않도록 bin/ CLI 로 분리했다. 수동으로는
 *     `php bin/discover.php --pending` 이 같은 함수를 부른다. 화면은 status 를 읽어 보여준다.
 *
 *   인가 경계 두 단:
 *     · 대역 등록·수정·삭제 · 대역 탐색 실행  → **admin** (남의 대역을 훑는 것은 관리 행위다)
 *     · 제외 표시·메모                   → **admin·operator** (매일 도는 분류 작업)
 *   제외·메모는 행마다 입력창을 세우지 않고 **표에서 고른 뒤 모달**로 한꺼번에 건다.
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
/** 한 행에 펼치는 열린 포트 수. 나머지는 개수와 툴팁으로만 말한다 — 여섯 개를 늘어놓으면
 *   행마다 줄 수가 달라져 표가 울퉁불퉁해졌다(사용자 지적). */
const VG_DISCOVERY_PORTS_SHOWN = 3;
/* 정리(제외·메모) 조작 어휘 — 모달의 선택지·감사로그 문구·POST 검증이 이 하나만 본다.
 *   '제외 해제' 를 따로 두는 건 여러 건을 한 번에 걸 때 토글이 행마다 다르게 튀기 때문이다. */
const VG_DISCOVERY_TRIAGE_OPS = ['ignore' => '제외로 표시', 'unignore' => '제외 해제', 'note' => '메모 저장'];
/** 한 번에 정리할 수 있는 발견 자산 수. 한 페이지 최대치(100)보다 넉넉하되 무한 POST 는 막는다. */
const VG_DISCOVERY_TRIAGE_MAX = 500;

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

/**
 * 제목 줄의 주 동작 — '대역 탐색'. 이 화면의 주 동작인데 예전에는 대역 카드 안에서 '수정·삭제'
 *   와 같은 무게로 놓여 눈에 안 들어왔다(사용자 지적). 카드 안 버튼은 없애고 여기 하나만 둔다 —
 *   버튼 수는 대역이 몇 개든 하나로 고정된다.
 *   대역이 하나면 그대로 실행하고, 여럿이면 어느 대역인지 고르게 한다. 선택지는 **지금 실행할 수
 *   있는 대역**만이다(사용 중지·이미 대기/진행 중인 대역은 어차피 POST 처리부가 거부한다).
 */
function vg_discovery_run_form(array $runnable, string $csrf): void
{
    if (!$runnable) {
        echo '<button type="button" class="btn btn--sm btn--primary" disabled'
            . ' title="지금 탐색할 수 있는 대역이 없습니다 — 사용 중지했거나 이미 대기·진행 중입니다.">대역 탐색</button>';
        return;
    }
    $one = count($runnable) === 1 ? $runnable[0] : null;
    ?>
    <form method="post" class="actions">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="scan">
      <?php if ($one !== null): ?>
        <input type="hidden" name="discovery_target_id" value="<?= (int) $one['discovery_target_id'] ?>">
      <?php else: ?>
        <select name="discovery_target_id" aria-label="탐색할 대역">
          <?php foreach ($runnable as $t): ?>
            <option value="<?= (int) $t['discovery_target_id'] ?>"><?= vg_h((string) $t['cidr']) ?></option>
          <?php endforeach; ?>
        </select>
      <?php endif; ?>
      <button class="btn btn--sm btn--primary" data-loading="요청 중…"
              title="<?= $one !== null ? vg_h((string) $one['cidr']) . ' 대역을 훑습니다' : '고른 대역을 훑습니다' ?>">대역 탐색</button>
    </form>
    <?php
}

$pdo = vg_pdo();

/* ── POST 처리 — GET 렌더보다 먼저·헤더 출력 전이어야 한다(전부 PRG 로 끝난다). ───────── */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        vg_redirect_flash(['err' => '세션이 만료되었습니다.']);
    }
    $action = (string) ($_POST['action'] ?? '');
    $me     = vg_current_user();
    $canManage = vg_has_role('admin');                 // 대역·탐색
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
            if (!$canManage) { throw new RuntimeException('대역 탐색을 실행할 권한이 없습니다.'); }
            $id = (int) ($_POST['discovery_target_id'] ?? 0);
            $st = $pdo->prepare(
                'SELECT cidr, enabled FROM tb_discovery_target WHERE discovery_target_id = ? AND is_deleted = 0'
            );
            $st->execute([$id]);
            $target = $st->fetch();
            if (!$target) { throw new RuntimeException('대역을 찾을 수 없습니다.'); }
            if ((int) $target['enabled'] !== 1) { throw new RuntimeException('사용 안 함으로 둔 대역은 탐색하지 않습니다.'); }
            /* 중복 실행 방지 — 버튼은 진행 중이면 이미 막혀 있지만, 두 사람이 동시에 눌렀거나
             *   조작된 POST 가 오면 여기서 걸린다(화면 숨김은 인가가 아니다와 같은 이유). */
            $busy = $pdo->prepare(
                "SELECT COUNT(*) FROM tb_discovery_run
                  WHERE discovery_target_id = ? AND is_deleted = 0 AND status IN ('pending','running')"
            );
            $busy->execute([$id]);
            if ((int) $busy->fetchColumn() > 0) {
                throw new RuntimeException('이미 대기 중이거나 진행 중인 탐색이 있습니다.');
            }
            $ins = $pdo->prepare(
                "INSERT INTO tb_discovery_run (discovery_target_id, status, created_by) VALUES (?, 'pending', ?)"
            );
            $ins->execute([$id, $me['id'] ?? null]);
            $runId = (int) $pdo->lastInsertId();
            /* "누가 어느 대역을 탐색했나" 는 이 기능에서 가장 중요한 기록이다. */
            vg_log_activity($pdo, 'DISCOVERY_RUN', $runId, 'discovery_scan_request',
                '대역 탐색 요청: ' . $target['cidr'],
                ['cidr' => $target['cidr'], 'discovery_target_id' => $id],
                subject: (string) $target['cidr'], action: 'EXECUTE');
            vg_redirect_flash(['msg' => '대역 탐색을 대기열에 넣었습니다: ' . $target['cidr'] . ' (집행기가 순서대로 처리합니다)']);

        } elseif ($action === 'asset_triage') {
            /* 제외·메모는 **표에서 고른 자산에 한꺼번에** 건다(행마다 입력창을 세우지 않는다 —
             *   자산 목록의 등급 일괄 확정과 같은 방식). 조작은 셋으로 나뉜다:
             *     ignore/unignore = 상태만, note = 메모만. 예전의 toggle 은 여러 건을 한 번에
             *     걸 때 "지금 상태의 반대" 가 행마다 달라져 결과를 예측할 수 없어 갈랐다. */
            if (!$canTriage) { throw new RuntimeException('발견 자산을 정리할 권한이 없습니다.'); }
            $op = (string) ($_POST['op'] ?? '');
            if (!isset(VG_DISCOVERY_TRIAGE_OPS[$op])) { throw new RuntimeException('알 수 없는 정리 작업입니다.'); }
            $ids = array_values(array_unique(array_filter(
                array_map('intval', (array) ($_POST['discovered_asset_ids'] ?? [])),
                static fn(int $id): bool => $id > 0
            )));
            if (!$ids) { throw new RuntimeException('정리할 발견 자산을 표에서 고르세요.'); }
            if (count($ids) > VG_DISCOVERY_TRIAGE_MAX) {
                throw new RuntimeException('한 번에 ' . VG_DISCOVERY_TRIAGE_MAX . '건까지 정리할 수 있습니다.');
            }
            $note = mb_substr(trim((string) ($_POST['note'] ?? '')), 0, 500);

            // 감사로그에 IP 를 남겨야 하므로 대상부터 확인한다(없는 id 는 여기서 걸러진다).
            $in = implode(',', array_fill(0, count($ids), '?'));
            $st = $pdo->prepare(
                "SELECT discovered_asset_id, ip FROM tb_discovered_asset
                  WHERE discovered_asset_id IN ($in) AND is_deleted = 0"
            );
            $st->execute($ids);
            $assets = $st->fetchAll();
            if (!$assets) { throw new RuntimeException('발견 자산을 찾을 수 없습니다.'); }
            $ids = array_map(static fn(array $a): int => (int) $a['discovered_asset_id'], $assets);
            $in  = implode(',', array_fill(0, count($ids), '?'));

            if ($op === 'ignore') {
                $pdo->prepare("UPDATE tb_discovered_asset SET state = 'ignored' WHERE discovered_asset_id IN ($in)")
                    ->execute($ids);
            } elseif ($op === 'unignore') {
                /* 해제하면 자동 판정 자리로 되돌린다 — host_id 가 있으면 관리 중, 없으면 미관리.
                 *   반대로 ignored 는 사람이 정한 값이라 집행기의 자동 판정이 덮지 않는다(스키마 주석). */
                $pdo->prepare(
                    "UPDATE tb_discovered_asset SET state = IF(host_id IS NULL, 'new', 'known')
                      WHERE discovered_asset_id IN ($in) AND state = 'ignored'"
                )->execute($ids);
            } else {
                $pdo->prepare("UPDATE tb_discovered_asset SET note = ? WHERE discovered_asset_id IN ($in)")
                    ->execute(array_merge([$note !== '' ? $note : null], $ids));
            }

            $label = $op === 'note' && $note === '' ? '메모 삭제' : VG_DISCOVERY_TRIAGE_OPS[$op];
            // 감사로그는 자산마다 남긴다 — "어느 IP 를 누가 제외했나" 가 이 기능의 기록이다.
            foreach ($assets as $a) {
                vg_log_activity($pdo, 'DISCOVERED_ASSET', (int) $a['discovered_asset_id'], 'discovered_asset_triage',
                    $label . ': ' . $a['ip'], ['ip' => $a['ip'], 'op' => $op],
                    subject: (string) $a['ip'], action: 'UPDATE');
            }
            vg_redirect_flash(['msg' => $label . ' — 발견 자산 ' . count($ids) . '건']);
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
$stateCounts = array_fill_keys(array_keys(VG_DISCOVERY_STATES), 0);
$targetStateCounts = [];
$rows = [];
$portsByAsset = [];
$total = 0;

try {
    /* 대역 + 그 대역의 **마지막 탐색**. 대역은 사람이 손으로 등록하는 것이라 수십 건 규모다
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

    /* 대역별 상태 배지 · 랭킹 차트가 쓰는 값 — 대역을 골랐으면 그 대역만, 아니면 화면에 남아
     *   있는(is_deleted=0) 대역들로 좁힌다. 상단 KPI(307-313)와 같은 필터를 따라야 대역을
     *   골랐을 때 KPI 는 줄고 카드·랭킹은 전체 그대로인 어긋남이 생기지 않는다. */
    $targetIdsForCounts = $targetId > 0
        ? [$targetId]
        : array_map(static fn(array $t): int => (int) $t['discovery_target_id'], $targets);
    if ($targetIdsForCounts) {
        $tin = implode(',', array_fill(0, count($targetIdsForCounts), '?'));
        $tsc = $pdo->prepare(
            "SELECT discovery_target_id, state, COUNT(*) AS n FROM tb_discovered_asset
              WHERE is_deleted = 0 AND discovery_target_id IN ($tin) GROUP BY discovery_target_id, state"
        );
        $tsc->execute($targetIdsForCounts);
        foreach ($tsc->fetchAll() as $r) {
            $tid = (int) $r['discovery_target_id'];
            if (!isset($targetStateCounts[$tid])) { $targetStateCounts[$tid] = array_fill_keys(array_keys(VG_DISCOVERY_STATES), 0); }
            if (isset($targetStateCounts[$tid][(string) $r['state']])) {
                $targetStateCounts[$tid][(string) $r['state']] = (int) $r['n'];
            }
        }
    }

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
    if ($q !== '')     {
        $where .= ' AND (da.ip LIKE ? OR da.hostname LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_discovered_asset da WHERE $where");
    $cnt->execute($params);
    $total  = (int) $cnt->fetchColumn();
    $offset = ($page - 1) * $perPage;

    /* 호스트·대역은 각각 한 번의 LEFT JOIN 으로 붙인다(행마다 다시 묻지 않는다 — N+1 금지).
     *   LIMIT/OFFSET 은 화이트리스트로 검증된 정수라 문자열로 넣어도 주입면이 없다. */
    $lst = $pdo->prepare(
        "SELECT da.discovered_asset_id, da.ip, da.hostname, da.state, da.note, da.first_seen, da.last_seen,
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
            "SELECT dp.discovered_asset_id, dp.port, dp.proto, dp.service_hint, dp.banner
               FROM tb_discovered_port dp
               JOIN tb_discovered_asset da ON da.discovered_asset_id = dp.discovered_asset_id
                                          AND da.last_run_id = dp.discovery_run_id
              WHERE dp.is_deleted = 0 AND dp.discovered_asset_id IN ($in)
              ORDER BY dp.discovered_asset_id, dp.port"
        );
        $ps->execute($ids);
        foreach ($ps->fetchAll() as $p) {
            $portsByAsset[(int) $p['discovered_asset_id']][] = [
                'port'   => (int) $p['port'],
                'proto'  => (string) $p['proto'],
                'hint'   => $p['service_hint'] !== null ? (string) $p['service_hint'] : '',
                'banner' => $p['banner'] !== null ? (string) $p['banner'] : '',
            ];
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

/* 제목 줄의 '대역 탐색' 이 고를 수 있는 대역 — 사용 중이고, 이미 대기·진행 중이 아닌 것.
 *   판정 자체는 POST 처리부가 다시 한다(화면에서 고르는 것은 인가도 검증도 아니다). */
$runnableTargets = array_values(array_filter($targets, static fn(array $t): bool =>
    (int) $t['enabled'] === 1 && !in_array((string) ($t['status'] ?? ''), ['pending', 'running'], true)));

vg_header('자산 탐색', 'discovery');
?>
  <?php /* 제목 줄이 이 화면의 액션 자리다 — '+ 대역 등록' 이 먼저 올라와 있었고(#733),
           이 화면의 **주 동작**인 '대역 탐색' 을 그 앞에 같이 올린다. 예전엔 대역 카드 안에서
           '수정·삭제' 옆에 있어 부수 동작과 같은 무게로 읽혔다(사용자 지적).
           대역이 하나도 없으면 할 일은 등록뿐이라 그때만 등록이 강조된다.
           인가 조건은 그대로 $canManage(대역·탐색은 admin). */ ?>
  <?php vg_page_title('자산 탐색', 'DISCOVERY', [
      'suffix_html' => vg_help('대역을 훑어 살아있는 IP 를 모읍니다. 에이전트가 대상 서버 안을 읽는 취약점 수집과는 별개입니다.'),
      'actions' => vg_capture(static function () use ($canManage, $targets, $runnableTargets, $csrf): void {
          if ($canManage && $targets) { vg_discovery_run_form($runnableTargets, $csrf); }
          if ($canManage) {
              vg_modal_btn('discoveryTarget', '+ 대역 등록', 'btn btn--sm ' . ($targets ? 'btn--ghost' : 'btn--primary'));
          }
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

  <?php /* ── 대역 · 탐색 ─────────────────────────────────────────────────── */ ?>
  <?php
  /* 대역을 골랐으면 카드·랭킹도 그 대역만 보인다 — 상단 KPI 만 줄고 카드는 전체 그대로면
   *   같은 화면에서 숫자가 어긋난다. */
  $visibleTargets = $targetId > 0
      ? array_values(array_filter($targets, static fn(array $t): bool => (int) $t['discovery_target_id'] === $targetId))
      : $targets;

  /* 대역별 발견 건수 랭킹 — 표 열로는 안 보이던 "어느 대역이 발견량 대부분을 차지하는가" 를
   *   막대 길이로 비교한다(packages.php 의 패키지별 CVE 랭킹과 같은 패턴).
   *   막대 하나짜리는 비교가 아니라 장식이라, 값이 있는 대역이 2곳 이상일 때만 그린다. */
  $rankItems = [];
  foreach ($visibleTargets as $t) {
      $tid = (int) $t['discovery_target_id'];
      $sc  = $targetStateCounts[$tid] ?? array_fill_keys(array_keys(VG_DISCOVERY_STATES), 0);
      $tf  = $sc['new'] + $sc['known'] + $sc['ignored'];
      if ($tf > 0) {
          $rankItems[] = [
              'label' => (string) $t['cidr'] . ($t['label'] !== null && $t['label'] !== '' ? ' · ' . (string) $t['label'] : ''),
              'value' => $tf,
              'tone'  => $sc['new'] > 0 ? 'crit' : 'ok',
              'href'  => vg_qs(['target' => $tid, 'page' => null, 'edit' => null]),
          ];
      }
  }
  if (count($rankItems) >= 2): ?>
    <div class="card">
      <strong>대역별 발견 자산</strong>
      <div class="card__body"><?php vg_rank_bars($rankItems, ['unit' => '건']); ?></div>
    </div>
  <?php endif; ?>

  <?php if (!$targets): ?>
    <div class="card">
      <?php vg_empty($canManage ? [
          'icon' => 'search', 'title' => '등록된 대역이 없습니다.',
          'hint' => '훑을 대역을 등록하면 그 안의 살아있는 IP 를 모읍니다.',
      ] : [
          'icon' => 'search', 'title' => '등록된 대역이 없습니다.',
          'hint' => '대역 등록은 관리자만 할 수 있습니다.',
      ]); ?>
    </div>
  <?php else: ?>
    <div class="discovery-targets">
      <?php foreach ($visibleTargets as $t):
          $tid    = (int) $t['discovery_target_id'];
          $sc     = $targetStateCounts[$tid] ?? array_fill_keys(array_keys(VG_DISCOVERY_STATES), 0);
          $status = (string) ($t['status'] ?? '');
      ?>
        <?php /* 탐색 포트는 대역의 설정값이라 카드에서 한 줄을 먹을 값이 아니다 — 대역 옆
                 툴팁으로 내린다(바꾸는 자리는 '수정' 모달이 그대로 갖는다). */ ?>
        <?php $portsTip = '탐색 포트 · ' . ($t['ports'] !== null && $t['ports'] !== ''
            ? (string) $t['ports'] : '기본 세트'); ?>
        <div class="card discovery-target">
          <div class="discovery-target__head">
            <code title="<?= vg_h($portsTip) ?>"><?= vg_h((string) $t['cidr']) ?></code>
            <?= (int) $t['enabled'] === 1 ? vg_badge('사용', 'ok') : vg_badge('중지', 'muted') ?>
          </div>
          <?php if ($t['label'] !== null && $t['label'] !== ''): ?>
            <div class="why"><?= vg_h((string) $t['label']) ?></div>
          <?php endif; ?>

          <?php /* 이 대역의 발견 자산을 상태별로 몇 건씩 물고 있는지 — 0건인 상태는 뺀다(자산 목록
                   KPI 와 같은 규칙: '미관리 0' 에 강조 테두리를 붙이면 경고로 잘못 읽힌다). */ ?>
          <div class="discovery-target__badges">
            <?php foreach (VG_DISCOVERY_STATES as $key => $label): ?>
              <?php if ($sc[$key] > 0): ?>
                <?= vg_badge(number_format($sc[$key]) . ' ' . $label, VG_DISCOVERY_TONES[$key]) ?>
              <?php endif; ?>
            <?php endforeach; ?>
          </div>

          <?php /* 마지막 탐색 — 얼마나 걸렸는지가 운영자에게 중요하다(대역을 더 넓힐지 판단한다).
                   실패는 **일반화된 문구**만 낸다: error_text 원문에는 대상 주소·예외 원문이 섞인다. */ ?>
          <div class="discovery-target__scan">
            <?php
            if ($status === '') { echo '<span class="why">탐색 이력 없음</span>'; }
            elseif ($status === 'pending') { echo vg_badge('대기 중', 'med') . ' <span class="why">집행기 대기</span>'; }
            elseif ($status === 'running') { echo vg_badge('진행 중', 'high')
                . ' <span class="why">' . vg_h(substr((string) ($t['started_at'] ?? ''), 0, 16)) . ' 시작</span>'; }
            elseif ($status === 'failed') { echo vg_badge('실패', 'crit')
                . ' <span class="why">탐색이 실패했습니다. 서버 로그를 확인하세요.</span>'; }
            else {
                /* 카드에 남는 건 '언제 끝났나' 뿐이다 — 응답 IP·포트 시도·열린 포트·소요는
                 *   한 카드 안에서 줄바꿈을 만들던 스캔 통계라 툴팁으로 내린다(사용자 지적). */
                $at   = substr((string) ($t['finished_at'] ?? ''), 0, 16);
                $stat = '응답 IP ' . number_format((int) $t['ip_alive']) . '/' . number_format((int) $t['ip_total'])
                    . ' · 포트 시도 ' . number_format((int) $t['port_checked'])
                    . ' · 열린 포트 ' . number_format((int) $t['open_total'])
                    . ($t['elapsed_seconds'] !== null ? ' · ' . (string) $t['elapsed_seconds'] . '초' : '');
                echo vg_badge('완료', 'ok') . ' <span class="why" title="' . vg_h($stat) . '">'
                    . vg_h($at) . '</span>';
            }
            ?>
          </div>

          <?php /* 실행은 카드가 아니라 제목 줄의 '대역 탐색' 이 갖는다 — 카드마다 버튼을 되살리면
                   대역 수만큼 같은 버튼이 늘어나고, 주 동작이 다시 '수정·삭제' 와 같은 무게가 된다.
                   진행 상태는 위의 뱃지(대기 중·진행 중·완료)가 그대로 말한다. */ ?>
          <?php if ($canManage): ?>
            <div class="actions discovery-target__ops mt">
              <a class="btn btn--xs btn--ghost" href="<?= vg_h(vg_qs(['edit' => $tid])) ?>">수정</a>
              <form method="post" data-confirm="이 대역을 삭제할까요? 지금까지 발견한 자산 이력은 남습니다.">
                <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
                <input type="hidden" name="action" value="target_delete">
                <input type="hidden" name="discovery_target_id" value="<?= $tid ?>">
                <button class="btn btn--xs btn--ghost">삭제</button>
              </form>
            </div>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php /* ── 발견 자산 ────────────────────────────────────────────────────── */ ?>
  <?php vg_toolbar([
      ['type' => 'select', 'name' => 'state', 'empty_label' => '전체 상태',
       'selected' => $state, 'options' => VG_DISCOVERY_STATES],
      ...($targetOptions ? [['type' => 'select', 'name' => 'target', 'empty_label' => '전체 대역',
       'selected' => $targetId > 0 ? (string) $targetId : '', 'options' => $targetOptions]] : []),
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'IP · 호스트명 검색', 'value' => $q],
  ]); ?>

  <?php
  $filtered = ($q !== '' || $state !== '' || $targetId > 0);
  /* 이 페이지 행들의 대역. 하나뿐이면 표 제목 옆에 한 번만 적고 행에서는 뺀다 — 예전엔 같은
   *   CIDR 이 행마다 반복돼 IP 칸의 절반이 같은 글자였다(사용자 지적). 여럿이면 행이 갖는다. */
  $pageCidrs = array_values(array_unique(array_map(static fn(array $r): string => (string) $r['cidr'], $rows)));
  $pageCidr  = count($pageCidrs) === 1 ? $pageCidrs[0] : null;
  /* 열은 'key' 로 찾는다 — 정리 권한이 있으면 앞에 선택 열이 붙는데, 인덱스로 맞춰 두면
   *   그때마다 칸 콜백이 한 칸씩 밀린다(자산 목록의 표도 같은 이유로 key 를 쓴다). */
  $headers = [
      ['label' => 'IP', 'key' => 'ip', 'width' => '10rem'],
      ['label' => '상태', 'key' => 'state', 'width' => '6rem'],
      ['label' => '열린 포트 · 서비스(추측)', 'key' => 'ports'],
      /* 두 날짜를 나란히 두던 자리다 — 실측으로 거의 모든 행이 같은 값이라 한 칸을 통째로
       *   같은 글자에 쓰고 있었다. 칸에는 최근만 적고 최초는 툴팁이 갖는다. */
      ['label' => '발견', 'key' => 'seen', 'width' => '9rem', 'nowrap' => true,
       'title' => '최근 발견 시각. 최초 발견은 값에 마우스를 올리면 보인다.'],
      ['label' => '연결된 자산', 'key' => 'host', 'width' => '14rem'],
  ];
  $cells = [
      /* IP 아래 두 번째 줄에 역DNS 호스트명을 붙인다 — **열을 늘리지 않는다**(화면 정리 국면).
       *   호스트명이 없으면 지금까지처럼 대역만 보인다(빈 자리표시를 만들지 않는다). */
      'ip' => function ($r) use ($pageCidr): string {
          $html = '<code>' . vg_h((string) $r['ip']) . '</code>';
          $hostname = trim((string) ($r['hostname'] ?? ''));
          if ($hostname !== '') {
              $html .= '<div class="why">' . vg_trunc($hostname, 28) . '</div>';
          }
          // 대역은 페이지 안에서 갈릴 때만 행이 적는다 — 하나뿐이면 표 제목이 이미 말했다.
          if ($pageCidr === null) {
              $html .= '<div class="why">' . vg_h((string) $r['cidr']) . '</div>';
          }
          /* 메모는 사람이 "이게 무엇인가" 를 적어 둔 값이라 정체를 말하는 IP 칸에 붙인다.
           *   열을 따로 세우지 않는다 — 메모가 있는 행은 드물고, 있을 때만 한 줄 늘어난다. */
          $note = trim((string) ($r['note'] ?? ''));
          if ($note !== '') {
              $html .= '<div class="why" title="' . vg_h($note) . '">메모 · ' . vg_trunc($note, 28) . '</div>';
          }
          return $html;
      },
      'state' => fn($r) => vg_badge(
          VG_DISCOVERY_STATES[(string) $r['state']] ?? (string) $r['state'],
          VG_DISCOVERY_TONES[(string) $r['state']] ?? 'muted'
      ),
      /* 포트 옆의 서비스는 **포트 번호 관례에서 유추한 추측**이다(22 가 항상 SSH 는 아니다).
       *   그래서 '?' 를 붙이고 열 제목에도 그 사실을 적는다 — 단정형으로 쓰면 사람이 확인을 건너뛴다.
       *   배너(HTTP Server 헤더·TLS 인증서 CN)는 열로 늘리지 않고 있을 때만 한 줄 덧붙인다. */
      'ports' => function ($r) use ($portsByAsset): string {
          $ports = $portsByAsset[(int) $r['discovered_asset_id']] ?? [];
          if (!$ports) { return '<span class="why">없음</span>'; }
          $label = static fn(array $p): string => $p['port'] . '/' . $p['proto']
              . ($p['hint'] !== '' ? ' ' . mb_strimwidth($p['hint'], 0, 14, '…') . '?' : '');
          $shown = array_slice($ports, 0, VG_DISCOVERY_PORTS_SHOWN);
          /* 툴팁이 전부를 갖는다 — 포트 전체와 배너(HTTP Server 헤더·TLS 인증서 CN). 배너를
           *   목록에서 뺀 이유가 이것이다: 행마다 줄을 하나 더 만들어 표를 울퉁불퉁하게 했다. */
          $tip = implode(' · ', array_map($label, $ports));
          $banners = [];
          foreach ($ports as $p) {
              if ($p['banner'] !== '') { $banners[] = $p['port'] . ' ' . $p['banner']; }
          }
          if ($banners) { $tip .= ' / 배너 · ' . implode(' · ', $banners); }
          return '<span title="' . vg_h($tip) . '"><b>' . number_format(count($ports)) . '</b>'
              . '<span class="why">개</span> <code>'
              . vg_h(mb_strimwidth(implode(' · ', array_map($label, $shown)), 0, 44, '…')) . '</code></span>';
      },
      'seen' => fn($r) => '<span class="why" title="'
          . vg_h('최초 발견 ' . substr((string) $r['first_seen'], 0, 16)
                 . ' · 최근 발견 ' . substr((string) $r['last_seen'], 0, 16)) . '">'
          . vg_h(substr((string) $r['last_seen'], 0, 16)) . '</span>',
      /* 이 열이 이 기능의 결론 동선이다 — 모르는 자산을 찾았으면 에이전트를 깔고 취약점
       *   취약점 수집으로 넘어간다. 그래서 연결이 없을 때 막다른 칸이 아니라 설치 안내로 잇는다. */
      'host' => function ($r): string {
          if ((int) ($r['host_id'] ?? 0) > 0 && $r['fqdn'] !== null) {
              return '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h((string) $r['fqdn']) . '</a>';
          }
          if ((string) $r['state'] === 'ignored') { return '<span class="why">제외됨</span>'; }
          return vg_capture(static function (): void {
              vg_modal_btn('agentInstall', '에이전트 설치 안내', 'btn btn--xs btn--ghost');
          });
      },
  ];
  /* 정리 조작은 **행이 아니라 선택**에 붙는다 — 예전엔 모든 행에 메모 입력창과 버튼 둘이
   *   상시로 붙어 있어, 10행이면 입력창 10개·버튼 20개가 표 오른쪽을 채웠다.
   *   여기 남는 건 체크박스 한 칸뿐이고, 입력(메모)과 제출은 표 위 버튼이 여는 모달이 갖는다. */
  if ($canTriage) {
      array_unshift($headers, [
          'label' => '', 'key' => 'pick', 'width' => '2.5rem', 'align' => 'center',
          'label_html' => '<input type="checkbox" data-checkall="discovered_asset_ids[]"'
              . ' aria-label="이 페이지 전체 선택" title="이 페이지 전체 선택">',
      ]);
      $cells['pick'] = fn($r) => '<input type="checkbox" name="discovered_asset_ids[]" value="'
          . (int) $r['discovered_asset_id'] . '" aria-label="' . vg_h((string) $r['ip']) . ' 선택">';
  }

  /* 표와 모달을 한 폼으로 감싼다 — 네이티브 dialog 는 렌더링만 top-layer 로 올라가고 DOM 상
   *   폼 소속은 그대로라, 표의 체크박스와 모달의 메모가 한 번에 전송된다(자산 목록과 같은 구조). */
  if ($canTriage) {
      echo '<form method="post">';
      echo '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">';
      echo '<input type="hidden" name="action" value="asset_triage">';
  }
  if ($rows): ?>
    <div class="form-bar">
      <?php /* 표 제목 줄. 대역이 하나면 여기서 한 번만 말한다(행에서는 뺐다).
               정리 버튼도 이 줄을 같이 쓴다 — 예전엔 비활성 버튼 하나가 한 줄을 통째로 먹었다. */ ?>
      <span class="form-bar__cap">발견 자산<?php if ($pageCidr !== null): ?>
        <span class="why" title="이 페이지에 뜬 발견 자산이 모두 이 대역이다 — 대역 필터와는 별개다."><?= vg_h($pageCidr) ?></span><?php endif; ?></span>
      <?php if ($canTriage): ?>
        <?php /* 선택 0개면 비활성. 개수 갱신·활성화·톤 전환은 app.js 의 위임 핸들러가 한다.
                 적용 범위(이 페이지에서 고른 것만)는 모달의 '적용 범위' 가 이미 말하므로
                 여기 title 로 겹쳐 적지 않는다 — 누를 수 없는 버튼은 툴팁도 안 뜬다. */ ?>
        <button type="button" class="btn btn--sm btn--ghost" data-modal="discoveryTriage"
                data-bulk-open="discovered_asset_ids[]" data-bulk-label="선택 {n}개 정리" disabled>선택 0개 정리</button>
        <noscript>
          <?php /* 스크립트가 꺼져 있으면 모달이 안 열린다 — 대체 경로는 값이라 남긴다. */ ?>
          <span class="why">스크립트가 꺼져 있어 제외·메모를 쓸 수 없다.</span>
        </noscript>
      <?php endif; ?>
    </div>
  <?php endif; ?>
  <?php
  vg_table($headers, $rows, [
      'empty' => $filtered ? [
          'icon' => 'search', 'title' => '조건에 맞는 발견 자산이 없습니다.',
          'cta' => ['href' => '/discovery.php', 'label' => '필터 초기화'],
      ] : [
          'icon' => 'search', 'title' => '아직 발견된 자산이 없습니다.',
          'hint' => '대역을 등록하고 "대역 탐색" 을 누르면 집행기가 순서대로 훑습니다.',
      ],
      'cell' => $cells,
  ]);
  if ($rows) { vg_page_nav($total, $perPage, $page); }

  /* 정리 모달 — 폼 **안**이라야 표의 체크박스가 같이 실려 간다(밖에 두면 0건으로 간다). */
  if ($canTriage && $rows) {
      vg_modal_open('discoveryTriage', '선택 발견 자산 정리');
      ?>
      <label for="triage-op">할 일</label>
      <?php /* 어휘는 VG_DISCOVERY_TRIAGE_OPS 가 소유한다 — 선택지 문구를 여기서 다시 적지 않는다. */ ?>
      <select id="triage-op" name="op" required>
        <?php foreach (VG_DISCOVERY_TRIAGE_OPS as $v => $opLabel): ?>
          <option value="<?= vg_h($v) ?>"><?= vg_h($opLabel) ?></option>
        <?php endforeach; ?>
      </select>

      <label for="triage-note">메모</label>
      <input id="triage-note" type="text" name="note" maxlength="500"
             placeholder="예: 프린터 · 스위치 · 게이트웨이">
      <dl class="criteria">
        <dt>제외</dt>
        <dd>커버리지 분모에서 뺍니다. ‘제외 해제’ 로 되돌립니다.</dd>
        <dt>메모</dt>
        <dd>‘메모 저장’ 일 때만 덮어씁니다(비우면 지웁니다).</dd>
        <dt>적용 범위</dt>
        <dd>지금 보고 있는 페이지에서 고른 자산만, 한 번에 <?= VG_DISCOVERY_TRIAGE_MAX ?>건까지. 자산마다 감사로그가 남습니다.</dd>
      </dl>
      <?php vg_modal_foot('적용', ['loading' => '적용 중…', 'cancel' => '취소']);
      vg_modal_close();
  }
  if ($canTriage) { echo '</form>'; }
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
