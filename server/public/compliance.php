<?php
declare(strict_types=1);

/**
 * compliance.php — KISA ISMS-P / ISO 27001 공통 통제항목 컴플라이언스 매핑. 로그인 필요.
 *   vuln-agent 가 이미 갖고 있는 findings/tb_host/tb_scan 데이터만으로 자동판정 가능한
 *   통제만 다룬다(정책 문서·승인이력처럼 사람이 심사해야 하는 항목은 판정 없이 체크리스트로만
 *   노출 — vuln-agent 가 못 채우는 걸 억지로 채우면 신뢰도만 깎인다).
 *   ingest 파이프라인은 건드리지 않는다 — 기존 데이터를 읽어 그때그때 판정만 한다(저장 없음).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';
vg_require_menu('findings');

// SLA 기준(하드코딩 상수 — 업계 관행값, 바뀔 일이 거의 없는 알려진 값이라 YAGNI 상 설정으로
//   빼지 않는다). KEV 등재가 가장 급하고, 그다음 CRITICAL, HIGH 순.
const VG_COMPLIANCE_SLA_KEV_DAYS  = 15;
const VG_COMPLIANCE_SLA_CRIT_DAYS = 30;
const VG_COMPLIANCE_SLA_HIGH_DAYS = 60;

// 위반 건수 → 준수 상태 컷라인. 세 통제가 전부 같은 어휘를 쓴다(사용자가 한 화면에서
//   "몇 건부터 부분준수인가"를 매 통제마다 다시 배우지 않게).
const VG_COMPLIANCE_PARTIAL_MAX = 5;   // 1~5건 = 부분준수, 6건 이상 = 미준수

/** 위반 건수 → ['label'=>..., 'tone'=>...]. 통제 3종이 공유하는 판정 어휘(SSOT). */
function vg_compliance_status(int $violations): array {
    if ($violations === 0) { return ['label' => '준수', 'tone' => 'ok']; }
    if ($violations <= VG_COMPLIANCE_PARTIAL_MAX) { return ['label' => '부분준수', 'tone' => 'high']; }
    return ['label' => '미준수', 'tone' => 'crit'];
}

/**
 * 통제 1: 패치관리(ISMS-P 2.10.8 / ISO 27001 A.8.8).
 *   판정: CRITICAL·HIGH 이면서 조치 가능(no_fix=0)한데 SLA 기준일을 넘겨 아직 살아있는 건.
 *   "최초 미조치 시각"은 tb_finding 에 없다(matcher 가 스캔마다 재작성 — 0009_findings_needs_restart.sql
 *   이후로도 추가 안 됨) — finding_history.php 의 first_found_at 계산(그 CVE+패키지가 처음
 *   나타난 스캔의 collected_at)과 같은 근사를 쓰되, 건별 반복 호출 대신 대상 호스트로만 좁힌
 *   배치 쿼리 1회로 묶는다(N+1 방지 — CLAUDE.md 인덱스 원칙).
 * @return array{violations: array<int, array<string, mixed>>, total: int}
 */
function vg_compliance_load_patch(PDO $pdo): array {
    // 호스트별 최신 scan_id 를 먼저 작은 결과로 뽑아 **리터럴 IN() 리스트**로 건넨다.
    //   findings.php 와 같은 이유(20260723093110_findings_scan_severity_index.sql 주석) —
    //   JOIN 으로 얽으면 옵티마이저가 tb_finding 을 드라이빙 테이블로 골라 idx_find_scan_sev
    //   를 안 타고 전체스캔한다(실측: EXPLAIN type=ALL, 21만행). scan_id IN(...) 리터럴이면
    //   그 인덱스를 그대로 탄다.
    $hosts = $pdo->query(
        'SELECT h.host_id, h.fqdn, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0'
    )->fetchAll();
    if (!$hosts) {
        return ['violations' => [], 'total' => 0];
    }
    $fqdnByScan = [];
    $hostIdByScan = [];
    foreach ($hosts as $h) {
        $fqdnByScan[(int) $h['scan_id']] = (string) $h['fqdn'];
        $hostIdByScan[(int) $h['scan_id']] = (int) $h['host_id'];
    }
    $scanIds = array_keys($fqdnByScan);

    // 지금 살아있는(최신 스캔) CRITICAL·HIGH·조치가능 건. idx_find_scan_sev(scan_id,severity) 를 탄다.
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $st = $pdo->prepare(
        "SELECT scan_id, container_id, cve_id, package_name, severity, in_kev
           FROM tb_finding
          WHERE scan_id IN ($in) AND severity IN ('CRITICAL','HIGH') AND no_fix = 0"
    );
    $st->execute($scanIds);
    $active = [];
    foreach ($st->fetchAll() as $r) {
        $sid = (int) $r['scan_id'];
        $r['host_id'] = $hostIdByScan[$sid] ?? 0;
        $r['fqdn'] = $fqdnByScan[$sid] ?? '';
        $active[] = $r;
    }
    if (!$active) {
        return ['violations' => [], 'total' => 0];
    }

    // 최초 발견 시각 배치 조회 — 대상 호스트로만 좁힌다(idx_scans_host_time 을 탄다).
    //   finding_history.php 의 vg_finding_history_summary() 와 같은 근사를 여러 건에 한 번에 적용.
    $hostIds = array_values(array_unique(array_map(static fn($r) => (int) $r['host_id'], $active)));
    $in = implode(',', array_fill(0, count($hostIds), '?'));
    $st = $pdo->prepare(
        "SELECT s2.host_id, f2.container_id, f2.cve_id, f2.package_name,
                MIN(COALESCE(s2.collected_at, s2.received_at)) AS first_seen
           FROM tb_scan s2
           JOIN tb_finding f2 ON f2.scan_id = s2.scan_id
          WHERE s2.host_id IN ($in) AND f2.severity IN ('CRITICAL','HIGH')
          GROUP BY s2.host_id, f2.container_id, f2.cve_id, f2.package_name"
    );
    $st->execute($hostIds);
    $firstSeenMap = [];
    foreach ($st->fetchAll() as $r) {
        $key = $r['host_id'] . '|' . $r['container_id'] . '|' . $r['cve_id'] . '|' . $r['package_name'];
        $firstSeenMap[$key] = $r['first_seen'];
    }

    $now = time();
    $violations = [];
    foreach ($active as $r) {
        $key = $r['host_id'] . '|' . $r['container_id'] . '|' . $r['cve_id'] . '|' . $r['package_name'];
        $firstSeen = $firstSeenMap[$key] ?? null;
        if ($firstSeen === null) { continue; }   // 최초 시각을 못 찾으면 판정 보류(과탐 방지)

        $days = (int) floor(($now - strtotime($firstSeen)) / 86400);
        $slaDays = $r['in_kev']
            ? VG_COMPLIANCE_SLA_KEV_DAYS
            : ($r['severity'] === 'CRITICAL' ? VG_COMPLIANCE_SLA_CRIT_DAYS : VG_COMPLIANCE_SLA_HIGH_DAYS);
        if ($days <= $slaDays) { continue; }

        $violations[] = [
            'host_id'   => (int) $r['host_id'],
            'fqdn'      => (string) $r['fqdn'],
            'cve_id'    => (string) $r['cve_id'],
            'package'   => (string) $r['package_name'],
            'severity'  => (string) $r['severity'],
            'in_kev'    => (bool) $r['in_kev'],
            'first_seen'=> $firstSeen,
            'days'      => $days,
            'sla_days'  => $slaDays,
        ];
    }
    usort($violations, static fn($a, $b) => $b['days'] <=> $a['days']);

    return ['violations' => $violations, 'total' => count($violations)];
}

/**
 * 통제 2: 정보자산 식별(ISMS-P 1.2.1 / ISO 27001 A.5.9).
 *   판정: 연결상태(assets.php 의 정상/지연/오프라인/수집없음 분류 재사용) 기준 오프라인·수집없음
 *   자산 + 필수 자산정보(OS·IP) 누락 자산. 같은 호스트가 두 사유에 다 걸려도 위반 1건으로 센다
 *   (사유별로 중복 집계하면 "위반 건수"가 자산 대수보다 부풀어 부분준수/미준수 컷라인의 의미가 흐려진다).
 * @return array{violations: array<int, array<string, mixed>>, total: int, totalHosts: int}
 */
function vg_compliance_load_asset(PDO $pdo): array {
    $latestSubq = vg_latest_scan_subq();
    $fromSql = 'FROM tb_host h
                LEFT JOIN ' . $latestSubq . ' t ON t.host_id = h.host_id
                LEFT JOIN tb_scan s ON s.scan_id = t.mid
                LEFT JOIN (
                    SELECT host_fqdn, MAX(last_seen_at) AS last_seen_at
                      FROM tb_agent_token
                     WHERE is_revoked = 0 AND is_deleted = 0
                     GROUP BY host_fqdn
                ) agent_seen ON agent_seen.host_fqdn = h.fqdn';
    // assets.php 의 $stateExpr 과 같은 식(같은 상수) — 다른 식을 쓰면 자산 화면과 다른 대수가 나온다.
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

    $totalHosts = (int) $pdo->query("SELECT COUNT(*) $fromSql WHERE h.is_deleted = 0")->fetchColumn();

    $st = $pdo->query(
        "SELECT h.host_id, h.fqdn, h.os_id, h.os_version, h.last_seen_ip, $stateExpr AS state
           $fromSql
          WHERE h.is_deleted = 0
            AND ($stateExpr IN ('offline','none')
                 OR h.os_id IS NULL OR h.os_id = ''
                 OR h.os_version IS NULL OR h.os_version = ''
                 OR h.last_seen_ip IS NULL OR h.last_seen_ip = '')
          ORDER BY h.fqdn"
    );
    $rows = $st->fetchAll();

    $violations = [];
    foreach ($rows as $r) {
        $reasons = [];
        if ($r['state'] === 'offline') { $reasons[] = '오프라인'; }
        if ($r['state'] === 'none') { $reasons[] = '수집없음'; }
        if (empty($r['os_id']) || empty($r['os_version'])) { $reasons[] = 'OS 정보 누락'; }
        if (empty($r['last_seen_ip'])) { $reasons[] = 'IP 정보 누락'; }
        $violations[] = [
            'host_id' => (int) $r['host_id'],
            'fqdn'    => (string) $r['fqdn'],
            'reasons' => $reasons,
        ];
    }

    return ['violations' => $violations, 'total' => count($violations), 'totalHosts' => $totalHosts];
}

/**
 * 통제 3: 보안시스템 운영(ISMS-P 2.10.1).
 *   판정: host.php 에 이미 있는 "설정 취약"(tb_cce_finding.result='FAIL') 판정을 최신 스캔
 *   기준으로 집계만 한다 — 판정 로직 자체는 새로 만들지 않는다(YAGNI).
 * @return array{violations: array<int, array<string, mixed>>, total: int}
 */
function vg_compliance_load_secconfig(PDO $pdo): array {
    $latestSubq = vg_latest_scan_subq();
    $st = $pdo->query(
        "SELECT t.host_id, h.fqdn, cf.code, cf.title, cf.severity, cf.rationale
           FROM tb_cce_finding cf
           JOIN $latestSubq t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
          WHERE cf.result = 'FAIL'
          ORDER BY FIELD(cf.severity,'HIGH','MEDIUM','LOW'), h.fqdn"
    );
    $rows = $st->fetchAll();
    $violations = [];
    foreach ($rows as $r) {
        $violations[] = [
            'host_id'   => (int) $r['host_id'],
            'fqdn'      => (string) $r['fqdn'],
            'code'      => (string) $r['code'],
            'title'     => (string) $r['title'],
            'severity'  => (string) $r['severity'],
            'rationale' => (string) ($r['rationale'] ?? ''),
        ];
    }
    return ['violations' => $violations, 'total' => count($violations)];
}

// 자동판정이 안 되는 통제 — 사람이 심사해야 하는 정책·승인이력류. 상태 판정 없이 항목명만.
const VG_COMPLIANCE_MANUAL_CHECKLIST = [
    ['ismsp' => 'ISMS-P 1.1.1~1.1.6 관리체계 기반 마련', 'iso' => 'ISO 27001 A.5.1 정보보안 정책',
     'desc' => '정보보안 정책·관리체계 범위가 문서로 수립·승인되어 있는가'],
    ['ismsp' => 'ISMS-P 2.5.1 사용자 계정 관리', 'iso' => 'ISO 27001 A.9.2 사용자 접근 관리',
     'desc' => '계정 발급·변경·해지에 대한 승인 이력이 남아있는가'],
    ['ismsp' => 'ISMS-P 2.5.3 접근권한 검토', 'iso' => 'ISO 27001 A.9.2.5 접근권한 검토',
     'desc' => '주기적으로 접근권한 적정성을 재검토하고 있는가'],
    ['ismsp' => 'ISMS-P 2.11.1 사고 예방 및 대응체계 구축', 'iso' => 'ISO 27001 A.5.24~A.5.28 정보보안 사고 관리',
     'desc' => '침해사고 대응 절차·연락체계가 문서화되어 있는가'],
    ['ismsp' => 'ISMS-P 2.12.1 재해복구 체계 구축', 'iso' => 'ISO 27001 A.5.29~A.5.30 업무연속성 관리',
     'desc' => '백업·복구 절차가 수립되고 정기적으로 검증되는가'],
];

$err = null;
$patch = ['violations' => [], 'total' => 0];
$asset = ['violations' => [], 'total' => 0, 'totalHosts' => 0];
$secconfig = ['violations' => [], 'total' => 0];
$judgedAt = date('Y-m-d H:i');

try {
    $pdo = vg_pdo();
    vg_log_activity($pdo, 'PAGE', null, 'view_compliance', '컴플라이언스 매핑 조회');
    $patch = vg_compliance_load_patch($pdo);
    $asset = vg_compliance_load_asset($pdo);
    $secconfig = vg_compliance_load_secconfig($pdo);
} catch (Throwable $e) {
    error_log('[compliance] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

$previewLimit = vg_ui_detail_preview_limit();

vg_header('컴플라이언스 매핑', 'compliance_mapping');
?>
  <?php vg_page_title(
      '컴플라이언스 매핑', 'COMPLIANCE',
      'KISA ISMS-P · ISO 27001 공통 통제항목을 vuln-agent 가 이미 수집한 데이터로 자동 판정합니다.'
  ); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else:
    $sPatch = vg_compliance_status($patch['total']);
    $sAsset = vg_compliance_status($asset['total']);
    $sSec   = vg_compliance_status($secconfig['total']);
?>
  <div class="cards">
    <div class="kpi kpi--sm tone-<?= vg_h($sPatch['tone']) ?>"><b><?= $patch['total'] ?></b><span>패치관리 위반</span></div>
    <div class="kpi kpi--sm tone-<?= vg_h($sAsset['tone']) ?>"><b><?= $asset['total'] ?></b><span>자산식별 위반</span></div>
    <div class="kpi kpi--sm tone-<?= vg_h($sSec['tone']) ?>"><b><?= $secconfig['total'] ?></b><span>보안설정 위반</span></div>
  </div>

  <div class="card">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong>패치관리</strong>
          <span class="why"> — ISMS-P 2.10.8 · ISO 27001 A.8.8</span>
        </div>
        <?= vg_badge($sPatch['label'], $sPatch['tone']) ?>
      </div>
      <p class="why">CRITICAL·HIGH 이면서 조치 가능(패치 존재)한데 SLA 기준일(KEV <?= VG_COMPLIANCE_SLA_KEV_DAYS ?>일 ·
        CRITICAL <?= VG_COMPLIANCE_SLA_CRIT_DAYS ?>일 · HIGH <?= VG_COMPLIANCE_SLA_HIGH_DAYS ?>일)을 넘겨 미조치 상태인 건수.
        위반 <?= number_format($patch['total']) ?>건 · 판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php if ($patch['violations']):
          $shown = array_slice($patch['violations'], 0, $previewLimit);
      ?>
        <?php vg_table(
            [
                ['label' => '호스트'],
                ['label' => 'CVE'],
                ['label' => '패키지'],
                ['label' => '등급', 'width' => '6.5rem'],
                ['label' => '최초 발견'],
                ['label' => '경과/기준'],
            ],
            $shown,
            [
                'cell' => [
                    0 => fn($v) => '<a href="/host.php?id=' . (int) $v['host_id'] . '">' . vg_h($v['fqdn']) . '</a>',
                    1 => fn($v) => '<a href="/cve.php?cve=' . urlencode($v['cve_id']) . '">' . vg_h($v['cve_id']) . '</a>',
                    2 => fn($v) => vg_h($v['package']),
                    3 => fn($v) => vg_sev_badge($v['severity']) . ($v['in_kev'] ? ' ' . vg_badge('KEV', 'crit') : ''),
                    4 => fn($v) => '<span class="why">' . vg_h((string) $v['first_seen']) . '</span>',
                    5 => fn($v) => $v['days'] . '일 / ' . $v['sla_days'] . '일',
                ],
            ]
        ); ?>
        <?php if ($patch['total'] > count($shown)): ?>
          <p class="why">상위 <?= count($shown) ?>건만 표시 · 전체 <?= number_format($patch['total']) ?>건은
            <a href="/findings.php?sev=CRITICAL">탐지 결과에서 확인</a></p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>

  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong>정보자산 식별</strong>
          <span class="why"> — ISMS-P 1.2.1 · ISO 27001 A.5.9</span>
        </div>
        <?= vg_badge($sAsset['label'], $sAsset['tone']) ?>
      </div>
      <p class="why">등록 자산 <?= number_format($asset['totalHosts']) ?>대 중 오프라인·수집없음이거나 필수 자산정보(OS·IP)가
        누락된 자산 건수. 위반 <?= number_format($asset['total']) ?>건 · 판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php if ($asset['violations']):
          $shown = array_slice($asset['violations'], 0, $previewLimit);
      ?>
        <?php vg_table(
            [['label' => '호스트'], ['label' => '사유']],
            $shown,
            [
                'cell' => [
                    0 => fn($v) => '<a href="/host.php?id=' . (int) $v['host_id'] . '">' . vg_h($v['fqdn']) . '</a>',
                    1 => fn($v) => implode(' · ', array_map('vg_h', $v['reasons'])),
                ],
            ]
        ); ?>
        <?php if ($asset['total'] > count($shown)): ?>
          <p class="why">상위 <?= count($shown) ?>건만 표시 · 전체는 <a href="/assets.php">자산 화면에서 확인</a></p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>

  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong>보안시스템 운영</strong>
          <span class="why"> — ISMS-P 2.10.1</span>
        </div>
        <?= vg_badge($sSec['label'], $sSec['tone']) ?>
      </div>
      <p class="why">최신 스캔 기준 보안설정 점검(SCAP) "설정 취약" 판정 건수. 위반 <?= number_format($secconfig['total']) ?>건 ·
        판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php if ($secconfig['violations']):
          $shown = array_slice($secconfig['violations'], 0, $previewLimit);
      ?>
        <?php vg_table(
            [['label' => '호스트'], ['label' => '항목'], ['label' => '등급', 'width' => '6.5rem'], ['label' => '근거']],
            $shown,
            [
                'cell' => [
                    0 => fn($v) => '<a href="/host.php?id=' . (int) $v['host_id'] . '&amp;tab=cce">' . vg_h($v['fqdn']) . '</a>',
                    1 => fn($v) => vg_h($v['title']) . ' <span class="why">' . vg_h($v['code']) . '</span>',
                    2 => fn($v) => vg_sev_badge($v['severity']),
                    3 => fn($v) => vg_trunc($v['rationale'], 80),
                ],
            ]
        ); ?>
        <?php if ($secconfig['total'] > count($shown)): ?>
          <p class="why">상위 <?= count($shown) ?>건만 표시</p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>

  <div class="card mt-lg">
    <div class="card__body">
      <strong>수동 확인 필요</strong>
      <p class="why">vuln-agent 가 자동판정할 수 없는 정책·승인이력류 통제입니다. 상태 판정 없이 점검 항목만 안내합니다.</p>
      <ul class="hint-list">
        <?php foreach (VG_COMPLIANCE_MANUAL_CHECKLIST as $item): ?>
          <li><?= vg_h($item['ismsp']) ?> · <?= vg_h($item['iso']) ?><br>
            <span class="why"><?= vg_h($item['desc']) ?></span></li>
        <?php endforeach; ?>
      </ul>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
