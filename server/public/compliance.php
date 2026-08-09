<?php
declare(strict_types=1);

/**
 * compliance.php — KISA ISMS-P / ISO 27001 공통 통제항목 컴플라이언스 매핑. 로그인 필요.
 *   vuln-agent 가 이미 갖고 있는 findings/tb_host/tb_scan 데이터만으로 자동판정 가능한
 *   통제만 다룬다(정책 문서·승인이력처럼 사람이 심사해야 하는 항목은 판정 없이 체크리스트로만
 *   노출 — vuln-agent 가 못 채우는 걸 억지로 채우면 신뢰도만 깎인다).
 *   ingest 파이프라인은 건드리지 않는다 — 기존 데이터를 읽어 그때그때 판정만 한다.
 *
 *   이 파일은 **화면 렌더만** 한다(SRP). 판정 로직·스냅샷 적재는 server/src/compliance.php 가
 *   갖고 있고 스케줄러(bin/scheduler.php)와 공유한다 — 두 벌이면 화면과 증적이 서로 다른
 *   답을 내기 시작한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';
require_once __DIR__ . '/../src/compliance.php';   // 판정 로직(웹·CLI 공용)
vg_require_menu('findings');

$err = null;
$patch = ['violations' => [], 'total' => 0, 'unjudged' => 0, 'na' => [], 'na_unknown' => 0];
$asset = ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0, 'unjudged_rows' => []];
$secconfig = ['violations' => [], 'total' => 0];
$policy = ['kev' => VG_COMPLIANCE_SLA_KEV_DAYS, 'crit' => VG_COMPLIANCE_SLA_CRIT_DAYS,
           'high' => VG_COMPLIANCE_SLA_HIGH_DAYS, 'partial_max' => VG_COMPLIANCE_PARTIAL_MAX,
           'margin' => VG_COMPLIANCE_HISTORY_MARGIN_DAYS];
$trend = [];
$judgedAt = date('Y-m-d H:i');
$previewLimit = vg_ui_detail_preview_limit();
// findings 메뉴 권한만으로는 자산 인벤토리(assets 메뉴 전용 정보)를 우회 열람할 수 없게 별도 게이트.
$canViewAssets = vg_can('assets');

try {
    $pdo = vg_pdo();
    // 감사로그는 무거운 집계 **앞**에 남긴다 — 집계가 실패해도 "누가 이 증적 화면을 열었나"는 기록돼야 한다.
    vg_log_activity($pdo, 'PAGE', null, 'view_compliance', '컴플라이언스 매핑·판정 스냅샷 조회');
    $policy = vg_compliance_policy();   // 설정(tb_setting) 반영 — 세션락 해제 전에 한 번만 읽는다
    session_write_close();   // 인가·감사로그 이후 무거운 집계 전 세션락 해제(connectors.php 선례)
    $patch = vg_compliance_load_patch($pdo, $policy);
    if ($canViewAssets) {
        $asset = vg_compliance_load_asset($pdo, $previewLimit);
    }
    $secconfig = vg_compliance_load_secconfig($pdo, $previewLimit);
    $trend = vg_compliance_trend($pdo, vg_ui_trend_limit());
} catch (Throwable $e) {
    error_log('[compliance] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('컴플라이언스 매핑', 'compliance_mapping');
?>
  <?php vg_page_title(
      '컴플라이언스 매핑', 'COMPLIANCE',
      'KISA ISMS-P · ISO 27001 공통 통제항목을 vuln-agent 가 이미 수집한 데이터로 자동 판정합니다.'
  ); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else:
    $sPatch = vg_compliance_status($patch['total'], $patch['unjudged'] > 0, $policy['partial_max']);
    $sAsset = vg_compliance_status($asset['total'], $asset['unjudged'] > 0, $policy['partial_max']);
    $sSec   = vg_compliance_status($secconfig['total'], false, $policy['partial_max']);
?>
  <?php
  // KPI 의 숫자는 "위반 건수"다. 위반 0건이어도 판정 불가가 남아 있으면 그 사실을 라벨에 함께
  //   적는다 — 숫자 0 만 보고 준수로 읽히면 안 된다(톤도 ok=초록이 아니라 med=주의로 바뀐다).
  $naSuffix = static fn(array $s, int $unjudged): string =>
      $s['label'] === '판정 불가' ? ' · 판정 불가 ' . number_format($unjudged) . '건' : '';
  ?>
  <div class="cards">
    <div class="kpi kpi--sm tone-<?= vg_h($sPatch['tone']) ?>"><b><?= $patch['total'] ?></b><span>패치관리 위반<?= vg_h($naSuffix($sPatch, (int) $patch['unjudged'])) ?></span></div>
    <?php if ($canViewAssets): ?>
      <div class="kpi kpi--sm tone-<?= vg_h($sAsset['tone']) ?>"><b><?= $asset['total'] ?></b><span>자산식별 위반<?= vg_h($naSuffix($sAsset, (int) $asset['unjudged'])) ?></span></div>
    <?php endif; ?>
    <div class="kpi kpi--sm tone-<?= vg_h($sSec['tone']) ?>"><b><?= $secconfig['total'] ?></b><span>보안설정 위반</span></div>
  </div>

  <div class="card">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['patch']['label']) ?></strong>
          <span class="why"> — <?= vg_h(VG_COMPLIANCE_CONTROLS['patch']['framework']) ?></span>
        </div>
        <?= vg_badge($sPatch['label'], $sPatch['tone']) ?>
      </div>
      <p class="why">패치가 있는 CRITICAL·HIGH 중 SLA 초과분(KEV <?= (int) $policy['kev'] ?>일 ·
        CRITICAL <?= (int) $policy['crit'] ?>일 · HIGH <?= (int) $policy['high'] ?>일).
        위반 <?= number_format($patch['total']) ?>건 ·
        판정 불가 <?= number_format($patch['unjudged']) ?>건 · 판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php
      // 판정 불가 사유를 그대로 노출한다 — "위반 0건"이 왜 준수를 뜻하지 않는지 화면에서 설명하지
      //   않으면, 근거가 모자란 0건이 다시 준수처럼 읽힌다(허위 안심).
      if ($patch['unjudged'] > 0):
          $hints = [];
          foreach ($patch['na'] as $b) {
              $hints[] = sprintf(
                  '%s SLA %d일 · 보유 이력 최대 %d일 → 판정 불가 %s건%s',
                  $b['label'], (int) $b['sla_days'], (int) $b['max_history_days'], number_format((int) $b['count']),
                  $b['judgeable_from'] !== null ? ' (' . $b['judgeable_from'] . ' 이후 판정 가능)' : ''
              );
          }
          if ($patch['na_unknown'] > 0) {
              $hints[] = sprintf('최초 발견 시각을 확인할 수 없는 %s건 — 경과일을 계산할 수 없어 판정 불가',
                  number_format((int) $patch['na_unknown']));
          }
          vg_alert([
              'type'  => 'warn',
              'title' => '판정 불가 ' . number_format($patch['unjudged']) . '건 — 위반 0건이 곧 준수를 뜻하지 않습니다',
              'hints' => $hints,
          ]);
      endif; ?>
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

  <?php if ($canViewAssets): ?>
  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['asset']['label']) ?></strong>
          <span class="why"> — <?= vg_h(VG_COMPLIANCE_CONTROLS['asset']['framework']) ?></span>
        </div>
        <?= vg_badge($sAsset['label'], $sAsset['tone']) ?>
      </div>
      <p class="why">등록 자산 <?= number_format($asset['totalHosts']) ?>대 중 오프라인·수집없음이거나
        OS·IP 가 누락된 자산. 위반 <?= number_format($asset['total']) ?>건 · 판정 불가 <?= number_format($asset['unjudged']) ?>건 ·
        판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php if ($asset['unjudged'] > 0):
          $hints = [];
          foreach ($asset['unjudged_rows'] as $u) { $hints[] = $u['fqdn'] . ' — ' . $u['reason']; }
          if ($asset['unjudged'] > count($asset['unjudged_rows'])) {
              $hints[] = sprintf('외 %s대', number_format($asset['unjudged'] - count($asset['unjudged_rows'])));
          }
          vg_alert([
              'type'  => 'warn',
              'title' => '판정 불가 ' . number_format($asset['unjudged']) . '대 — 부분 수집(root 아님)이라 식별 근거가 빠져 있습니다',
              'hints' => $hints,
          ]);
      endif; ?>
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
  <?php endif; ?>

  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['secops']['label']) ?></strong>
          <span class="why"> — <?= vg_h(VG_COMPLIANCE_CONTROLS['secops']['framework']) ?></span>
        </div>
        <?= vg_badge($sSec['label'], $sSec['tone']) ?>
      </div>
      <p class="why">최신 스캔의 SCAP "설정 취약" 건수. 위반 <?= number_format($secconfig['total']) ?>건 ·
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

  <?php
  // --- 판정 추이(스냅샷) ---------------------------------------------------
  // 위 카드들은 "지금"만 말한다. 심사에서 필요한 건 "그 시점엔 어땠나" 라서, 스케줄러가
  //   하루 1건 남긴 스냅샷을 날짜별로 펼친다. 화면은 저장된 값을 읽기만 한다(재판정 안 함).
  $trendControls = ['patch'];
  if ($canViewAssets) { $trendControls[] = 'asset'; }   // 자산정보는 assets 권한자에게만(위 카드와 동일 게이트)
  $trendControls[] = 'secops';
  ?>
  <div class="card mt-lg">
    <div class="card__body">
      <strong>판정 추이</strong>
      <p class="why">하루 1건 저장되는 통제별 판정 스냅샷입니다.
        <?php if ($trend): ?>최근 <?= count($trend) ?>일치 · 최신 기록 <?= vg_h($trend[0]['taken_at']) ?><?php endif; ?></p>
      <?php if (!$trend): ?>
        <?php vg_empty([
            'icon'  => '🗓',
            'title' => '아직 저장된 판정 스냅샷이 없습니다.',
            'hint'  => '스케줄러가 하루 1회 자동으로 남깁니다.',
        ]); ?>
      <?php else: ?>
        <?php
        $headers = [['label' => '판정일', 'width' => '9rem']];
        $cells = [0 => fn($r) => vg_h($r['date'])];
        foreach ($trendControls as $i => $key) {
            $headers[] = ['label' => VG_COMPLIANCE_CONTROLS[$key]['label']];
            $cells[$i + 1] = static function ($r) use ($key) {
                $c = $r['controls'][$key] ?? null;
                if ($c === null) { return '<span class="why">기록 없음</span>'; }
                // 판정 불가는 "위반 0건"과 색(tone med)으로 구분되고, 몇 건이 판정 불가였는지도
                //   함께 적는다 — 저장된 0 만 보고 준수로 되읽히면 스냅샷이 허위 안심이 된다.
                $na = (int) ($c['unjudged'] ?? 0);
                return number_format($c['count']) . '건 '
                    . vg_badge($c['label'], vg_compliance_tone_of($c['label']))
                    . ($na > 0 ? ' <span class="why">판정 불가 ' . number_format($na) . '건</span>' : '');
            };
        }
        vg_table($headers, $trend, ['cell' => $cells, 'card' => false]);
        ?>
      <?php endif; ?>
    </div>
  </div>

  <div class="card mt-lg">
    <div class="card__body">
      <strong>수동 확인 필요</strong>
      <p class="why">자동판정 대상이 아닌 정책·승인이력류 통제입니다.
        판정 조건·근거는 저장소 문서 <code>docs/dev/화면-안내.md</code> 참고.</p>
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
