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
$patch = ['violations' => [], 'total' => 0, 'unjudged' => 0, 'na' => [], 'na_unknown' => 0, 'buckets' => []];
$asset = ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0, 'unjudged_rows' => []];
$secconfig = ['violations' => [], 'total' => 0];
$account = ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0,
            'unjudged_rows' => [], 'pending_hosts' => 0];
$review = ['violations' => [], 'total' => 0, 'unjudged' => 0,
           'interval_days' => VG_COMPLIANCE_ACCESS_REVIEW_DAYS, 'last' => null, 'days_since' => null];
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
    // 계정 정보는 자산 인벤토리보다 민감하다(계정명·sudo 권한자 목록) — 자산과 같은 게이트를 건다.
    if ($canViewAssets) {
        $account = vg_compliance_load_account($pdo, $previewLimit);
    }
    $review = vg_compliance_load_access_review($pdo);
    $trend = vg_compliance_trend($pdo, vg_ui_trend_limit());
} catch (Throwable $e) {
    error_log('[compliance] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('컴플라이언스 매핑', 'compliance_mapping');
?>
  <?php vg_page_title(
      '컴플라이언스 매핑', 'COMPLIANCE',
      '수집 데이터로 ISMS-P·ISO 27001 통제 5종을 판정합니다 · ' . $judgedAt
  ); ?>
  <?php
  // 이름이 비슷해 헷갈리는 두 화면을 나란히 세운다 — 여기는 **판정**(준수/미준수/판정 불가),
  //   통제 기준 매핑은 같은 CCE 점검 결과를 기준별 통제로 **묶어 보기만** 한다(판정 안 함).
  vg_subtabs([
      'compliance'      => ['label' => '컴플라이언스 매핑', 'href' => '/compliance.php'],
      'control_mapping' => ['label' => '통제 기준 매핑',   'href' => '/control_mapping.php'],
  ], 'compliance');
  ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else:
    $sPatch = vg_compliance_status($patch['total'], $patch['unjudged'] > 0, $policy['partial_max']);
    $sAsset = vg_compliance_status($asset['total'], $asset['unjudged'] > 0, $policy['partial_max']);
    $sSec   = vg_compliance_status($secconfig['total'], false, $policy['partial_max']);
    $sAcct  = vg_compliance_status($account['total'], $account['unjudged'] > 0, $policy['partial_max']);
    $sRev   = vg_compliance_status($review['total'], false, $policy['partial_max']);
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
    <?php if ($canViewAssets): ?>
      <div class="kpi kpi--sm tone-<?= vg_h($sAcct['tone']) ?>"><b><?= $account['total'] ?></b><span>계정관리 위반<?= vg_h($naSuffix($sAcct, (int) $account['unjudged'])) ?></span></div>
    <?php endif; ?>
    <div class="kpi kpi--sm tone-<?= vg_h($sRev['tone']) ?>"><b><?= $review['total'] ?></b><span>권한검토 위반</span></div>
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
      <?php // 건수·판정 시각은 위 KPI 카드와 페이지 부제가 이미 말한다 — 여기는 "무엇을 셌는가"만. ?>
      <p class="why">조치 가능한 CRITICAL·HIGH 취약점의 SLA 초과분. 버킷별로 따로 판정합니다.</p>
      <?php
      // 버킷 3행을 각각 판정한다. 예전엔 통제 전체에 뱃지 하나만 달아, 이력이 짧아 판정 불가인
      //   HIGH 하나가 잘 지킨 KEV·CRITICAL 까지 회색으로 눌렀다(운영 실측).
      //   같은 말을 하던 노란 경고 박스는 이 표로 대체됐다 — 설명 두 벌은 화면만 길게 만든다.
      vg_table(
          [
              ['label' => '버킷', 'width' => '7rem'],
              ['label' => 'SLA', 'width' => '5rem', 'align' => 'right'],
              ['label' => '판정', 'width' => '7rem'],
              ['label' => '위반', 'width' => '5rem', 'align' => 'right'],
              ['label' => '판정 불가', 'width' => '6rem', 'align' => 'right'],
              ['label' => '근거'],
          ],
          $patch['buckets'],
          [
              'card' => false,
              'cell' => [
                  0 => fn($b) => vg_h((string) $b['label']),
                  1 => fn($b) => (int) $b['sla_days'] . '일',
                  2 => static function ($b) use ($policy) {
                      // 대상이 0건이면 준수도 위반도 아니다 — "대상 없음"으로 따로 말한다.
                      if ((int) $b['targets'] === 0) { return vg_badge('대상 없음', 'muted'); }
                      $s = vg_compliance_status((int) $b['violations'], (int) $b['unjudged'] > 0, $policy['partial_max']);
                      return vg_badge($s['label'], $s['tone']);
                  },
                  3 => fn($b) => number_format((int) $b['violations']) . '건',
                  4 => fn($b) => number_format((int) $b['unjudged']) . '건',
                  5 => static function ($b) {
                      $sla = max(1, (int) $b['sla_days']);
                      if ((int) $b['targets'] === 0) {
                          $restart = (int) $b['restart_excluded'];
                          return '<span class="why">판정 대상 없음'
                              . ($restart > 0 ? ' · 재시작 대기 ' . number_format($restart) . '건 제외' : '')
                              . '</span>';
                      }
                      if ((int) $b['unjudged'] > 0) {
                          // 이력이 SLA 에 얼마나 찼는지를 게이지로 — "언제부터 판정되는가"가 사용자의 질문이다.
                          $hist = (int) $b['max_history_days'];
                          $txt = '보유 이력 최대 ' . $hist . '일 / SLA ' . $sla . '일'
                               . ($b['judgeable_from'] !== null ? ' · ' . $b['judgeable_from'] . ' 이후 판정 가능' : '');
                          return vg_meter('med', $hist / $sla * 100, $txt) . '<span class="why">' . vg_h($txt) . '</span>';
                      }
                      return '<span class="why">판정 대상 ' . number_format((int) $b['targets']) . '건'
                          . ((int) $b['restart_excluded'] > 0
                              ? ' · 재시작 대기 ' . number_format((int) $b['restart_excluded']) . '건 제외' : '')
                          . '</span>';
                  },
              ],
          ]
      ); ?>
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
                ['label' => '경과/기준', 'align' => 'right'],   // "12일 / 30일" — 숫자 칸
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
      <p class="why">등록 <?= number_format($asset['totalHosts']) ?>대 중 오프라인·수집 없음 또는 OS·IP 누락 자산</p>
      <?php if ($asset['unjudged'] > 0):
          $hints = [];
          foreach ($asset['unjudged_rows'] as $u) { $hints[] = $u['fqdn'] . ' — ' . $u['reason']; }
          if ($asset['unjudged'] > count($asset['unjudged_rows'])) {
              $hints[] = sprintf('외 %s대', number_format($asset['unjudged'] - count($asset['unjudged_rows'])));
          }
          vg_alert([
              'type'  => 'warn',
              'title' => '판정 불가 ' . number_format($asset['unjudged']) . '대 · 부분 수집으로 식별 근거가 부족합니다',
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
      <p class="why">최신 스캔에서 FAIL로 판정된 보안 설정</p>
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

  <?php if ($canViewAssets): ?>
  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['account']['label']) ?></strong>
          <span class="why"> — <?= vg_h(VG_COMPLIANCE_CONTROLS['account']['framework']) ?></span>
        </div>
        <?= vg_badge($sAcct['label'], $sAcct['tone']) ?>
      </div>
      <p class="why">호스트 <?= number_format($account['totalHosts']) ?>대의 최신 계정 인벤토리 판정입니다.</p>
      <?php
      // REVIEW(추정)·NA(원자료 미수집)·수집 대기는 준수로 흡수하지 않는다 — 계정 목록이 아직
      //   안 들어온 호스트를 준수로 세면 그 자체가 허위 안심이다.
      if ($account['unjudged'] > 0):
          $hints = [];
          foreach ($account['unjudged_rows'] as $u) {
              $hints[] = $u['fqdn'] . ' · ' . $u['title'] . '(' . $u['result'] . ') — ' . $u['reason'];
          }
          if ($account['unjudged'] > count($account['unjudged_rows'])) {
              $hints[] = sprintf('외 %s건', number_format($account['unjudged'] - count($account['unjudged_rows'])));
          }
          vg_alert([
              'type'  => 'warn',
              'title' => '판정 불가 ' . number_format($account['unjudged']) . '건'
                       . ($account['pending_hosts'] > 0
                          ? ' · 계정 수집 대기 ' . number_format($account['pending_hosts']) . '대' : ''),
              'hints' => $hints,
          ]);
      endif; ?>
      <?php if ($account['violations']):
          $shown = array_slice($account['violations'], 0, $previewLimit);
      ?>
        <?php vg_table(
            [['label' => '호스트'], ['label' => '점검 항목'], ['label' => '결과', 'width' => '6rem'], ['label' => '근거']],
            $shown,
            [
                'cell' => [
                    0 => fn($v) => '<a href="/host.php?id=' . (int) $v['host_id'] . '&amp;tab=account">' . vg_h($v['fqdn']) . '</a>',
                    1 => fn($v) => vg_h($v['title']) . ' <span class="why">' . vg_h($v['code']) . '</span>',
                    2 => fn($v) => vg_badge($v['result'], 'crit'),
                    // 계정명 등 근거 문자열. 패스워드 해시·비밀값은 수집·저장 자체를 하지 않는다.
                    3 => fn($v) => vg_trunc(implode(', ', $v['names']), 80),
                ],
            ]
        ); ?>
        <?php if ($account['total'] > count($shown)): ?>
          <p class="why">상위 <?= count($shown) ?>건만 표시 · 전체 <?= number_format($account['total']) ?>건은
            호스트 상세의 계정 탭에서 확인</p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['access_review']['label']) ?></strong>
          <span class="why"> — <?= vg_h(VG_COMPLIANCE_CONTROLS['access_review']['framework']) ?></span>
        </div>
        <?= vg_badge($sRev['label'], $sRev['tone']) ?>
      </div>
      <p class="why">검토 주기 <?= (int) $review['interval_days'] ?>일 · 접속기록 점검 이력으로 판정합니다.</p>
      <?php if ($review['last'] !== null): ?>
        <p class="why">최근 검토 <?= vg_h($review['last']['reviewed_at']) ?>
          (<?= vg_h($review['last']['period_start']) ?> ~ <?= vg_h($review['last']['period_end']) ?>)
          · <?= (int) $review['days_since'] ?>일 경과</p>
      <?php endif; ?>
      <?php if ($review['violations']): ?>
        <?php vg_table(
            [['label' => '사유'], ['label' => '근거']],
            $review['violations'],
            ['cell' => [0 => fn($v) => vg_h($v['reason']), 1 => fn($v) => '<span class="why">' . vg_h($v['detail']) . '</span>']]
        ); ?>
      <?php endif; ?>
      <p class="why"><a href="/activity.php">접속기록 화면에서 점검 기록 남기기</a></p>
    </div>
  </div>

  <?php
  // --- 판정 추이(스냅샷) ---------------------------------------------------
  // 위 카드들은 "지금"만 말한다. 심사에서 필요한 건 "그 시점엔 어땠나" 라서, 스케줄러가
  //   하루 1건 남긴 스냅샷을 날짜별로 펼친다. 화면은 저장된 값을 읽기만 한다(재판정 안 함).
  $trendControls = ['patch'];
  if ($canViewAssets) { $trendControls[] = 'asset'; }   // 자산정보는 assets 권한자에게만(위 카드와 동일 게이트)
  $trendControls[] = 'secops';
  if ($canViewAssets) { $trendControls[] = 'account'; } // 계정 통제도 같은 게이트
  $trendControls[] = 'access_review';
  ?>
  <div class="card mt-lg">
    <div class="card__body">
      <strong>판정 추이</strong>
      <p class="why">일별 판정 스냅샷<?php if ($trend): ?> · 최근 <?= count($trend) ?>일 · 최신 <?= vg_h($trend[0]['taken_at']) ?><?php endif; ?></p>
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
      <?php // 증적이 제품 밖(문서·절차)에 있는 항목만 남았다 — 기본은 접어 두고 요약 줄만 보인다. ?>
      <details>
        <summary>수동 확인 필요 <?= count(VG_COMPLIANCE_MANUAL_CHECKLIST) ?>건 — 정책·절차 문서(자동판정 불가)</summary>
        <ul class="hint-list">
          <?php foreach (VG_COMPLIANCE_MANUAL_CHECKLIST as $item): ?>
            <li><?= vg_h($item['ismsp']) ?> · <?= vg_h($item['iso']) ?><br>
              <span class="why"><?= vg_h($item['desc']) ?></span></li>
          <?php endforeach; ?>
        </ul>
      </details>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
