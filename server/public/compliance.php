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
vg_require_menu('compliance');

$err = null;
$patch = ['violations' => [], 'total' => 0, 'unjudged' => 0, 'na' => [], 'na_unknown' => 0, 'buckets' => []];
$asset = ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0, 'unjudged_rows' => []];
$secconfig = ['violations' => [], 'total' => 0, 'checked' => 0];
$account = ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0,
            'unjudged_rows' => [], 'pending_hosts' => 0];
$policy = ['kev' => VG_COMPLIANCE_SLA_KEV_DAYS, 'crit' => VG_COMPLIANCE_SLA_CRIT_DAYS,
           'high' => VG_COMPLIANCE_SLA_HIGH_DAYS, 'partial_max' => VG_COMPLIANCE_PARTIAL_MAX,
           'margin' => VG_COMPLIANCE_HISTORY_MARGIN_DAYS];
$trend = [];
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
    $trend = vg_compliance_trend($pdo, vg_ui_trend_limit());
} catch (Throwable $e) {
    error_log('[compliance] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('컴플라이언스 매핑', 'compliance_mapping');
?>
  <?php // 제목은 계열 이름만 — 어느 화면인지는 바로 아래 서브탭이 말한다(예전엔 같은 말이 두 줄이었다). ?>
  <?php vg_page_title('컴플라이언스', 'COMPLIANCE'); ?>
  <?php // 통제 기준 매핑은 사이드바에 없고 이 줄로만 들어온다(정의는 nav.php 한 곳). ?>
  <?php vg_compliance_subtabs('mapping'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else:
    $sPatch = vg_compliance_status($patch['total'], $patch['unjudged'] > 0, $policy['partial_max']);
    $sAsset = vg_compliance_status($asset['total'], $asset['unjudged'] > 0, $policy['partial_max']);
    $sSec   = vg_compliance_status($secconfig['total'], false, $policy['partial_max']);
    $sAcct  = vg_compliance_status($account['total'], $account['unjudged'] > 0, $policy['partial_max']);

?>
  <?php
  // 결론 배너는 걷었다 — "통제 4종 중 1종이 미준수입니다" 는 바로 아래 표가 통제마다
  //   뱃지로 이미 말하던 것을 문장으로 되풀이한 줄이었다. 권한 때문에 빠진 통제도 표의
  //   '권한 없음' 행이 그대로 말한다(일부만 센 걸 숨기지 않는다는 원칙은 그 행이 지킨다).
  ?><section id="automatic" data-compliance-zone="automatic" aria-label="자동 판정과 조치 근거"><?php
  ?>

  <?php
  // 첫 화면은 **통제 1종당 한 줄**. 예전엔 통제마다 호스트별 위반을 10건씩 미리 깔아서,
  //   정작 "무엇이 준수이고 무엇이 아닌가"가 스크롤 아래로 밀렸다. 전체를 보려면 어차피
  //   그 근거만 보여주는 다른 화면으로 가야 하므로, 여기서는 판정만 세우고 근거는 링크로 보낸다.
  //   판정·건수는 위 vg_compliance_status() 결과 그대로다(요약 방식만 바뀐다).
  // 판정 불가 건수 부기("· 판정 불가 232건")는 걷었다 — 통제 4종이 전부 같은 문구를 달고 있어
  //   화면이 "체크되지 않은 것" 목록처럼 읽혔다. **판정 자체는 그대로다**: 판정 불가인 통제는
  //   판정 칸의 뱃지가 그대로 '판정 불가' 로 말하고(준수로 바꾸지 않는다), 건수와 사유는
  //   스냅샷 증적(JSON)에 계속 저장된다.
  // 요약 칸은 **건수만** 적는다. 뒤에 잇던 분모 설명("— 조치 대상 232건 중 SLA 초과분")은
  //   무엇을 셌는지 풀어 쓴 문장이라 걷었다 — 그 분모는 옆 판정 칸 게이지의 title 이 그대로
  //   갖고 있고, 더 필요하면 '근거 →' 가 가리키는 상세 화면이 답한다.
  // 판정 칸: 뱃지 **아래에 비율 게이지**를 깐다. 게이지가 없으면 "위반 174건"이 큰 수인지
  //   작은 수인지 읽을 방법이 없었다(분모가 화면에 없었다). 요약 칸이 아니라 판정 칸에
  //   두는 건 두 가지 이유다 — (1) 게이지는 그 판정의 근거지 요약문의 일부가 아니고,
  //   (2) 요약 칸에 3번째 줄로 넣으면 행이 85px 이 돼 통제 목록이 첫 화면 밖으로 밀린다.
  //   meter 는 톤이 crit/high/med/low 뿐이다(app.css) — 'ok' 는 low 로 떨군다. 준수면 채움이
  //   0% 라 색이 보이지도 않지만, 존재하지 않는 클래스를 만들지는 않는다.
  // $what 은 **막대가 무엇의 비율인가** 를 말하는 짧은 라벨이다. 없을 때는 붉은 막대가 꽉 찬 행이
  //   "위반율 100%" 인지 "판정 진행률" 인지 화면만 보고는 알 수 없었다(마우스를 올려야만 알았다).
  //   막대 바로 위에 라벨을 적는다 — packages.php 의 EPSS·조치율 게이지와 같은 규약이다
  //   (막대 위 글자가 그 막대의 라벨).
  //   **값은 라벨에 붙이지 않는다** — "위반율 0.0%" 와 옆 칸 "위반 0건" 은 같은 말이라 한 행에
  //   두 번 적히던 것이었다. 건수는 요약 칸이 갖고, 비율과 분모는 지금처럼 vg_meter 의
  //   title/aria-label 이 갖는다(막대 길이도 그 비율이다).
  $verdictCell = static function (array $s, ?float $pct, string $why, string $what = ''): string {
      $badge = vg_badge($s['label'], $s['tone']);
      if ($pct === null) { return $badge; }
      $val = number_format($pct, 1) . '%';
      return $badge . ' <span class="why">' . vg_h($what) . '</span>'
          . vg_meter($s['tone'] === 'ok' ? 'low' : $s['tone'], $pct, $what . ' ' . $val . ' · ' . $why);
  };
  // 통제별 분모. 판정 기준이 아니라 **표시용**이다(무엇이 위반인지는 그대로다).
  $patchTargets = 0;
  foreach ($patch['buckets'] as $b) { $patchTargets += (int) $b['targets']; }
  // 계정은 위반이 호스트당 여러 건 나올 수 있어 건수/대수의 분모가 다르다 — 게이지는
  //   "몇 대에서 위반이 나왔나"로 잡는다(건수를 호스트 수로 나누면 100% 를 넘는다).
  $acctViolHosts = count(array_unique(array_column($account['violations'], 'host_id')));
  // assets 권한이 없으면 자산·계정 통제는 **건수까지 감춘다**(위반 수 자체가 자산 정보다).
  //   줄을 통째로 빼지 않는 이유: 이 화면의 존재 이유가 "통제 ↔ 조항" 매핑이라,
  //   권한에 따라 통제가 줄어 보이면 매핑 자체를 잘못 읽게 된다.
  $deniedRow = static fn(string $key): array => [
      'key' => $key, 'badge' => vg_badge('권한 없음', 'muted'),
      'summary' => '<span class="why">자산 열람 권한이 필요합니다</span>', 'link' => '',
  ];

  // 계정 통제의 접힘 상세를 실제로 그리는가 — 요약 줄의 앵커 링크와 조건이 어긋나면
  //   눌러도 아무 데도 안 가는 링크가 된다(그래서 한 변수로 묶어 둔다).
  //   판정 불가·수집 대기만 있을 때는 이 블록을 아예 안 그린다: 예전엔 위반이 0건인데도
  //   "판정 불가 25건" 한 줄짜리 접힘만 남아, 근거 블록이 근거 없이 자리만 차지했다.
  $acctDetails = $canViewAssets && (bool) $account['violations'];

  $summaryRows = [];
  // $why 는 화면에 문장으로 안 나온다 — 게이지의 title/aria-label 이 갖는 분모다.
  $whyPatch = '조치 대상 ' . number_format($patchTargets) . '건 중 SLA 초과분';
  $summaryRows[] = [
      'key' => 'patch',
      'badge' => $verdictCell($sPatch, $patchTargets > 0 ? $patch['total'] / $patchTargets * 100 : null,
          $whyPatch, '위반율'),
      'summary' => '위반 ' . number_format((int) $patch['total']) . '건',
      // 이 통제가 센 것 = 조치 가능한 미조치 취약점. findings 의 fx=action 이 같은 모집단이다
      //   (SLA 초과 필터는 없으므로 건수는 여기가 더 적다 — 링크 라벨을 "근거"로만 둔다).
      'link' => '<a href="/findings.php?type=cve&amp;fx=action">근거 →</a>',
  ];
  $whyAsset = '등록 ' . number_format((int) $asset['totalHosts']) . '대 중 · 오프라인·수집없음·OS/IP 누락';
  $summaryRows[] = $canViewAssets ? [
      'key' => 'asset',
      'badge' => $verdictCell($sAsset,
          $asset['totalHosts'] > 0 ? $asset['total'] / $asset['totalHosts'] * 100 : null, $whyAsset, '위반율'),
      'summary' => '위반 ' . number_format((int) $asset['total']) . '건',
      'link' => '<a href="/assets.php">근거 →</a>',
  ] : $deniedRow('asset');
  $whySec = '최신 스캔 점검 ' . number_format((int) $secconfig['checked']) . '건 중 FAIL 판정';
  $summaryRows[] = [
      'key' => 'secops',
      'badge' => $verdictCell($sSec,
          $secconfig['checked'] > 0 ? $secconfig['total'] / $secconfig['checked'] * 100 : null, $whySec, '위반율'),
      'summary' => '위반 ' . number_format((int) $secconfig['total']) . '건',
      // 보안설정(CCE) 위반 목록 전용 탭. 기본 필터가 res=FAIL 이라 이 통제가 센 것과 같다.
      'link' => '<a href="/findings.php?type=cce">근거 →</a>',
  ];
  $whyAcct = '호스트 ' . number_format((int) $account['totalHosts']) . '대 중 위반 '
           . number_format($acctViolHosts) . '대'
           . ($account['pending_hosts'] > 0
              ? ' · 수집 대기 ' . number_format((int) $account['pending_hosts']) . '대' : '');
  $summaryRows[] = $canViewAssets ? [
      'key' => 'account',
      // 이 통제만 게이지 분모가 **호스트 수**다(위반은 호스트당 여러 건 나온다) — 라벨도
      //   '위반율' 이 아니라 '위반 호스트' 로 다르게 적는다. 같은 말로 적으면 옆 행과 같은
      //   비율인 줄 읽힌다.
      'badge' => $verdictCell($sAcct,
          $account['totalHosts'] > 0 ? $acctViolHosts / $account['totalHosts'] * 100 : null,
          $whyAcct, '위반 호스트'),
      'summary' => '위반 ' . number_format((int) $account['total']) . '건',
      // 전 호스트 계정 위반을 한 번에 보는 화면은 없다(호스트별로만 있다). 없는 화면을
      //   만들어 링크하지 않고, 이 통제만 아래 근거 블록에 호스트별 링크를 둔다.
      'link' => $acctDetails ? '<a href="#compliance-account">호스트별 ↓</a>' : '',
  ] : $deniedRow('account');

  vg_table(
      [
          ['label' => '통제'],
          // 13rem 은 실측값이다 — 9rem 은 물론 12rem 에서도 가장 긴 뱃지+라벨 조합
          //   ('판정 불가' + '위반 호스트 0.0%')이 두 줄로 접혀 그 행만 20px 높아졌다.
          ['label' => '판정', 'width' => '13rem'],
          ['label' => '요약'],
          // 링크 라벨은 짧다 — 접히면 화살표가 다음 줄로 떨어져 링크로 안 보인다.
          ['label' => '근거', 'width' => '7rem', 'nowrap' => true],
      ],
      $summaryRows,
      [
          'cell' => [
              // 조항 번호(ISMS-P 2.10.8 / ISO 27001 A.8.8)는 통제 상세(control.php)가 갖는다 —
              //   목록에서 통제명마다 잇던 줄은 걷었다. 여기서 고르는 축은 통제이지 조항이 아니다.
              0 => fn($r) => '<strong>' . vg_h(VG_COMPLIANCE_CONTROLS[$r['key']]['label']) . '</strong>',
              1 => fn($r) => $r['badge'],
              2 => fn($r) => $r['summary'],
              3 => fn($r) => $r['link'],
          ],
      ]
  );
  // 판정 칸의 색이 무슨 뜻인지 한 줄로. 어휘·톤은 vg_compliance_tone_of() 가 SSOT 라
  //   여기서 색을 새로 정하지 않는다(같은 말이 두 벌이 되면 표와 범례가 갈라진다).
  vg_legend([
      ['label' => '준수',      'tone' => vg_compliance_tone_of('준수')],
      ['label' => '부분준수',   'tone' => vg_compliance_tone_of('부분준수')],
      ['label' => '미준수',     'tone' => vg_compliance_tone_of('미준수')],
      ['label' => '판정 불가',  'tone' => vg_compliance_tone_of('판정 불가')],
  ], ['inline' => true, 'caption' => '판정']);
  ?>
  </section>

  <?php
  // ── 접기 기준(이 화면 전체에 적용) ──────────────────────────────────────
  // 접는 건 "행이 실제로 많아 아래 블록을 화면 밖으로 밀어낼 때"뿐이다. 즉 한 블록의
  //   행 수가 미리보기 상한(vg_ui_detail_preview_limit(), 기본 10행)을 넘길 때만 접는다.
  //   예전엔 3~5행짜리 블록까지 전부 <details> 로 닫혀 있어서, 화면 아래 절반이 회색 띠
  //   4줄(내용 0)이었다 — "판정 불가 203건"의 이유가 그 안에 있는데도 안 보였다.
  //   지금 접혀 있는 건 판정 추이의 오래된 날짜뿐이다(스냅샷은 최대 50일까지 쌓인다).
  ?>
  <?php if ($acctDetails): ?>
  <div class="card mt-lg" id="compliance-account">
    <?php
    // 이 블록은 이 화면에만 있다 — 전 호스트 계정 위반을 한 번에 보는 화면이 없어서
    //   요약 줄의 "근거 →" 가 갈 곳이 없다. 표시되는 행은 미리보기 상한 이하라 펼쳐 둔다.
    ?>
    <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['account']['label']) ?> — 호스트별 근거</strong>
    <div class="card__body">
      <?php
      // 판정 불가(REVIEW·NA)·수집 대기 목록은 화면에서 걷었다. 위반이 아니라 "아직 못 봤다"인
      //   행이라 여기서 근거로 읽히지 않고, 접힘 요약("판정 불가 25건")만 남아 화면을 어지럽혔다.
      //   **판정이 바뀌는 것은 아니다** — 통제 줄의 뱃지는 그대로 '판정 불가'이고, 호스트별 사유는
      //   호스트 상세의 계정 탭과 스냅샷 증적(JSON)이 계속 갖는다.
      ?>
      <?php $shown = array_slice($account['violations'], 0, $previewLimit); ?>
        <?php vg_table(
            [['label' => '호스트'], ['label' => '점검 항목'], ['label' => '결과', 'width' => '6rem'], ['label' => '근거']],
            $shown,
            [
                'card' => false,
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
    </div>
  </div>
  <?php endif; ?>

  <?php
  // --- 판정 추이(스냅샷) ---------------------------------------------------
  // 위 카드들은 "지금"만 말한다. 심사에서 필요한 건 "그 시점엔 어땠나" 라서, 스케줄러가
  //   하루 1건 남긴 스냅샷을 날짜별로 펼친다. 화면은 저장된 값을 읽기만 한다(재판정 안 함).
  $trendControls = ['patch'];
  if ($canViewAssets) { $trendControls[] = 'asset'; }   // 자산정보는 assets 권한자에게만(위 카드와 동일 게이트)
  $trendControls[] = 'secops';
  if ($canViewAssets) { $trendControls[] = 'account'; } // 계정 통제도 같은 게이트
  // 기간 내내 판정이 '판정 불가' 한 종류뿐인 통제는 **열을 뺀다** — 10일 × 4열이 전부 같은
  //   글자면 그건 추이가 아니라 벽지다. 한 번이라도 다른 판정이 있었으면 남긴다(그때의
  //   판정 불가는 그 칸에 그대로 보인다). 어휘는 vg_compliance_status() 가 SSOT 라
  //   문자열을 새로 박지 않고 거기서 받아 온다.
  $naLabel = vg_compliance_status(0, true)['label'];
  $trendControls = array_values(array_filter($trendControls, static function (string $key) use ($trend, $naLabel): bool {
      foreach ($trend as $r) {
          $c = $r['controls'][$key] ?? null;
          if ($c !== null && $c['label'] !== $naLabel) { return true; }
      }
      return false;
  }));
  // 남는 열이 없으면 카드를 통째로 내린다(판정일만 남은 표는 아무것도 말하지 않는다).
  //   스냅샷이 아예 없을 때는 "없습니다" 안내를 그대로 남긴다 — 그건 벽지가 아니라 상태다.
  $showTrend = !$trend || $trendControls;
  ?>
  <?php if ($showTrend): ?>
  <div class="card mt-lg" id="trend" data-compliance-zone="trend">
    <strong>판정 추이</strong>
    <?php // 제목 옆에는 값만 둔다 — 무엇을 세는 표인지는 아래 열 머리글이 말한다. ?>
    <?php if ($trend): ?>
    <span class="why">최근 <?= count($trend) ?>일 · 최신 <?= vg_h($trend[0]['taken_at']) ?></span>
    <?php endif; ?>
    <div class="card__body">
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
                // 판정 불가 건수 부기는 걷었다 — 칸마다 같은 문구가 반복돼 정작 판정 뱃지가
                //   안 읽혔다. 그 날 판정이 판정 불가였다는 사실은 뱃지(tone med)가 그대로
                //   말하고, 건수는 스냅샷 증적(unjudged_count·evidence JSON)에 남아 있다.
                return number_format($c['count']) . '건 '
                    . vg_badge($c['label'], vg_compliance_tone_of($c['label']));
            };
        }
        // 최근 며칠은 펼쳐 두고(심사에서 먼저 보는 구간), 그보다 오래된 날짜만 접는다 —
        //   스냅샷은 최대 vg_ui_trend_limit()일(기본 50일)까지 쌓여서 전부 펼치면 이 표
        //   하나가 화면을 몇 배로 늘린다. 위에 적어 둔 접기 기준(미리보기 상한 초과분)의
        //   유일한 적용 대상이다. 잘라서 감추는 게 아니라 아래 접힘 블록에 그대로 있다.
        $recent = array_slice($trend, 0, $previewLimit);
        $older  = array_slice($trend, $previewLimit);
        vg_table($headers, $recent, ['cell' => $cells, 'card' => false]);
        ?>
        <?php if ($older): ?>
          <details>
            <summary>이전 <?= count($older) ?>일 더 보기 — <?= vg_h($older[count($older) - 1]['date']) ?> ~ <?= vg_h($older[0]['date']) ?></summary>
            <?php vg_table($headers, $older, ['cell' => $cells, 'card' => false]); ?>
          </details>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <?php
  // 정책·절차 문서 심사 체크리스트(VG_COMPLIANCE_MANUAL_CHECKLIST)는 **화면에서 내렸다**.
  //   스스로 '자동판정 대상 아님' 이라 적고 있던 카드다 — 증적이 제품 밖(문서·승인이력)에 있어
  //   이 제품이 확인해 줄 수 있는 게 한 줄도 없는데, 자동판정 4종 아래에 같은 크기로 붙어
  //   화면의 마지막 한 판을 먹었다. 이 화면은 **체크되는 것만** 보여준다.
  //   삭제가 아니라 강등이다: 상수·조항 매핑(server/src/compliance/policy.php)은 그대로 살아 있고
  //   심사 항목 자체는 docs/dev/화면-안내.md 가 갖는다. 다시 화면에 세울 근거(제품 안의 증적)가
  //   생기면 그때는 자동판정 통제로 올라오는 게 맞다(계정 관리가 그렇게 올라왔다).
  ?>
<?php endif; ?>

<?php // 통제 기준 매핑으로 가는 길은 상단 서브탭이 갖는다 — 본문 하단 링크는 그래서 없앴다.
vg_footer();
