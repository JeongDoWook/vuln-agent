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
    // 화면에 실제로 보여줄 만큼만 가져온다(아래 판정 추이 카드가 $previewLimit 행만 렌더) —
    //   더 넉넉히 가져와 봐야 렌더 전에 잘려 나가 조회만 하는 죽은 여유분이 된다.
    $trend = vg_compliance_trend($pdo, $previewLimit);
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
  $whySec = '최신 수집 점검 ' . number_format((int) $secconfig['checked']) . '건 중 FAIL 판정';
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

  /* 이 표는 제목 없는 카드였다 — 이 화면에 표가 둘(통제별 판정 · 판정 추이)인데 아래 것만
   *   제목을 갖고 있어서, 위 표가 무엇을 세는 표인지는 열 머리글을 읽어야 알 수 있었다.
   *   카드 문법(한 카드 한 이야기 · 제목 필수)대로 제목을 세우고 통제 수를 배지로 단다.
   *   표 자체는 한 글자도 안 바뀐다 — vg_table 의 카드 래핑만 vg_card 로 옮긴다('card' => false). */

  // --- 판정 추이(스냅샷) ---------------------------------------------------
  // 이 계산은 **카드를 그리기 전에** 해야 한다 — 추이 카드가 서는지($showTrend)를 알아야
  //   위 카드와 묶을 2열 그리드를 열지 말지 정할 수 있다(카드 한 장이면 안 연다).
  // 위 카드는 "지금"만 말한다. 심사에서 필요한 건 "그 시점엔 어땠나" 라서, 스케줄러가
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
  /* '통제별 판정'(4열 4행)과 '판정 추이'(4열 10행)를 **나란히** 세운다. 위아래로 쌓으면
   *   1,022px 이라 1440·1920px 어디서도 한 화면에 안 들어갔다 — 두 칸으로 두면 702px 로
   *   줄고 말줄임·행 접힘은 0이다(실측). 둘 다 열이 넷 이하라 절반 폭에서도 값이 안 잘린다.
   *   추이 카드가 안 서는 상황(스냅샷이 있는데 전 기간 판정 불가뿐)에는 그리드를 만들지
   *   않는다 — 한 장짜리 그리드는 카드 옆에 빈 칸 반쪽을 남긴다.
   *   구역 표식(data-compliance-zone)은 감싸던 <section> 에서 카드 자신으로 옮겼다:
   *   그리드 칸이 되는 건 카드라, 카드가 아닌 껍데기가 한 겹 끼면 칸 안에서 여백이 어긋난다. */
  if ($showTrend) { echo '<div class="card-row card-row--2">'; }
  vg_card('통제별 판정', static function () use ($summaryRows): void {
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
              'card' => false,
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
  }, [
      'badge' => '통제 ' . number_format(count($summaryRows)) . '종',
      'id'    => 'automatic',
      'attrs' => ['data-compliance-zone' => 'automatic'],
  ]);
  // 판정 범례는 걷었다 — 판정 칸의 뱃지가 '준수'·'부분준수'·'미준수'·'판정 불가' 를
  //   **글자로** 달고 있어 색→이름 대응을 따로 설명할 자리가 아니었다(1차 정리에서 다른
  //   화면의 범례를 전수 제거한 것과 같은 기준). **판정 어휘 4종은 그대로다** — 뱃지·추이
  //   표·스냅샷 증적이 계속 같은 말을 쓴다. 톤 SSOT 도 vg_compliance_tone_of() 그대로다.
  ?>
  <?php if ($showTrend): ?>
  <?php
  /* 제목 옆에는 값만 둔다 — 무엇을 세는 표인지는 아래 열 머리글이 말한다.
   *   예전엔 이 값이 제목 뒤에 그냥 이어 붙어 제목의 일부처럼 읽혔다. 이제 vg_card 의
   *   'aside' 자리(제목 줄 오른쪽 끝)로 간다 — 위 '통제별 판정' 카드의 배지와 같은 자리다. */
  vg_card('판정 추이', static function () use ($trend, $trendControls): void {
      if (!$trend) {
          vg_empty([
              'icon'  => '🗓',
              'title' => '아직 저장된 판정 스냅샷이 없습니다.',
              'hint'  => '스케줄러가 하루 1회 자동으로 남깁니다.',
          ]);
      } else {
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
        // 최근 며칠만 보여준다(심사에서 먼저 보는 구간) — $trend 자체가 이미 $previewLimit 행만
        //   불러온 것이라 여기서 다시 자를 필요가 없다(접이식 이력 표는 왜 있는지 알기 어렵다는
        //   요청으로 완전히 제거했다). 오래된 스냅샷은 DB(tb_compliance_snapshot)에 그대로 남아
        //   감사 목적으로 조회 가능하다.
        vg_table($headers, $trend, ['cell' => $cells, 'card' => false]);
      }
  }, [
      'id'    => 'trend',
      'attrs' => ['data-compliance-zone' => 'trend'],
      'aside' => $trend
          ? '<span class="why">최근 ' . count($trend) . '일 · 최신 ' . vg_h((string) $trend[0]['taken_at']) . '</span>'
          : '',
  ]);
  ?>
  <?php // 그리드는 이 카드까지가 끝이다 — 아래 계정 근거 카드는 전폭으로 선다.
        //   근거 칸이 80자짜리 계정명 나열이라 절반 폭에서는 값이 잘린다. ?>
  <?php echo '</div>'; endif; ?>

  <?php
  // ── 미리보기 상한(이 화면 전체에 적용) ──────────────────────────────────
  // 한 블록의 행 수가 미리보기 상한(vg_ui_detail_preview_limit(), 기본 10행)을 넘기면
  //   상위 N건만 보여주고 나머지는 다른 화면(호스트 상세 등)으로 링크한다. 예전엔
  //   3~5행짜리 블록까지 전부 <details> 로 닫혀 있어서, 화면 아래 절반이 회색 띠
  //   4줄(내용 0)이었다 — "판정 불가 203건"의 이유가 그 안에 있는데도 안 보였다.
  //   판정 추이의 오래된 날짜를 접어 보여주던 이력 표는 완전히 제거했다(왜 있는지
  //   알기 어렵다는 요청 — 오래된 스냅샷은 DB 에 그대로 남는다).
  ?>
  <?php if ($acctDetails): ?>
  <?php
  // 이 블록은 이 화면에만 있다 — 전 호스트 계정 위반을 한 번에 보는 화면이 없어서
  //   요약 줄의 "근거 →" 가 갈 곳이 없다. 표시되는 행은 미리보기 상한 이하라 펼쳐 둔다.
  // 판정 불가(REVIEW·NA)·수집 대기 목록은 화면에서 걷었다. 위반이 아니라 "아직 못 봤다"인
  //   행이라 여기서 근거로 읽히지 않고, 접힘 요약("판정 불가 25건")만 남아 화면을 어지럽혔다.
  //   **판정이 바뀌는 것은 아니다** — 통제 줄의 뱃지는 그대로 '판정 불가'이고, 호스트별 사유는
  //   호스트 상세의 계정 탭과 스냅샷 증적(JSON)이 계속 갖는다.
  $shown = array_slice($account['violations'], 0, $previewLimit);
  vg_card(VG_COMPLIANCE_CONTROLS['account']['label'] . ' — 호스트별 근거',
      static function () use ($shown, $account): void {
          vg_table(
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
          );
          if ($account['total'] > count($shown)) {
              echo '<p class="why">상위 ' . count($shown) . '건만 표시 · 전체 '
                  . number_format((int) $account['total']) . '건은 호스트 상세의 계정 탭에서 확인</p>';
          }
      },
      ['class' => 'mt-lg', 'id' => 'compliance-account',
       'badge' => '위반 ' . number_format((int) $account['total']) . '건']);
  ?>
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
