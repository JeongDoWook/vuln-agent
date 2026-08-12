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
$secconfig = ['violations' => [], 'total' => 0, 'checked' => 0];
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
  <?php
  // 설명 한 줄이 "이 화면이 무엇을 증명하는가"를 말한다 — 예전엔 "판정합니다" 로만 끝나
  //   자동판정 3건이 왜 빠졌는지가 화면 어디에도 없었다. 별도 문단으로 빼지 않는 이유는
  //   첫 화면 세로 예산이다(통제 5종까지 675px 안에 들어와야 한다).
  vg_page_title(
      '컴플라이언스 매핑', 'COMPLIANCE',
      'ISMS-P·ISO 27001 통제 ' . count(VG_COMPLIANCE_CONTROLS) . '종 자동 판정 결과 · 정책·절차 문서 '
      . count(VG_COMPLIANCE_MANUAL_CHECKLIST) . '건은 자동판정 대상 아님(맨 아래)'
      // 판정 기준시각은 아래 결론 배너의 note 로 옮겼다 — 같은 화면에 두 번 적을 값이 아니다.
  ); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else:
    $sPatch = vg_compliance_status($patch['total'], $patch['unjudged'] > 0, $policy['partial_max']);
    $sAsset = vg_compliance_status($asset['total'], $asset['unjudged'] > 0, $policy['partial_max']);
    $sSec   = vg_compliance_status($secconfig['total'], false, $policy['partial_max']);
    $sAcct  = vg_compliance_status($account['total'], $account['unjudged'] > 0, $policy['partial_max']);
    $sRev   = vg_compliance_status($review['total'], false, $policy['partial_max']);

    // ── 결론 먼저 ──────────────────────────────────────────────────────────
    // 예전 첫 화면은 판정 5행짜리 표 하나였다. 통제마다의 판정은 있는데 "그래서 결론이
    //   무엇인가"가 없어서, 사용자가 표를 다 읽고 스스로 세야 알 수 있었다(운영 피드백:
    //   "뭐가 된다는 거지, 뭘 증명한다는 거지").
    // 단위는 **통제 "종"** 이지 위반 건수가 아니다 — 같은 칸에 뭉개면 "미준수 1" 이 1건인지
    //   1종인지 못 읽는다. 그래서 라벨에 단위를 붙여 둔다.
    // 판정 어휘·색은 vg_compliance_status()/vg_compliance_tone_of() 가 SSOT 다(여기서 다시
    //   정하지 않는다 — 두 벌이 되면 표의 뱃지와 이 카드의 색이 갈라진다).
    $verdicts = ['patch' => $sPatch, 'secops' => $sSec, 'access_review' => $sRev];
    // assets 권한이 없으면 자산·계정은 건수까지 감춘다(아래 $deniedRow 와 같은 게이트) —
    //   집계에서도 빼고, 몇 종이 빠졌는지는 따로 밝힌다(5종 중 3종만 센 걸 숨기지 않는다).
    if ($canViewAssets) { $verdicts['asset'] = $sAsset; $verdicts['account'] = $sAcct; }
    $tally = ['준수' => 0, '부분준수' => 0, '미준수' => 0, '판정 불가' => 0];
    foreach ($verdicts as $s) { $tally[$s['label']] = ($tally[$s['label']] ?? 0) + 1; }
    $denied = count(VG_COMPLIANCE_CONTROLS) - count($verdicts);
?>
  <?php
  // 결론 배너(vg_verdict) — 예전엔 KPI 카드 4장이 이 자리에 있었는데, 숫자 넷을 나란히
  //   놓아도 "그래서 준수인가 아닌가"는 여전히 사용자가 세어야 했다. 배너는 그 한 문장을
  //   먼저 말하고 숫자를 근거로 뒤에 붙인다. 화면에 하나만 둔다(role="status").
  // 톤 어휘가 두 벌이 되지 않게, 배너 톤은 판정 톤(vg_compliance_tone_of — SSOT)에서 옮긴다.
  //   판정 톤은 ok/high/crit/med 인데 배너는 ok/warn/crit/muted 라 어휘만 갈아 끼운다.
  $toVerdictTone = ['ok' => 'ok', 'high' => 'warn', 'crit' => 'crit', 'med' => 'muted'];
  $stats = [];
  foreach ($tally as $label => $n) {
      $stats[] = ['label' => $label, 'value' => number_format($n),
                  'tone'  => $toVerdictTone[vg_compliance_tone_of($label)] ?? 'muted'];
  }
  if ($denied > 0) {
      $stats[] = ['label' => '권한 없음', 'value' => number_format($denied), 'tone' => 'muted'];
  }
  $judged = count($verdicts);
  if ($tally['미준수'] > 0) {
      $banner = ['crit', '판정한 통제 ' . $judged . '종 중 ' . $tally['미준수'] . '종이 미준수입니다 — 즉시 조치가 필요합니다.'];
  } elseif ($tally['부분준수'] > 0 || $tally['판정 불가'] > 0) {
      $banner = ['warn', '판정한 통제 ' . $judged . '종 중 ' . $tally['준수'] . '종만 준수입니다 — 나머지는 부분준수·판정 불가입니다.'];
  } else {
      $banner = ['ok', '판정한 통제 ' . $judged . '종이 모두 준수입니다.'];
  }
  // 단위를 note 에 못박는다 — 숫자만 보면 "미준수 1" 이 1건인지 1종인지 못 읽는다
  //   (예전 KPI 카드는 라벨마다 '· 통제 종' 을 붙여 이걸 해결했다. 배너는 한 줄로 끝낸다).
  vg_verdict($banner[0], $banner[1], $stats,
      '기준 ' . $judgedAt . ' 판정 · 집계 단위는 통제 종(위반 건수가 아니다) · '
      . ($denied > 0
          ? '자산 열람 권한이 없어 통제 ' . $denied . '종은 집계에서 제외'
          : '통제 ' . count(VG_COMPLIANCE_CONTROLS) . '종 전수'));
  ?>

  <?php
  // 첫 화면은 **통제 5종 × 한 줄**. 예전엔 통제마다 호스트별 위반을 10건씩 미리 깔아서,
  //   정작 "무엇이 준수이고 무엇이 아닌가"가 스크롤 아래로 밀렸다. 전체를 보려면 어차피
  //   그 근거만 보여주는 다른 화면으로 가야 하므로, 여기서는 판정만 세우고 근거는 링크로 보낸다.
  //   판정·건수는 위 vg_compliance_status() 결과 그대로다(요약 방식만 바뀐다).
  // 위반 0건과 판정 불가를 한 칸에 뭉개지 않는다 — 뭉개는 순간 허위 안심이 된다(건수를 따로 적는다).
  $naText = static fn(int $n, string $unit = '건'): string =>
      $n > 0 ? ' · <span class="why">판정 불가 ' . number_format($n) . vg_h($unit) . '</span>' : '';
  // 요약 칸: **한 줄**이다 — 건수 뒤에 작게 "몇 개 중에 셌는가"(분모)를 잇는다.
  //   두 줄로 쓰면 행이 73px 이 되고, 통제 5종이 첫 화면(1440×675) 밖으로 밀린다(실측).
  //   판정 5종을 한눈에 보는 것이 이 표의 목적이라 줄 수를 예산으로 잡고 문구를 줄였다.
  //   구분자(—)가 없으면 "위반 3건 · 판정 불가 5,758건 조치 대상 5,761건" 처럼 두 수치가
  //   한 문장으로 붙어 읽힌다(실측). 색만으로는 경계가 안 잡힌다.
  $sumCell = static fn(string $head, string $why): string =>
      $head . ' <span class="why">— ' . vg_h($why) . '</span>';
  // 판정 칸: 뱃지 **아래에 비율 게이지**를 깐다. 게이지가 없으면 "위반 174건"이 큰 수인지
  //   작은 수인지 읽을 방법이 없었다(분모가 화면에 없었다). 요약 칸이 아니라 판정 칸에
  //   두는 건 두 가지 이유다 — (1) 게이지는 그 판정의 근거지 요약문의 일부가 아니고,
  //   (2) 요약 칸에 3번째 줄로 넣으면 행이 85px 이 돼 통제 5종이 첫 화면 밖으로 밀린다.
  //   meter 는 톤이 crit/high/med/low 뿐이다(app.css) — 'ok' 는 low 로 떨군다. 준수면 채움이
  //   0% 라 색이 보이지도 않지만, 존재하지 않는 클래스를 만들지는 않는다.
  $verdictCell = static function (array $s, ?float $pct, string $why): string {
      return vg_badge($s['label'], $s['tone'])
          . ($pct === null ? '' : vg_meter($s['tone'] === 'ok' ? 'low' : $s['tone'], $pct, $why));
  };
  // 통제별 분모. 판정 기준이 아니라 **표시용**이다(무엇이 위반인지는 그대로다).
  $patchTargets = 0;
  foreach ($patch['buckets'] as $b) { $patchTargets += (int) $b['targets']; }
  // 계정은 위반이 호스트당 여러 건 나올 수 있어 건수/대수의 분모가 다르다 — 게이지는
  //   "몇 대에서 위반이 나왔나"로 잡는다(건수를 호스트 수로 나누면 100% 를 넘는다).
  $acctViolHosts = count(array_unique(array_column($account['violations'], 'host_id')));
  // assets 권한이 없으면 자산·계정 통제는 **건수까지 감춘다**(위반 수 자체가 자산 정보다).
  //   줄을 통째로 빼지 않는 이유: 이 화면의 존재 이유가 "통제 5종 ↔ 조항" 매핑이라,
  //   권한에 따라 통제가 3종으로 보이면 매핑 자체를 잘못 읽게 된다.
  $deniedRow = static fn(string $key): array => [
      'key' => $key, 'badge' => vg_badge('권한 없음', 'muted'),
      'summary' => '<span class="why">자산 열람 권한이 필요합니다</span>', 'link' => '',
  ];

  // 계정 통제의 접힘 상세를 실제로 그리는가 — 요약 줄의 앵커 링크와 조건이 어긋나면
  //   눌러도 아무 데도 안 가는 링크가 된다(그래서 한 변수로 묶어 둔다).
  $acctDetails = $canViewAssets
      && ($account['violations'] || $account['unjudged'] > 0 || $account['pending_hosts'] > 0);

  $summaryRows = [];
  // 분모 문구는 짧게 — 한 줄에 건수와 같이 들어가야 한다(아래 버킷 표가 상세를 갖는다).
  $whyPatch = '조치 대상 ' . number_format($patchTargets) . '건 중 SLA 초과분';
  $summaryRows[] = [
      'key' => 'patch',
      'badge' => $verdictCell($sPatch, $patchTargets > 0 ? $patch['total'] / $patchTargets * 100 : null, $whyPatch),
      'summary' => $sumCell(
          '위반 ' . number_format((int) $patch['total']) . '건' . $naText((int) $patch['unjudged']),
          $whyPatch
      ),
      // 이 통제가 센 것 = 조치 가능한 미조치 취약점. findings 의 fx=action 이 같은 모집단이다
      //   (SLA 초과 필터는 없으므로 건수는 여기가 더 적다 — 링크 라벨을 "근거"로만 둔다).
      'link' => '<a href="/findings.php?type=cve&amp;fx=action">근거 →</a>',
  ];
  $whyAsset = '등록 ' . number_format((int) $asset['totalHosts']) . '대 중 · 오프라인·수집없음·OS/IP 누락';
  $summaryRows[] = $canViewAssets ? [
      'key' => 'asset',
      'badge' => $verdictCell($sAsset,
          $asset['totalHosts'] > 0 ? $asset['total'] / $asset['totalHosts'] * 100 : null, $whyAsset),
      'summary' => $sumCell(
          '위반 ' . number_format((int) $asset['total']) . '건' . $naText((int) $asset['unjudged'], '대'),
          $whyAsset
      ),
      'link' => '<a href="/assets.php">근거 →</a>',
  ] : $deniedRow('asset');
  $whySec = '최신 스캔 점검 ' . number_format((int) $secconfig['checked']) . '건 중 FAIL 판정';
  $summaryRows[] = [
      'key' => 'secops',
      'badge' => $verdictCell($sSec,
          $secconfig['checked'] > 0 ? $secconfig['total'] / $secconfig['checked'] * 100 : null, $whySec),
      'summary' => $sumCell('위반 ' . number_format((int) $secconfig['total']) . '건', $whySec),
      // 보안설정(CCE) 위반 목록 전용 탭. 기본 필터가 res=FAIL 이라 이 통제가 센 것과 같다.
      'link' => '<a href="/findings.php?type=cce">근거 →</a>',
  ];
  $whyAcct = '호스트 ' . number_format((int) $account['totalHosts']) . '대 중 위반 '
           . number_format($acctViolHosts) . '대'
           . ($account['pending_hosts'] > 0
              ? ' · 수집 대기 ' . number_format((int) $account['pending_hosts']) . '대' : '');
  $summaryRows[] = $canViewAssets ? [
      'key' => 'account',
      'badge' => $verdictCell($sAcct,
          $account['totalHosts'] > 0 ? $acctViolHosts / $account['totalHosts'] * 100 : null, $whyAcct),
      'summary' => $sumCell(
          '위반 ' . number_format((int) $account['total']) . '건' . $naText((int) $account['unjudged']),
          $whyAcct
      ),
      // 전 호스트 계정 위반을 한 번에 보는 화면은 없다(호스트별로만 있다). 없는 화면을
      //   만들어 링크하지 않고, 이 통제만 아래 근거 블록에 호스트별 링크를 둔다.
      'link' => $acctDetails ? '<a href="#compliance-account">호스트별 ↓</a>' : '',
  ] : $deniedRow('account');
  // 이 통제만 분모가 "건수"가 아니라 **주기**다 — 게이지는 검토 주기가 얼마나 찼는지를
  //   보여준다(100% 를 넘으면 그 자체가 위반). 위반/대상 비율을 억지로 만들지 않는다.
  $whyRev = ($review['last'] === null
              ? '수행 이력 0건'
              : '최근 검토 ' . $review['last']['reviewed_at'] . ' · ' . (int) $review['days_since'] . '일 경과')
          . ' · 주기 ' . (int) $review['interval_days'] . '일';
  $summaryRows[] = [
      'key' => 'access_review',
      'badge' => $verdictCell($sRev,
          ($review['days_since'] !== null && $review['interval_days'] > 0)
              ? (int) $review['days_since'] / (int) $review['interval_days'] * 100 : null, $whyRev),
      'summary' => $sumCell('위반 ' . number_format((int) $review['total']) . '건', $whyRev),
      'link' => '<a href="/activity.php">기록 →</a>',
  ];

  vg_table(
      [
          ['label' => '통제'],
          ['label' => '판정', 'width' => '9rem'],
          ['label' => '요약'],
          // 링크 라벨은 짧다 — 접히면 화살표가 다음 줄로 떨어져 링크로 안 보인다.
          ['label' => '근거', 'width' => '7rem', 'nowrap' => true],
      ],
      $summaryRows,
      [
          'cell' => [
              // 조항 번호(ISMS-P/ISO)는 이 화면의 존재 이유다 — 작게 내릴 뿐 지우지 않는다.
              //   줄바꿈 없이 같은 줄에 잇는다: 통제명과 조항을 두 줄로 쌓으면 행이 두 줄이 되고,
              //   요약 칸을 한 줄로 줄여도 5종이 첫 화면에 안 들어온다.
              0 => fn($r) => '<strong>' . vg_h(VG_COMPLIANCE_CONTROLS[$r['key']]['label']) . '</strong>'
                           . ' <span class="why">' . vg_h(VG_COMPLIANCE_CONTROLS[$r['key']]['framework']) . '</span>',
              1 => fn($r) => $r['badge'],
              2 => fn($r) => $r['summary'],
              3 => fn($r) => $r['link'],
          ],
      ]
  );
  ?>

  <?php
  // ── 접기 기준(이 화면 전체에 적용) ──────────────────────────────────────
  // 접는 건 "행이 실제로 많아 아래 블록을 화면 밖으로 밀어낼 때"뿐이다. 즉 한 블록의
  //   행 수가 미리보기 상한(vg_ui_detail_preview_limit(), 기본 10행)을 넘길 때만 접는다.
  //   예전엔 3~5행짜리 블록까지 전부 <details> 로 닫혀 있어서, 화면 아래 절반이 회색 띠
  //   4줄(내용 0)이었다 — "판정 불가 203건"의 이유가 그 안에 있는데도 안 보였다.
  //   지금 접혀 있는 건 판정 추이의 오래된 날짜뿐이다(스냅샷은 최대 50일까지 쌓인다).
  ?>
  <div class="card mt-lg">
    <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['patch']['label']) ?> 버킷별 판정</strong>
    <span class="why">— KEV·CRITICAL·HIGH · "판정 불가"의 이유가 여기 있다</span>
    <div class="card__body">
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
      <?php // 호스트별 위반 목록은 근거 링크(findings.php) 가 전부 보여준다 — 여기서 미리 깔지 않는다. ?>
    </div>
  </div>

  <?php if ($acctDetails): ?>
  <div class="card mt-lg" id="compliance-account">
    <?php
    // 이 블록은 이 화면에만 있다 — 전 호스트 계정 위반을 한 번에 보는 화면이 없어서
    //   요약 줄의 "근거 →" 가 갈 곳이 없다. 표시되는 행은 미리보기 상한 이하라 펼쳐 둔다.
    ?>
    <strong><?= vg_h(VG_COMPLIANCE_CONTROLS['account']['label']) ?> — 호스트별 근거</strong>
    <span class="why">— 위반 <?= number_format((int) $account['total']) ?>건<?php if ($account['unjudged'] > 0): ?> · 판정 불가 <?= number_format((int) $account['unjudged']) ?>건<?php endif; ?></span>
    <div class="card__body">
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
  $trendControls[] = 'access_review';
  ?>
  <div class="card mt-lg">
    <strong>판정 추이</strong>
    <span class="why">— 일별 판정 스냅샷<?php if ($trend): ?> · 최근 <?= count($trend) ?>일 · 최신 <?= vg_h($trend[0]['taken_at']) ?><?php endif; ?>
      · 심사에서 "그 시점엔 어땠나"의 근거</span>
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
                // 판정 불가는 "위반 0건"과 색(tone med)으로 구분되고, 몇 건이 판정 불가였는지도
                //   함께 적는다 — 저장된 0 만 보고 준수로 되읽히면 스냅샷이 허위 안심이 된다.
                $na = (int) ($c['unjudged'] ?? 0);
                return number_format($c['count']) . '건 '
                    . vg_badge($c['label'], vg_compliance_tone_of($c['label']))
                    . ($na > 0 ? ' <span class="why">판정 불가 ' . number_format($na) . '건</span>' : '');
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

  <div class="card mt-lg">
    <?php
    // 예전 제목은 "수동 확인 필요 · 자동판정 불가" 였다 — 제품이 못 해서 빠진 것처럼 읽혀
    //   오히려 신뢰도를 깎았다. 실제로는 증적이 제품 밖(정책·절차 문서)에 있어서 원리적으로
    //   수집 대상이 아닌 항목이다. 그 사실을 제목에서 바로 말한다.
    ?>
    <strong>정책·절차 문서 심사 <?= count(VG_COMPLIANCE_MANUAL_CHECKLIST) ?>건</strong>
    <span class="why">— 증적이 제품 밖(문서·승인이력)에 있어 수집 대상이 아닌 항목 · 위 판정 <?= count(VG_COMPLIANCE_CONTROLS) ?>종에 포함되지 않는다</span>
    <div class="card__body">
      <ul class="hint-list">
        <?php foreach (VG_COMPLIANCE_MANUAL_CHECKLIST as $item): ?>
          <li><?= vg_h($item['ismsp']) ?> · <?= vg_h($item['iso']) ?><br>
            <span class="why"><?= vg_h($item['desc']) ?></span></li>
        <?php endforeach; ?>
      </ul>
    </div>
  </div>
<?php endif; ?>

  <?php
  // 통제 기준 매핑은 상시로 볼 화면이 아니다(판정 없이 같은 CCE 결과를 기준별로 묶어 세기만 한다)
  //   — 서브탭에서 내리고 이 한 줄만 남긴다. 화면은 그대로 살아 있으므로 링크까지 지워
  //   고아 페이지로 만들지는 않는다. 위치가 아래인 것도 의도다(발견성을 낮춘다).
  ?>
  <p class="why mt-lg">같은 점검 결과를 기준별 통제로 묶어 보려면 →
    <a href="/control_mapping.php">통제 기준 매핑</a></p>
<?php vg_footer();
