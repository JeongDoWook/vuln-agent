<?php
declare(strict_types=1);

/**
 * control_mapping.php — 보안설정 점검(CCE) 결과를 "기준"으로 바꿔 끼워 보는 화면. 로그인 필요.
 *   ?fw=ISMS_P|KISA_U|N2SF  ·  ?page=N/?per_page=N
 *
 * 통제 하나의 상세는 control.php 가 갖는다 — 이 파일은 목록만(SRP). 예전 `?control=` 드릴다운
 *   URL 은 아래에서 그 주소로 302 한다(링크만 갈아끼우면 이미 공유·북마크된 주소가 목록으로
 *   되돌아가 "눌렀는데 아무 일도 안 일어난다"가 된다).
 *
 * 왜 새 화면인가: compliance_rules.php/compliance_rule.php 는 SSG(SCAP) 룰 카탈로그이지 CCE
 *   점검 결과 목록이 아니고, compliance.php 는 통제 3종을 자동판정하는 화면이다(판정 로직은
 *   건드리지 않는다). "같은 점검 결과를 U-코드·ISMS-P·N2SF 로 바꿔 본다" 는 목적은 어느 쪽에도
 *   없어서, tb_control_mapping 을 읽어 기준별로 그룹핑만 하는 화면을 따로 둔다.
 *   판정은 하지 않는다 — 이 화면은 "이 통제에 걸린 점검 결과가 몇 건인가" 만 센다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';           // vg_log_activity
require_once __DIR__ . '/../src/control_mapping.php'; // vg_control_frameworks, vg_control_framework_param
require_once __DIR__ . '/../src/compliance/policy.php'; // vg_compliance_status — 판정 어휘 SSOT
// 인가 게이트. 이게 없어서 **비로그인 상태로도 200 + CCE 점검 결과 전량**이 나갔다(실측:
//   빈 쿠키로 curl 하면 다른 화면은 302 login 인데 여기만 200). 상세인 control.php 는 처음부터
//   갖고 있었다 — 목록만 빠져 있었다. 같은 데이터를 여는 두 URL 은 같은 게이트를 지나야 한다.
vg_require_menu('compliance');

$err = null;
$fw = vg_control_framework_param($_GET['fw'] ?? null);   // 화이트리스트 검증(SSOT)
$frameworks = vg_control_frameworks();

// 옛 드릴다운 URL 호환 — 상세는 control.php 로 이관했다.
$legacyControl = trim((string) ($_GET['control'] ?? ''));
if ($legacyControl !== '') {
    header('Location: /control.php?fw=' . urlencode($fw) . '&control=' . urlencode($legacyControl), true, 302);
    exit;
}

// U-코드는 이 화면이 답하지 않는다. 여기는 **매핑된 통제**만 나열해서 위반이 있는 21개만
//   보였고, kisa-u.php 는 가이드 전체 72개를 분모로 놓아 미점검 51개와 커버리지까지 답한다
//   — 뒤가 앞을 포함한다. 같은 질문에 두 화면이 따로 답하는 상태를 남기지 않으려고 U-코드는
//   kisa-u.php 하나로 모으고, 이미 공유·북마크된 이 주소는 302 로 그리로 보낸다(칩만 지우면
//   "눌렀는데 아무 일도 안 일어난다"가 된다 — 옛 ?control= 을 이관할 때와 같은 이유).
if ($fw === 'KISA_U') {
    header('Location: /kisa-u.php', true, 302);
    exit;
}

$rows = [];            // 매핑된 통제 전체(점검 결과 없는 통제 포함)
$total = 0;            // 페이지네이션 대상 총건수
$mappedRules = 0;      // 이 기준에 매핑된 CCE 룰 수
$findingTotal = 0;     // 이 기준으로 묶인 점검 결과 총건수
$failTotal = 0;        // 그중 FAIL 총건수(기준 전체 — 페이지가 아니다)
$failControls = 0;     // FAIL 이 하나라도 있는 통제 수
$noResultControls = 0; // 매핑은 있으나 점검 결과가 0건인 통제 수
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();
    vg_log_activity($pdo, 'PAGE', null, 'view_control_mapping', '통제 기준 매핑 조회 · ' . $fw);
    session_write_close();   // 인가·감사로그 이후 집계 전 세션락 해제(compliance.php 선례)

    // 호스트별 최신 수집의 CCE 결과만 본다 — 지난 스캔까지 세면 같은 위반이 중복 집계된다.
    $baseSql =
        "FROM tb_cce_finding cf
           JOIN " . vg_latest_scan_subq() . " t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
           JOIN tb_control_mapping m ON m.rule_code = cf.code AND m.framework = ? AND m.is_deleted = 0
          WHERE cf.is_deleted = 0";

    $mappedRules = (int) (function () use ($pdo, $fw) {
        $st = $pdo->prepare(
            'SELECT COUNT(DISTINCT rule_code) FROM tb_control_mapping WHERE framework = ? AND is_deleted = 0'
        );
        $st->execute([$fw]);
        return $st->fetchColumn();
    })();

    $st = $pdo->prepare("SELECT COUNT(*) $baseSql");
    $st->execute([$fw]);
    $findingTotal = (int) $st->fetchColumn();

    // ── 실제 점검 결과를 기준의 통제 ID 로 그룹핑 ──
    $groupSql =
        "SELECT m.control_id, m.control_name,
                COUNT(*) AS finding_cnt,
                SUM(cf.result = 'FAIL') AS fail_cnt,
                SUM(cf.result = 'PASS') AS pass_cnt,
                SUM(cf.result = 'NA')   AS na_cnt,
                COUNT(DISTINCT cf.code) AS rule_cnt,
                GROUP_CONCAT(DISTINCT cf.code ORDER BY cf.code SEPARATOR ', ') AS codes
         $baseSql
          GROUP BY m.control_id, m.control_name";

    $st = $pdo->prepare($groupSql);
    $st->execute([$fw]);
    $findingsByControl = [];
    foreach ($st->fetchAll() as $r) {
        $findingsByControl[(string) $r['control_id']] = $r;
    }

    // 매핑된 통제를 하나의 목록으로 만든다. 예전에는 결과가 있는 통제와 없는 통제를 표/카드로
    //   갈라 같은 통제를 찾는 동선이 두 벌이었다. 매핑 정본을 기준으로 합치고, 결과가 없으면
    //   명시적인 "점검 결과 없음" 상태를 붙인다(0건 준수로 보이지 않게).
    $st = $pdo->prepare(
        "SELECT control_id, control_name, COUNT(DISTINCT rule_code) AS mapped_rule_cnt,
                GROUP_CONCAT(DISTINCT rule_code ORDER BY rule_code SEPARATOR ', ') AS codes
           FROM tb_control_mapping
          WHERE framework = ? AND is_deleted = 0
          GROUP BY control_id, control_name"
    );
    $st->execute([$fw]);
    $allRows = [];
    foreach ($st->fetchAll() as $mapped) {
        $observed = $findingsByControl[(string) $mapped['control_id']] ?? [];
        $allRows[] = array_merge($mapped, [
            'finding_cnt' => (int) ($observed['finding_cnt'] ?? 0),
            'fail_cnt'    => (int) ($observed['fail_cnt'] ?? 0),
            'pass_cnt'    => (int) ($observed['pass_cnt'] ?? 0),
            'na_cnt'      => (int) ($observed['na_cnt'] ?? 0),
        ]);
    }
    usort($allRows, static fn(array $a, array $b): int =>
        ((int) $b['fail_cnt'] <=> (int) $a['fail_cnt'])
        ?: strnatcasecmp((string) $a['control_id'], (string) $b['control_id'])
    );
    $total = count($allRows);
    // 결론 집계 — 페이지가 아니라 **기준 전체** 기준이다(1페이지만 세면 "위반 0" 이 거짓이 된다).
    //   판정이 아니라 집계다: 이 화면은 위반 건수를 세기만 하고 준수/미준수를 말하지 않는다.
    foreach ($allRows as $r) {
        $failTotal += (int) $r['fail_cnt'];
        if ((int) $r['fail_cnt'] > 0) { $failControls++; }
        if ((int) $r['finding_cnt'] === 0) { $noResultControls++; }
    }
    $offset = ($page - 1) * $perPage;
    $rows = array_slice($allRows, $offset, $perPage);
} catch (Throwable $e) {
    error_log('[control_mapping] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('통제 기준 매핑', 'control_mapping');
?>
  <?php // 제목은 계열 이름만 — 어느 화면인지는 바로 아래 서브탭이 말한다(compliance.php 와 같은 규약). ?>
  <?php vg_page_title('컴플라이언스', 'CONTROL MAPPING', ['count' => $total]); ?>
  <?php // 컴플라이언스 계열 서브탭(정의는 nav.php 한 곳) — 저쪽 화면과 같은 줄을 그린다.
        //   판정하지 않는다는 사실은 위 부제가 이미 말한다. ?>
  <?php vg_compliance_subtabs('control'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <div class="tabs">
    <?php // U-코드 칩은 없다 — 위 서브탭 '기반시설 U-코드' 가 그 기준의 정본 화면이다. ?>
    <?php foreach ($frameworks as $code => $label): ?>
      <?php if ($code === 'KISA_U') { continue; } ?>
      <a class="pill<?= $code === $fw ? ' pill--on' : '' ?>"
         href="/control_mapping.php?fw=<?= urlencode($code) ?>"><?= vg_h($label) ?></a>
    <?php endforeach; ?>
  </div>
  <?php
  /* 결론을 앞에 세운다(compliance.php 와 같은 원칙) — 예전엔 "매핑된 점검 항목 / 점검 결과"
   *   두 숫자뿐이라, 표를 다 훑기 전엔 이 기준에서 무엇이 걸렸는지 알 수 없었다.
   *   단위를 라벨에 붙인다: 건(점검 결과)과 종(통제 가짓수)이 한 줄에 섞여 있다.
   *   격자를 손으로 짜지 않고 vg_kpi_strip() 에 맡긴다(kisa-u.php 와 같은 줄) — 항목을
   *   나열하는 격자가 아니라 **요약 지표**라 표로 바꾸지 않는다. 나열이던 건 아래 통제
   *   목록이고, 그쪽이 표가 됐다. */
  vg_kpi_strip([
      ['value' => number_format($failTotal),        'label' => '위반(FAIL) · 건',      'tone' => 'crit'],
      ['value' => number_format($failControls),     'label' => '위반 있는 통제 · 종',   'tone' => 'high'],
      ['value' => number_format($noResultControls), 'label' => '점검 결과 없음 · 종',   'tone' => 'muted'],
      ['value' => number_format($mappedRules),      'label' => '매핑된 점검 항목 · 개'],
      ['value' => number_format($findingTotal),     'label' => '최신 수집 점검 결과 · 건'],
  ], ['compact' => true]);
  ?>
<?php /* 같은 말이 부제에 이미 있다 — 여기서 한 번 더 적지 않는다(부제가 정본). */ ?>

  <?php
  $detailHref = fn(array $r): string => '/control.php?fw=' . urlencode($fw)
      . '&control=' . urlencode((string) $r['control_id']);
  $policy = vg_compliance_policy();
  // 판정 어휘는 control.php·compliance.php 와 같은 함수로 뽑는다(SSOT) — 0건을 준수로 찍지
  //   않는다는 원칙이 표의 판정 뱃지·미준수율 톤에 그대로 적용된다.
  $status = fn(array $r): array => (int) $r['finding_cnt'] === 0
      ? ['label' => '점검 결과 없음', 'tone' => 'muted']
      : vg_compliance_status((int) $r['fail_cnt'], (int) $r['na_cnt'] > 0, $policy['partial_max']);
  $naLabel = vg_compliance_status(0, true)['label'];
  ?>
  <?php
  /* 카드 격자 → **표**. 통제가 수십 종이면 카드는 스크롤만 길어지고 "어느 통제가 더 나쁜가" 를
   *   나란히 비교할 수 없다(같은 이유로 컨테이너 탭·CCE 카탈로그도 표로 되돌렸다).
   *   카드 안에 길게 깔리던 CCE 코드 목록(CCE-FILE-CRONTAB, CCE-FILE-GROUP, …)은 **개수만**
   *   남기고 상세(control.php)로 내린다 — 그 목록이 카드 폭을 정하고 있었다. */
  vg_table(
      [
          ['label' => '통제 코드', 'width' => '9%', 'class' => 'col-id'],
          ['label' => '판정',     'width' => '7rem', 'nowrap' => true],
          ['label' => '통제명'],
          ['label' => '매핑 점검', 'align' => 'right', 'width' => '5.5rem', 'nowrap' => true,
           'title' => '이 통제에 매핑된 CCE 점검 항목 수 — 코드 목록은 상세에 있습니다'],
          // '결과' 는 세 값(FAIL·PASS·판정 불가)이 한 줄에 서야 행 높이가 안 늘어난다 —
          //   18% 로 뒀더니 '판정 불가 455' 가 접혀 행이 3줄이 됐다(실측 1440px).
          ['label' => '결과', 'width' => '23%'],
          /* 숫자 열이지만 좌측정렬로 둔다 — 이 칸은 숫자 하나가 아니라 [불릿 그래프]+[%] 한 쌍이고,
             그래프는 블록이라 칸 폭을 그대로 쓴다. 우측정렬하면(실측) 8% 짜리 막대는 칸 왼쪽 끝에,
             숫자는 180px 떨어진 오른쪽 끝에 서서 둘이 한 값이라는 게 안 읽힌다. 우측정렬 규약은
             '매핑 점검' 같은 맨숫자 칸이 지킨다. 목표(0%)는 세로 눈금으로, 부분준수 컷라인은
             배경 밴드로 같이 보인다(vg_bullet — 초기 요청: 원형 게이지 대신 불릿). */
          ['label' => '미준수율', 'width' => '13%',
           'title' => 'FAIL ÷ 최신 수집 점검 결과. 판정이 아니라 집계다.'],
      ],
      $rows,
      [
          'card'  => false,
          'empty' => [
              'icon'  => 'chart',
              'title' => '이 기준에 매핑된 통제가 없습니다.',
              'hint'  => '근거가 확인된 통제 매핑이 등록되면 이 목록에 표시됩니다.',
          ],
          'cell' => [
              // 코드·통제명 둘 다에 링크를 건다 — "누르면 들어간다"가 요구사항이라 누르는
              //   면적을 코드 한 조각으로 좁혀 두지 않는다(kisa-u.php 와 같은 규약).
              0 => fn(array $r): string => '<a href="' . vg_h($detailHref($r)) . '"><code>'
                  . vg_h((string) $r['control_id']) . '</code></a>',
              1 => fn(array $r): string => vg_badge($status($r)['label'], $status($r)['tone']),
              2 => fn(array $r): string => '<a class="body-link" href="' . vg_h($detailHref($r)) . '">'
                  . vg_h((string) $r['control_name']) . '</a>',
              3 => fn(array $r): string => number_format((int) $r['mapped_rule_cnt']),
              // 0 인 값은 적지 않는다 — 신호는 FAIL 하나뿐인데 모든 행이 'PASS 0 · 판정 불가 0' 으로
              //   채워지면 정작 읽어야 할 값을 덮는다(cce-rules.php·kisa-u.php 와 같은 어휘).
              4 => function (array $r): string {
                  if ((int) $r['finding_cnt'] === 0) { return '<span class="why">아직 점검된 결과가 없습니다.</span>'; }
                  $parts = ['FAIL <b>' . number_format((int) $r['fail_cnt']) . '</b>'];
                  if ((int) $r['pass_cnt'] > 0) { $parts[] = 'PASS ' . number_format((int) $r['pass_cnt']); }
                  if ((int) $r['na_cnt'] > 0)   { $parts[] = '판정 불가 ' . number_format((int) $r['na_cnt']); }
                  return implode(' <span class="why">·</span> ', $parts)
                       . '<div class="why">전체 ' . number_format((int) $r['finding_cnt']) . '건</div>';
              },
              // meter 에는 ok 톤이 없다(app.css) → low 로 떨군다. 0% 라 색은 안 보인다.
              // 판정 자체가 판정 불가(이력 부족 등 근거 없음)면 0% 막대를 그리지 않는다 —
              //   위반 0건이 아니라 "볼 수 없다" 이므로, 그리면 없는 준수 사실을 만들어낸다.
              5 => function (array $r) use ($status, $policy, $naLabel): string {
                  $cnt = (int) $r['finding_cnt'];
                  if ($cnt === 0) { return '<span class="why">–</span>'; }
                  $fail = (int) $r['fail_cnt'];
                  $s = $status($r);
                  if ($s['label'] === $naLabel) {
                      return vg_bullet('muted', 0, 0, '미준수율 · 판정 불가 — 근거 없음', ['na' => true]);
                  }
                  $tone = $s['tone'] === 'ok' ? 'low' : $s['tone'];
                  $pct = $fail / $cnt * 100;
                  return vg_bullet($tone, $pct, 0,
                                  'FAIL ' . number_format($fail) . ' / 전체 ' . number_format($cnt) . '건',
                                  ['bands' => vg_bullet_bands($policy['partial_max'], $cnt)])
                       . '<span class="why">' . number_format($pct, 1) . '%</span>';
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
