<?php
declare(strict_types=1);

/**
 * control.php — 통제 하나의 상세 화면. 로그인 필요.
 *   ?fw=ISMS_P|KISA_U|N2SF  ·  ?control=<통제 ID>  ·  ?page=N/?per_page=N
 *
 * 왜 별도 파일인가: control_mapping.php 가 목록과 드릴다운을 한 파일에서 `?control=` 분기로
 *   갈랐는데, 드릴다운은 "이 통제에 걸린 결과 표" 하나뿐이라 정작 사용자가 알아야 할
 *   "이 기준이 무엇을 요구하나 / 어떻게 고치나" 를 담을 자리가 없었다. 상세는 여기로 옮기고
 *   목록 파일은 목록만 갖는다(SRP). 옛 `?control=` URL 은 그 파일이 이 주소로 302 한다.
 *   화면 골격은 compliance_rule.php 의 상세 패턴(히어로 + stat-grid + 섹션)을 그대로 쓴다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';           // vg_log_activity
require_once __DIR__ . '/../src/control_mapping.php'; // vg_control_frameworks, vg_control_guide, vg_cce_rule_guides
vg_require_menu_any('compliance', 'findings');   // 통제 상세: 통제 기준 매핑·판정 이력·패키지 상세에서 함께 열린다

$err = null;
$fw = vg_control_framework_param($_GET['fw'] ?? null);   // 화이트리스트 검증(SSOT)
$control = trim((string) ($_GET['control'] ?? ''));
$frameworks = vg_control_frameworks();

$controlName = '';                                    // 이 기준에서의 통제 정식 명칭
$found = false;                                       // 매핑에 존재하는 통제인가
$guide = null;                                        // 기준 설명(없을 수 있다)
$ruleCodes = [];                                      // 이 통제에 매핑된 CCE 룰코드
$ruleRows = [];                                       // 룰코드 + 점검 제목 + 가이드
$counts = ['FAIL' => 0, 'PASS' => 0, 'NA' => 0];
$hostCount = 0;
$lastCheckedAt = null;                                // 이 통제로 점검된 가장 최근 수집 시각
$rows = [];
$total = 0;
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();

    $st = $pdo->prepare(
        'SELECT DISTINCT rule_code, control_name FROM tb_control_mapping
          WHERE framework = ? AND control_id = ? AND is_deleted = 0
          ORDER BY rule_code'
    );
    $st->execute([$fw, $control]);
    foreach ($st->fetchAll() as $m) {
        $found = true;
        $ruleCodes[] = (string) $m['rule_code'];
        if ($controlName === '') { $controlName = (string) $m['control_name']; }
    }

    // 상세 열람은 감사 대상이다(CLAUDE.md 원칙 7). 통제 ID 는 정수 PK 가 아니라 message·subject 로
    //   남긴다 — compliance_rule.php 의 view_compliance_rule 과 같은 형태.
    $subject = $fw . '/' . $control;
    vg_log_activity($pdo, 'CONTROL', null, 'view_control', $subject, subject: $subject, action: 'READ');
    session_write_close();   // 인가·감사로그 이후 집계 전 세션락 해제(control_mapping.php 선례)

    if ($found) {
        $guide = vg_control_guide($pdo, $fw, $control);

        // 점검 제목·SSG 룰 ID 는 판정 결과에 붙어 있다(cce.php 가 코드마다 같은 값을 쓴다).
        //   아직 한 번도 점검되지 않은 룰은 둘 다 없다 — 코드와 자체 가이드만 보여준다.
        $in = implode(',', array_fill(0, count($ruleCodes), '?'));
        $st = $pdo->prepare(
            "SELECT code, MIN(title) AS title,
                    MIN(NULLIF(ssg_rule_id, '')) AS ssg_rule_id,
                    COUNT(DISTINCT NULLIF(ssg_rule_id, '')) AS ssg_rule_count
               FROM tb_cce_finding
              WHERE is_deleted = 0 AND code IN ($in) GROUP BY code"
        );
        $st->execute($ruleCodes);
        $titles = [];
        $ssgRuleIds = [];
        foreach ($st->fetchAll() as $t) {
            $code = (string) $t['code'];
            $titles[$code] = (string) $t['title'];
            // 배포판별로 같은 CCE 코드가 여러 SSG 룰에 대응할 수 있다. 그때 임의의 MIN 룰로
            //   보내면 잘못된 상세 링크가 되므로 고유 대응일 때만 링크한다.
            $ssgRuleIds[$code] = (int) ($t['ssg_rule_count'] ?? 0) === 1
                ? (string) ($t['ssg_rule_id'] ?? '')
                : '';
        }

        $guides = vg_cce_rule_guides($ruleCodes);

        // 호스트별 최신 스캔의 CCE 결과만 본다 — 지난 스캔까지 세면 같은 위반이 중복 집계된다
        //   (control_mapping.php 드릴다운이 쓰던 쿼리를 그대로 옮겼다).
        //   tb_scan 조인은 PK 단건 조회라 싸다 — "언제 점검한 결과인가" 를 행마다 밝히려고 붙였다
        //   (compliance_rule.php 의 수집일 컬럼과 같은 사실).
        $baseSql =
            "FROM tb_cce_finding cf
               JOIN " . vg_latest_scan_subq() . " t ON t.mid = cf.scan_id
               JOIN tb_scan s ON s.scan_id = cf.scan_id
               JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
               JOIN tb_control_mapping m ON m.rule_code = cf.code AND m.framework = ? AND m.is_deleted = 0
              WHERE cf.is_deleted = 0 AND m.control_id = ?";

        // 통제 전체뿐 아니라 점검 항목별 현황도 한 번에 집계한다. 상세 표에서 조치 설명과 현재
        //   결과를 함께 보여 주어, 사용자가 호스트 표를 다시 훑어 같은 코드를 셀 필요가 없게 한다.
        $st = $pdo->prepare(
            "SELECT cf.code,
                    SUM(cf.result = 'FAIL') AS fail_cnt,
                    SUM(cf.result = 'PASS') AS pass_cnt,
                    SUM(cf.result = 'NA') AS na_cnt
               $baseSql GROUP BY cf.code"
        );
        $st->execute([$fw, $control]);
        $resultByCode = [];
        foreach ($st->fetchAll() as $r) {
            $code = (string) $r['code'];
            $resultByCode[$code] = [
                'FAIL' => (int) $r['fail_cnt'],
                'PASS' => (int) $r['pass_cnt'],
                'NA'   => (int) $r['na_cnt'],
            ];
            foreach ($counts as $result => $_) { $counts[$result] += $resultByCode[$code][$result]; }
        }
        $total = array_sum($counts);

        foreach ($ruleCodes as $code) {
            $current = $resultByCode[$code] ?? ['FAIL' => 0, 'PASS' => 0, 'NA' => 0];
            $ruleRows[] = [
                'code'        => $code,
                'title'       => $titles[$code] ?? '',
                'ssg_rule_id' => $ssgRuleIds[$code] ?? '',
                'summary'     => $guides[$code]['summary'] ?? '',
                'remediation' => $guides[$code]['remediation'] ?? '',
                'fail_cnt'    => $current['FAIL'],
                'pass_cnt'    => $current['PASS'],
                'na_cnt'      => $current['NA'],
                'result_cnt'  => array_sum($current),
            ];
        }

        $st = $pdo->prepare("SELECT COUNT(DISTINCT h.host_id) AS hosts, MAX(s.collected_at) AS last_at $baseSql");
        $st->execute([$fw, $control]);
        $agg = $st->fetch() ?: [];
        $hostCount = (int) ($agg['hosts'] ?? 0);
        $lastCheckedAt = $agg['last_at'] ?? null;

        $offset = ($page - 1) * $perPage;
        $st = $pdo->prepare(
            "SELECT h.host_id, h.fqdn, cf.code, cf.title, cf.result, cf.severity, cf.rationale, s.collected_at
             $baseSql
              ORDER BY FIELD(cf.result,'FAIL','NA','PASS'),
                       FIELD(cf.severity,'HIGH','MEDIUM','LOW'), h.fqdn, cf.code
              LIMIT $perPage OFFSET $offset"
        );
        $st->execute([$fw, $control]);
        $rows = $st->fetchAll();
    }
} catch (Throwable $e) {
    error_log('[control] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header($control !== '' ? $control : '통제 상세', 'control_mapping');

if ($err !== null) {
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}

$listUrl = '/control_mapping.php?fw=' . urlencode($fw);

if (!$found) {
    ?>
    <div class="card">
      <?php vg_empty([
          'icon'  => '🧭',
          'title' => '이 기준에 없는 통제입니다.',
          'hint'  => '통제 ID 가 정확한지, 기준(ISMS-P · U-코드 · N2SF)을 맞게 골랐는지 확인하세요.',
          'cta'   => ['href' => $listUrl, 'label' => '통제 목록으로'],
      ]); ?>
    </div>
    <?php
    vg_footer();
    return;
}

$failTone = $counts['FAIL'] > 0 ? 'crit'
          : ($counts['NA'] > 0 ? 'med' : ($total > 0 ? 'ok' : 'muted'));
vg_hero(
    vg_h($control),
    [
        vg_h($controlName),
        vg_h($frameworks[$fw]),
        '<a href="' . vg_h($listUrl) . '">통제 목록으로</a>',
    ],
    number_format($counts['FAIL']) . '건',
    $failTone,
    'FAIL',
    'CONTROL DETAIL'
);
?>

<?php
// 히어로는 FAIL 건수만 크게 말한다 — 분모가 없으면 그 수가 큰지 작은지 못 읽는다.
//   결론 한 줄을 히어로 바로 아래 세운다(control_mapping.php·compliance.php 와 같은 원칙).
//   이 화면도 판정은 하지 않는다 — 그 사실을 여기서 분명히 한다.
?>
<p class="sub">이 통제에 매핑된 점검
  <?= number_format($total) ?>건 중 FAIL <?= number_format($counts['FAIL']) ?>건입니다.
  준수/미준수 판정은 하지 않습니다(판정은 컴플라이언스 매핑 화면).</p>

<div class="card">
  <div class="card__body stat-grid">
    <div class="stat">
      <span class="stat__val"><?= number_format($counts['FAIL']) ?></span>
      <div class="why">FAIL</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= number_format($counts['PASS']) ?></span>
      <div class="why">PASS</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= number_format($counts['NA']) ?></span>
      <div class="why">NA(판정 불가)</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= number_format($hostCount) ?></span>
      <div class="why">해당 자산</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= number_format(count($ruleCodes)) ?></span>
      <div class="why">매핑된 점검 항목</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= $lastCheckedAt !== null ? vg_h((string) $lastCheckedAt) : '<span class="why">–</span>' ?></span>
      <div class="why">최근 점검</div>
    </div>
  </div>
</div>

<nav class="subtabs subtabs--sticky">
  <a href="#guide">기준 설명</a>
  <a href="#rules">점검 항목과 조치<span class="n"><?= number_format(count($ruleCodes)) ?></span></a>
  <a href="#hosts">해당 자산<span class="n"><?= number_format($total) ?></span></a>
  <a href="#origin">식별과 출처</a>
</nav>

<section id="guide">
  <div class="card">
    <strong>이 통제가 요구하는 것</strong>
    <span class="why">— <?= vg_h($frameworks[$fw]) ?> · <?= vg_h($control) ?></span>
    <div class="card__body">
      <?php if ($guide !== null): ?>
        <p class="why"><?= vg_h((string) $guide['description']) ?></p>
      <?php else: ?>
        <div class="why">설명이 아직 준비되지 않았습니다. 아래 점검 항목을 먼저 확인하세요.</div>
      <?php endif; ?>
    </div>
  </div>
</section>

<section id="rules">
  <div class="card">
    <strong>점검 항목과 조치 방법</strong>
    <span class="why">— 이 통제에 매핑된 보안설정 점검(CCE)</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '점검 항목', 'width' => '23%'],
            ['label' => '현재 결과', 'width' => '15%'],
            ['label' => '무엇을 보는가'],
            ['label' => '조치 방법'],
        ],
        $ruleRows,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '📋',
                'title' => '이 통제에 매핑된 점검 항목이 없습니다.',
                'hint'  => '매핑은 근거가 있는 항목만 넣습니다 — 없으면 행을 만들지 않습니다.',
            ],
            'cell' => [
                0 => function ($r) {
                    $title = $r['title'] !== '' ? vg_h((string) $r['title']) : '';
                    if ($title !== '' && $r['ssg_rule_id'] !== '') {
                        $title = '<a href="/compliance_rule.php?rule=' . urlencode((string) $r['ssg_rule_id']) . '">'
                               . $title . '</a>';
                    }
                    return '<code class="why">' . vg_h((string) $r['code']) . '</code>'
                         . ($title !== '' ? '<br>' . $title : '');
                },
                1 => function ($r) {
                    if ((int) $r['result_cnt'] === 0) { return vg_badge('점검 결과 없음', 'muted'); }
                    $cnt  = (int) $r['result_cnt'];
                    $fail = (int) $r['fail_cnt'];
                    $tone = $fail > 0 ? 'crit' : ((int) $r['na_cnt'] > 0 ? 'med' : 'ok');
                    $why  = 'PASS ' . number_format((int) $r['pass_cnt'])
                          . ' · 판정 불가 ' . number_format((int) $r['na_cnt']);
                    // 항목별 위반 비율 — 자산 수가 제각각이라 "FAIL 3" 만으로는 크기를 못 읽는다.
                    //   meter 에는 ok 톤이 없다(app.css) → low 로 떨군다. 0% 라 색은 안 보인다.
                    return vg_badge('FAIL ' . number_format($fail), $tone)
                         . '<br><span class="why">' . vg_h($why) . '</span>'
                         . vg_meter($tone === 'ok' ? 'low' : $tone, $fail / $cnt * 100,
                                    'FAIL ' . number_format($fail) . ' / 점검 ' . number_format($cnt) . '건');
                },
                2 => fn($r) => '<span class="why">'
                             . ($r['summary'] !== '' ? vg_h((string) $r['summary']) : '설명 준비 중')
                             . '</span>',
                3 => fn($r) => '<span class="why">'
                             . ($r['remediation'] !== '' ? vg_h((string) $r['remediation']) : '조치 방법 준비 중')
                             . '</span>',
            ],
        ]
    );
    ?>
    </div>
  </div>
</section>

<section id="hosts">
  <div class="card">
    <strong>해당 자산(호스트)</strong>
    <span class="why">— 호스트별 최신 스캔 기준 · NA는 판정 불가</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '호스트'],
            ['label' => '점검 항목'],
            ['label' => '결과', 'key' => 'result', 'width' => '6rem'],
            ['label' => '판정 사유'],
            ['label' => '수집일', 'nowrap' => true, 'width' => '11rem'],
        ],
        $rows,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '📭',
                'title' => '이 통제에 걸린 점검 결과가 없습니다.',
                'hint'  => '수집 결과가 없으며 준수로 간주하지 않습니다.',
            ],
            'cell' => [
                0 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '&amp;tab=cce">'
                             . vg_h((string) $r['fqdn']) . '</a>',
                1 => fn($r) => vg_h((string) $r['title'])
                             . ' <code class="why">' . vg_h((string) $r['code']) . '</code>',
                'result' => function ($r) {
                    $tone = $r['result'] === 'FAIL' ? vg_sev_tone((string) $r['severity'])
                          : ($r['result'] === 'PASS' ? 'low' : 'muted');
                    return vg_badge((string) $r['result'], $tone);
                },
                3 => fn($r) => '<span class="why">' . vg_trunc((string) ($r['rationale'] ?? ''), 80) . '</span>',
                4 => fn($r) => '<span class="why">' . vg_h((string) ($r['collected_at'] ?? '')) . '</span>',
            ],
        ]
    );
    // 결과 뱃지의 색 규칙을 한 줄로 — FAIL 은 그 점검 항목의 **심각도 색**을 그대로 쓴다
    //   (위 셀 콜백의 vg_sev_tone). 그래서 같은 FAIL 이라도 색이 다르게 보인다.
    vg_legend([
        ['label' => 'FAIL(심각도 색)', 'tone' => 'crit'],
        ['label' => 'PASS',            'tone' => 'low'],
        ['label' => 'NA · 판정 불가',   'tone' => 'muted'],
    ], ['inline' => true, 'caption' => '결과']);
    if ($rows) { vg_page_nav($total, $perPage, $page); }
    ?>
    </div>
  </div>
</section>

<section id="origin">
  <div class="card">
    <strong>식별과 출처</strong>
    <span class="why">— 이 통제가 무엇이고 어디까지 점검됐는가</span>
    <div class="card__body">
      <dl class="kv">
        <dt>기준</dt><dd><?= vg_h($frameworks[$fw]) ?></dd>
        <dt>통제 ID</dt><dd><code><?= vg_h($control) ?></code></dd>
        <dt>통제명</dt><dd><?= vg_h($controlName) ?></dd>
        <dt>매핑 점검 항목</dt><dd><?= number_format(count($ruleCodes)) ?>개(CCE 룰코드)</dd>
        <dt>최근 점검</dt>
        <dd><?= $lastCheckedAt !== null ? vg_h((string) $lastCheckedAt) : '<span class="why">점검 이력 없음</span>' ?></dd>
        <dt>집계 기준</dt><dd>호스트별 최신 스캔 1건</dd>
      </dl>
      <div class="actions mt">
        <?php vg_copy_btn($control, '통제 ID 복사'); ?>
        <a class="btn btn--sm btn--ghost" href="<?= vg_h($listUrl) ?>">통제 목록으로</a>
      </div>
    </div>
  </div>
</section>

<?php vg_footer();
