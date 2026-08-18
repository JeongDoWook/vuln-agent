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

// 돌아갈 목록. U-코드는 control_mapping.php 가 kisa-u.php 로 302 하므로 곧장 그리로 보낸다
//   (한 번 튀는 대신 바로 간다 — 목적지는 같다).
$listUrl = $fw === 'KISA_U' ? '/kisa-u.php' : '/control_mapping.php?fw=' . urlencode($fw);

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

<div class="card">
  <div class="card__body stat-grid">
    <?php /* FAIL 타일은 걷었다 — 바로 위 히어로가 같은 수를 같은 라벨('FAIL')로 이미 세워 두었다.
             여기 남는 것은 그 옆에 놓고 봐야 뜻이 생기는 값들(PASS·NA·자산·항목 수)이다. */ ?>
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

<?php /* 설명이 없는 통제는 '기준 설명' 절을 아예 세우지 않는다 — 예전엔 "설명이 아직
         준비되지 않았습니다" 한 줄짜리 카드가 첫 화면 한 판을 먹고, 위 서브탭은 그 빈 카드로
         내려가는 링크였다. 없는 설명을 자리표시 문구로 채우지 않는 건 이 화면이 이미 점검
         항목 표에서 쓰던 기준이다(빈 칸이 '아직 없다'를 그대로 말한다). */ ?>
<nav class="subtabs subtabs--sticky">
  <?php if ($guide !== null): ?><a href="#guide">기준 설명</a><?php endif; ?>
  <a href="#rules">점검 항목과 조치<span class="n"><?= number_format(count($ruleCodes)) ?></span></a>
  <a href="#hosts">해당 자산<span class="n"><?= number_format($total) ?></span></a>
  <a href="#origin">식별과 출처</a>
</nav>

<?php if ($guide !== null): ?>
<section id="guide">
  <div class="card">
    <strong>이 통제가 요구하는 것</strong>
    <?php /* '기준 · 통제 ID' 부제는 걷었다 — 화면 제목이 통제 ID 이고 그 부제가 기준이라,
             한 화면에서 세 번째로 같은 말을 하는 자리였다(식별과 출처 절이 정본으로 갖는다). */ ?>
    <div class="card__body">
      <p class="why"><?= vg_h((string) $guide['description']) ?></p>
    </div>
  </div>
</section>
<?php endif; ?>

<section id="rules">
  <div class="card">
    <strong>점검 항목과 조치 방법</strong>
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
                    // 0 인 항목은 적지 않는다 — 신호는 FAIL 하나뿐인데 'PASS 0' 이 행마다 서서
                    //   읽어야 할 값을 덮었다(cce-rules.php·kisa-u.php 와 같은 어휘).
                    $parts = [];
                    if ((int) $r['pass_cnt'] > 0) { $parts[] = 'PASS ' . number_format((int) $r['pass_cnt']); }
                    if ((int) $r['na_cnt'] > 0)   { $parts[] = '판정 불가 ' . number_format((int) $r['na_cnt']); }
                    $why  = implode(' · ', $parts);
                    // 항목별 위반 비율 — 자산 수가 제각각이라 "FAIL 3" 만으로는 크기를 못 읽는다.
                    //   meter 에는 ok 톤이 없다(app.css) → low 로 떨군다. 0% 라 색은 안 보인다.
                    return vg_badge('FAIL ' . number_format($fail), $tone)
                         . ($why === '' ? '' : '<br><span class="why">' . vg_h($why) . '</span>')
                         . vg_meter($tone === 'ok' ? 'low' : $tone, $fail / $cnt * 100,
                                    'FAIL ' . number_format($fail) . ' / 점검 ' . number_format($cnt) . '건');
                },
                // 없는 설명·조치는 '준비 중' 으로 채우지 않는다 — 빈 칸이 '아직 없다' 를 그대로 말하고,
                //   자리표시 문구는 실제로 적힌 설명과 같은 무게로 읽혀 훑을 때 걸린다.
                2 => fn($r) => $r['summary'] !== ''     ? '<span class="why">' . vg_h((string) $r['summary']) . '</span>' : '',
                3 => fn($r) => $r['remediation'] !== '' ? '<span class="why">' . vg_h((string) $r['remediation']) . '</span>' : '',
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
                    /* FAIL 은 그 점검 항목의 **심각도 색**을 쓴다 — 같은 FAIL 이라도 색이 다르다.
                     *   그 사실을 표 아래 범례로 설명하던 줄은 걷고, 뱃지 자신이 title 로 말하게
                     *   한다(색만으로 남는 정보를 없애지 않으면서 범례 한 줄을 던다). */
                    $title = $r['result'] === 'FAIL' ? '심각도 ' . (string) $r['severity'] : '';
                    return vg_badge((string) $r['result'], $tone, $title);
                },
                3 => fn($r) => '<span class="why">' . vg_trunc((string) ($r['rationale'] ?? ''), 80) . '</span>',
                4 => fn($r) => '<span class="why">' . vg_h((string) ($r['collected_at'] ?? '')) . '</span>',
            ],
        ]
    );
    // 결과 범례는 걷었다 — 뱃지가 FAIL·PASS·NA 를 글자로 달고 있고, 색이 더 말하던
    //   심각도는 위 셀 콜백이 뱃지 title 로 옮겨 갔다.
    if ($rows) { vg_page_nav($total, $perPage, $page); }
    ?>
    </div>
  </div>
</section>

<section id="origin">
  <div class="card">
    <strong>식별과 출처</strong>
    <div class="card__body">
      <?php /* 이 목록에서 네 줄(기준·통제명·매핑 점검 항목·최근 점검)을 걷었다 — 전부 이 화면
               위쪽이 이미 말하던 값이다: 기준·통제명은 히어로 메타, 매핑 점검 항목 수는 서브탭
               숫자와 요약 타일, 최근 점검은 요약 타일. 같은 사실을 한 화면에서 두 번 적지 않는다.
               남긴 둘은 여기서만 말하는 것이다 — 통제 ID 는 아래 복사 버튼이 무엇을 복사하는지
               가리키고, 집계 기준은 이 화면의 모든 숫자가 무엇을 센 것인지 밝힌다. */ ?>
      <dl class="kv">
        <dt>통제 ID</dt><dd><code><?= vg_h($control) ?></code></dd>
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
