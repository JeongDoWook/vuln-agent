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
vg_require_menu('findings');

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

        // 점검 제목은 판정 결과에 붙어 있다(cce.php 가 코드마다 같은 제목을 쓴다).
        //   아직 한 번도 점검되지 않은 룰은 제목이 없다 — 코드만 보여준다.
        $in = implode(',', array_fill(0, count($ruleCodes), '?'));
        $st = $pdo->prepare(
            "SELECT code, MIN(title) AS title FROM tb_cce_finding
              WHERE is_deleted = 0 AND code IN ($in) GROUP BY code"
        );
        $st->execute($ruleCodes);
        $titles = [];
        foreach ($st->fetchAll() as $t) { $titles[(string) $t['code']] = (string) $t['title']; }

        $guides = vg_cce_rule_guides($ruleCodes);
        foreach ($ruleCodes as $code) {
            $ruleRows[] = [
                'code'        => $code,
                'title'       => $titles[$code] ?? '',
                'summary'     => $guides[$code]['summary'] ?? '',
                'remediation' => $guides[$code]['remediation'] ?? '',
            ];
        }

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

        $st = $pdo->prepare("SELECT cf.result, COUNT(*) AS c $baseSql GROUP BY cf.result");
        $st->execute([$fw, $control]);
        foreach ($st->fetchAll() as $r) {
            if (isset($counts[$r['result']])) { $counts[$r['result']] = (int) $r['c']; }
        }
        $total = array_sum($counts);

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
          'hint'  => '통제 ID 가 정확한지, 기준(ISMS-P · U-코드 · N2SF)을 맞게 골랐는지 확인해 주세요.',
          'cta'   => ['href' => $listUrl, 'label' => '통제 목록으로'],
      ]); ?>
    </div>
    <?php
    vg_footer();
    return;
}

$failTone = $counts['FAIL'] > 0 ? 'crit' : 'ok';
vg_hero(
    vg_h($control),
    [
        vg_h($controlName),
        vg_h($frameworks[$fw]),
        '<a href="' . vg_h($listUrl) . '">통제 목록으로</a>',
    ],
    number_format($counts['FAIL']) . '건',
    $failTone,
    '위반',
    'CONTROL DETAIL'
);
?>

<div class="card">
  <strong><?= vg_h($controlName) ?></strong>
  <span class="why">— <?= vg_h($frameworks[$fw]) ?> · 호스트별 최신 스캔 기준</span>
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
      <div class="why">NA(미점검)</div>
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
        <div class="why">설명이 아직 준비되지 않았습니다. 아래 점검 항목을 먼저 확인해 주세요.</div>
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
            ['label' => '점검 항목', 'width' => '26%'],
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
                0 => fn($r) => '<code class="why">' . vg_h((string) $r['code']) . '</code>'
                             . ($r['title'] !== '' ? '<br>' . vg_h((string) $r['title']) : ''),
                1 => fn($r) => '<span class="why">'
                             . ($r['summary'] !== '' ? vg_h((string) $r['summary']) : '설명 준비 중')
                             . '</span>',
                2 => fn($r) => '<span class="why">'
                             . ($r['remediation'] !== '' ? vg_h((string) $r['remediation']) : '조치 방법 준비 중')
                             . '</span>',
            ],
        ]
    );
    ?>
      <?php // 링크를 걸지 않는 이유: docs/ 는 웹으로 서빙하지 않아 누르면 404 가 된다. ?>
      <p class="why">여기 조치는 한 줄 요약입니다. 예시 명령·주의사항·검증 방법을 포함한 자세한 절차는
        저장소 문서 <code>docs/dev/보안설정-조치가이드.md</code> 를 참고하세요.</p>
    </div>
  </div>
</section>

<section id="hosts">
  <div class="card">
    <strong>해당 자산(호스트)</strong>
    <span class="why">— 호스트별 최신 스캔 기준(PASS/FAIL/NA)</span>
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
                'hint'  => '에이전트가 해당 항목을 점검한 뒤 다시 확인해 주세요. 결과가 없다고 준수로 간주하지 않습니다.',
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
        <dt>점검 결과</dt>
        <dd>자산 <?= number_format($hostCount) ?>대 · 결과 <?= number_format($total) ?>건(FAIL <?= number_format($counts['FAIL']) ?>)</dd>
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
