<?php
declare(strict_types=1);

/**
 * cce-rule.php — CCE 점검 항목 하나의 상세. 로그인 필요.
 *   ?code=CCE-SSH-ROOT  ·  ?page=N/?per_page=N (이 항목에서 FAIL 인 자산)
 *
 * control.php 와 방향이 반대다 — 저기는 "기준(통제) 하나 → 걸린 CCE 결과", 여기는
 *   "CCE 점검 하나 → 그 점검이 증적이 되는 기준·위반 자산". 서로 링크로 오간다.
 *   화면 골격(히어로 + stat-grid + 섹션)은 compliance_rule.php·control.php 와 같은 패턴이다.
 *
 * 점검 항목의 정본은 server/src/cce.php(vg_cce_rules) 이고, 기준 문자열의 정본은
 *   tb_control_mapping 이다 — 이 화면은 둘 다 조회만 한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';           // vg_log_activity
require_once __DIR__ . '/../src/cce.php';             // vg_cce_rules
require_once __DIR__ . '/../src/control_mapping.php'; // vg_control_frameworks, vg_control_mapping_for, vg_cce_rule_guides
// 카탈로그에서도, 통제 상세·탐지 결과에서도 열린다 — compliance_rule.php 와 같은 이유로 넓게 연다.
vg_require_menu_any('catalog', 'compliance', 'findings');

$err = null;
$code = trim((string) ($_GET['code'] ?? ''));
$rule = null;                                   // 점검 항목 메타(코드·제목·심각도·SSG 룰)
$guide = ['summary' => '', 'remediation' => ''];
$mapping = [];                                  // [framework => [['control_id','control_name'], …]]
$ssgRule = null;                                // 참조 근거로 붙는 SSG 룰(있을 때만)
$counts = ['FAIL' => 0, 'PASS' => 0, 'NA' => 0];
$hostCount = 0; $failHosts = 0; $lastCheckedAt = null;
$rows = []; $total = 0;
$page = vg_page();
$perPage = vg_perpage();
$frameworks = vg_control_frameworks();
$fwShort = vg_control_framework_short();

try {
    $catalog = vg_cce_rules();
    // 존재하는 코드만 통과시킨다 — 임의 문자열이 쿼리·감사로그·화면으로 흘러가지 않게.
    $rule = $catalog[$code] ?? null;

    if ($rule !== null) {
        $pdo = vg_pdo();

        // 상세 열람은 감사 대상이다(CLAUDE.md 원칙 7). 코드는 정수 PK 가 아니라 message·subject
        //   로 남긴다(compliance_rule.php 의 view_compliance_rule 과 같은 형태).
        vg_log_activity($pdo, 'CCE_RULE', null, 'view_cce_rule', $code, subject: $code, action: 'READ');
        session_write_close();   // 인가·감사로그 이후 집계 전 세션락 해제(control.php 선례)

        $guide   = vg_cce_rule_guides([$code])[$code] ?? $guide;
        $mapping = vg_control_mapping_for([$code])[$code] ?? [];

        // 호스트별 최신 스캔의 결과만 본다 — 지난 스캔까지 세면 같은 위반이 중복 집계된다
        //   (control.php·control_mapping.php 와 같은 기준).
        $baseSql =
            "FROM tb_cce_finding cf
               JOIN " . vg_latest_scan_subq() . " t ON t.mid = cf.scan_id
               JOIN tb_scan s ON s.scan_id = cf.scan_id
               JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
              WHERE cf.is_deleted = 0 AND cf.code = ?";

        $st = $pdo->prepare(
            "SELECT SUM(cf.result = 'FAIL') AS fail_cnt,
                    SUM(cf.result = 'PASS') AS pass_cnt,
                    SUM(cf.result = 'NA')   AS na_cnt,
                    COUNT(DISTINCT h.host_id) AS hosts,
                    COUNT(DISTINCT CASE WHEN cf.result = 'FAIL' THEN h.host_id END) AS fail_hosts,
                    MAX(s.collected_at) AS last_at
             $baseSql"
        );
        $st->execute([$code]);
        $agg = $st->fetch() ?: [];
        $counts['FAIL'] = (int) ($agg['fail_cnt'] ?? 0);
        $counts['PASS'] = (int) ($agg['pass_cnt'] ?? 0);
        $counts['NA']   = (int) ($agg['na_cnt'] ?? 0);
        $hostCount      = (int) ($agg['hosts'] ?? 0);
        $failHosts      = (int) ($agg['fail_hosts'] ?? 0);
        $lastCheckedAt  = $agg['last_at'] ?? null;

        // 목록은 FAIL 만 — 이 화면의 질문은 "어디를 고쳐야 하나" 다. 전체 결과(PASS·NA 포함)는
        //   탐지 결과 탭으로 보낸다(아래 링크).
        $total = $counts['FAIL'];
        if ($total > 0) {
            $page = min($page, (int) ceil($total / $perPage));
            $offset = ($page - 1) * $perPage;
            $st = $pdo->prepare(
                "SELECT h.host_id, h.fqdn, cf.severity, cf.evidence, cf.rationale, s.collected_at
                 $baseSql AND cf.result = 'FAIL'
                  ORDER BY h.fqdn
                  LIMIT $perPage OFFSET $offset"
            );
            $st->execute([$code]);
            $rows = $st->fetchAll();
        }

        // 참조 근거 — 대응하는 SSG 룰이 있는 항목만(없는 항목은 자체 기준으로 남는다).
        if ($rule['ssg_rule_id'] !== null) {
            $st = $pdo->prepare(
                'SELECT rule_id, title, severity, rationale, ssg_version
                   FROM tb_compliance_rule WHERE rule_id = ? AND is_deleted = 0 LIMIT 1'
            );
            $st->execute([$rule['ssg_rule_id']]);
            $ssgRule = $st->fetch() ?: null;
        }
    }
} catch (Throwable $e) {
    error_log('[cce_rule] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header($code !== '' ? $code : 'CCE 점검 항목', 'cce_rules');

if ($err !== null) {
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}

if ($rule === null) {
    ?>
    <div class="card">
      <?php vg_empty([
          'icon'  => '📋',
          'title' => '이런 점검 항목은 없습니다.',
          'hint'  => 'CCE 코드가 정확한지 확인하세요. 점검 항목은 카탈로그에서 모두 볼 수 있습니다.',
          'cta'   => ['href' => '/cce-rules.php', 'label' => 'CCE 카탈로그로'],
      ]); ?>
    </div>
    <?php
    vg_footer();
    return;
}

$sev = (string) $rule['severity'];
vg_hero(
    vg_h((string) $rule['title']),
    [
        '<code class="why">' . vg_h($code) . '</code>',
        '점검된 자산 ' . number_format($hostCount) . '대',
        '<a href="/cce-rules.php">← CCE 카탈로그</a>',
    ],
    $sev,
    vg_sev_tone($sev),
    '점검 심각도',
    'CCE DETAIL'
);
?>

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
      <span class="stat__val"><?= number_format($hostCount) ?>대</span>
      <div class="why">점검 자산</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= number_format($failHosts) ?>대</span>
      <div class="why">위반 자산</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= $lastCheckedAt !== null ? vg_h((string) $lastCheckedAt) : '<span class="why">–</span>' ?></span>
      <div class="why">최근 점검</div>
    </div>
  </div>
</div>

<?php vg_decision_flow([
    ['label' => '점검 근거', 'hint' => '무엇을 보고 판정했나', 'href' => '#check'],
    ['label' => '영향 대상', 'hint' => number_format($failHosts) . '대 위반', 'href' => '#hosts'],
    ['label' => '조치', 'hint' => '기준값과 조치 방법', 'href' => '#check'],
    ['label' => '재검증', 'hint' => '최신 자산 스캔 판정 확인', 'href' => '/findings.php?type=cce&q=' . urlencode($code) . '&res=ALL'],
]); ?>

<nav class="subtabs subtabs--sticky">
  <a href="#check">점검과 조치</a>
  <a href="#controls">기준 매핑<span class="n"><?= number_format(array_sum(array_map('count', $mapping))) ?></span></a>
  <a href="#hosts">위반 자산<span class="n"><?= number_format($total) ?></span></a>
  <a href="#origin">식별과 출처</a>
</nav>

<section id="check">
  <div class="card">
    <strong>무엇을 점검하고 어떻게 고치나</strong>
    <span class="why">— 판정 로직과 같은 기준(server/src/cce.php)</span>
    <div class="card__body">
      <dl class="kv">
        <dt>무엇을 보는가</dt>
        <dd><?= $guide['summary'] !== '' ? vg_h($guide['summary']) : '<span class="why">설명 준비 중</span>' ?></dd>
        <dt>조치 방법</dt>
        <dd><?= $guide['remediation'] !== '' ? vg_h($guide['remediation']) : '<span class="why">조치 방법 준비 중</span>' ?></dd>
        <dt>심각도</dt><dd><?= vg_badge($sev, vg_sev_tone($sev)) ?></dd>
      </dl>
      <p class="why">수집값이 없으면 PASS 가 아니라 NA(판정 불가)로 남습니다 — 못 본 것을 괜찮다고 하지 않습니다.</p>
    </div>
  </div>
</section>

<section id="controls">
  <div class="card">
    <strong>이 점검이 증적이 되는 기준</strong>
    <span class="why">— 매핑의 정본은 통제 기준 매핑(tb_control_mapping)</span>
    <div class="card__body">
    <?php
    $mapRows = [];
    foreach ($mapping as $fw => $items) {
        foreach ($items as $it) {
            $mapRows[] = [
                'fw'           => (string) $fw,
                'control_id'   => $it['control_id'],
                'control_name' => $it['control_name'],
            ];
        }
    }
    vg_table(
        [
            ['label' => '기준', 'width' => '22%'],
            ['label' => '통제 ID', 'width' => '18%'],
            ['label' => '통제명'],
        ],
        $mapRows,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '🧭',
                'title' => '대응하는 기준 통제가 없습니다.',
                'hint'  => '근거가 있는 항목만 매핑합니다 — 없으면 행을 만들지 않습니다(자체 기준 점검).',
            ],
            'cell' => [
                0 => fn($r) => vg_h($frameworks[$r['fw']] ?? $r['fw']),
                1 => fn($r) => '<a href="/control.php?fw=' . urlencode((string) $r['fw'])
                             . '&amp;control=' . urlencode((string) $r['control_id']) . '">'
                             . vg_badge(($fwShort[$r['fw']] ?? $r['fw']) . ' ' . $r['control_id'], 'muted')
                             . '</a>',
                2 => fn($r) => vg_h((string) $r['control_name']),
            ],
        ]
    );
    ?>
    </div>
  </div>
</section>

<section id="hosts">
  <div class="card">
    <strong>이 점검에서 FAIL 인 자산</strong>
    <span class="why">— 호스트별 최신 스캔 기준</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '호스트'],
            ['label' => '근거값'],
            ['label' => '판정 사유'],
            ['label' => '수집일', 'nowrap' => true, 'width' => '11rem'],
        ],
        $rows,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '📭',
                'title' => $counts['FAIL'] + $counts['PASS'] + $counts['NA'] === 0
                    ? '아직 이 항목으로 점검된 자산이 없습니다.'
                    : '이 항목에서 FAIL 인 자산이 없습니다.',
                'hint'  => 'NA(판정 불가) ' . number_format($counts['NA']) . '건은 수집이 안 된 항목입니다 — 위반 0건이 "준수"를 뜻하지 않습니다.',
            ],
            'cell' => [
                0 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '&amp;tab=cce">'
                             . vg_h((string) $r['fqdn']) . '</a>',
                1 => fn($r) => '<span class="why">' . vg_trunc((string) ($r['evidence'] ?? ''), 80) . '</span>',
                2 => fn($r) => '<span class="why">' . vg_trunc((string) ($r['rationale'] ?? ''), 80) . '</span>',
                3 => fn($r) => '<span class="why">' . vg_h((string) ($r['collected_at'] ?? '')) . '</span>',
            ],
        ]
    );
    if ($rows) { vg_page_nav($total, $perPage, $page); }
    ?>
      <div class="actions mt">
        <a class="btn btn--sm btn--ghost" href="/findings.php?type=cce&amp;q=<?= urlencode($code) ?>">전체 판정 결과 보기(PASS·NA 포함)</a>
      </div>
    </div>
  </div>
</section>

<section id="origin">
  <div class="card">
    <strong>식별과 출처</strong>
    <span class="why">— 이 점검이 무엇이고 근거를 어디서 가져오는가</span>
    <div class="card__body">
      <dl class="kv">
        <dt>CCE 코드</dt><dd><code><?= vg_h($code) ?></code></dd>
        <dt>점검 항목</dt><dd><?= vg_h((string) $rule['title']) ?></dd>
        <dt>판정 주체</dt><dd>중앙 서버(에이전트는 수집만 한다)</dd>
        <dt>최근 점검</dt>
        <dd><?= $lastCheckedAt !== null ? vg_h((string) $lastCheckedAt) : '<span class="why">점검 이력 없음</span>' ?></dd>
        <dt>집계 기준</dt><dd>호스트별 최신 스캔 1건</dd>
      </dl>

      <details>
        <summary>참조 근거 · SSG 룰<?= $ssgRule !== null ? ' ' . vg_h((string) $ssgRule['rule_id']) : '' ?></summary>
        <?php if ($rule['ssg_rule_id'] === null): ?>
          <p class="why">대응하는 SSG(SCAP Security Guide) 룰이 없는 자체 기준 항목입니다.
            KISA 가이드 고유 항목이거나, SSG 가 같은 대상을 다루지 않는 경우입니다.</p>
        <?php elseif ($ssgRule === null): ?>
          <p class="why">대응 룰은 <code><?= vg_h((string) $rule['ssg_rule_id']) ?></code> 이지만
            아직 수집되지 않았습니다 — SSG 커넥터가 한 번은 돌아야 합니다.</p>
        <?php else: ?>
          <?php
          // SSG 원문은 XHTML 조각이다. <br> 만 줄바꿈으로 살리고 나머지 태그는 걷어낸다
          //   (compliance_rule.php 와 같은 처리 — 태그가 글자로 보이는 것을 막는다).
          $ssgWhy = preg_replace('/<br\s*\/?>/i', "\n", (string) ($ssgRule['rationale'] ?? '')) ?? '';
          $ssgWhy = trim(strip_tags($ssgWhy));
          ?>
          <dl class="kv">
            <dt>룰 ID</dt>
            <dd><a href="/compliance_rule.php?rule=<?= urlencode((string) $ssgRule['rule_id']) ?>">
              <code><?= vg_h((string) $ssgRule['rule_id']) ?></code></a></dd>
            <dt>제목</dt><dd><?= vg_h((string) $ssgRule['title']) ?></dd>
            <dt>SSG 심각도</dt>
            <dd><?= vg_badge(mb_strtoupper((string) $ssgRule['severity']), vg_sev_tone(mb_strtoupper((string) $ssgRule['severity']))) ?></dd>
            <dt>SSG 버전</dt>
            <dd><?= !empty($ssgRule['ssg_version']) ? vg_h((string) $ssgRule['ssg_version']) : '<span class="why">–</span>' ?></dd>
            <dt>근거</dt>
            <dd class="why"><?= $ssgWhy !== '' ? nl2br(vg_h($ssgWhy), false) : '수집된 근거가 없습니다.' ?></dd>
          </dl>
        <?php endif; ?>
      </details>

      <div class="actions mt">
        <?php vg_copy_btn($code, 'CCE 코드 복사'); ?>
        <a class="btn btn--sm btn--ghost" href="/cce-rules.php?q=<?= urlencode($code) ?>">카탈로그에서 보기</a>
      </div>
    </div>
  </div>
</section>

<?php vg_footer();
