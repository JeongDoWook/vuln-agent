<?php
declare(strict_types=1);

/**
 * compliance_rule.php — SSG(SCAP Security Guide) 룰 상세페이지. 로그인 필요.
 *   ?rule=<rule_id>  ·  ?page=N/?per_page=N (이 룰로 점검된 호스트)
 *
 * compliance_rules.php 는 목록(근거 96자 절단, CIS/NIST/STIG 만 표시)만 있고 상세가 없었다.
 * host.php CCE 탭의 $refBadges 가 이미 이 페이지로 링크를 걸어 두고 있다(수정 전엔 목록 검색으로만 갔다).
 * cve.php 의 상세페이지 패턴(히어로 + 통계 그리드 + 섹션)을 그대로 재사용한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
vg_require_menu('findings');

$err = null; $ruleId = ''; $rule = null; $rows = []; $total = 0;
$counts = ['PASS' => 0, 'FAIL' => 0, 'NA' => 0];
$page = vg_page(); $perPage = vg_perpage();

try {
    $ruleId = trim((string) ($_GET['rule'] ?? ''));
    if ($ruleId !== '') {
        $pdo = vg_pdo();

        $stmt = $pdo->prepare('SELECT * FROM tb_compliance_rules WHERE rule_id = ? AND is_deleted = 0');
        $stmt->execute([$ruleId]);
        $rule = $stmt->fetch() ?: null;

        if ($rule) {
            // 룰 상세 열람 감사로그. rule_id 는 정수 PK 가 아니라 message 에 담는다(cve.php 의 view_cve 와 동일 패턴).
            vg_log_activity($pdo, 'COMPLIANCE_RULE', null, 'view_compliance_rule', $ruleId);

            // 호스트별 최신 스캔 기준으로 이 룰로 점검된 결과만 본다(cve.php 의 $locSql 패턴 재사용).
            $hostSql =
                "FROM tb_cce_findings f
                 JOIN tb_scans s ON s.id = f.scan_id
                 JOIN tb_hosts h ON h.id = s.host_id
                 JOIN " . vg_latest_scan_subq() . " latest
                   ON latest.host_id = s.host_id AND latest.mid = s.id
                 WHERE f.ssg_rule_id = ?";

            $stmt = $pdo->prepare("SELECT COUNT(*) $hostSql");
            $stmt->execute([$ruleId]);
            $total = (int) $stmt->fetchColumn();

            $stmt = $pdo->prepare("SELECT f.result, COUNT(*) AS c $hostSql GROUP BY f.result");
            $stmt->execute([$ruleId]);
            foreach ($stmt->fetchAll() as $r) {
                if (isset($counts[$r['result']])) { $counts[$r['result']] = (int) $r['c']; }
            }

            $offset = ($page - 1) * $perPage;
            $stmt = $pdo->prepare(
                "SELECT h.id AS host_id, h.fqdn, f.result, f.severity, f.evidence, s.collected_at
                 $hostSql
                 ORDER BY FIELD(f.result,'FAIL','NA','PASS'), h.fqdn
                 LIMIT $perPage OFFSET $offset"
            );
            $stmt->execute([$ruleId]);
            $rows = $stmt->fetchAll();
        }
    }
} catch (Throwable $e) {
    error_log('[compliance_rule] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header($ruleId !== '' ? $ruleId : '보안설정 룰', 'compliance');

if ($err !== null) {
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}

$sevUp = $rule ? mb_strtoupper((string) $rule['severity']) : null;
$tone  = $sevUp !== null ? vg_sev_tone($sevUp) : 'muted';

$title = vg_h($ruleId);
vg_hero($title, $rule ? ['<code class="why">' . vg_h($ruleId) . '</code>'] : [], $sevUp, $tone, 'SSG 심각도');
?>

<?php if ($rule === null): ?>
  <div class="card">
    <?php vg_empty([
        'icon'  => '📋',
        'title' => '이 룰은 존재하지 않습니다.',
        'hint'  => 'SSG(SCAP Security Guide) 커넥터가 수집한 룰 ID 인지 확인해 주세요.',
        'cta'   => ['href' => '/compliance_rules.php', 'label' => '룰셋 목록으로'],
    ]); ?>
  </div>
<?php else: ?>
<div class="card">
  <strong><?= vg_h((string) $rule['title']) ?></strong>
  <span class="why">— SSG 보안설정 룰</span>
  <div class="card__body stat-grid">
    <div class="stat">
      <span class="stat__val"><?= vg_badge((string) $sevUp, $tone) ?></span>
      <div class="why">심각도</div>
    </div>
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
      <div class="why">NA(미수집)</div>
    </div>
    <div class="stat">
      <span class="stat__val"><?= !empty($rule['ssg_version']) ? vg_h((string) $rule['ssg_version']) : '<span class="why">–</span>' ?></span>
      <div class="why">SSG 버전</div>
    </div>
  </div>
</div>

<nav class="subtabs subtabs--sticky">
  <a href="#rationale">근거</a>
  <a href="#refs">참조 매핑</a>
  <a href="#hosts">점검된 호스트<span class="n"><?= number_format($total) ?></span></a>
</nav>

<section id="rationale">
  <div class="card">
    <strong>근거(rationale)</strong>
    <span class="why">— SSG 원문 전문</span>
    <div class="card__body">
      <p class="why prose"><?= !empty($rule['rationale']) ? vg_h((string) $rule['rationale']) : '수집된 근거가 없습니다.' ?></p>
    </div>
  </div>
</section>

<section id="refs">
  <div class="card">
    <strong>참조 매핑</strong>
    <span class="why">— 이 룰이 근거로 삼는 모든 기준(CIS/NIST/STIG/PCI-DSS 등)</span>
    <div class="card__body">
      <?php $refs = vg_json_col($rule['refs_json'] ?? null); ?>
      <?php if ($refs): ?>
        <dl class="kv">
          <?php foreach ($refs as $k => $v): ?>
            <dt><?= vg_h((string) $k) ?></dt>
            <dd><?= vg_h(is_array($v) ? implode(', ', $v) : (string) $v) ?></dd>
          <?php endforeach; ?>
        </dl>
      <?php else: ?>
        <div class="why">참조 매핑 정보가 없습니다.</div>
      <?php endif; ?>
      <dl class="kv mt">
        <dt>수집일</dt>
        <dd><?= !empty($rule['created_at']) ? vg_h((string) $rule['created_at']) : '<span class="why">–</span>' ?></dd>
        <dt>갱신일</dt>
        <dd><?= !empty($rule['updated_at']) ? vg_h((string) $rule['updated_at']) : '<span class="why">–</span>' ?></dd>
      </dl>
    </div>
  </div>
</section>

<section id="hosts">
  <div class="card">
    <strong>이 룰로 점검된 호스트</strong>
    <span class="why">— 호스트별 최신 스캔 기준(PASS/FAIL/NA)</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '호스트'],
            ['label' => '결과', 'key' => 'result', 'width' => '6rem'],
            ['label' => '근거'],
            ['label' => '수집일', 'nowrap' => true],
        ],
        $rows,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '📭',
                'title' => '아직 이 룰로 점검된 호스트가 없습니다.',
                'hint'  => '에이전트가 이 항목을 점검한 뒤 다시 확인해 주세요.',
            ],
            'cell' => [
                0 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                'result' => function ($r) {
                    $tone = $r['result'] === 'FAIL' ? vg_sev_tone((string) $r['severity'])
                          : ($r['result'] === 'PASS' ? 'low' : 'muted');
                    return vg_badge((string) $r['result'], $tone);
                },
                2 => fn($r) => '<span class="why">' . vg_trunc((string) $r['evidence'], 60) . '</span>',
                3 => fn($r) => '<span class="why">' . vg_h((string) $r['collected_at']) . '</span>',
            ],
        ]
    );
    if ($rows) { vg_page_nav($total, $perPage, $page); }
    ?>
    </div>
  </div>
</section>
<?php endif; ?>

<?php vg_footer();
