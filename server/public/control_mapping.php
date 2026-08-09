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
// 인가 게이트. 이게 없어서 **비로그인 상태로도 200 + CCE 점검 결과 전량**이 나갔다(실측:
//   빈 쿠키로 curl 하면 다른 화면은 302 login 인데 여기만 200). 상세인 control.php 는 처음부터
//   갖고 있었다 — 목록만 빠져 있었다. 같은 데이터를 여는 두 URL 은 같은 게이트를 지나야 한다.
vg_require_menu('findings');

$err = null;
$fw = vg_control_framework_param($_GET['fw'] ?? null);   // 화이트리스트 검증(SSOT)
$frameworks = vg_control_frameworks();

// 옛 드릴다운 URL 호환 — 상세는 control.php 로 이관했다.
$legacyControl = trim((string) ($_GET['control'] ?? ''));
if ($legacyControl !== '') {
    header('Location: /control.php?fw=' . urlencode($fw) . '&control=' . urlencode($legacyControl), true, 302);
    exit;
}

$rows = [];            // 통제별 집계
$total = 0;            // 페이지네이션 대상 총건수
$uncovered = [];       // 매핑은 있으나 아직 점검 결과가 없는 통제
$mappedRules = 0;      // 이 기준에 매핑된 CCE 룰 수
$findingTotal = 0;     // 이 기준으로 묶인 점검 결과 총건수
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();
    vg_log_activity($pdo, 'PAGE', null, 'view_control_mapping', '통제 기준 매핑 조회 · ' . $fw);
    session_write_close();   // 인가·감사로그 이후 집계 전 세션락 해제(compliance.php 선례)

    // 호스트별 최신 스캔의 CCE 결과만 본다 — 지난 스캔까지 세면 같은 위반이 중복 집계된다.
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

    $offset = ($page - 1) * $perPage;

    // ── 기준의 통제 ID 로 그룹핑 ──
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

    $st = $pdo->prepare("SELECT COUNT(*) FROM ($groupSql) g");
    $st->execute([$fw]);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare("$groupSql ORDER BY fail_cnt DESC, m.control_id LIMIT $perPage OFFSET $offset");
    $st->execute([$fw]);
    $rows = $st->fetchAll();

    // 매핑은 돼 있는데 아직 점검 결과가 하나도 없는 통제 — "안 걸린 것"과 "아직 못 본 것"을
    //   구분해 보여준다(못 채운 걸 준수로 위장하지 않는다). 기준당 통제 수가 수십 개라 전량 조회.
    $st = $pdo->prepare(
        'SELECT DISTINCT control_id, control_name FROM tb_control_mapping
          WHERE framework = ? AND is_deleted = 0 ORDER BY control_id'
    );
    $st->execute([$fw]);
    $all = $st->fetchAll();

    $st = $pdo->prepare("SELECT DISTINCT m.control_id $baseSql");
    $st->execute([$fw]);
    $covered = array_flip(array_map('strval', $st->fetchAll(PDO::FETCH_COLUMN)));
    foreach ($all as $c) {
        if (!isset($covered[(string) $c['control_id']])) { $uncovered[] = $c; }
    }
} catch (Throwable $e) {
    error_log('[control_mapping] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('통제 기준 매핑', 'control_mapping');
?>
  <?php vg_page_title(
      '통제 기준 매핑', 'CONTROL MAPPING',
      '같은 보안설정 점검(CCE) 결과를 고른 기준의 통제로 묶어 셉니다. 준수 여부는 판정하지 않습니다.',
      ['count' => $total]
  ); ?>
  <?php
  // 컴플라이언스 매핑과 이름이 겹쳐 보여 나란히 세운다 — 저기는 준수/미준수까지 **판정**하고,
  //   여기는 같은 점검 결과를 기준별로 **묶어 세기만** 한다(compliance.php 쪽 주석과 한 쌍).
  vg_subtabs([
      'compliance'      => ['label' => '컴플라이언스 매핑', 'href' => '/compliance.php'],
      'control_mapping' => ['label' => '통제 기준 매핑',   'href' => '/control_mapping.php'],
  ], 'control_mapping');
  ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <div class="tabs">
    <?php foreach ($frameworks as $code => $label): ?>
      <a class="pill<?= $code === $fw ? ' pill--on' : '' ?>"
         href="/control_mapping.php?fw=<?= urlencode($code) ?>"><?= vg_h($label) ?></a>
    <?php endforeach; ?>
  </div>

  <div class="cards">
    <div class="kpi kpi--sm"><b><?= number_format($mappedRules) ?></b><span>매핑된 점검 항목</span></div>
    <div class="kpi kpi--sm"><b><?= number_format($findingTotal) ?></b><span>최신 스캔 점검 결과</span></div>
  </div>

  <?php
  // 통제 ID·통제명 모두 상세로 들어가는 링크다 — "누르면 들어간다"가 요구사항이라
  //   누르는 면적을 ID 한 조각으로 좁혀 두지 않는다.
  $detailHref = fn(array $r): string => '/control.php?fw=' . urlencode($fw)
      . '&amp;control=' . urlencode((string) $r['control_id']);
  vg_table(
      [
          ['label' => '통제 ID', 'width' => '9rem', 'class' => 'col-id'],
          ['label' => '통제명'],
          ['label' => '점검 항목', 'width' => '20%'],
          // 'PASS n · NA n · n건' 이 9rem 에서 두 줄로 접혔다 — 한 줄에 들어오게 넓힌다.
          //   11rem 도 세 자리 수가 겹치면 여전히 접혀서(실측 'PASS 176 · NA 484 · 740건') 13rem.
          ['label' => '결과', 'width' => '13rem'],
          ['label' => '위반', 'width' => '6rem', 'align' => 'right'],
      ],
      $rows,
      [
          'empty' => [
              'icon'  => '🧭',
              'title' => '이 기준으로 묶인 점검 결과가 없습니다.',
              'hint'  => '에이전트 수집이 한 번은 돌아야 보안설정 점검 결과가 생깁니다.',
              'cta'   => ['href' => '/assets.php', 'label' => '자산 확인'],
          ],
          'cell' => [
              0 => fn($r) => '<a href="' . $detailHref($r) . '">'
                           . '<code class="why">' . vg_h((string) $r['control_id']) . '</code></a>',
              1 => fn($r) => '<a class="control-name" href="' . $detailHref($r) . '">'
                           . vg_h((string) $r['control_name']) . '</a>',
              2 => fn($r) => '<span class="why">' . vg_trunc((string) ($r['codes'] ?? ''), 60) . '</span>',
              3 => fn($r) => '<span class="why">'
                           . 'PASS ' . number_format((int) $r['pass_cnt'])
                           . ' · NA ' . number_format((int) $r['na_cnt'])
                           . ' · ' . number_format((int) $r['finding_cnt']) . '건</span>',
              4 => function ($r) {
                  $fail = (int) $r['fail_cnt'];
                  return vg_badge(number_format($fail) . '건', $fail > 0 ? 'crit' : 'ok');
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <?php if ($uncovered): ?>
    <div class="card mt-lg">
      <div class="card__body">
        <strong>아직 점검 결과가 없는 통제</strong>
        <p class="why">최신 스캔에 점검 결과가 없습니다 — 준수로 간주하지 않습니다.</p>
        <ul class="hint-list">
          <?php foreach ($uncovered as $c): ?>
            <li><a class="control-name" href="/control.php?fw=<?= urlencode($fw) ?>&amp;control=<?= urlencode((string) $c['control_id']) ?>"><?= vg_h((string) $c['control_id']) ?> · <?= vg_h((string) $c['control_name']) ?></a></li>
          <?php endforeach; ?>
        </ul>
      </div>
    </div>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
