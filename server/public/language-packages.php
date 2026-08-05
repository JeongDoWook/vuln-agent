<?php
declare(strict_types=1);

/**
 * language-packages.php — 언어 패키지(pip/npm/gem/composer/maven/nuget/cargo/go) 라이선스 조회.
 *   design-review 승인 사항: 기존 asset-packages.php/assets.php/host.php(전부 manager IN
 *   dpkg/rpm/apk 라 언어 패키지가 애초에 안 뜬다)는 건드리지 않고 별도 화면으로 신설했다.
 *   라이선스 값의 소스는 v1 기준 SBOM(CycloneDX/SPDX) + pip METADATA + composer installed.json
 *   뿐이다(ingest_parse.php 참고) — 그 외 매니저는 라이선스 없이 이름/버전만 보인다.
 *   KPI·위험도 필터는 사전집계(tb_package_license_summary, OSV 커넥터 실행 시 갱신)만 읽는다 —
 *   tb_package 는 스캔마다 누적되는 원본이라 여기 직접 필터를 걸면 packages 40초 사고가 재현된다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/license_summary.php';   // VG_LANG_MANAGERS, vg_license_risk_*
vg_require_menu('findings');

$err = null; $rows = []; $total = 0; $summaryAt = '';
$riskCounts = ['permissive' => 0, 'copyleft' => 0, 'unknown' => 0];

$q       = trim((string) ($_GET['q'] ?? ''));
$manager = trim((string) ($_GET['manager'] ?? ''));
$risk    = trim((string) ($_GET['risk'] ?? ''));
$page    = vg_page();
$perPage = vg_perpage();

$managerOptions = array_combine(VG_LANG_MANAGERS, VG_LANG_MANAGERS) ?: [];
if (!isset($managerOptions[$manager])) { $manager = ''; }
$riskOptions = ['permissive' => vg_license_risk_label('permissive'), 'copyleft' => vg_license_risk_label('copyleft'), 'unknown' => vg_license_risk_label('unknown')];
if (!isset($riskOptions[$risk])) { $risk = ''; }

try {
    $pdo = vg_pdo();

    // KPI·위험도 집계는 사전집계 테이블에서만 읽는다(원본 tb_package 재집계 금지).
    // SUM(pkg_count) 를 쓴다 — COUNT(*) 는 (manager,name,license) 조합 종류 수라 목록 필터
    // 건수(설치 인스턴스 수, SUM(pkg_count) 기준)와 단위가 달라 KPI 와 목록이 서로 다른
    // 숫자를 보여줬다. pkg_count 컬럼을 여기서 실제로 사용해 통일한다.
    $summaryAt = (string) ($pdo->query('SELECT MAX(updated_at) FROM tb_package_license_summary')->fetchColumn() ?: '');
    foreach ($pdo->query('SELECT risk, SUM(pkg_count) AS c FROM tb_package_license_summary GROUP BY risk') as $r) {
        if (isset($riskCounts[$r['risk']])) { $riskCounts[$r['risk']] = (int) $r['c']; }
    }

    $mgrPlaceholders = implode(',', array_fill(0, count(VG_LANG_MANAGERS), '?'));
    $from = 'FROM tb_host h
             JOIN ' . vg_latest_scan_subq() . ' latest ON latest.host_id = h.host_id
             JOIN tb_scan s ON s.scan_id = latest.mid
             JOIN tb_package p ON p.scan_id = s.scan_id
             LEFT JOIN tb_container c ON c.container_id = p.container_id AND p.container_id <> 0
             LEFT JOIN tb_package_license_summary sm
                    ON sm.manager = p.manager AND sm.name = p.name AND sm.license = p.license';
    $where  = "h.is_deleted = 0 AND p.is_deleted = 0 AND p.manager IN ($mgrPlaceholders)";
    $params = VG_LANG_MANAGERS;
    if ($q !== '') {
        // LIKE 메타문자(%, _, \) 를 이스케이프해 사용자가 입력한 문자 그대로 매칭한다.
        // MySQL LIKE 의 기본 이스케이프 문자가 backslash 라 addcslashes 만으로 충분하다.
        // 접두 검색(뒤쪽 % 만)으로 제한해 idx_package_manager_name(manager, name) 을 탄다 —
        // 앞쪽 와일드카드는 인덱스를 못 써 packages 40초 사고와 같은 무인덱스 스캔이 된다.
        $where .= ' AND p.name LIKE ?';
        $params[] = addcslashes($q, '%_\\') . '%';
    }
    if ($manager !== '') {
        $where .= ' AND p.manager = ?';
        $params[] = $manager;
    }
    if ($risk !== '') {
        $where .= ' AND COALESCE(sm.risk, \'unknown\') = ?';
        $params[] = $risk;
    }

    $st = $pdo->prepare("SELECT COUNT(*) $from WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    // 오프셋에 상한을 둔다 — 총 건수 기준 마지막 페이지를 넘어가지 못하게 clamp.
    if ($total > 0) {
        $page = min($page, (int) ceil($total / $perPage));
    }
    $offset = ($page - 1) * $perPage;
    $st = $pdo->prepare(
        "SELECT h.host_id, h.fqdn, c.name AS container_name, p.manager, p.name, p.version, p.license,
                COALESCE(sm.risk, 'unknown') AS risk, s.collected_at
           $from WHERE $where
          ORDER BY p.name, h.fqdn, p.version, p.package_id
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();
    // 표시용 위험도는 사전집계(요약) 조인이 아니라 vg_license_classify() 순수함수로 직접 계산한다
    // — 페이지당 $perPage 행뿐이라 가볍고, 요약 테이블이 아직 그 (manager,name,license) 조합을
    // 못 따라잡았어도("값은 있는데 뱃지는 미상") 항상 올바른 위험도를 보여준다. 필터(risk=)는
    // 여전히 요약 테이블을 쓴다 — 최대 1분(스케줄러 주기) 지연은 감수한다.
    foreach ($rows as &$row) {
        $row['risk'] = vg_license_classify((string) ($row['license'] ?? ''));
    }
    unset($row);
} catch (Throwable $e) {
    error_log('[language-packages] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

// 열람 감사로그: vg_header() 가 모든 GET 페이지에 대해 자동으로 남긴다(vg_log_page_view) —
//   packages.php/asset-packages.php 등 다른 목록 화면과 동일하게 여기서 따로 호출하지 않는다.
vg_header('언어 패키지 · 라이선스', 'language_packages');
?>
  <?php vg_page_title('언어 패키지 · 라이선스', 'SCA', 'pip/npm/gem/composer/maven/nuget/cargo/go 패키지의 라이선스를 확인합니다.', ['count' => $total, 'count_label' => '건']); ?>
  <?php if ($summaryAt !== ''): ?>
  <div class="sub"><span class="why">집계 기준 <?= vg_h($summaryAt) ?> (OSV 수집 시 갱신) · 라이선스 값은 SBOM/METADATA/composer 소스에서만 채워집니다.</span></div>
  <?php endif; ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <div class="cards">
    <?php foreach (['copyleft', 'permissive', 'unknown'] as $rk): ?>
      <a href="<?= vg_h(vg_qs(['risk' => $risk === $rk ? '' : $rk, 'page' => 1])) ?>"
         class="kpi kpi--sm tone-<?= vg_h(vg_license_risk_tone($rk)) ?><?= $risk === $rk ? ' is-selected' : '' ?>">
        <b><?= number_format($riskCounts[$rk]) ?></b><span><?= vg_h(vg_license_risk_label($rk)) ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'manager', 'selected' => $manager,
       'empty_label' => '전체 매니저', 'options' => $managerOptions],
      ['type' => 'select', 'name' => 'risk', 'selected' => $risk,
       'empty_label' => '전체 위험도', 'options' => $riskOptions],
  ]); ?>

  <?php
  $hasFilter = $q !== '' || $manager !== '' || $risk !== '';
  vg_table(
      [
          ['label' => '패키지', 'width' => '22%', 'class' => 'col-id'],
          ['label' => '매니저', 'width' => '10%'],
          ['label' => '버전', 'width' => '12%'],
          ['label' => '라이선스', 'width' => '20%'],
          ['label' => '위치', 'width' => '20%'],
          ['label' => '수집 시각', 'width' => '16%', 'nowrap' => true],
      ],
      $rows,
      [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 언어 패키지가 없습니다.',
                  'hint'  => '검색어나 매니저·위험도 필터를 바꿔 보세요.',
                  'cta'   => ['href' => '/language-packages.php', 'label' => '필터 초기화'],
              ]
              : array_filter([
                  'icon'  => '📦',
                  'title' => '아직 수집된 언어 패키지가 없습니다.',
                  'hint'  => '에이전트가 pip/npm/gem/composer/maven/nuget/cargo/go 패키지를 수집해야 이 목록이 채워집니다.',
                  'cta'   => vg_connectors_empty_cta(),
              ]),
          'cell' => [
              0 => fn($r) => '<strong>' . vg_h((string) $r['name']) . '</strong>',
              1 => fn($r) => '<code>' . vg_h((string) $r['manager']) . '</code>',
              2 => fn($r) => '<code>' . vg_h((string) ($r['version'] ?? '')) . '</code>',
              3 => function ($r) {
                  if (empty($r['license'])) { return '<span class="why">–</span>'; }
                  return vg_h((string) $r['license']) . ' '
                      . vg_badge(vg_license_risk_label((string) $r['risk']), vg_license_risk_tone((string) $r['risk']));
              },
              4 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '&amp;tab=packages">'
                  . vg_h((string) $r['fqdn']) . '</a>'
                  . (!empty($r['container_name']) ? ' <span class="why">(' . vg_h((string) $r['container_name']) . ')</span>' : ''),
              5 => fn($r) => '<span class="why">' . vg_h((string) $r['collected_at']) . '</span>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
