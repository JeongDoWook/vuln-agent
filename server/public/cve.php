<?php
declare(strict_types=1);

/**
 * cve.php — CVE 상세페이지. 로그인 필요.
 *   ?cve=CVE-XXXX-XXXXX  ·  ?page=N/?per_page=N (발견 위치) ·  ?vpage=N/?vper_page=N (벤더 판정) ·
 *   ?apage=N/?aper_page=N (영향 패키지)
 *
 * 구성: 히어로(식별 + 등급) → 통계 그리드(핵심 지표 한눈에) → 앵커 내비(sticky) →
 *   요약 → 공격 벡터 → (있으면) 벤더 판정 → 영향 패키지 → 발견 위치 → 참조 자료.
 *   예전엔 탭 3개(개요/영향 패키지/발견 위치) 뒤에 숨기고 지표를 사이드바에 따로 뒀는데,
 *   "한눈에 안 들어온다" 는 사용자 피드백의 핵심 원인이었다 — 탭 전환 없이 스크롤 한 번으로
 *   전부 보이는 단일 페이지로 바꾼다. 세 섹션(벤더 판정·영향 패키지·발견 위치) 모두 같은 화면에
 *   동시에 존재해 건수가 많을 수 있으므로 각각 독립된 쿼리 파라미터로 페이지네이션한다
 *   (vg_page_nav 의 파라미터명을 섹션마다 다르게 줘서 서로의 페이지 이동이 섞이지 않게 한다).
 *
 * cvss_vector·cwe·due_date·ransomware 는 커넥터가 이제야 받아오기 시작한 필드라
 * 예전에 수집된 행은 NULL 이다. 전부 "없으면 그 줄을 생략" 으로 처리한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
vg_require_menu('findings');

/**
 * 벤더 판정 5종 — vendor.php 의 VG_VENDOR_SRC 를 이 CVE 하나로 좁혀 최소 재현한다
 * (의도적 중복 — vendor.php 는 필터·페이지네이션까지 갖춘 별도 화면이라 그대로 재사용할 수
 * 없고, 여긴 "한 CVE 분량" 이라 COUNT·LIMIT 도 필요 없다. vendor.php 자체는 건드리지 않는다).
 * cols 는 UNION 컬럼을 (src, vendor, rel, pkg, fixed, state) 로 고정 — 다섯 갈래가 같아야 한다.
 */
const VG_CVE_VENDOR_SRC = [
    'debtracker' => [
        'label' => '데비안 보안 트래커',
        'from'  => 'tb_debian_tracker',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'debtracker' AS src, 'debian' AS vendor, release_codename AS rel, pkg_name AS pkg,"
                 . " fixed_version AS fixed, IF(has_fix = 1, '수정본 있음', '수정본 없음') AS state,"
                 . " other_versions AS extra1, is_binary AS extra2",
    ],
    'rhoval' => [
        'label' => 'RHEL 계열 벤더 권고(OVAL)',
        'from'  => 'tb_vendor_errata',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'rhoval' AS src, vendor, release_major AS rel, pkg_name AS pkg,"
                 . " fixed_evr AS fixed, severity AS state, advisory AS extra1, NULL AS extra2",
    ],
    'rhunfixed' => [
        'label' => 'Red Hat 미수정 CVE(조치 불가)',
        'from'  => 'tb_vendor_unfixed',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'rhunfixed' AS src, vendor, release_major AS rel, component AS pkg,"
                 . " NULL AS fixed, fix_state AS state, cvss AS extra1, checked_at AS extra2",
    ],
    'ubuntuoval' => [
        'label' => '우분투 보안 OVAL',
        'from'  => 'tb_ubuntu_oval',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'ubuntuoval' AS src, 'ubuntu' AS vendor, release_codename AS rel, pkg_name AS pkg,"
                 . " fixed_evr AS fixed, severity AS state, NULL AS extra1, NULL AS extra2",
    ],
    'kcve' => [
        'label' => '리눅스 커널 CNA(kernel.org)',
        'from'  => 'tb_kernel_cve_fixes f JOIN tb_kernel_cves k ON k.cve_id = f.cve_id',
        'cve'   => 'f.cve_id',
        'soft'  => false,   // 커널 두 테이블엔 소프트삭제 컬럼이 없다(vendor.php 와 같은 확인 사항).
        'cols'  => "'kcve' AS src, 'kernel' AS vendor, f.stream AS rel, 'linux' AS pkg,"
                 . " f.fixed_version AS fixed, k.mainline_fixed AS state, NULL AS extra1, NULL AS extra2",
    ],
];

$err = null; $cveId = ''; $cve = null; $kev = null; $affected = []; $locations = []; $vendorRows = [];
$locTotal = 0; $assetTotal = 0; $page = vg_page(); $perPage = vg_perpage();
$vendorTotal = 0; $vPage = vg_page('vpage'); $vPerPage = vg_perpage(VG_PERPAGE_DEFAULT, 'vper_page');
$affectedTotal = 0; $aPage = vg_page('apage'); $aPerPage = vg_perpage(VG_PERPAGE_DEFAULT, 'aper_page');

try {
    $raw = (string) ($_GET['cve'] ?? '');
    // 이 정규식은 vendor.php 의 CVE 컬럼 렌더러(cell[3], 링크 여부 판정)와 동기화되어야 한다 —
    //   거기서도 같은 식을 그대로 복제해 쓴다(의도적 중복, 공유 상수로 안 뽑음 — 최초 작업 지침의
    //   YAGNI). 둘 중 하나만 고치면 "링크는 걸리는데 여긴 튕긴다" 가 조용히 생기니 같이 바꿀 것.
    if (!preg_match('/^CVE-\d{4}-\d+$/i', $raw)) {
        $err = '잘못된 CVE 형식입니다.';
    } else {
        $cveId = strtoupper($raw);
        $pdo = vg_pdo();

        $stmt = $pdo->prepare('SELECT * FROM tb_cves WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $cve = $stmt->fetch() ?: null;

        if ($cve) {
            // CVE 상세 열람 감사로그. CVE ID 는 정수 PK 가 아니라 message 에 담는다(host.php 의 fqdn 과 동일한 방식).
            vg_log_activity($pdo, 'CVE', null, 'view_cve', $cveId);
        }

        $stmt = $pdo->prepare('SELECT * FROM tb_kev_catalog WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $kev = $stmt->fetch() ?: null;

        // 벤더 판정 5종 UNION — 커널/RHEL/우분투는 릴리스·패키지별로 행이 쪼개져 CVE 하나가
        //   수백~수천 건도 나올 수 있다(CVE-2023-44487 실측 373건). 정확한 총 건수를 COUNT 로
        //   구하고, 목록은 페이지 단위(vpage/vper_page)만 가져온다.
        $vParts = []; $vParams = [];
        foreach (VG_CVE_VENDOR_SRC as $def) {
            $w = ($def['soft'] ? 'is_deleted = 0 AND ' : '') . $def['cve'] . ' = ?';
            $vParts[] = "SELECT {$def['cols']} FROM {$def['from']} WHERE $w";
            $vParams[] = $cveId;
        }
        $vUnion = implode(' UNION ALL ', $vParts);

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM ($vUnion) t");
        $stmt->execute($vParams);
        $vendorTotal = (int) $stmt->fetchColumn();

        $vOffset = ($vPage - 1) * $vPerPage;
        $stmt = $pdo->prepare("$vUnion ORDER BY src, vendor, rel LIMIT $vPerPage OFFSET $vOffset");
        $stmt->execute($vParams);
        $vendorRows = $stmt->fetchAll();

        $stmt = $pdo->prepare('SELECT COUNT(*) FROM tb_cve_affected_packages WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $affectedTotal = (int) $stmt->fetchColumn();

        $aOffset = ($aPage - 1) * $aPerPage;
        $stmt = $pdo->prepare(
            "SELECT ecosystem, package_name, fixed_version FROM tb_cve_affected_packages WHERE cve_id = ?
             ORDER BY ecosystem, package_name LIMIT $aPerPage OFFSET $aOffset"
        );
        $stmt->execute([$cveId]);
        $affected = $stmt->fetchAll();

        // 호스트별 최신 스캔 기준으로 이 CVE 가 발견된 위치.
        //   한 자산에서 여러 건이 나온다: 같은 CVE 가 여러 패키지에 걸리고(curl·libcurl4t64 처럼
        //   같은 소스의 바이너리들), 컨테이너 안에서도 따로 잡힌다.
        $locSql =
            "FROM tb_findings f
             JOIN tb_scans s ON s.id = f.scan_id
             JOIN tb_hosts h ON h.id = s.host_id
             LEFT JOIN tb_containers c ON c.id = f.container_id
             JOIN " . vg_latest_scan_subq() . " latest
               ON latest.host_id = s.host_id AND latest.mid = s.id
             WHERE f.cve_id = ?";
        $stmt = $pdo->prepare("SELECT COUNT(*) $locSql");
        $stmt->execute([$cveId]);
        $locTotal = (int) $stmt->fetchColumn();

        // **영향 자산은 발견 건수가 아니라 호스트 수다.** COUNT(*) 를 "N대"로 찍으면
        //   서버 1대인데 "4대"가 된다(패키지 2종 × CVE 2건 = 4행이었을 뿐 — 실측).
        //   위험 범위를 부풀려 보여주는 셈이라, 중복 없는 호스트로 센다.
        $stmt = $pdo->prepare("SELECT COUNT(DISTINCT h.id) $locSql");
        $stmt->execute([$cveId]);
        $assetTotal = (int) $stmt->fetchColumn();

        $offset = ($page - 1) * $perPage;
        $stmt = $pdo->prepare(
            "SELECT h.id AS host_id, h.fqdn, IFNULL(c.cid, '') AS ctr,
                    f.severity, f.runtime_status, f.package_name, f.installed_version, s.collected_at
             $locSql
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), h.fqdn, c.cid
             LIMIT $perPage OFFSET $offset"
        );
        $stmt->execute([$cveId]);
        $locations = $stmt->fetchAll();
    }
} catch (Throwable $e) {
    error_log('[cve] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header($cveId !== '' ? $cveId : 'CVE', 'findings');

if ($err !== null) {
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}

// 등급은 CVSS 점수에서 파생한다 — tb_cves 엔 등급 컬럼이 없다(cves.php 목록과 같은 구간).
$cvss    = $cve['cvss'] ?? null;
$sevName = vg_cvss_sev($cvss === null ? null : (string) $cvss);
$sevUp   = $sevName !== '' ? strtoupper($sevName) : null;
$tone    = $sevUp !== null ? vg_sev_tone($sevUp) : 'muted';

// KEV 패치 기한 — "언제까지 고쳐야 하나" 를 말해주는 유일한 신호. 지났으면 붉게.
//   통계 그리드·사이드 카드가 둘 다 이 값을 쓰므로 히어로보다 먼저 계산해 둔다.
$due = $kev['due_date'] ?? null;
$dLeft = null; $overdue = false;
if ($due) {
    $dLeft   = (int) (new DateTimeImmutable('today'))->diff(new DateTimeImmutable((string) $due))->format('%r%a');
    $overdue = $dLeft < 0;
}

// 히어로 제목 — KEV·랜섬웨어는 다른 무엇보다 먼저 보여야 할 신호라 제목 옆에 붙인다.
$title = vg_h($cveId);
if ($kev) {
    $title .= ' ' . vg_badge('KEV', 'crit', '악용이 확인된 취약점 — CISA KEV 등재');
    if (!empty($kev['ransomware'])) {
        $title .= ' ' . vg_badge('랜섬웨어', 'crit', '랜섬웨어 캠페인에 실제로 사용된 취약점');
    }
}

vg_hero($title, ['<a href="/findings.php?q=' . urlencode($cveId) . '">취약점 현황에서 보기</a>'], $sevUp ?? '등급 미상', $tone, 'CVSS 등급');
?>

<?php if ($cve === null): ?>
  <div class="card">
    <?php vg_empty([
        'icon'  => '📭',
        'title' => '이 CVE 는 아직 수집되지 않았습니다.',
        'hint'  => 'NVD 커넥터가 수집한 뒤 다시 확인해 주세요.',
    ]); ?>
  </div>
<?php else: ?>
<div class="card">
  <strong>핵심 지표</strong>
  <span class="why">— 흩어놓지 않고 한 카드에 모았다</span>
  <div class="card__body stat-grid">
    <div class="stat">
      <?php if ($cvss !== null): ?>
        <div class="score tone-<?= vg_h($tone) ?>"><?= vg_h((string) $cvss) ?><small> / 10</small></div>
        <div class="meter meter--<?= vg_h($tone) ?>">
          <i style="width:<?= (int) round(min(10.0, max(0.0, (float) $cvss)) * 10) ?>%"></i>
        </div>
      <?php else: ?>
        <span class="stat__val"><span class="why">–</span></span>
      <?php endif; ?>
      <div class="why">CVSS 기본점수</div>
    </div>

    <div class="stat">
      <span class="stat__val"><?= vg_epss_cell($cve['epss'] ?? null, $cve['epss_percentile'] ?? null) ?></span>
      <div class="why">EPSS(악용확률)</div>
    </div>

    <div class="stat">
      <span class="stat__val">
        <?= $kev ? vg_badge('등재됨', 'crit', '실제 악용이 확인된 취약점') : vg_badge('미등재', 'muted') ?>
      </span>
      <div class="why">CISA KEV</div>
    </div>

    <?php if ($kev && $due !== null && $due !== ''): ?>
      <div class="stat">
        <span class="stat__val <?= $overdue ? 'is-danger' : '' ?>"><?= vg_h((string) $due) ?></span>
        <div class="why"><?= $overdue ? vg_h(abs($dLeft) . '일 초과') : vg_h('D-' . $dLeft) ?> · 패치 기한</div>
      </div>
    <?php endif; ?>

    <div class="stat">
      <span class="stat__val"><?= !empty($cve['cwe']) ? vg_h((string) $cve['cwe']) : '<span class="why">–</span>' ?></span>
      <div class="why">CWE 유형</div>
    </div>

    <div class="stat">
      <span class="stat__val"><?= $cve['published'] ? vg_h((string) $cve['published']) : '<span class="why">–</span>' ?></span>
      <div class="why">공개일</div>
    </div>

    <div class="stat">
      <span class="stat__val"><?= number_format($assetTotal) ?>대</span>
      <div class="why">영향 자산<?= $locTotal > $assetTotal ? ' · 발견 ' . number_format($locTotal) . '건' : '' ?></div>
    </div>
  </div>
</div>
<?php endif; ?>

<nav class="subtabs subtabs--sticky">
  <a href="#summary">요약</a>
  <a href="#vector">공격 벡터</a>
  <?php if ($vendorTotal > 0): ?><a href="#vendor">벤더 판정<span class="n"><?= number_format($vendorTotal) ?></span></a><?php endif; ?>
  <a href="#affected">영향 패키지<span class="n"><?= number_format($affectedTotal) ?></span></a>
  <a href="#locations">발견 위치<span class="n"><?= number_format($locTotal) ?></span></a>
  <a href="#references">참조 자료</a>
</nav>

<section id="summary">
  <div class="card">
    <strong>요약</strong>
    <p class="why prose"><?= $cve && $cve['summary'] ? vg_h($cve['summary']) : '수집된 설명이 없습니다.' ?></p>
  </div>

  <?php if ($kev && !empty($kev['note'])): ?>
    <div class="card">
      <strong>CISA KEV</strong>
      <span class="why">— 실제 악용 확인 · 최우선 대응 대상</span>
      <div class="card__body">
        <p class="why prose"><?= vg_h((string) $kev['note']) ?></p>
      </div>
    </div>
  <?php endif; ?>
</section>

<section id="vector">
  <?php
  // CVSS 벡터 분해 — 점수 하나로는 "원격인지 로컬인지, 인증이 필요한지" 를 알 수 없다.
  $parts  = vg_cvss_vector_parts($cve['cvss_vector'] ?? null);
  $vecRaw = $cve['cvss_vector'] ?? null;
  ?>
  <?php if ($parts): ?>
    <div class="card">
      <strong>공격 벡터</strong>
      <span class="why">— 붉은 값이 공격자에게 유리한 조건이다</span>
      <div class="card__body">
        <dl class="kv">
          <?php foreach ($parts as $p): ?>
            <dt><?= vg_h($p['label']) ?></dt>
            <dd class="<?= $p['danger'] ? 'is-danger' : '' ?>"><?= vg_h($p['value']) ?></dd>
          <?php endforeach; ?>
        </dl>
        <div class="why mt"><code><?= vg_h((string) $vecRaw) ?></code></div>
      </div>
    </div>
  <?php elseif (!empty($vecRaw)): ?>
    <div class="card">
      <strong>공격 벡터</strong>
      <div class="card__body">
        <code><?= vg_h((string) $vecRaw) ?></code>
        <div class="why">해독할 수 없는 형식입니다(CVSS v2 벡터일 수 있음).</div>
      </div>
    </div>
  <?php else: ?>
    <div class="card">
      <strong>공격 벡터</strong>
      <div class="card__body">
        <div class="why">벡터 정보가 없습니다. NVD 커넥터가 다시 돌면 채워집니다.</div>
      </div>
    </div>
  <?php endif; ?>
</section>

<?php if ($vendorTotal > 0): ?>
<section id="vendor">
  <div class="card">
    <strong>벤더 판정</strong>
    <span class="why">— 벤더별 패치 여부 원본(5개 소스)</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '소스', 'width' => '11rem'],
            ['label' => '벤더/릴리스', 'width' => '12rem'],
            ['label' => '패키지'],
            ['label' => '고친 버전 / 상태'],
        ],
        $vendorRows,
        [
            'card' => false,
            'empty' => [
                'icon'  => '🏷️',
                'title' => '이 페이지에 표시할 벤더 판정이 없습니다.',
                'hint'  => '앞 페이지로 돌아가 보세요.',
            ],
            'cell' => [
                0 => function ($r) {
                    $d = VG_CVE_VENDOR_SRC[$r['src']] ?? null;
                    $label = $d !== null ? $d['label'] : (string) $r['src'];
                    return '<span class="pill">' . vg_h($label) . '</span>';
                },
                1 => fn($r) => vg_h((string) $r['vendor']) . '<span class="why">/</span>' . vg_h((string) $r['rel']),
                2 => fn($r) => '<a href="/findings.php?q=' . urlencode((string) $r['pkg']) . '">'
                             . vg_trunc((string) $r['pkg'], 32) . '</a>',
                3 => function ($r) use ($cveId) {
                    // vendor.php 와 같은 벤더 링크·툴팁 규칙(작업 1·2) — 한쪽만 반영되면 사용자가 헷갈린다.
                    $src = (string) $r['src'];
                    $tipParts = [];
                    if ($src === 'debtracker') {
                        $tipParts[] = ((int) $r['extra2']) === 1 ? '바이너리 패키지' : '소스 패키지';
                        $ov = trim((string) ($r['extra1'] ?? ''));
                        if ($ov !== '') { $tipParts[] = '예외 버전 ' . $ov; }
                    } elseif ($src === 'rhunfixed') {
                        $cvss = trim((string) ($r['extra1'] ?? ''));
                        if ($cvss !== '') { $tipParts[] = 'CVSS ' . $cvss; }
                        $checkedAt = trim((string) ($r['extra2'] ?? ''));
                        if ($checkedAt !== '') { $tipParts[] = '확인일 ' . substr($checkedAt, 0, 10); }
                    }
                    $tipAttr = $tipParts ? ' title="' . vg_h(implode(' · ', $tipParts)) . '"' : '';

                    if (!empty($r['fixed'])) {
                        $body = '<span class="pill"' . $tipAttr . '>' . vg_h((string) $r['fixed']) . ' 이상</span>';
                    } else {
                        $state = trim((string) ($r['state'] ?? ''));
                        $body = $state !== ''
                            ? '<span class="why"' . $tipAttr . '>' . vg_h($state) . '</span>'
                            : '<span class="why">–</span>';
                    }

                    $link = $src === 'rhoval'
                        ? vg_vendor_advisory_url((string) $r['vendor'], (string) ($r['extra1'] ?? ''), (string) $r['rel'])
                        : (in_array($src, ['debtracker', 'ubuntuoval', 'rhunfixed'], true) ? vg_vendor_cve_url($src, $cveId) : null);
                    if ($link !== null) {
                        $body .= ' <a class="why" href="' . vg_h($link) . '" target="_blank" rel="noopener">원문 ↗</a>';
                    }
                    return $body;
                },
            ],
        ]
    );
    if ($vendorRows) { vg_page_nav($vendorTotal, $vPerPage, $vPage, 'vpage', 'vper_page'); }
    ?>
    </div>
    <div class="why mt">
      <a href="/vendor.php?q=<?= urlencode($cveId) ?>">벤더 판정 전체 보기(필터·상세) →</a>
    </div>
  </div>
</section>
<?php endif; ?>

<section id="affected">
  <div class="card">
    <strong>영향 패키지</strong>
    <span class="why">— 이 CVE 의 전역 영향 범위(설치 여부 무관)</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '생태계', 'key' => 'ecosystem', 'width' => '10rem'],
            ['label' => '패키지', 'key' => 'package_name'],
            ['label' => '수정 버전', 'width' => '16rem'],
        ],
        $affected,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '📦',
                'title' => '영향 패키지 정보가 없습니다.',
                'hint'  => '피드(OSV·NVD)가 이 CVE 의 패키지 범위를 아직 안 알려준 경우입니다.',
            ],
            'cell' => [
                2 => fn($a) => !empty($a['fixed_version'])
                    ? '<span class="pill">' . vg_h($a['fixed_version']) . ' 이상</span>'
                    : '<span class="why">수정 버전 미공개</span>',
            ],
        ]
    );
    if ($affected) { vg_page_nav($affectedTotal, $aPerPage, $aPage, 'apage', 'aper_page'); }
    ?>
    </div>
  </div>
</section>

<section id="locations">
  <div class="card">
    <strong>이 CVE 가 발견된 위치</strong>
    <span class="why">— 실제 설치 확인된 위치(호스트별 최신 스캔 기준)</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '호스트'],
            ['label' => '위치'],
            ['label' => '등급', 'key' => 'severity', 'width' => '6rem'],
            ['label' => '상태', 'key' => 'runtime_status', 'width' => '7rem'],
            ['label' => '패키지', 'key' => 'package_name'],
            ['label' => '설치 버전'],
            ['label' => '수집일', 'nowrap' => true],
        ],
        $locations,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '✅',
                'title' => '이 CVE 에 노출된 자산이 없습니다.',
                'hint'  => '최신 스캔 기준으로 영향받는 호스트가 없습니다.',
            ],
            'row_class' => fn($l) => vg_sev_row((string) $l['severity']),
            'cell' => [
                0 => fn($l) => '<a href="/host.php?id=' . (int) $l['host_id'] . '">' . vg_h($l['fqdn']) . '</a>',
                // 같은 호스트가 여러 줄로 반복되는 이유를 밝힌다 — 호스트냐 그 안의 컨테이너냐.
                1 => fn($l) => $l['ctr'] !== ''
                      ? '<span class="why">컨테이너 ' . vg_h($l['ctr']) . '</span>'
                      : '<span class="why">호스트</span>',
                'severity'       => fn($l) => vg_sev_badge((string) $l['severity']),
                'runtime_status' => fn($l) => vg_status_badge($l['runtime_status']),
                5 => fn($l) => '<code>' . vg_h($l['installed_version']) . '</code>',
                6 => fn($l) => '<span class="why">' . vg_h($l['collected_at']) . '</span>',
            ],
        ]
    );
    if ($locations) { vg_page_nav($locTotal, $perPage, $page); }
    ?>
    </div>
  </div>
</section>

<section id="references">
  <div class="card">
    <strong>참조 자료</strong>
    <span class="why">— 원본·벤더 패치·공지 링크</span>
    <div class="card__body">
      <div class="links">
        <a href="https://nvd.nist.gov/vuln/detail/<?= urlencode($cveId) ?>" target="_blank" rel="noopener">NVD</a>
        <a href="https://www.cve.org/CVERecord?id=<?= urlencode($cveId) ?>" target="_blank" rel="noopener">CVE.org</a>
        <a href="https://osv.dev/vulnerability/<?= urlencode($cveId) ?>" target="_blank" rel="noopener">OSV</a>
      </div>
      <?php
      // 벤더 패치/공지 URL 목록 — NVD 는 fixed_version 처럼 구조화된 조치버전을 안 주는 경우가
      // 대부분이라, 최소한 참고 링크라도 보여준다. 옛 CVE(아직 재수집 전)는 컬럼이 비어 목록만 생략.
      $refUrls = [];
      $refsJson = $cve['ref_urls_json'] ?? null;
      if ($refsJson) {
          $decoded = json_decode((string) $refsJson, true);
          if (is_array($decoded)) { $refUrls = $decoded; }
      }
      ?>
      <?php if ($refUrls): ?>
        <ul class="hint-list mt">
          <?php foreach ($refUrls as $r):
            // 컬럼이 TEXT 라 형식이 강제되지 않는다 — 원소가 배열이 아니거나(백필/수동 INSERT
            //   등 이 파일이 쓰지 않은 경로로 들어온 값) 스킴이 http(s) 가 아니면 건너뛴다.
            $url = is_array($r) ? (string) ($r['url'] ?? '') : '';
            if (!vg_is_safe_http_url($url)) { continue; }
          ?>
            <li>
              <a href="<?= vg_h($url) ?>" target="_blank" rel="noopener noreferrer"><?= vg_h($url) ?></a>
              <?php foreach ((array) ($r['tags'] ?? []) as $t): ?>
                <?= vg_badge((string) $t, 'muted') ?>
              <?php endforeach; ?>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>
    </div>
  </div>
</section>

<?php vg_footer();
