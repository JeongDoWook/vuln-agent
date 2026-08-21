<?php
declare(strict_types=1);

/**
 * advisory.php — 국내 보안공지 상세. 로그인 필요.
 *   ?id=N  ·  ?cpage=N/?cper_page=N (관련 CVE 표)
 *   본문은 평문으로 저장돼 있다(feeds.php · vg_kisa_parse_content).
 *
 * 구성은 다른 상세 화면과 같다: 히어로(식별 + 무게) → 핵심 지표(stat-grid) → 앵커 내비 →
 *   관련 CVE → 본문 → 원문·수집 정보. 관련 CVE 는 알약처럼 이름만 늘어놓지 않고 등급·EPSS·KEV
 *   까지 붙인 표로 낸다 — 패치데이 공지는 CVE 가 수백 건이라(실측 793건) 페이지네이션이 필수다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
vg_require_menu('advisories');

$err = null; $adv = null; $cves = []; $assets = [];
$cveTotal = 0; $kevTotal = 0; $maxCvss = null; $sevCounts = [];
$assetTotal = 0; $assetHostTotal = 0; $assetLocMixed = false;
$cPage = vg_page('cpage'); $cPerPage = vg_perpage(null, 'cper_page');
$aPage = vg_page('apage'); $aPerPage = vg_perpage(null, 'aper_page');

try {
    $id = (int) ($_GET['id'] ?? 0);
    if ($id <= 0) {
        $err = '잘못된 공지 번호입니다.';
    } else {
        $pdo = vg_pdo();
        $stmt = $pdo->prepare(
            'SELECT advisory_id, source, title, url, published, content, content_fetched_at,
                    created_at, updated_at, CHAR_LENGTH(content) AS content_len
             FROM tb_advisory WHERE advisory_id = ? AND is_deleted = 0'
        );
        $stmt->execute([$id]);
        $adv = $stmt->fetch() ?: null;
        if (!$adv) {
            $err = '존재하지 않는 공지입니다.';
        } else {
            // 보안공지 상세 열람 감사로그.
            vg_log_activity($pdo, 'ADVISORY', $id, 'view_advisory', (string) ($adv['title'] ?? null),
                subject: (string) ($adv['title'] ?? ''), action: 'READ');

            // 관련 CVE 는 정규화된 junction(tb_advisory_cve)에서 조회한다.
            //   총건수·KEV 포함 건수·최고 CVSS 를 한 번에 — 화면 상단 지표가 이 셋뿐이라
            //   쿼리를 셋으로 쪼갤 이유가 없다.
            // 등급 분포(CRITICAL/HIGH/MEDIUM/LOW) 카운트도 같은 질의에 얹는다 — 경계값을 SQL 에
            //   따로 적지 않고 format/severity.php 의 VG_SEV_RANGES 에서 바인딩 파라미터로 뽑는다
            //   (표 쪽 vg_cvss_sev() 와 같은 정본을 쓰게 해 이원화를 구조적으로 막는다).
            $sevSelect = []; $sevParams = [];
            foreach (VG_SEV_RANGES as $name => [$lo, $hi]) {
                $sevSelect[] = "SUM(c.cvss BETWEEN ? AND ?) AS n_$name";
                $sevParams[] = $lo;
                $sevParams[] = $hi;
            }
            $cst = $pdo->prepare(
                'SELECT COUNT(*) AS n, SUM(k.cve_id IS NOT NULL) AS kev_cnt, MAX(c.cvss) AS max_cvss,
                        ' . implode(",\n                        ", $sevSelect) . '
                   FROM tb_advisory_cve ac
                   LEFT JOIN tb_cve c ON c.cve_id = ac.cve_id AND c.is_deleted = 0
                   LEFT JOIN tb_kev_catalog k ON k.cve_id = ac.cve_id AND k.is_deleted = 0
                  WHERE ac.advisory_id = ? AND ac.is_deleted = 0'
            );
            $cst->execute([...$sevParams, $id]);
            $agg = $cst->fetch() ?: [];
            $cveTotal = (int) ($agg['n'] ?? 0);
            $kevTotal = (int) ($agg['kev_cnt'] ?? 0);
            $maxCvss  = $agg['max_cvss'] ?? null;
            $sevCounts = [];
            foreach (VG_SEV_RANGES as $name => $_range) {
                $sevCounts[strtoupper($name)] = (int) ($agg["n_$name"] ?? 0);
            }

            // 표에 낼 한 페이지분만. 아직 수집 안 된 CVE 는 tb_cve 에 없으므로 LEFT JOIN 이다
            //   — 공지가 먼저 오고 NVD 수집이 나중인 경우가 흔하다.
            $cOffset = ($cPage - 1) * $cPerPage;
            $cst = $pdo->prepare(
                "SELECT ac.cve_id, c.cvss, c.epss, c.epss_percentile, c.published,
                        (c.cve_id IS NOT NULL) AS collected, (k.cve_id IS NOT NULL) AS is_kev
                   FROM tb_advisory_cve ac
                   LEFT JOIN tb_cve c ON c.cve_id = ac.cve_id AND c.is_deleted = 0
                   LEFT JOIN tb_kev_catalog k ON k.cve_id = ac.cve_id AND k.is_deleted = 0
                  WHERE ac.advisory_id = ? AND ac.is_deleted = 0
                  ORDER BY c.cvss IS NULL, c.cvss DESC, ac.cve_id
                  LIMIT $cPerPage OFFSET $cOffset"
            );
            $cst->execute([$id]);
            $cves = $cst->fetchAll();

            // 목록의 빠른 모달은 일부 행만 보여주므로 상세에서는 최신 수집의 전체 영향 범위를 제공한다.
            $assetFrom = 'FROM tb_advisory_cve ac
                          JOIN tb_finding f ON f.cve_id = ac.cve_id AND f.is_deleted = 0
                          JOIN tb_scan s ON s.scan_id = f.scan_id
                          JOIN ' . vg_latest_scan_subq() . ' latest
                            ON latest.host_id = s.host_id AND latest.mid = s.scan_id
                          JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                          LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id';
            $assetWhere = 'WHERE ac.advisory_id = ? AND ac.is_deleted = 0';

            // loc_kinds — '위치'(호스트 자신 / 각 컨테이너)가 몇 가지나 되는가. 한 가지뿐이면
            //   표에 열을 세우지 않고 카드 제목 옆 한 줄로 올린다(vg_place_note). **페이지가 아니라
            //   전체 기준**이라야 페이지를 넘길 때 열이 생겼다 사라지지 않는다 — 그래서 이미 도는
            //   집계 쿼리에 식 하나를 얹었다(새 쿼리를 추가하지 않는다).
            $ast = $pdo->prepare("SELECT COUNT(*) AS n, COUNT(DISTINCT h.host_id) AS host_cnt,
                                         COUNT(DISTINCT IFNULL(ctr.cid, '')) AS loc_kinds
                                    $assetFrom $assetWhere");
            $ast->execute([$id]);
            $assetAgg = $ast->fetch() ?: [];
            $assetTotal = (int) ($assetAgg['n'] ?? 0);
            $assetHostTotal = (int) ($assetAgg['host_cnt'] ?? 0);
            $assetLocMixed = ((int) ($assetAgg['loc_kinds'] ?? 0)) > 1;

            $aOffset = ($aPage - 1) * $aPerPage;
            $ast = $pdo->prepare(
                "SELECT h.host_id, h.fqdn, IFNULL(ctr.cid, '') AS ctr, f.cve_id,
                        f.package_name, f.installed_version, f.severity, f.runtime_status, s.collected_at
                   $assetFrom $assetWhere
                  ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), h.fqdn, ctr.cid, f.cve_id
                  LIMIT $aPerPage OFFSET $aOffset"
            );
            $ast->execute([$id]);
            $assets = $ast->fetchAll();
        }
    }
} catch (Throwable $e) {
    error_log('[advisory] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header($adv ? (string) $adv['title'] : '보안 공지', 'advisories');
?>
<?php if ($err !== null): ?>
  <?php vg_page_title('공지를 찾을 수 없습니다', 'ADVISORY'); ?>
  <?php vg_alert('오류 · ' . $err); ?>
  <div class="sub"><a href="/advisories.php">← 공지 목록으로</a></div>
<?php else: ?>
  <?php
  // url 은 KISA RSS/operator 피드에서 온 외부 입력이다. vg_h() 는 HTML 이스케이프만 할 뿐
  // javascript:/data: 같은 스킴은 막지 못하므로, http/https 스킴일 때만 링크로 낸다.
  $advUrl = (string) $adv['url'];
  $advUrlSafe = vg_is_safe_http_url($advUrl);

  $maxSev = vg_cvss_sev($maxCvss === null ? null : (string) $maxCvss);

  // 다른 상세 페이지(호스트·CVE)와 같은 히어로 패턴. 관련 CVE 수가 이 공지의 무게다.
  /* '핵심 지표' 카드(stat-grid 네 칸)를 이 줄로 접었다 — 네 값이 전부 짧은데(배지 하나·숫자
     하나) .stat-grid 의 auto-fit 1fr 이 그 값을 본문 폭 전체로 늘려, 카드 하나가 한 줄을
     통째로 쓰면서 칸 사이는 300px 씩 비어 있었다(1920px 실측). 히어로 부제는 이미 같은 성격의
     식별값을 담는 자리이고 flex-wrap 이라 값이 늘어도 접힌다. **값은 그대로 넷 다 남는다.** */
  $meta = [
      vg_h((string) $adv['source']),
      '발행일 ' . vg_h((string) ($adv['published'] ?? '–')),
      '공지 #' . (int) $adv['advisory_id'],
      'KEV ' . ($kevTotal > 0
          ? vg_badge(number_format($kevTotal) . '건', 'crit', '실제 악용이 확인된 취약점(CISA KEV)이 포함됨')
          : vg_badge('없음', 'muted')),
      '최고 CVSS ' . ($maxCvss !== null
          ? vg_h((string) $maxCvss) . ' ' . vg_sev_badge(strtoupper($maxSev))
          : '–'),
      '영향 자산 ' . number_format($assetHostTotal) . '대'
          . ($assetTotal > $assetHostTotal ? ' · 발견 ' . number_format($assetTotal) . '건' : ''),
      '본문 ' . (!empty($adv['content'])
          ? number_format((int) $adv['content_len']) . '자'
          : vg_badge('미수집', 'warn')),
      '<a href="/advisories.php">← 공지 목록</a>',
  ];
  vg_hero(
      vg_h((string) $adv['title']),
      $meta,
      $cveTotal ? 'CVE ' . number_format($cveTotal) . '건' : 'CVE 없음',
      $cveTotal ? ($kevTotal > 0 ? 'crit' : 'info') : 'muted',
      '관련 취약점'
  );
  ?>

<nav class="subtabs subtabs--sticky">
  <a href="#cves">관련 CVE</a>
  <a href="#assets">영향 자산</a>
  <a href="#content">본문</a>
  <a href="#origin">원문·수집 정보</a>
</nav>

<section id="cves">
  <div class="card">
    <strong>관련 CVE</strong>
    <div class="card__body<?= $cveTotal > 0 ? ' split' : '' ?>">
    <?php if ($cveTotal > 0): ?>
      <div><?php vg_sev_donut($sevCounts); ?></div>
    <?php endif; ?>
    <div>
    <?php
    vg_table(
        [
            ['label' => 'CVE', 'key' => 'cve_id', 'nowrap' => true],
            ['label' => '등급', 'width' => '6rem'],
            ['label' => 'CVSS', 'align' => 'right', 'width' => '5rem'],
            ['label' => 'EPSS', 'align' => 'right', 'width' => '8rem'],
            ['label' => '공개일', 'nowrap' => true, 'width' => '8rem'],
        ],
        $cves,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '□',
                'title' => '이 공지에서 추출된 CVE 가 없습니다.',
                'hint'  => '제목·본문에 CVE 번호가 없는 공지(경보단계·일반 안내)입니다.',
            ],
            'row_class' => fn($r) => vg_sev_row(strtoupper(vg_cvss_sev(
                $r['cvss'] === null ? null : (string) $r['cvss']
            ))),
            'cell' => [
                'cve_id' => function ($r) {
                    $out = '<a href="/cve.php?cve=' . urlencode((string) $r['cve_id']) . '">'
                         . vg_h((string) $r['cve_id']) . '</a>';
                    return $out . (!empty($r['is_kev']) ? ' ' . vg_badge('KEV', 'crit', '악용이 확인된 취약점 — CISA KEV 등재') : '');
                },
                1 => function ($r) {
                    if (empty($r['collected'])) {
                        return vg_badge('미수집', 'muted', 'NVD 커넥터가 아직 이 CVE 를 가져오지 않았습니다');
                    }
                    $sev = vg_cvss_sev($r['cvss'] === null ? null : (string) $r['cvss']);
                    return $sev !== '' ? vg_sev_badge(strtoupper($sev)) : '<span class="why">–</span>';
                },
                2 => fn($r) => $r['cvss'] !== null ? vg_h((string) $r['cvss']) : '<span class="why">–</span>',
                3 => fn($r) => vg_epss_cell($r['epss'] ?? null, $r['epss_percentile'] ?? null),
                4 => fn($r) => !empty($r['published'])
                    ? '<span class="why">' . vg_h((string) $r['published']) . '</span>'
                    : '<span class="why">–</span>',
            ],
        ]
    );
    if ($cves) { vg_page_nav($cveTotal, $cPerPage, $cPage, 'cpage', 'cper_page'); }
    ?>
    </div>
    </div>
  </div>
</section>

<section id="assets">
  <div class="card">
    <strong>영향 자산</strong>
    <?php
    /* 이 카드가 답하는 질문은 "이 공지가 우리 자산 중 **어디**에 영향을 주나" 다.
     *   ★ '수집일' 열을 걷었다 — 날짜는 그 판단에 안 쓰이는데(어제 수집이든 오늘 수집이든
     *     조치 대상은 같다) 열 하나를 통째로 먹었다. 지운 게 아니라 **호스트 링크의 툴팁**으로
     *     내렸고, 회차별 정본은 그 호스트 상세의 '수집 이력' 탭이 그대로 갖는다.
     *   ★ '위치' 열은 값이 섞여 있을 때만 세운다 — 전 행이 '호스트' 인 공지가 대부분이라
     *     그때 이 열의 정보량은 0이다(제목 옆 한 줄로 올린다 — vg_place_note).
     *   8열 → 6열. 1200px 아래에서 잘리던 식별자 열(패키지·설치 버전)이 그 폭을 가져간다. */
    $assetNote = '최신 수집 기준';
    if ($assets) {
        $placeNote = vg_place_note($assetLocMixed, (string) $assets[0]['ctr']);
        if ($placeNote !== '') { $assetNote .= ' · ' . $placeNote; }
    }
    ?>
    <span class="why"> · <?= vg_h($assetNote) ?></span>
    <div class="card__body">
    <?php
    $assetHeaders = [['label' => '호스트', 'key' => 'fqdn']];
    if ($assetLocMixed) {
        // 같은 이유로 nowrap — cve.php '발견 위치' 표의 같은 열과 규칙을 맞춘다.
        $assetHeaders[] = ['label' => '위치', 'key' => 'ctr', 'width' => '9rem', 'nowrap' => true];
    }
    // 열이 조건부라 칸 콜백은 **인덱스가 아니라 key** 로 건다 — 인덱스로 걸면 '위치' 열이
    //   빠지는 순간 그 뒤 칸이 통째로 한 칸씩 밀린다.
    $assetHeaders = array_merge($assetHeaders, [
        ['label' => 'CVE', 'key' => 'cve_id', 'nowrap' => true],
        // key 를 준다 — 콜백도 key 도 없던 탓에 **패키지 칸이 통째로 빈칸으로 나왔다**
        //   (vg_table 은 둘 다 없으면 빈 문자열을 그린다). 값이 사라진 자리라 링크·서식보다
        //   먼저 값부터 되살린다.
        ['label' => '패키지', 'key' => 'package_name'],
        ['label' => '설치 버전', 'key' => 'installed_version'],
        ['label' => '등급', 'key' => 'severity', 'width' => '6rem'],
        ['label' => '상태', 'key' => 'runtime_status', 'width' => '7rem'],
    ]);
    vg_table(
        $assetHeaders,
        $assets,
        [
            'card' => false,
            'empty' => [
                'icon'  => '✅',
                'title' => '이 공지에 노출된 자산이 없습니다.',
                'hint'  => '최신 수집 기준으로 관련 CVE가 발견되지 않았습니다.',
            ],
            'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
            'cell' => [
                // 걷어낸 '수집일' 이 여기로 온다 — 이 행이 어느 회차 수집인지는 호스트에 붙은 사실이다.
                'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id']
                    . '" title="' . vg_h('수집 ' . (string) $r['collected_at']) . '">'
                    . vg_h((string) $r['fqdn']) . '</a>',
                'ctr' => fn($r) => vg_place_cell((string) $r['ctr']),
                'cve_id' => fn($r) => '<a href="/cve.php?cve=' . urlencode((string) $r['cve_id']) . '">'
                    . vg_h((string) $r['cve_id']) . '</a>',
                'installed_version' => fn($r) => !empty($r['installed_version'])
                    ? '<code>' . vg_h((string) $r['installed_version']) . '</code>'
                    : '<span class="why">–</span>',
                'severity' => fn($r) => vg_sev_badge((string) $r['severity']),
                'runtime_status' => fn($r) => vg_status_badge($r['runtime_status']),
            ],
        ]
    );
    if ($assets) { vg_page_nav($assetTotal, $aPerPage, $aPage, 'apage', 'aper_page'); }
    ?>
    </div>
  </div>
</section>

<section id="content">
  <div class="card">
    <strong>본문</strong>
    <?php if (!empty($adv['content'])): ?>
      <p class="why prose"><?= vg_h($adv['content']) ?></p>
    <?php elseif (!empty($adv['content_fetched_at'])): ?>
      <?php // 수집은 했지만 본문 텍스트가 없는 공지(이미지 전용·경보단계). 재수집해도 같다. ?>
      <div class="card__body">
        <?php vg_empty([
            'icon'  => '🖼️',
            'title' => '본문이 이미지나 표로만 되어 있습니다.',
            'hint'  => '옮겨올 텍스트가 없습니다. 아래 원문에서 확인하세요.',
        ]); ?>
      </div>
    <?php else: ?>
      <div class="card__body">
        <?php vg_empty([
            'icon'  => '📄',
            'title' => '본문이 아직 수집되지 않았습니다.',
            'hint'  => '아래 원문 링크로 확인하거나, php bin/backfill_kisa_content.php 로 수집하세요.',
        ]); ?>
      </div>
    <?php endif; ?>
  </div>
</section>

<section id="origin">
  <div class="card">
    <strong>원문·수집 정보</strong>
    <div class="card__body">
      <dl class="kv">
        <dt>공지 번호</dt><dd>#<?= (int) $adv['advisory_id'] ?></dd>
        <dt>출처 피드</dt><dd><?= vg_h((string) $adv['source']) ?></dd>
        <dt>발행일</dt><dd><?= vg_h((string) ($adv['published'] ?? '–')) ?></dd>
        <dt>목록 수집</dt><dd><?= vg_h((string) $adv['created_at']) ?></dd>
        <dt>본문 수집</dt>
        <dd><?= !empty($adv['content_fetched_at']) ? vg_h((string) $adv['content_fetched_at']) : '<span class="why">미수집</span>' ?></dd>
        <dt>마지막 갱신</dt><dd><?= vg_h((string) $adv['updated_at']) ?></dd>
      </dl>
      <div class="actions mt">
        <?php if ($advUrlSafe): ?>
          <a class="btn btn--sm btn--ghost" href="<?= vg_h($advUrl) ?>" target="_blank" rel="noopener noreferrer">보호나라 원문 열기 ↗</a>
          <?php vg_copy_btn($advUrl, '원문 주소 복사'); ?>
        <?php else: ?>
          <span class="why">원문 링크가 안전하지 않은 형식이라 표시하지 않습니다.</span>
        <?php endif; ?>
      </div>
    </div>
  </div>
</section>
<?php endif; ?>
<?php vg_footer();
