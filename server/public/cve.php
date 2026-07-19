<?php
declare(strict_types=1);

/**
 * cve.php — CVE 상세페이지. 로그인 필요.
 *   ?cve=CVE-XXXX-XXXXX  ·  ?tab=overview|affected|locations  ·  ?page=N (발견 위치 탭)
 *
 * 구성: 히어로(식별 + 등급) → 본문 탭 + 우측 고정 메트릭 사이드바.
 *   수치(CVSS·EPSS·KEV)를 사이드바에 sticky 로 붙인 건, 본문 위에 눕히면 읽으려고
 *   스크롤하는 순간 사라지기 때문이다 — "얼마나 위험한가" 는 계속 보여야 한다.
 *
 * cvss_vector·cwe·due_date·ransomware 는 커넥터가 이제야 받아오기 시작한 필드라
 * 예전에 수집된 행은 NULL 이다. 전부 "없으면 그 줄을 생략" 으로 처리한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

$err = null; $cveId = ''; $cve = null; $kev = null; $affected = []; $locations = [];
$locTotal = 0; $assetTotal = 0; $page = vg_page(); $perPage = vg_perpage();

$tab = (string) ($_GET['tab'] ?? 'overview');
if (!in_array($tab, ['overview', 'affected', 'locations'], true)) { $tab = 'overview'; }

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

        $stmt = $pdo->prepare('SELECT * FROM tb_kev_catalog WHERE cve_id = ?');
        $stmt->execute([$cveId]);
        $kev = $stmt->fetch() ?: null;

        $stmt = $pdo->prepare('SELECT ecosystem, package_name, fixed_version FROM tb_cve_affected_packages WHERE cve_id = ? ORDER BY ecosystem, package_name');
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
    $err = $e->getMessage();
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

// 히어로 제목 — KEV·랜섬웨어는 다른 무엇보다 먼저 보여야 할 신호라 제목 옆에 붙인다.
$title = vg_h($cveId);
if ($kev) {
    $title .= ' ' . vg_badge('KEV', 'crit', '악용이 확인된 취약점 — CISA KEV 등재');
    if (!empty($kev['ransomware'])) {
        $title .= ' ' . vg_badge('랜섬웨어', 'crit', '랜섬웨어 캠페인에 실제로 사용된 취약점');
    }
}

$meta = [$cve && $cve['published'] ? '공개 ' . vg_h((string) $cve['published']) : '공개일 미상'];
if ($cve && !empty($cve['cwe'])) { $meta[] = '유형 ' . vg_h((string) $cve['cwe']); }
$meta[] = '<a href="/findings.php?q=' . urlencode($cveId) . '">취약점 현황에서 보기</a>';

vg_hero($title, $meta, $sevUp ?? '등급 미상', $tone, 'CVSS 등급');

vg_subtabs([
    'overview'  => ['label' => '개요',        'n' => null],
    'affected'  => ['label' => '영향 패키지', 'n' => count($affected)],
    'locations' => ['label' => '발견 위치',   'n' => $locTotal],
], $tab);
?>

<div class="detail">
  <div class="detail__main">
    <?php if ($tab === 'overview'): ?>
      <div class="card">
        <strong>요약</strong>
        <p class="why prose"><?= $cve && $cve['summary'] ? vg_h($cve['summary']) : '수집된 설명이 없습니다.' ?></p>
        <?php if ($cve && !empty($cve['summary_ko'])): ?>
          <p class="why mt">자동 번역 · 참고용</p>
          <p class="prose"><?= vg_h((string) $cve['summary_ko']) ?></p>
        <?php endif; ?>
      </div>

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

      <?php
      // 벤더 패치/공지 URL 목록 — NVD 는 fixed_version 처럼 구조화된 조치버전을 안 주는 경우가
      // 대부분이라, 최소한 참고 링크라도 보여준다. 옛 CVE(아직 재수집 전)는 컬럼이 비어 카드째 생략.
      $refUrls = [];
      $refsJson = $cve['ref_urls_json'] ?? null;
      if ($refsJson) {
          $decoded = json_decode((string) $refsJson, true);
          if (is_array($decoded)) { $refUrls = $decoded; }
      }
      ?>
      <?php if ($refUrls): ?>
        <div class="card">
          <strong>참조 자료</strong>
          <span class="why">— NVD 가 제공하는 벤더 패치·공지 URL</span>
          <div class="card__body">
            <ul class="hint-list">
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
          </div>
        </div>
      <?php endif; ?>

      <?php if ($kev && !empty($kev['note'])): ?>
        <div class="card">
          <strong>CISA KEV</strong>
          <span class="why">— 실제 악용이 확인된 취약점. 등재되면 우선순위가 최상단으로 올라간다</span>
          <div class="card__body">
            <p class="why prose"><?= vg_h((string) $kev['note']) ?></p>
            <?php if (!empty($kev['note_ko'])): ?>
              <p class="why mt">자동 번역 · 참고용</p>
              <p class="prose"><?= vg_h((string) $kev['note_ko']) ?></p>
            <?php endif; ?>
          </div>
        </div>
      <?php endif; ?>

    <?php elseif ($tab === 'affected'): ?>
      <div class="card">
        <strong>영향 패키지</strong>
        <span class="why">— 피드가 알려준, 이 CVE 가 적용되는 패키지와 수정 버전</span>
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
        ?>
        </div>
      </div>

    <?php else: ?>
      <div class="card">
        <strong>이 CVE 가 발견된 위치</strong>
        <span class="why">— 호스트별 최신 스캔 기준</span>
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
    <?php endif; ?>
  </div>

  <aside class="detail__side">
    <div class="card">
      <strong>위험도</strong>
      <div class="card__body">
        <?php if ($cvss !== null): ?>
          <div class="score tone-<?= vg_h($tone) ?>"><?= vg_h((string) $cvss) ?><small> / 10</small></div>
          <div class="meter meter--<?= vg_h($tone) ?>">
            <i style="width:<?= (int) round(min(10.0, max(0.0, (float) $cvss)) * 10) ?>%"></i>
          </div>
          <div class="why">CVSS 기본점수</div>
        <?php else: ?>
          <div class="why">CVSS 점수 없음</div>
        <?php endif; ?>

        <dl class="kv mt-lg">
          <dt>EPSS</dt>
          <dd><?= $cve ? vg_epss_cell($cve['epss'] ?? null, $cve['epss_percentile'] ?? null) : '<span class="why">–</span>' ?></dd>

          <?php if ($cve && !empty($cve['cwe'])): ?>
            <dt>유형</dt><dd><?= vg_h((string) $cve['cwe']) ?></dd>
          <?php endif; ?>

          <dt>공개일</dt>
          <dd><?= $cve && $cve['published'] ? vg_h((string) $cve['published']) : '<span class="why">–</span>' ?></dd>

          <dt>영향 자산</dt>
          <dd><?= number_format($assetTotal) ?>대
            <?php if ($locTotal > $assetTotal): ?>
              <span class="why">(발견 <?= number_format($locTotal) ?>건 — 패키지·컨테이너별)</span>
            <?php endif; ?>
          </dd>
        </dl>
      </div>
    </div>

    <?php if ($kev): ?>
      <?php
      // KEV 패치 기한 — "언제까지 고쳐야 하나" 를 말해주는 유일한 신호. 지났으면 붉게.
      $due = $kev['due_date'] ?? null;
      $dLeft = null; $overdue = false;
      if ($due) {
          $dLeft   = (int) (new DateTimeImmutable('today'))->diff(new DateTimeImmutable((string) $due))->format('%r%a');
          $overdue = $dLeft < 0;
      }
      ?>
      <div class="card">
        <strong>CISA KEV</strong>
        <div class="card__body">
          <dl class="kv">
            <dt>등재일</dt>
            <dd><?= !empty($kev['date_added']) ? vg_h((string) $kev['date_added']) : '<span class="why">–</span>' ?></dd>

            <?php if ($due !== null && $due !== ''): ?>
              <dt>패치 기한</dt>
              <dd class="<?= $overdue ? 'is-danger' : '' ?>">
                <?= vg_h((string) $due) ?>
                <div class="why"><?= $overdue ? vg_h(abs($dLeft) . '일 초과') : vg_h('D-' . $dLeft) ?></div>
              </dd>
            <?php endif; ?>

            <dt>랜섬웨어</dt>
            <dd class="<?= !empty($kev['ransomware']) ? 'is-danger' : '' ?>">
              <?= !empty($kev['ransomware']) ? '악용 확인' : '확인 안 됨' ?>
            </dd>
          </dl>
        </div>
      </div>
    <?php endif; ?>

    <div class="card">
      <strong>원본</strong>
      <span class="why">— 참조 링크는 쌓지 않고 원본으로 내보낸다</span>
      <div class="card__body links">
        <a href="https://nvd.nist.gov/vuln/detail/<?= urlencode($cveId) ?>" target="_blank" rel="noopener">NVD</a>
        <a href="https://www.cve.org/CVERecord?id=<?= urlencode($cveId) ?>" target="_blank" rel="noopener">CVE.org</a>
        <a href="https://osv.dev/vulnerability/<?= urlencode($cveId) ?>" target="_blank" rel="noopener">OSV</a>
      </div>
    </div>
  </aside>
</div>

<?php vg_footer();
