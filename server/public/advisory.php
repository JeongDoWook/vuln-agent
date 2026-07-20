<?php
declare(strict_types=1);

/**
 * advisory.php — 국내 보안공지 상세. 로그인 필요.
 *   ?id=N. 저장된 본문을 그대로 보여주고, 원문 링크는 이 안에서만 연다.
 *   본문은 평문으로 저장돼 있다(feeds.php · vg_kisa_parse_content).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('advisories');

$err = null; $adv = null; $cves = [];

try {
    $id = (int) ($_GET['id'] ?? 0);
    if ($id <= 0) {
        $err = '잘못된 공지 번호입니다.';
    } else {
        $pdo = vg_pdo();
        $stmt = $pdo->prepare(
            'SELECT id, source, title, url, published, content, content_fetched_at
             FROM tb_advisories WHERE id = ? AND is_deleted = 0'
        );
        $stmt->execute([$id]);
        $adv = $stmt->fetch() ?: null;
        if (!$adv) {
            $err = '존재하지 않는 공지입니다.';
        } else {
            // cve_ids CSV 대신 정규화된 junction 에서 조회(tb_advisory_cves).
            $cst = $pdo->prepare('SELECT cve_id FROM tb_advisory_cves WHERE advisory_id = ? AND is_deleted = 0 ORDER BY cve_id');
            $cst->execute([$id]);
            $cves = $cst->fetchAll(PDO::FETCH_COLUMN);
        }
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header($adv ? (string) $adv['title'] : '국내 보안공지', 'advisories');
?>
<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
  <div class="sub"><a href="/advisories.php">← 공지 목록으로</a></div>
<?php else: ?>
  <?php
  // 다른 상세 페이지(호스트·CVE)와 같은 히어로 패턴. 관련 CVE 수가 이 공지의 무게다.
  $meta = [
      vg_h((string) $adv['source']),
      '발행일 ' . vg_h($adv['published'] ?? '–'),
      '<a href="/advisories.php">국내 보안공지</a>',
  ];
  vg_hero(
      vg_h((string) $adv['title']),
      $meta,
      $cves ? 'CVE ' . count($cves) . '건' : 'CVE 없음',
      $cves ? 'info' : 'muted',
      '관련 취약점'
  );
  ?>

  <?php if ($cves): ?>
  <div class="card">
    <strong>관련 CVE</strong>
    <span class="why">— 누르면 그 CVE 의 상세와 영향받는 자산을 봅니다</span>
    <div class="card__body">
      <?php foreach ($cves as $cv): ?>
        <a class="pill" href="/cve.php?cve=<?= urlencode($cv) ?>"><?= vg_h($cv) ?></a>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>

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

  <?php
  // url 은 KISA RSS/operator 피드에서 온 외부 입력이다. vg_h() 는 HTML 이스케이프만 할 뿐
  // javascript:/data: 같은 스킴은 막지 못하므로, http/https 스킴일 때만 링크로 낸다.
  $advUrl = (string) $adv['url'];
  $advUrlSafe = preg_match('#^https?://#i', $advUrl) === 1;
  ?>
  <div class="card">
    <strong>원문</strong>
    <div class="why card__body">
      보호나라 원문 페이지입니다. 첨부파일·표 서식은 원문에서만 볼 수 있습니다.
    </div>
    <div class="actions card__body">
      <?php if ($advUrlSafe): ?>
        <a class="btn btn--sm btn--ghost" href="<?= vg_h($advUrl) ?>" target="_blank" rel="noopener noreferrer">원문 열기 ↗</a>
      <?php else: ?>
        <span class="why">원문 링크가 안전하지 않은 형식이라 표시하지 않습니다.</span>
      <?php endif; ?>
      <?php if (!empty($adv['content_fetched_at'])): ?>
        <span class="why">본문 수집 <?= vg_h((string) $adv['content_fetched_at']) ?></span>
      <?php endif; ?>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
