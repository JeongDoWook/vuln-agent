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
            'SELECT id, source, title, url, published, cve_ids, content, content_fetched_at
             FROM tb_advisories WHERE id = ? AND is_deleted = 0'
        );
        $stmt->execute([$id]);
        $adv = $stmt->fetch() ?: null;
        if (!$adv) {
            $err = '존재하지 않는 공지입니다.';
        } elseif (!empty($adv['cve_ids'])) {
            $cves = array_filter(array_map('trim', explode(',', (string) $adv['cve_ids'])));
        }
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header($adv ? (string) $adv['title'] : '국내 보안공지', 'advisories');
?>
<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
  <div class="sub" style="margin-top:.8rem;"><a href="/advisories.php">← 공지 목록으로</a></div>
<?php else: ?>
  <div class="sub"><a href="/advisories.php">← 국내 보안공지</a></div>
  <h1><?= vg_h($adv['title']) ?></h1>
  <div class="sub">
    <?= vg_h((string) $adv['source']) ?> ·
    발행일 <?= vg_h($adv['published'] ?? '–') ?>
  </div>

  <?php if ($cves): ?>
  <div class="card">
    <strong>관련 CVE</strong>
    <div style="margin-top:.6rem;">
      <?php foreach ($cves as $cv): ?>
        <a class="pill" href="/cve.php?cve=<?= urlencode($cv) ?>"><?= vg_h($cv) ?></a>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>

  <div class="card">
    <strong>본문</strong>
    <?php if (!empty($adv['content'])): ?>
      <p class="why" style="margin:.6rem 0 0;white-space:pre-wrap;line-height:1.7;"><?= vg_h($adv['content']) ?></p>
    <?php elseif (!empty($adv['content_fetched_at'])): ?>
      <?php // 수집은 했지만 본문 텍스트가 없는 공지(이미지 전용·경보단계). 재수집해도 같다. ?>
      <p class="why" style="margin:.6rem 0 0;">
        이 공지는 본문이 이미지나 표로만 되어 있어 옮겨올 텍스트가 없습니다. 아래 원문에서 확인하세요.
      </p>
    <?php else: ?>
      <p class="why" style="margin:.6rem 0 0;">
        본문이 아직 수집되지 않았습니다. 아래 원문 링크로 확인하세요.
        <br>(수집: <code>php bin/backfill_kisa_content.php</code>)
      </p>
    <?php endif; ?>
  </div>

  <div class="card">
    <strong>원문</strong>
    <div class="why" style="margin:.4rem 0 .8rem;">
      보호나라 원문 페이지입니다. 첨부파일·표 서식은 원문에서만 볼 수 있습니다.
    </div>
    <a class="btn-sm" href="<?= vg_h($adv['url']) ?>" target="_blank" rel="noopener noreferrer">원문 열기 ↗</a>
    <?php if (!empty($adv['content_fetched_at'])): ?>
      <span class="why" style="margin-left:.6rem;">본문 수집 <?= vg_h((string) $adv['content_fetched_at']) ?></span>
    <?php endif; ?>
  </div>
<?php endif; ?>
<?php vg_footer();
