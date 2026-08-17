<?php
declare(strict_types=1);
/* 참조 자료 섹션 — 원본·벤더 패치·공지 링크. */
?>
<section id="references">
  <div class="card">
    <strong>참조 자료</strong>
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
