<?php
declare(strict_types=1);

/**
 * language-packages.php — 기존 링크·북마크 호환용 리다이렉트. 화면 자체는
 *   packages.php 의 언어 패키지·라이선스 탭(?tab=lang)으로 흡수됐다. 경로만이 아니라
 *   기존 쿼리파라미터(q·manager·risk 등)까지 그대로 넘긴다.
 *
 *   인가·감사로그는 packages.php 와 동일한 기준(catalog 메뉴)을 쓴다 — 리다이렉트만 하고
 *   화면을 그리지 않아 vg_header() 안의 vg_log_page_view() 를 못 타므로 여기서 직접 남긴다(#476 항목3).
 */

require __DIR__ . '/../src/auth.php';
vg_require_menu('catalog');
vg_log_page_view(vg_pdo(), (string) ($_SERVER['SCRIPT_NAME'] ?? ''), '언어 패키지 · 라이선스(구 URL)', 'catalog');

$qs = $_GET;
$qs['tab'] = 'lang';
header('Location: /packages.php?' . http_build_query($qs), true, 302);
exit;
