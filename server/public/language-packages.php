<?php
declare(strict_types=1);

/**
 * language-packages.php — 기존 링크·북마크 호환용 리다이렉트. 화면 자체는
 *   packages.php 의 언어 패키지·라이선스 탭(?tab=lang)으로 흡수됐다. 경로만이 아니라
 *   기존 쿼리파라미터(q·manager·risk 등)까지 그대로 넘긴다.
 */

$qs = $_GET;
$qs['tab'] = 'lang';
header('Location: /packages.php?' . http_build_query($qs), true, 302);
exit;
