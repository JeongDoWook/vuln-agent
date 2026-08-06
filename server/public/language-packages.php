<?php
declare(strict_types=1);

/**
 * language-packages.php — 기존 링크·북마크 호환용 리다이렉트. 화면 자체는
 *   packages.php 의 언어 패키지·라이선스 탭(?tab=lang)으로 흡수됐다.
 */

header('Location: /packages.php?tab=lang', true, 302);
