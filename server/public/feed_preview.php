<?php
declare(strict_types=1);

/**
 * feed_preview.php — 커넥터 설정 화면의 "미리보기".
 *   현재 폼 값(type/url/...)으로 소스에서 최대 10건을 가져와 JSON 으로 돌려준다(저장 안 함).
 *   admin 세션 필요. 읽기 전용이라 상태 변경 없음.
 */

header('Content-Type: application/json; charset=utf-8');

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/feeds.php';
vg_require_login();
vg_require_admin();

$type = (string) ($_GET['type'] ?? $_POST['type'] ?? '');
$conn = [
    'url'       => trim((string) ($_GET['url'] ?? $_POST['url'] ?? '')),
    'api_key'   => trim((string) ($_GET['api_key'] ?? $_POST['api_key'] ?? '')),
    'ecosystem' => trim((string) ($_GET['ecosystem'] ?? $_POST['ecosystem'] ?? '')),
    'days'      => (int) ($_GET['days'] ?? $_POST['days'] ?? 7),
];

try {
    $res = vg_feed_preview($type, $conn, vg_pdo());
} catch (Throwable $e) {
    $res = ['ok' => false, 'error' => $e->getMessage()];
}
// 통일 에러 포맷: 실패 응답에 code/ts 부가.
if (empty($res['ok'])) {
    $res += ['code' => 'preview_error', 'ts' => date('c')];
}
echo json_encode($res, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
