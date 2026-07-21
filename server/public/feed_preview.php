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
vg_require_menu('connectors');   // 미리보기: 피드 메뉴 권한

$type = (string) ($_GET['type'] ?? $_POST['type'] ?? '');
if ($type === 'generic_api') {
    // 범용 API 커넥터는 폼 전체가 g_config_json 하나에 직렬화돼 온다(connectors.js
    // vgGenericSerialize) — connectors.php 저장 처리와 같은 shape 라 그대로 preview()에 넘긴다.
    $conn = json_decode((string) ($_POST['g_config_json'] ?? ''), true);
    if (!is_array($conn)) { $conn = []; }
} else {
    // 이 타입이 실제로 읽는 필드만 담는다(근거는 src/feeds.php 카탈로그 — 저장 로직과 같은 표).
    //   전엔 넷을 무조건 넣었고, 안 쓰는 타입엔 빈 값이 실려 갔다. 빈 값은 키를 만들지 않는다
    //   — 그래야 커넥터가 자기 기본 URL 을 쓴다.
    $conn = [];
    foreach (vg_connector_fields($type) as $f) {
        $v = trim((string) ($_GET[$f] ?? $_POST[$f] ?? ''));
        if ($v === '') { continue; }
        $conn[$f] = $f === 'days' ? (int) $v : $v;
    }
}

try {
    $res = vg_feed_preview($type, $conn, vg_pdo());
} catch (Throwable $e) {
    error_log('[feed_preview] ' . $e->getMessage());
    $res = ['ok' => false, 'error' => 'internal error'];
}
// 통일 에러 포맷: 실패 응답에 code/ts 부가.
if (empty($res['ok'])) {
    $res += ['code' => 'preview_error', 'ts' => date('c')];
}
echo json_encode($res, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
