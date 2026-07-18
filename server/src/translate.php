<?php
declare(strict_types=1);

/**
 * translate.php — LibreTranslate(자체 호스팅 컨테이너)로 영어 텍스트를 한글로 번역.
 *   실패해도(연결 실패·타임아웃·빈 응답) 예외를 던지지 않고 null 을 반환한다 — 번역은
 *   CVE 상세 화면의 부가 기능일 뿐이라 실패가 CVE 수집/매칭 파이프라인을 막으면 안 된다.
 *
 *   feeds/http.php 의 vg_http_json() 을 안 쓰는 이유: 그 경로는 사설/루프백 대역을 SSRF 로
 *   차단한다(커넥터 URL 이 사용자 입력이라서). translate 컨테이너는 우리가 직접 띄운 신뢰된
 *   내부 호스트라 그 차단 대상 대역(도커 브리지 네트워크) 안에 있는 게 정상이다 — 여기선
 *   별도로 가벼운 curl 요청만 쓴다.
 */

require_once __DIR__ . '/config.php';

// LibreTranslate 단일 요청 처리 한계를 고려한 보수적 입력 상한(글자 수). 원문 저장
//   (tb_cves.summary/tb_kev_catalog.note)엔 영향 없다 — 번역 입력에만 자른다.
const VG_TRANSLATE_INPUT_MAX = 5000;

if (!function_exists('vg_translate_ko')) {
    function vg_translate_ko(string $text): ?string {
        $text = trim($text);
        if ($text === '') {
            return null;
        }
        if (mb_strlen($text) > VG_TRANSLATE_INPUT_MAX) {
            $text = mb_substr($text, 0, VG_TRANSLATE_INPUT_MAX);
        }

        $host = rtrim((string) vg_env('TRANSLATE_HOST', 'http://translate:5000'), '/');
        $ch   = curl_init($host . '/translate');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'q'      => $text,
                'source' => 'en',
                'target' => 'ko',
                'format' => 'text',
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT        => 30,
        ]);
        $body = curl_exec($ch);
        $err  = curl_error($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false) {
            error_log("[translate] 연결 실패: $err");
            return null;
        }
        if ($code !== 200) {
            error_log("[translate] HTTP $code: " . substr((string) $body, 0, 200));
            return null;
        }

        $data = json_decode((string) $body, true);
        $out  = is_array($data) ? ($data['translatedText'] ?? null) : null;
        if (!is_string($out) || trim($out) === '') {
            error_log('[translate] 빈 응답');
            return null;
        }
        return $out;
    }
}
