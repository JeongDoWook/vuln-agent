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

/**
 * 여러 텍스트를 curl_multi 로 **동시에** 번역한다(POST, 개별 요청). feeds/http.php 의
 *   vg_http_get_many() 와 같은 슬라이딩 윈도우 관용구를 그대로 본떴다(GET→POST, SSRF 가드
 *   없음 — 이유는 파일 상단 vg_translate_ko() 주석 참고).
 *
 *   LibreTranslate 는 한 요청에 q 를 배열로 넣는 배치 API 도 지원하지만(실측 확인됨), 서버가
 *   그 배열을 **요청 하나 안에서 순차 처리**한다(app.py 의 batch for-loop) — 즉 배치 요청 1개는
 *   워커 스레드 하나를 그 배치가 끝날 때까지 통째로 붙잡는다. 반면 텍스트당 개별 요청으로
 *   쪼개 동시에 보내면 LibreTranslate 워커 스레드(LT_THREADS) 여러 개가 동시에 처리한다 —
 *   실측으로 후자가 더 빨랐다(이 워크트리 벤치마크: ARGOS_INTRA_THREADS 로 요청당 코어 점유를
 *   제한한 뒤 concurrency=16 이 순차 대비 약 1.5~1.9배).
 *
 * @param array<int|string,string> $texts 키 보존 — 반환값도 같은 키를 쓴다.
 * @return array<int|string,?string> 성공: 번역문, 실패: null
 */
function vg_translate_ko_batch(array $texts, int $concurrency = 8): array {
    $results = [];
    $keys    = [];
    foreach ($texts as $k => $t) {
        $t = trim((string) $t);
        if ($t === '') { $results[$k] = null; continue; }
        if (mb_strlen($t) > VG_TRANSLATE_INPUT_MAX) { $t = mb_substr($t, 0, VG_TRANSLATE_INPUT_MAX); }
        $keys[$k] = $t;
    }
    if (!$keys) { return $results; }

    $host = rtrim((string) vg_env('TRANSLATE_HOST', 'http://translate:5000'), '/');
    $opt  = [
        CURLOPT_POST           => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT        => 30,
    ];

    $order       = array_keys($keys);
    $concurrency = max(1, min($concurrency, count($order)));
    $mh          = curl_multi_init();
    $inflight    = [];   // spl_object_id => key
    $i = 0;
    $n = count($order);

    $launch = static function () use (&$i, $n, $order, $keys, $opt, $host, $mh, &$inflight): void {
        if ($i >= $n) { return; }
        $k  = $order[$i++];
        $ch = curl_init($host . '/translate');
        curl_setopt_array($ch, $opt + [
            CURLOPT_POSTFIELDS => http_build_query([
                'q'      => $keys[$k],
                'source' => 'en',
                'target' => 'ko',
                'format' => 'text',
            ]),
        ]);
        curl_multi_add_handle($mh, $ch);
        $inflight[spl_object_id($ch)] = ['key' => $k, 'ch' => $ch];
    };
    for ($c = 0; $c < $concurrency; $c++) { $launch(); }

    do {
        curl_multi_exec($mh, $running);
        curl_multi_select($mh, 1.0);
        while ($info = curl_multi_info_read($mh)) {
            $ch  = $info['handle'];
            $id  = spl_object_id($ch);
            $k   = $inflight[$id]['key'] ?? null;
            if ($k !== null) {
                $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $body = (string) curl_multi_getcontent($ch);
                $err  = curl_error($ch);
                if ($body === '' || $code !== 200) {
                    error_log("[translate] 배치 실패 (code={$code}): " . ($err !== '' ? $err : substr($body, 0, 200)));
                    $results[$k] = null;
                } else {
                    $data = json_decode($body, true);
                    $out  = is_array($data) ? ($data['translatedText'] ?? null) : null;
                    $results[$k] = (is_string($out) && trim($out) !== '') ? $out : null;
                }
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            unset($inflight[$id]);
            $launch();
        }
    } while ($running > 0 || $inflight);

    curl_multi_close($mh);
    return $results;
}
