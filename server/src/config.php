<?php
declare(strict_types=1);

// 환경변수 조회 헬퍼 (중복 로드 대비 가드)
if (!function_exists('vg_env')) {
    function vg_env(string $key, ?string $default = null): ?string {
        $v = getenv($key);
        return ($v === false || $v === '') ? $default : $v;
    }
}

// 시크릿 조회: <KEY>_FILE(도커 시크릿) 우선 → 일반 <KEY> → default
// 예) DB_PASS_FILE=/run/secrets/mysql_password 가 있으면 그 파일 내용을 읽음.
if (!function_exists('vg_secret')) {
    function vg_secret(string $key, ?string $default = null): ?string {
        $file = getenv($key . '_FILE');
        if ($file !== false && $file !== '' && is_readable($file)) {
            $val = trim((string) file_get_contents($file));
            if ($val !== '') {
                return $val;
            }
        }
        return vg_env($key, $default);
    }
}

// 요청 헤더 1건 조회(대소문자 무시). Apache(mod_php)는 Authorization 헤더를 $_SERVER 에
// 안 실어주므로 getallheaders() 로 폴백한다. rewrite 를 거친 경우의 REDIRECT_ 접두도 본다.
if (!function_exists('vg_request_header')) {
    function vg_request_header(string $name): string {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        foreach ([$key, 'REDIRECT_' . $key] as $k) {
            if (!empty($_SERVER[$k])) { return (string) $_SERVER[$k]; }
        }
        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $hk => $hv) {
                if (strcasecmp($hk, $name) === 0 && $hv !== '') { return (string) $hv; }
            }
        }
        return '';
    }
}

// 인증 토큰 추출: 지정한 커스텀 헤더(X-API-Token 등) 우선, 없으면 Authorization: Bearer.
//   Bearer 는 Apache 가 $_SERVER 에서 떨어뜨리므로 vg_request_header 의 getallheaders 폴백에 의존한다.
if (!function_exists('vg_auth_token')) {
    function vg_auth_token(string $customHeader): string {
        $t = trim(vg_request_header($customHeader));
        if ($t !== '') { return $t; }
        $auth = vg_request_header('Authorization');
        if ($auth !== '' && preg_match('/Bearer\s+(.+)/i', $auth, $m)) { return trim($m[1]); }
        return '';
    }
}

// 설정 배열 반환 (docker-compose 의 environment / secrets 로 주입됨)
return [
    'db_host'      => vg_env('DB_HOST', 'db'),
    'db_port'      => vg_env('DB_PORT', '3306'),   // 컨테이너 내부는 항상 3306
    'db_name'      => vg_env('DB_NAME', 'vulnagent'),
    'db_user'      => vg_env('DB_USER', 'vulnagent'),
    'db_pass'      => vg_secret('DB_PASS', ''),        // DB_PASS_FILE 우선
    'ingest_token' => vg_secret('INGEST_TOKEN', ''),   // INGEST_TOKEN_FILE 우선
];
