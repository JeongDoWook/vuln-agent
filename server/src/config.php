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

// 설정 배열 반환 (docker-compose 의 environment / secrets 로 주입됨)
return [
    'db_host'      => vg_env('DB_HOST', 'db'),
    'db_port'      => vg_env('DB_PORT', '3306'),   // 컨테이너 내부는 항상 3306
    'db_name'      => vg_env('DB_NAME', 'vulnagent'),
    'db_user'      => vg_env('DB_USER', 'vulnagent'),
    'db_pass'      => vg_secret('DB_PASS', ''),        // DB_PASS_FILE 우선
    'ingest_token' => vg_secret('INGEST_TOKEN', ''),   // INGEST_TOKEN_FILE 우선
];
