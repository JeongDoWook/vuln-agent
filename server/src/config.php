<?php
declare(strict_types=1);

// 환경변수 조회 헬퍼 (중복 로드 대비 가드)
if (!function_exists('vg_env')) {
    function vg_env(string $key, ?string $default = null): ?string {
        $v = getenv($key);
        return ($v === false || $v === '') ? $default : $v;
    }
}

// 설정 배열 반환 (docker-compose 의 environment 로 주입됨)
return [
    'db_host'      => vg_env('DB_HOST', 'db'),
    'db_port'      => vg_env('DB_PORT', '3306'),   // 컨테이너 내부는 항상 3306
    'db_name'      => vg_env('DB_NAME', 'vulnagent'),
    'db_user'      => vg_env('DB_USER', 'vulnagent'),
    'db_pass'      => vg_env('DB_PASS', ''),
    'ingest_token' => vg_env('INGEST_TOKEN', ''),
];
