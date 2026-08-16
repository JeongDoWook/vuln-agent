<?php
declare(strict_types=1);

/**
 * ingest/runtime.php — "지금 무엇이 돌고 있나" 스트림의 파서(호스트 기준).
 *   노출 상관(포트↔프로세스↔패키지) · 실행 프로세스 · 재시작 필요(stale libs) · 패키지 무결성.
 *   공통 성격: 전부 파이프 구분 + 첫 줄 헤더이고, **explode 의 limit 이 곧 방어선**이다 —
 *   경로·lib 이름에 '|' 가 섞여도 앞 필드를 밀지 못하게 필드 수를 고정한다(각 함수 주석 참고).
 *
 * ingest_parse.php 가 require 한다.
 */

// ── 노출 상관 (pipe 구분, 첫 줄 헤더) ──────────────────────────────────────
//   pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
function vg_ingest_parse_exposures(string $correlation): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $correlation) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|proc|proto', 14) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 8) { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 실행 프로세스 (pipe, 첫 줄 헤더) ───────────────────────────────────────
//   pid|comm|user|exe_pkg|loaded_pkgs
function vg_ingest_parse_processes(string $processesText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $processesText) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|user', 13) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 5) { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 재시작 필요(stale libs) (pipe, 첫 줄 헤더) ────────────────────────────
//   pid|comm|pkg|lib
function vg_ingest_parse_stale(string $staleText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $staleText) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|pkg', 12) === 0) { continue; }
        // limit=4: lib(마지막 필드)는 /proc/PID/maps 경로라 비특권 사용자가 임의 파일명으로
        //   통제 가능 — 필드 수를 고정해 lib 안의 '|' 가 필드를 밀지 못하게 한다(에이전트측
        //   sanitize 와 이중 방어).
        $f = explode('|', $line, 4);
        if (count($f) < 4 || trim($f[2]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 패키지 무결성 (pipe, 첫 줄 헤더) ──────────────────────────────────────
//   package|flags|path   (rpm -Va / dpkg --verify 원본 플래그를 그대로 보존한다 — 해석은 중앙)
//   에이전트가 `c`(설정파일) 줄은 이미 버리고 보낸다.
//   상한(VG_INTEGRITY_MAX_ROWS)은 에이전트가 이미 줄 수를 줄여 보내는 것과 별개의 이중 방어다 —
//   구버전·조작된 페이로드가 수십만 줄을 밀어 넣어도 여기서 멈춘다. 전체 건수는 total 로 따로 온다.
const VG_INTEGRITY_MAX_ROWS = 1000;

function vg_ingest_parse_integrity(string $integrityText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $integrityText) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'package|flags|path', 18) === 0) { continue; }
        // limit=3: path 는 파일 경로라 '|' 가 섞이면 필드가 밀린다. 필드 수를 고정해
        //   경로 안의 구분자가 앞 필드를 오염시키지 못하게 한다(에이전트측 치환과 이중 방어).
        $f = explode('|', $line, 3);
        if (count($f) !== 3) { continue; }
        [$pkg, $flags, $path] = array_map('trim', $f);
        if ($path === '' || $flags === '' || $path[0] !== '/') { continue; }
        $rows[] = [
            mb_strimwidth($pkg, 0, 255, ''),
            mb_strimwidth($flags, 0, 32, ''),
            mb_strimwidth($path, 0, 512, ''),
        ];
        if (count($rows) >= VG_INTEGRITY_MAX_ROWS) { break; }
    }
    return $rows;
}
