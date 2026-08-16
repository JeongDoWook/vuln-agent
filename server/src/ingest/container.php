<?php
declare(strict_types=1);

/**
 * ingest/container.php — 컨테이너 스트림의 파서(목록 · 내부 패키지 · 프로세스 · 노출).
 *   호스트 파서와 형식은 닮았지만 **대상이 다르다** — 앞에 cid 가 붙고, ingest.php 가 그 cid 로
 *   tb_container 의 container_id 를 매핑한다. 호스트 신호와 섞이면 오탐(호스트 노출이 컨테이너로)
 *   또는 미탐(호스트 근거로 컨테이너를 억제)이 되므로, 파서 단계부터 갈라 둔다.
 *   외부에서 올라온 SBOM 문서는 여기가 아니라 ingest/sbom.php 가 읽는다(형식이 JSON 이라 성격이 다르다).
 *
 * ingest_parse.php 가 require 한다.
 */

// ── 컨테이너 목록 — 기본 7필드 + digest/Kubernetes/runtime/SBOM 선택 필드 ────
//   cid 로 유일(키가 cid) — ingest.php 가 tb_container insert 후 container_id 매핑에 그대로 쓴다.
function vg_ingest_parse_container_list(string $listText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $listText) as $line) {
        if ($line === '' || strncmp($line, 'cid|name|image', 14) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 7 || trim($f[0]) === '') { continue; }
        $f = array_pad($f, 15, '');
        $rows[$f[0]] = $f;
    }
    return $rows;
}

// ── 컨테이너 내부 패키지 — cid|manager|name|version|source ───────────────
function vg_ingest_parse_container_packages(string $packagesText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $packagesText) as $line) {
        if ($line === '' || strncmp($line, 'cid|manager|name', 16) === 0) { continue; }
        // limit(5) — 형식은 cid|manager|name|version|source 로 정확히 5필드다. limit 없이 쓰면
        //   source 필드에 '|' 가 섞였을 때(패키지 출처 문자열 등) 6번째 칸이 생겨, ingest_store.php
        //   가 그 자리를 SBOM 전용 라이선스 필드로 읽는 경로와 인덱스가 겹쳐 조용히 승격된다.
        $f = explode('|', $line, 5);
        if (count($f) < 4 || trim($f[0]) === '' || trim($f[2]) === '' || trim($f[3]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 컨테이너 런타임 증거: 프로세스 — cid|pid|comm|user|exe_pkg|loaded_pkgs ─
function vg_ingest_parse_container_processes(string $processesText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $processesText) as $line) {
        if ($line === '' || strncmp($line, 'cid|pid|comm', 12) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 6 || trim($f[0]) === '' || trim($f[1]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 컨테이너 런타임 증거: 노출 — cid|pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
function vg_ingest_parse_container_exposures(string $exposureText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $exposureText) as $line) {
        if ($line === '' || strncmp($line, 'cid|pid|proc', 12) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 9 || trim($f[0]) === '' || trim($f[5]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}
