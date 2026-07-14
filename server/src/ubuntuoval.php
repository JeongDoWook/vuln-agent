<?php
declare(strict_types=1);

/**
 * ubuntuoval.php — 우분투 보안 OVAL **판정**(매처가 쓴다). 수집은 feeds/ubuntuoval.php.
 *
 *   데비안 트래커(debtracker.php)의 우분투 판이다. 반환 모양도 같아서 매처의 기존 억제 경로를
 *   그대로 탄다: container_id => [바이너리패키지 => [cve => has_fix(0|1)]]
 *     · 맵에 없다        → 벤더가 "해당 없음/이미 수정" 으로 본다 → 억제
 *     · 있고 has_fix=1   → 지금 apt 로 고칠 수 있다(조치 대상)
 *     · 있고 has_fix=0   → 우분투가 아직 안 고쳤다 → 조치 불가로 표시(등급은 그대로)
 *
 *   우분투는 백포트를 한다(1.2-3ubuntu0.1). 그래서 설치 EVR 이 조치 EVR 이상이면 이미 패치된 것이다
 *   — 업스트림 버전만 보면 낮아 보여도 그렇다. 비교는 dpkg 규칙(vg_ver_cmp)으로 한다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/vercmp.php';

/**
 * 우분투 VERSION_ID → 릴리스 코드명. OVAL 은 코드명으로만 배포된다.
 *   모르는 버전이면 빈 문자열 → 호출자는 억제하지 않는다(모르면 안 지운다).
 */
function vg_ubuntu_codename(?string $osVersion): string {
    $v = trim((string) $osVersion);
    if ($v === '') { return ''; }
    return [
        '18.04' => 'bionic',
        '20.04' => 'focal',
        '22.04' => 'jammy',
        '24.04' => 'noble',
        '24.10' => 'oracular',
        '25.04' => 'plucky',
        '25.10' => 'questing',
    ][$v] ?? '';
}

/**
 * 이 스캔의 **우분투 호스트와 우분투 컨테이너**에 OVAL 을 적용해 "아직 취약" 맵을 만든다.
 *   조회는 이 스캔이 실제로 가진 패키지 이름으로 한정한다 — 릴리스 전량(수십만 행)을 배열에
 *   올리면 매처 메모리가 터진다(운영에서 실제로 겪었다).
 *
 * @return array<int, array<string, array<string,int>>>  ctrId => [pkg => [cve => has_fix]]
 */
function vg_ubuntu_evidence(PDO $pdo, int $scanId, string $hostCodename): array {
    $relOf = [];
    if ($hostCodename !== '') { $relOf[0] = $hostCodename; }

    $cs = $pdo->prepare('SELECT id, os_id, os_version FROM tb_containers WHERE scan_id = ?');
    $cs->execute([$scanId]);
    foreach ($cs->fetchAll() as $c) {
        if (strtolower((string) $c['os_id']) !== 'ubuntu') { continue; }
        $code = vg_ubuntu_codename((string) $c['os_version']);
        if ($code !== '') { $relOf[(int) $c['id']] = $code; }
    }
    if (!$relOf) { return []; }

    $ids = array_keys($relOf);
    $inC = implode(',', array_fill(0, count($ids), '?'));
    $ps  = $pdo->prepare(
        "SELECT container_id, name, version
           FROM tb_packages
          WHERE scan_id = ? AND manager = 'dpkg' AND container_id IN ($inC)"
    );
    $ps->execute(array_merge([$scanId], $ids));
    $pkgs = $ps->fetchAll();
    if (!$pkgs) { return []; }

    $names = [];
    foreach ($pkgs as $p) { $names[(string) $p['name']] = true; }
    $names = array_keys($names);

    $byRelPkg = [];   // 코드명 => [pkg => [cve => fixed_evr|null]]
    foreach (array_unique($relOf) as $code) {
        $byRelPkg[$code] = [];
        foreach (array_chunk($names, 500) as $chunk) {
            $inN = implode(',', array_fill(0, count($chunk), '?'));
            $st  = $pdo->prepare(
                "SELECT pkg_name, cve_id, fixed_evr
                   FROM tb_ubuntu_oval
                  WHERE is_deleted = 0 AND release_codename = ? AND pkg_name IN ($inN)"
            );
            $st->execute(array_merge([$code], $chunk));
            foreach ($st->fetchAll() as $r) {
                $byRelPkg[$code][(string) $r['pkg_name']][(string) $r['cve_id']] =
                    $r['fixed_evr'] !== null ? (string) $r['fixed_evr'] : null;
            }
        }
    }
    if (!array_filter($byRelPkg)) { return []; }

    $out = [];
    foreach ($pkgs as $p) {
        $ctrId = (int) $p['container_id'];
        $rows  = $byRelPkg[$relOf[$ctrId] ?? ''][(string) $p['name']] ?? null;
        if (!$rows) { continue; }

        foreach ($rows as $cve => $fixed) {
            if ($fixed === null) {
                $out[$ctrId][(string) $p['name']][$cve] = 0;      // 아직 수정본 없음 → 취약 + 조치 불가
                continue;
            }
            // 설치 EVR 이 조치 EVR 미만일 때만 아직 취약하다(백포트는 여기서 걸러진다).
            if (vg_ver_cmp((string) $p['version'], $fixed, 'dpkg') < 0) {
                $out[$ctrId][(string) $p['name']][$cve] = 1;      // 취약하지만 고칠 수 있다
            }
        }
    }
    return $out;
}
