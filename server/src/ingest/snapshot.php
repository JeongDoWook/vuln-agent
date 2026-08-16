<?php
declare(strict_types=1);

/**
 * ingest/snapshot.php — 파싱 **다음** 단계: "이 수집물이 직전과 다른가"를 판단한다.
 *   내용 해시(바뀔 때만 새 스냅샷) · 패키지 맵 · 두 스냅샷의 변경 목록(설치/제거/업/다운그레이드).
 *   위 파서들이 만든 행을 입력으로 받을 뿐, 원시 텍스트를 직접 읽지 않는다.
 *   해시는 **저장하는 값 전부**를 넣어야 한다 — 빠뜨린 필드는 재수집돼도 영원히 갱신되지 않는다
 *   (출처·라이선스·의존 그래프가 실제로 그렇게 누락됐다. vg_ingest_content_hash 안 주석 참고).
 *
 * ingest_parse.php 가 require 한다.
 */

// ── 내용 해시 — "바뀔 때만 스냅샷" 판정에 쓰는 정규화 해시 ────────────────
//   PID 는 절대 넣지 않는다 — 재부팅·프로세스 재시작마다 바뀌어서 매번 "변경됨"이 된다.
function vg_ingest_content_hash(
    array $pkgRows,
    string $manager,
    array $langRows,
    array $expRows,
    array $procRows,
    array $staleRows,
    array $ctrPkgRows,
    array $ctrRows,
    array $ctrExpRows,
    string $runningKernel,
    string $kernelLatest,
    int $kernelReboot,
    array $vm,
    array $sys,
    array $originMap = [],
    array $pomDepRows = [],
    array $sbomDepRows = []
): string {
    // v2는 프로세스 행을 해시에 포함한다. salt가 없으면 배포 직후 프로세스 수집이 비어 있는
    // payload가 구버전 해시와 같아져 stale tb_process가 든 옛 스캔을 재사용할 수 있다.
    $hashParts = ['schema|2'];
    // **저장하는 값 전부**를 해시에 넣는다(이름·버전만 넣으면 안 된다).
    //   예전엔 이름·버전만 봤다. 그래서 에이전트가 **출처(origin) 판정을 고쳐서 보내도** 패키지·버전이
    //   그대로면 "변경 없음" 으로 스캔을 재사용했고, tb_package 를 다시 쓰지 않아 옛 출처가 영원히
    //   남았다(실측: 에이전트 2.2 가 curl→Debian 으로 고쳐 보냈는데 DB 엔 LOCAL 이 그대로였다).
    //   소스패키지·벤더도 같은 이유로 포함한다 — 저장은 하는데 해시가 안 보면 갱신되지 않는다.
    foreach ($pkgRows as $r)  {
        $hashParts[] = "p|$manager|" . implode('|', array_map('strval', $r))
                     . '|' . (string) ($originMap[$r[0]] ?? '');
    }
    // 라이선스 값도 해시에 넣는다 — 안 넣으면 라이선스만 바뀐 재스캔이 "변경 없음"으로
    //   스킵돼 스캔 재사용 시 라이선스 변경이 구조적으로 누락된다(출처 필드 실사고와 동일 유형).
    foreach ($langRows as $r) { $hashParts[] = "l|{$r[0]}|{$r[1]}|{$r[2]}|" . ($r[3] ?? ''); }
    foreach ($expRows as $f)  { $hashParts[] = 'e|' . implode('|', array_slice($f, 1, 7)); }   // pid 제외
    // 자산등급 제안은 프로세스 comm을 읽는다. PID는 실행마다 달라질 수 있으므로 제외하되,
    // 역할 프로세스의 시작/종료는 반드시 새 스냅샷과 제안 재평가를 만들게 한다.
    foreach ($procRows as $r) { $hashParts[] = 'r|' . implode('|', $r); }
    foreach ($staleRows as $r) { $hashParts[] = "s|{$r[2]}|{$r[3]}"; }
    foreach ($ctrPkgRows as $r) { $hashParts[] = "c|{$r[0]}|{$r[1]}|{$r[2]}|{$r[3]}|" . ($r[5] ?? ''); }
    foreach ($ctrRows as $r)    { $hashParts[] = "C|{$r[0]}|{$r[2]}|{$r[3]}|{$r[4]}"; }   // cid|image|os
    foreach ($ctrExpRows as $f) { $hashParts[] = 'CE|' . $f[0] . '|' . implode('|', array_slice($f, 2, 7)); }   // pid 제외
    $hashParts[] = 'k|' . $runningKernel . '|' . $kernelLatest . '|' . $kernelReboot;
    $hashParts[] = 'o|' . ($vm['distro_id'] ?? '') . '|' . ($vm['distro_version'] ?? '')
                 . '|' . ($sys['kernel_release'] ?? ($sys['kernel'] ?? ''));
    // 의존성 그래프도 해시에 넣는다 — 안 넣으면 그래프만 바뀐 재스캔이 "변경 없음"으로 스킵돼
    //   tb_package_dependency 가 영구히 비는 문제가 생긴다(PR#399 리뷰 지적).
    foreach ($pomDepRows as $r)  { $hashParts[] = 'pd|' . implode('|', $r); }
    foreach ($sbomDepRows as $r) { $hashParts[] = 'sd|' . implode('|', array_map(static fn($v) => (string) $v, $r)); }
    sort($hashParts);
    return hash('sha256', implode("\n", $hashParts));
}

// ── 패키지 변경 이력 계산 (직전 스냅샷과 비교) ────────────────────────────
//   manager|name(OS 패키지) 또는 lang_manager|name(언어 패키지) 를 키로 쓴다.
function vg_ingest_build_pkg_map(string $manager, array $pkgRows, array $langRows): array
{
    $map = [];
    foreach ($pkgRows as $r)  { $map[$manager . '|' . $r[0]] = (string) $r[1]; }
    foreach ($langRows as $r) { $map[$r[0] . '|' . $r[1]]    = (string) $r[2]; }
    return $map;
}

// ── 두 스냅샷의 패키지 맵을 비교해 설치/제거/업그레이드/다운그레이드 목록을 낸다 ──
//   반환 원소: [키(manager|name), change_type, old_version, new_version]
//   $verCmp 는 vg_ver_cmp(string $a, string $b, string $manager): int 와 같은 시그니처.
function vg_ingest_diff_packages(array $prevPkgs, array $curPkgs, callable $verCmp): array
{
    $changes = [];
    foreach ($curPkgs as $k => $v) {
        if (!isset($prevPkgs[$k])) {
            $changes[] = [$k, 'installed', null, $v];
        } elseif ($prevPkgs[$k] !== $v) {
            [$mgr] = explode('|', $k, 2);
            $up = $verCmp($v, $prevPkgs[$k], $mgr) >= 0;
            $changes[] = [$k, $up ? 'upgraded' : 'downgraded', $prevPkgs[$k], $v];
        }
    }
    foreach ($prevPkgs as $k => $v) {
        if (!isset($curPkgs[$k])) { $changes[] = [$k, 'removed', $v, null]; }
    }
    return $changes;
}
