<?php
declare(strict_types=1);

/**
 * host/depgraph.php — "무엇부터 올리나" 를 만드는 묶음 조회 + 의존성 판정 셀.
 *   같은 패키지에서 나온 묶음(vg_host_load_pkg_rollup)과, 전이 의존성 판정을 화면 문구로
 *   바꾸는 헬퍼(vg_host_dep_*)가 한 질문에 답하므로 같은 파일에 둔다.
 *   키 형식·경로 조회의 정본은 src/packagedep.php 다(이 파일은 그것을 화면 어휘로 옮길 뿐).
 */

/**
 * 같은 패키지에서 나온 CRITICAL·HIGH 묶음 — "이 하나를 올리면 N건 해결".
 *
 *   왜 필요한가: 표를 행 단위로만 보면 libc6 하나가 만든 CVE 5건이 "서로 다른 다섯 문제"처럼
 *   보인다. 근거 문장까지 사실상 같아서 화면이 반복으로 채워진다. 손댈 대상 기준으로 먼저
 *   묶어 두면 "무엇부터 올리나"에 한 줄로 답한다.
 *   의존성 부모별 묶음(vg_pkgdep_scan_rollup)과 같은 질문에 답하지만 대상이 다르다 —
 *   저쪽은 **전이 의존성이 있는 자산**(언어 패키지), 이쪽은 **모든 자산**의 OS 패키지다.
 *
 *   집계는 스캔 전체 기준이라 페이지·검색을 넘겨도 값이 변하지 않는다.
 *   2건 이상 묶이는 것만 남긴다(1건짜리는 묶음이 아니라 그냥 그 행이다).
 */
function vg_host_load_pkg_rollup(PDO $pdo, int $sid, int $limit): array {
    // FIELD() 는 CRITICAL=1, HIGH=2 — MIN 이 그 묶음의 최고 등급이다.
    //   상한+1 을 읽어 "더 있다"를 알 수 있게 한다 — 조용히 자르면 이게 전부처럼 보인다.
    $st = $pdo->prepare(
        "SELECT package_name, installed_version, COUNT(*) AS cnt,
                MIN(FIELD(severity,'CRITICAL','HIGH')) AS sev_rank,
                MAX(in_kev) AS kev, MAX(needs_restart) AS needs_restart
           FROM tb_finding
          WHERE scan_id = ? AND severity IN ('CRITICAL','HIGH')
          GROUP BY package_name, installed_version
         HAVING cnt > 1
          ORDER BY cnt DESC, sev_rank, package_name
          LIMIT " . ($limit + 1)
    );
    $st->execute([$sid]);
    $rows = $st->fetchAll();
    $truncated = count($rows) > $limit;
    if ($truncated) { $rows = array_slice($rows, 0, $limit); }
    foreach ($rows as &$r) {
        $r['severity'] = ((int) $r['sev_rank']) === 1 ? 'CRITICAL' : 'HIGH';
    }
    unset($r);
    return ['rows' => $rows, 'truncated' => $truncated];
}

/** 취약점 행 → 의존성 판정 캐시의 키. 형식의 정본은 packagedep.php 다(집계도 같은 키를 쓴다). */
function vg_host_dep_key(array $f): string {
    return vg_pkgdep_finding_key(
        (int) ($f['container_id'] ?? 0),
        (string) ($f['package_name'] ?? ''),
        (string) ($f['installed_version'] ?? '')
    );
}

/** 손댈 대상(부모) 라벨 — "이름 버전 이 끌어옴 [외 N개]". 이스케이프 전의 평문이다. */
function vg_host_dep_parent_label(array $o): string {
    $p = vg_pkgdep_parts((string) $o['parents'][0]);
    $more = count($o['parents']) - 1;
    return $p['name'] . ' ' . $p['version'] . ' 이 끌어옴' . ($more > 0 ? ' 외 ' . $more . '개' : '');
}

/**
 * 전이 의존성일 때의 조치 셀 — "직접 조치 불가" + 손댈 대상 + 의존성 경로 링크.
 *   **버전은 제안하지 않는다.** 설치되지 않은 부모 버전이 무엇을 끌어오는지 우리는 모른다
 *   (그걸 알려면 업스트림 버전별 의존성 DB 가 필요하다). 틀린 조치 제안은 없는 것보다 나쁘다.
 */
function vg_host_dep_origin_cell(array $o, int $hostId): string {
    $t = vg_pkgdep_parts((string) $o['key']);
    $url = '/depgraph.php?id=' . $hostId . '&cid=' . (int) $o['container_id']
         . '&mgr=' . urlencode($t['manager']) . '&name=' . urlencode($t['name'])
         . '&ver=' . urlencode($t['version']) . '&tab=from';
    return '<span class="pill">직접 조치 불가</span>'
        . '<div class="why">' . vg_h(vg_host_dep_parent_label($o))
        . ' · <a href="' . vg_h($url) . '">의존성 경로</a></div>';
}

/**
 * 손댈 대상(부모) 요약 표의 한 행 → 이름·버전 + 의존성 그래프 링크.
 *   링크는 "무엇을 끌어오나"(tab=to) 로 건다 — 이 부모를 올리면 무엇이 함께 바뀌는지가
 *   여기서 궁금한 것이다(행 단위 셀의 링크는 반대로 "무엇이 끌어왔나"였다).
 */
function vg_host_dep_rollup_target(array $p, int $hostId): string {
    $t = vg_pkgdep_parts((string) $p['key']);
    $url = '/depgraph.php?id=' . $hostId . '&cid=' . (int) $p['container_id']
         . '&mgr=' . urlencode($t['manager']) . '&name=' . urlencode($t['name'])
         . '&ver=' . urlencode($t['version']) . '&tab=to';
    return '<strong>' . vg_h($t['name']) . '</strong> <span class="why">' . vg_h($t['version']) . '</span>'
        . ' <a class="pill" href="' . vg_h($url) . '">의존성 그래프</a>';
}
