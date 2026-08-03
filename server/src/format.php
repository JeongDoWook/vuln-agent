<?php
declare(strict_types=1);

/**
 * format.php — 순수 포맷/변환 헬퍼. 입력값 → 이스케이프된 문자열(또는 배열), side-effect 없음.
 *   echo 하지 않는다 — DB·세션·파일시스템에 안 닿는다. 그래서 서버 없이 단위테스트가 가능하다.
 *   레이아웃·테이블 렌더(echo 하는 것들)는 view.php 에 남는다. view.php 가 이 파일을 require 한다.
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/* --- 톤 어휘 --------------------------------------------------------------
 * 색은 CSS 의 .tone-* 이 정한다. PHP 는 "어떤 톤인가" 만 고른다.
 * 뱃지를 쓰는 모든 화면(심각도·런타임상태·피드상태·노출범위·자산상태)이 이 어휘를 공유한다. */

const VG_TONE_SEV = ['CRITICAL' => 'crit', 'HIGH' => 'high', 'MEDIUM' => 'med', 'LOW' => 'low'];

/** 임의의 라벨을 톤 뱃지로. $label 은 여기서 이스케이프한다. */
function vg_badge(string $label, string $tone = 'muted', string $title = ''): string {
    return '<span class="badge tone-' . vg_h($tone) . '"'
        . ($title !== '' ? ' title="' . vg_h($title) . '"' : '')
        . '>' . vg_h($label) . '</span>';
}

/** 심각도(CRITICAL/HIGH/MEDIUM/LOW) 뱃지. */
function vg_sev_badge(string $sev): string {
    return vg_badge($sev, vg_sev_tone($sev));
}

/** 심각도 → 톤 클래스명. KPI 카드도 같은 톤을 쓴다. */
function vg_sev_tone(string $sev): string {
    return VG_TONE_SEV[$sev] ?? 'muted';
}

/* CVSS 기본점수 → 심각도 구간(NVD v3 기준). cves.php 에만 있었는데 cve.php 도 쓰게 돼 공용으로. */
const VG_SEV_RANGES = [
    'critical' => [9.0, 10.0],
    'high'     => [7.0, 8.9],
    'medium'   => [4.0, 6.9],
    'low'      => [0.1, 3.9],
];

/** CVSS 점수 → 심각도 라벨(소문자). 점수가 없으면 빈 문자열. */
function vg_cvss_sev(?string $cvss): string {
    if ($cvss === null || $cvss === '') { return ''; }
    $v = (float) $cvss;
    foreach (VG_SEV_RANGES as $name => [$lo, $hi]) {
        if ($v >= $lo && $v <= $hi) { return $name; }
    }
    return '';
}

/* EPSS(악용확률 0~1) → 게이지 톤 구간. packages.php 최고 EPSS 셀에서 쓴다.
 * CVSS→심각도(VG_SEV_RANGES)와 같은 성격의 분류 기준이라 매직 넘버 대신 이름있는 상수로 둔다.
 * 큰 값부터 위에 두고 순서대로 맞춰본다(vg_epss_tone). */
const VG_EPSS_RANGES = ['high' => 0.5, 'med' => 0.1];

/** EPSS 확률(0~1) → 게이지 톤 라벨. 가장 높은 구간부터 맞춰보고, 아무 데도 안 걸리면 low. */
function vg_epss_tone(float $epss): string {
    foreach (VG_EPSS_RANGES as $tone => $min) {
        if ($epss >= $min) { return $tone; }
    }
    return 'low';
}

/**
 * 값 게이지(진행바) 마크업 — "0~100 중 어디" 를 시각적으로 보인다. 숫자만으로는 크기 감이 안 온다.
 *   cve.php(CVSS)·packages.php(최고 EPSS·조치 완료율)가 공유한다. $tone 은 meter-- 뒤 클래스
 *   (crit/high/med/low). $pct 는 채움 비율(%) — 0~100 밖은 잘라낸다.
 *   width:N% 인라인은 app.css 규칙의 명시적 예외(게이지 폭 계산).
 */
function vg_meter(string $tone, float $pct): string {
    $pct = max(0.0, min(100.0, $pct));
    return '<div class="meter meter--' . vg_h($tone) . '">'
         . '<i style="width:' . number_format($pct, 1) . '%"></i></div>';
}

/* CVSS v3 벡터 해독표. 점수 하나로는 "원격인지 로컬인지, 인증이 필요한지" 를 알 수 없다.
 * 벡터가 그걸 말한다 — 같은 9.8 이라도 AV:N/PR:N 이면 인터넷에서 무인증 공격이 가능하다는 뜻.
 * 축약키만 담는다(v2 벡터는 키가 달라 해독 안 되고, 그대로 원문만 보여준다). */
const VG_CVSS_METRICS = [
    'AV' => ['label' => '공격 경로',   'v' => ['N' => '네트워크', 'A' => '인접 네트워크', 'L' => '로컬', 'P' => '물리']],
    'AC' => ['label' => '공격 복잡도', 'v' => ['L' => '낮음', 'H' => '높음']],
    'PR' => ['label' => '필요 권한',   'v' => ['N' => '불필요', 'L' => '일반 사용자', 'H' => '관리자']],
    'UI' => ['label' => '사용자 개입', 'v' => ['N' => '불필요', 'R' => '필요']],
    'S'  => ['label' => '범위 변경',   'v' => ['U' => '없음', 'C' => '있음']],
    'C'  => ['label' => '기밀성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
    'I'  => ['label' => '무결성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
    'A'  => ['label' => '가용성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
];

/**
 * CVSS 벡터 문자열 → [['label'=>'공격 경로','value'=>'네트워크','danger'=>true], …]
 * 해독 못하는 키(v2 벡터 등)는 건너뛴다 — 빈 배열이면 호출부가 원문만 보여준다.
 * 'danger' 는 "공격자에게 유리한 값"(원격·무인증·개입불필요·영향높음) — UI 가 붉게 강조한다.
 */
function vg_cvss_vector_parts(?string $vector): array {
    if ($vector === null || $vector === '') { return []; }
    $worst = ['AV' => 'N', 'AC' => 'L', 'PR' => 'N', 'UI' => 'N', 'S' => 'C', 'C' => 'H', 'I' => 'H', 'A' => 'H'];
    $out = [];
    foreach (explode('/', $vector) as $part) {
        $kv = explode(':', $part, 2);
        if (count($kv) !== 2) { continue; }
        [$k, $v] = $kv;
        if (!isset(VG_CVSS_METRICS[$k]['v'][$v])) { continue; }   // CVSS:3.1 접두나 v2 키는 여기서 걸러진다
        $out[] = [
            'label'  => VG_CVSS_METRICS[$k]['label'],
            'value'  => VG_CVSS_METRICS[$k]['v'][$v],
            'danger' => ($worst[$k] ?? null) === $v,
        ];
    }
    return $out;
}

/**
 * 표의 <tr> 심각도 클래스. CSS 가 왼쪽 띠(+상위 등급은 옅은 배경)로 칠한다.
 * vg_table 의 'row_class' 에 심각도를 뽑아 넘긴다:
 *     'row_class' => fn($r) => vg_sev_row((string) $r['severity'])
 * 심각도가 어느 컬럼에 있는지는 표마다 다르고(base_severity), CVSS 에서 파생시키는
 * 표(cves.php)도 있어서, 컬럼명을 추측하지 않고 호출부가 문자열로 건네게 한다.
 * 어휘에 없는 값이면 빈 문자열 — 클래스 없는 평범한 행이 된다.
 */
function vg_sev_row(?string $sev): string {
    return isset(VG_TONE_SEV[(string) $sev]) ? 'sev-' . VG_TONE_SEV[(string) $sev] : '';
}

/**
 * 심각도별 건수 뱃지 묶음. 0건인 등급은 생략하고, 전부 0이면 '–'.
 *   $href 를 주면 각 뱃지를 링크로 만든다(자산관리: 등급별 취약점 목록으로).
 *   대시보드 · 자산관리 · 호스트 스캔이력이 공유한다.
 */
function vg_sev_counts(array $counts, ?callable $href = null): string {
    $out = [];
    foreach (VG_TONE_SEV as $sev => $tone) {
        $n = (int) ($counts[$sev] ?? 0);
        if ($n === 0) {
            continue;
        }
        $attr = 'class="badge tone-' . $tone . '" title="' . vg_h($sev) . '"';
        $out[] = $href !== null
            ? '<a ' . $attr . ' href="' . vg_h($href($sev)) . '">' . $n . '</a>'
            : '<span ' . $attr . '>' . $n . '</span>';
    }
    return $out ? implode(' ', $out) : '<span class="why">–</span>';
}

/**
 * 심각도 구성 막대(가로 누적). 숫자 뱃지만 있으면 호스트끼리 "누가 더 나쁜지"를
 * 머리로 더해야 한다 — 막대는 그걸 눈으로 보게 한다. 뱃지와 같이 쓴다(색만으로 말하지 않게).
 * 폭 계산(width:N%)은 app.css 로 옮길 수 없는 값이라 인라인 style 예외에 해당한다.
 */
function vg_sev_bar(array $counts): string {
    $total = 0;
    foreach (VG_TONE_SEV as $sev => $tone) { $total += (int) ($counts[$sev] ?? 0); }
    if ($total === 0) { return ''; }

    $out = '';
    foreach (VG_TONE_SEV as $sev => $tone) {
        $n = (int) ($counts[$sev] ?? 0);
        if ($n === 0) { continue; }
        $pct = round($n / $total * 100, 2);
        $out .= '<i class="tone-' . $tone . '" style="width:' . $pct . '%" title="'
              . vg_h($sev . ' ' . number_format($n) . '건') . '"></i>';
    }
    return '<span class="riskbar">' . $out . '</span>';
}

// 런타임 상태(EXTERNAL/LAN/FILTERED/LISTENING/RUNNING/LOADED/INSTALLED)
//   LAN·FILTERED 의 문구는 아래 vg_scope_label() 과 글자까지 동일하게 유지한다(같은 값을 두 곳에서
//   다르게 부르지 않게). 톤도 host.php 의 $scopeTone 과 맞춘다 — LAN=med, FILTERED=muted.
function vg_status_label(?string $s): string {
    $m = ['EXTERNAL' => '외부노출', 'LAN' => '로컬 세그먼트 노출', 'FILTERED' => '방화벽 차단',
          'LISTENING' => '로컬리스닝', 'RUNNING' => '실행중', 'LOADED' => '사용중', 'INSTALLED' => '설치만'];
    return $m[$s ?? ''] ?? (string) $s;
}
function vg_status_badge(?string $s): string {
    $tone = ['EXTERNAL' => 'crit', 'LAN' => 'med', 'FILTERED' => 'muted',
             'LISTENING' => 'high', 'RUNNING' => 'med', 'LOADED' => 'purple', 'INSTALLED' => 'muted'];
    return vg_badge(vg_status_label($s), $tone[$s ?? ''] ?? 'muted');
}

// 노출 범위(tb_exposure.scope: EXTERNAL/LAN/BOUND/FILTERED/LOCAL).
//   문구는 matcher.php vg_classify()/agent 판정 주석과 통일(같은 값을 두 곳에서 다르게 부르지 않게).
//   톤(색) 매핑은 host.php 의 $scopeTone 이 계속 갖는다 — 여기는 라벨 텍스트만.
function vg_scope_label(?string $s): string {
    $m = [
        'EXTERNAL' => '외부노출',
        'LAN'      => '로컬 세그먼트 노출',
        'BOUND'    => '특정 IP 바인딩',
        'FILTERED' => '방화벽 차단',
        'LOCAL'    => '로컬 전용',
    ];
    return $m[$s ?? ''] ?? (string) $s;
}

/* 수집 단계(tb_collection_stage.stage_code) → 한글 라벨.
 *   ingest.php 가 스캔마다 이 5종만 기록한다(고정된 알려진 구조라 하드코딩이 맞다 — 새 단계는
 *   생산자와 함께 여기 한 줄을 늘린다). 모르는 코드가 오면 코드 원문을 그대로 보여준다. */
const VG_COLLECTION_STAGE_LABEL = [
    'packages'          => '설치 패키지',
    'language_packages' => '언어 패키지',
    'runtime_processes' => '실행 프로세스',
    'network_exposure'  => '네트워크 노출',
    'containers'        => '컨테이너',
];

/* 수집 상태 판정 기준(분). 에이전트 기본 스케줄이 매시간이라 3시간까지는 정상으로 본다.
 *   자산관리 목록(assets.php)과 호스트 상세(host.php) 히어로가 공유한다. */
const VG_STALE_MIN   = 180;        // 3시간 초과 → 지연
const VG_OFFLINE_MIN = 10080;      // 7일 초과 → 오프라인

/** 최신 수집 경과시간(분)으로 수집 상태 뱃지. 스캔이 없으면(null) '수집없음'. */
function vg_asset_state($ageMin): string {
    if ($ageMin === null) { return vg_badge('수집없음', 'muted'); }
    $m = (int) $ageMin;
    if ($m > VG_OFFLINE_MIN) { return vg_badge('오프라인', 'crit'); }
    if ($m > VG_STALE_MIN)   { return vg_badge('지연', 'high'); }
    return vg_badge('정상', 'ok');
}

/**
 * 에이전트 자기계측 셀 — 실행당 리소스 발자국(담당자 안심용).
 *   피크 메모리는 프로세스 트리 전체 최댓값, CPU 는 자식 포함 실제 점유(벽시계 아님).
 *   값이 없으면(구버전 에이전트·측정 불가) 대시. 옛 스캔은 컬럼이 비어 있는 게 정상이다.
 */
function vg_resource_mem($mb): string {
    if ($mb === null || $mb === '') { return '<span class="why">–</span>'; }
    return number_format((float) $mb, 0) . '<span class="why">MB</span>';
}
function vg_resource_cpu($sec): string {
    if ($sec === null || $sec === '') { return '<span class="why">–</span>'; }
    return vg_h(number_format((float) $sec, 1)) . '<span class="why">s</span>';
}

/**
 * 리소스 사용률(%) 셀 — 호스트 스펙(메모리 총량·CPU 코어수) 대비 퍼센트.
 *   host.php 리소스 탭·대시보드 함대 카드 양쪽에서 쓴다. 스펙 미수집 스캔은 null.
 */
function vg_resource_pct(?float $pct): string {
    if ($pct === null) { return '<span class="why">–</span>'; }
    return number_format($pct, 1) . '<span class="why">%</span>';
}

/** 한 번의 에이전트 실행이 차지한 호스트 메모리 비율. 잘못된 누적 계측값은 제외한다. */
function vg_agent_mem_pct($peakMb, $totalMb): ?float {
    if ($peakMb === null || $peakMb === '' || $totalMb === null || $totalMb === '' || (float) $totalMb <= 0) {
        return null;
    }
    $pct = (float) $peakMb / (float) $totalMb * 100;
    return $pct >= 0 && $pct <= 100 ? $pct : null;
}

/** 실행 시간 동안 에이전트 프로세스 트리가 사용한 전체 CPU 용량 비율. */
function vg_agent_cpu_pct($cpuSeconds, $elapsedSeconds, $cores): ?float {
    if ($cpuSeconds === null || $cpuSeconds === '' || $elapsedSeconds === null || $elapsedSeconds === ''
        || $cores === null || $cores === '' || (float) $elapsedSeconds <= 0 || (float) $cores <= 0) {
        return null;
    }
    $pct = (float) $cpuSeconds / ((float) $elapsedSeconds * (float) $cores) * 100;
    // 한 호스트의 전체 코어 용량을 분모로 삼았으므로 100% 초과는 과거 누적 cgroup 계측값이다.
    return $pct >= 0 && $pct <= 100 ? $pct : null;
}

/**
 * EPSS 셀 — 악용확률과 백분위를 함께.
 *
 * 확률만 보면 크기 감이 안 온다. EPSS 는 절대다수가 1% 미만이라 "2.7%" 도 실은 상위권이다.
 * FIRST 가 같이 주는 백분위(epss_percentile)를 "상위 N%" 로 뒤집어 붙여 맥락을 준다.
 *   epss=0.02719, percentile=0.97281  →  "2.7% 상위 2.7%"
 * 값이 없으면(1999년대 CVE 등 FIRST 가 점수를 안 매기는 건) 대시.
 */
function vg_epss_cell($epss, $percentile = null): string {
    if ($epss === null || $epss === '') {
        return '<span class="why">–</span>';
    }
    $out = vg_h(number_format((float) $epss * 100, 1)) . '%';
    if ($percentile !== null && $percentile !== '') {
        $top = (1.0 - (float) $percentile) * 100;
        if ($top < 0.01) { $top = 0.01; }   // percentile=1.0 이 "상위 0%" 로 보이지 않게
        $dec = $top < 1 ? 2 : ($top < 10 ? 1 : 0);
        $out .= ' <span class="why">상위 ' . vg_h(number_format($top, $dec)) . '%</span>';
    }
    return $out;
}

// 긴 텍스트 말줄임 + 툴팁(title 에 원문). 안 잘리면 그냥 이스케이프만.
function vg_trunc(?string $text, int $len = 72): string {
    $text = (string) $text;
    $cut = mb_strimwidth($text, 0, $len, '…');
    if ($cut === $text) {
        return vg_h($text);
    }
    return '<span class="trunc" title="' . vg_h($text) . '">' . vg_h($cut) . '</span>';
}

/**
 * href 로 그대로 출력해도 안전한 URL 인가(http/https 스킴만). 저장 시점(vg_nvd_extract_ref_urls)과
 * 출력 시점(vg_cve_first_ref·cve.php 참조 목록)이 각자 정규식을 들고 있으면 한쪽만 고쳤을 때
 * 다른 쪽에 구멍이 남는다 — 검증을 여기 한 곳으로 모은다.
 */
function vg_is_safe_http_url(?string $url): bool {
    return $url !== null && preg_match('#^https?://#i', $url) === 1;
}

/**
 * tb_cve.ref_urls_json(첫 항목)에서 url·tags 를 꺼낸다. findings.php/host.php 는 대표 링크
 * 1개만 보여주면 되므로(전체 표는 cve.php 개요 탭) 파싱 실패·빈 배열·안전하지 않은 스킴이면 null.
 * tags 를 함께 돌려주는 건 호출부가 "이게 실제로 패치 링크인지"를 판단해야 하기 때문 —
 * vg_nvd_extract_ref_urls 의 정렬은 Patch/Vendor Advisory 가 있을 때만 앞으로 올리므로,
 * 태그가 없거나 Mailing List/Broken Link 뿐인 CVE 는 첫 항목이 패치 링크가 아닐 수 있다.
 */
function vg_cve_first_ref(?string $json): ?array {
    if ($json === null || $json === '') { return null; }
    $list = json_decode($json, true);
    if (!is_array($list) || !isset($list[0]['url'])) { return null; }
    $url = (string) $list[0]['url'];
    if (!vg_is_safe_http_url($url)) { return null; }
    $tags = [];
    foreach ((array) ($list[0]['tags'] ?? []) as $t) { $tags[] = (string) $t; }
    return ['url' => $url, 'tags' => $tags];
}

/**
 * 조치 열 공통 표시 규칙 — findings.php/host.php 가 각자 들고 있던 같은 삼항 로직을 통일.
 *   조치버전이 있으면 "현재버전 → 조치버전 이상", 없고 NVD 대표 참조링크가 있으면 링크,
 *   둘 다 없으면 평문 — 두 경우 모두 현재 버전을 곁들여 패키지 열과 오가지 않아도 되게 한다.
 *   링크 문구는 태그로 갈린다 — Patch/Vendor Advisory 가 아니면 "패치 확인"이라고 단정하지
 *   않는다(무관한 메일링리스트·죽은 링크를 패치인 줄 알고 클릭하게 만들 수 있다).
 */
function vg_fix_cell(?string $fixedVersion, ?string $refUrlsJson, ?string $installedVersion = null): string {
    $installed = ($installedVersion !== null && $installedVersion !== '') ? vg_h($installedVersion) : null;
    if ($fixedVersion !== null && $fixedVersion !== '') {
        $ver = $installed !== null ? $installed . ' → ' . vg_h($fixedVersion) : vg_h($fixedVersion);
        // 조치 버전은 rhel 모듈처럼 아주 긴 것이 있다(1:1.22.1-3.module+el9.2.0+15280+45c505d6.1).
        //   좁은 칸에서 세 줄로 부풀어 행 높이를 혼자 결정하므로 두 줄까지만 보이게 하고(clamp-2)
        //   전체 값은 title 로 남긴다 — 목록에서 훑고, 정확한 버전은 상세·툴팁에서 본다.
        $plain = ($installedVersion !== null && $installedVersion !== '' ? $installedVersion . ' → ' : '')
               . $fixedVersion . ' 이상';
        return '<span class="pill clamp-2" title="' . vg_h($plain) . '">' . $ver . ' 이상</span>';
    }
    $currentLine = $installed !== null ? '<div class="why">현재 ' . $installed . '</div>' : '';
    $ref = vg_cve_first_ref($refUrlsJson);
    if ($ref === null) {
        return '<span class="why">패치 확인</span>' . $currentLine;
    }
    $isPatch = in_array('Patch', $ref['tags'], true) || in_array('Vendor Advisory', $ref['tags'], true);
    return '<a class="why" href="' . vg_h($ref['url']) . '" target="_blank" rel="noopener noreferrer">'
        . ($isPatch ? '패치 확인 →' : '참고 링크 →') . '</a>' . $currentLine;
}

/**
 * 벤더 판정 advisory → 벤더 공식 권고 URL. 확신 가능한 두 벤더만(레드햇·알마리눅스) — vendor.php·
 *   cve.php 가 공유한다(원본 지침: 한쪽만 링크되면 사용자가 헷갈린다).
 *   AlmaLinux 는 OVAL 자체엔 ALSA 참조도 있지만 커넥터(feeds/rhoval.php)가 RHSA/ELSA 참조만
 *   골라 저장한다 — 그래서 vendor='almalinux' 행도 advisory 값은 "RHSA-YYYY:NNNN" 이다.
 *   실물 OVAL(org.almalinux.alsa-9.xml) 대조 결과 같은 정의 안에서 RHSA·ALSA 번호(연도:일련번호)는
 *   1610건 전수 동일했다(AlmaLinux 가 RHEL 권고를 그대로 재빌드하며 번호를 유지) — 그래서 접두만
 *   RHSA→ALSA 로 바꿔 재구성해도 안전하다. 확신 없는 패턴(Oracle ELSA 등)은 null.
 */
function vg_vendor_advisory_url(string $vendor, ?string $advisory, string $releaseMajor = ''): ?string {
    $advisory = trim((string) $advisory);
    if ($advisory === '') { return null; }
    if ($vendor === 'redhat' && preg_match('/^RHSA-\d+:\d+$/i', $advisory)) {
        return 'https://access.redhat.com/errata/' . rawurlencode($advisory);
    }
    if ($vendor === 'almalinux' && $releaseMajor !== '' && preg_match('/^RHSA-(\d+:\d+)$/i', $advisory, $m)) {
        return 'https://errata.almalinux.org/' . rawurlencode($releaseMajor) . '/ALSA-' . str_replace(':', '-', $m[1]) . '.html';
    }
    return null;
}

/**
 * 벤더 판정 소스 cve_id → 벤더 공식 CVE 페이지 URL. advisory 가 없는 소스(rhunfixed)이거나
 *   패키지가 아니라 CVE 단위로 원문을 보여주는 소스(debtracker·ubuntuoval)만 해당.
 *   kcve 는 마땅한 벤더 페이지가 없어 null(호출부가 링크 없이 텍스트만 보여준다).
 */
function vg_vendor_cve_url(string $src, string $cveId): ?string {
    $cveId = trim($cveId);
    if ($cveId === '' || !preg_match('/^CVE-\d{4}-\d+$/i', $cveId)) { return null; }
    switch ($src) {
        case 'rhunfixed':  return 'https://access.redhat.com/security/cve/' . rawurlencode($cveId);
        case 'debtracker': return 'https://security-tracker.debian.org/tracker/' . rawurlencode($cveId);
        case 'ubuntuoval': return 'https://ubuntu.com/security/' . rawurlencode($cveId);
        default: return null;
    }
}

/**
 * 도움말 툴팁. 본문에 늘어놓으면 화면이 무거워지는 부연설명을 아이콘 뒤로 보낸다.
 * 네이티브 title 을 쓴다 — 스크린리더도 읽고, JS 도 필요 없다.
 */
function vg_help(string $text): string {
    return '<span class="help" title="' . vg_h($text) . '" tabindex="0" role="note">?</span>';
}

/**
 * ⓘ 인포팁. 제목·라벨 옆에 붙여 부연설명을 감춰 둔다(말풍선은 app.css 가 그린다).
 * 설명은 data-tip 으로 넘긴다 — title 로 주면 브라우저 기본 툴팁이 우리 말풍선과
 * 같이 떠서 두 개가 겹친다. 화면에 보이는 건 ⓘ 글자뿐이라 스크린리더가 읽을 게
 * 없으므로 aria-label 로 같은 문구를 준다.
 */
function vg_info_icon(string $text): string {
    return '<span class="info-icon" data-tip="' . vg_h($text) . '" aria-label="' . vg_h($text)
        . '" tabindex="0" role="note">ⓘ</span>';
}
