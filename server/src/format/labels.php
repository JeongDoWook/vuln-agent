<?php
declare(strict_types=1);

/**
 * format/labels.php — DB 의 코드값 → 사람이 읽는 한글 어휘. 이 파일이 어휘의 **정본**이다.
 *   런타임 상태 · 조치 상태 · 노출 범위 · 무결성 플래그 · 수집 단계.
 *   같은 값을 두 화면에서 다르게 부르지 않게 하려고 여기 하나로 모아 뒀다 —
 *   문구를 고칠 일이 생기면 여기만 고친다.
 */

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

/* 조치 상태(tb_finding_status.status) — 사람이 정하는 값이다.
 *   바로 위 vg_status_label() 의 '상태'(런타임 노출 상태)와는 **다른 축**이다. 화면에서도
 *   '노출 상태' / '조치 상태' 로 라벨을 갈라 부른다 — 한 화면에 둘이 같이 서기 때문이다.
 *   행이 없는 조합(= 아직 아무도 손대지 않은 취약점)은 OPEN 으로 읽는다. 그래서 라벨을
 *   찾을 때 null 도 OPEN 으로 눕힌다 — 화면마다 '값이 없으면 미조치' 를 다시 쓰지 않게.
 *   값 4개와 순서(급한 것 → 끝난 것)의 정본이 여기 하나다: 필터 드롭다운·모달 셀렉트·
 *   배지가 전부 이 표를 읽는다. */
function vg_finding_status_labels(): array {
    return ['OPEN' => '미조치', 'IN_PROGRESS' => '조치중', 'DONE' => '완료', 'EXCEPTED' => '예외'];
}
function vg_finding_status_label(?string $s): string {
    $s = ($s === null || $s === '') ? 'OPEN' : $s;
    return vg_finding_status_labels()[$s] ?? $s;
}
function vg_finding_status_badge(?string $s): string {
    // 톤: 미조치는 '아직 남은 일' 이라 주의색, 조치중은 진행, 완료는 ok, 예외는 중립.
    //   예외를 완료와 같은 초록으로 두지 않는다 — "고쳤다" 와 "안 고치기로 했다" 는 다른 사실이다.
    $tone = ['OPEN' => 'high', 'IN_PROGRESS' => 'med', 'DONE' => 'ok', 'EXCEPTED' => 'muted'];
    $s = ($s === null || $s === '') ? 'OPEN' : $s;
    return vg_badge(vg_finding_status_label($s), $tone[$s] ?? 'muted');
}

// 노출 범위(tb_exposure.scope: EXTERNAL/LAN/BOUND/FILTERED/LOCAL/-).
//   문구는 matcher.php vg_classify()/agent 판정 주석과 통일(같은 값을 두 곳에서 다르게 부르지 않게).
//   톤(색) 매핑은 host.php 의 $scopeTone 이 계속 갖는다 — 여기는 라벨 텍스트만.
function vg_scope_label(?string $s): string {
    $m = [
        'EXTERNAL' => '외부노출',
        'LAN'      => '로컬 세그먼트 노출',
        'BOUND'    => '특정 IP 바인딩',
        'FILTERED' => '방화벽 차단',
        'LOCAL'    => '로컬 전용',
        // 에이전트가 bind 주소를 못 읽은 소켓(vuln-inventory-agent.sh 의 scope="-").
        //   "로컬 전용" 으로 낙관하지 않는다 — 모르는 것은 모른다고 적는다.
        '-'        => '범위 미상',
    ];
    return $m[$s ?? ''] ?? (string) $s;
}

/* 패키지 무결성 플래그(rpm -Va / dpkg --verify 원본) → 사람이 읽는 설명.
 *   ★ 어휘는 **단정하지 않는다** — "변조됨"이 아니라 "패키지 원본과 다름(관측)"이다.
 *     운영자가 직접 바꾼 파일일 수 있고, 우리가 아는 건 "설치 기록과 다르다"는 사실뿐이다.
 *   dpkg 는 판정하지 못한 항목을 '?' 로 준다 — 알 수 없는 자리는 설명하지 않는다. */
const VG_INTEGRITY_FLAG_LABEL = [
    '5' => '내용 다름',
    'S' => '크기 다름',
    'M' => '권한 다름',
    'U' => '소유자 다름',
    'G' => '그룹 다름',
    'L' => '링크 대상 다름',
    'D' => '장치번호 다름',
    'T' => '수정시각 다름',
    'P' => '권한(capability) 다름',
];

function vg_integrity_flag_label(string $flags): string {
    if (strcasecmp(trim($flags), 'missing') === 0) { return '파일 없음'; }
    $out = [];
    foreach (str_split($flags) as $ch) {
        if (isset(VG_INTEGRITY_FLAG_LABEL[$ch])) { $out[$ch] = VG_INTEGRITY_FLAG_LABEL[$ch]; }
    }
    return $out ? implode(' · ', $out) : '차이 있음';
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
