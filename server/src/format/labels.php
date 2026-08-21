<?php
declare(strict_types=1);

/**
 * format/labels.php — DB 의 코드값 → 사람이 읽는 한글 어휘. 이 파일이 어휘의 **정본**이다.
 *   런타임 상태 · 조치 상태 · 노출 범위 · 발견 위치 · 무결성 플래그 · 수집 단계.
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

/* 발견의 '위치' — 호스트 자신인가, 그 안의 컨테이너인가(tb_finding.container_id → 컨테이너 cid).
 *   같은 두 갈래를 advisory.php(영향 자산) · cve.php(발견 위치) · package.php(벤더 미수정이 몰린
 *   자산) 세 표가 각자 그리고 있었다 — 문구가 갈리면 같은 값이 화면마다 달라 보인다.
 *   빈 문자열/NULL 이 곧 "호스트 자신" 이다(container_id = 0 → LEFT JOIN 미스 → IFNULL '').  */
function vg_place_label(?string $ctr): string {
    return ($ctr ?? '') !== '' ? '컨테이너 ' . $ctr : '호스트';
}
function vg_place_cell(?string $ctr): string {
    return '<span class="why">' . vg_h(vg_place_label($ctr)) . '</span>';
}
/**
 * 위치 열을 세울지 정한다 — **값이 한 가지뿐이면 열이 아니라 제목 옆 한 줄이다.**
 *   모든 행이 같은 값인 열의 정보량은 0인데 폭은 그대로 먹어, 정작 잘리는 식별자 열이
 *   그 폭을 못 쓴다(8열 표가 1200px 아래에서 값을 자르던 실측 — 열을 셋 줄이자 1000px 까지 버텼다).
 * @param bool $mixed 표 **전체**(현재 페이지가 아니라)에 위치가 두 가지 이상 있는가
 * @return string 제목 옆에 붙일 문구('전부 호스트') 또는 ''(섞여 있어 열이 필요하다)
 */
function vg_place_note(bool $mixed, ?string $ctr): string {
    return $mixed ? '' : '전부 ' . vg_place_label($ctr);
}

/* 패키지 무결성 플래그(rpm -Va / dpkg --verify 원본) → 사람이 읽는 설명.
 *   ★ 어휘는 **단정하지 않는다** — "변조됨"이 아니라 "패키지 원본과 다름(관측)"이다.
 *     운영자가 직접 바꾼 파일일 수 있고, 우리가 아는 건 "설치 기록과 다르다"는 사실뿐이다.
 *   ★ 플래그는 **자리(position)로 읽는다.** 9칸 각각이 검사 항목 하나이고, 그 자리에 항목의
 *     글자가 서면 "다름", '.' 이면 "같음", '?' 이면 **"검사하지 않음"** 이다.
 *     '?' 를 "같음"으로 읽으면 안 본 항목이 정상으로 둔갑한다 — 이 구분이 결과의 범위를 정한다.
 *   ★ 원문(`??5??????`)은 화면에 흘리지 않는다. 사람이 읽을 수 있는 항목 이름으로 풀고,
 *     원문은 툴팁에만 남긴다(디버깅 근거는 필요하되 표는 어지럽히지 않는다). */
const VG_INTEGRITY_FLAG_SLOTS = [
    ['S', '크기'],
    ['M', '권한'],
    ['5', '내용'],
    ['D', '장치번호'],
    ['L', '링크 대상'],
    ['U', '소유자'],
    ['G', '그룹'],
    ['T', '수정시각'],
    ['P', 'capability'],
];
// 내용(MD5) 자리 — dpkg 는 여기 하나만 검사한다. 아래 검사범위 판정이 이 자리를 기준으로 쓴다.
const VG_INTEGRITY_MD5_SLOT = 2;

/* 다른 것으로 관측된 항목만 한글 이름으로 돌려준다(자리순 = 위 표 순서). */
function vg_integrity_diff_items(string $flags): array {
    $out = [];
    foreach (VG_INTEGRITY_FLAG_SLOTS as $i => [$ch, $name]) {
        if (($flags[$i] ?? '') === $ch) { $out[] = $name; }
    }
    return $out;
}

/* 표 한 칸에 들어갈 한 줄. 여러 항목이면 **전부** 나열한다(하나만 보여주고 자르지 않는다). */
function vg_integrity_flag_label(string $flags): string {
    if (strcasecmp(trim($flags), 'missing') === 0) { return '파일 없음'; }
    $items = vg_integrity_diff_items($flags);
    // 해석할 글자가 하나도 없어도 "차이 없음"이라고 하지 않는다 — rpm·dpkg 는 문제가 있는
    //   파일만 출력하므로, 이 줄이 존재한다는 것 자체가 "무언가 걸렸다"는 관측이다.
    return $items ? implode(' · ', $items) : '차이 있음';
}

const VG_INTEGRITY_RPM_SKIPPED = ['수정시각', '소유자', '그룹'];   // rpm -Va --nomtime --nouser --nogroup

/* 이 결과가 **무엇을 검사한 것인지**를 한 줄로 돌려준다.
 *   왜 필요한가: dpkg 는 내용(MD5)만 본다. 그 사실을 안 적으면 "크기·권한·소유자는 정상"으로
 *   읽히는데, 실제로는 **보지 않은 것**이다. 이건 친절한 설명이 아니라 결과의 범위를 정하는 사실이다.
 *
 *   판정 근거는 플래그 자리다(따로 저장하는 값이 없다):
 *     · 내용 자리를 뺀 나머지가 전부 '?' → 내용만 검사(dpkg --verify).
 *     · 다른 자리에 '?' 아닌 글자가 하나라도 있으면 rpm -Va 다.
 *   ⚠ rpm 은 **검사에서 뺀 항목도 '.'(같음)으로 찍는다** — 2026-08-21 almalinux:9 실측:
 *     같은 파일이 `rpm -V` 로는 `SM5..UGT.`, `rpm -V --nomtime --nouser --nogroup` 로는
 *     `SM5......` 였다. 그래서 rpm 쪽 제외 항목은 플래그로 알 수 없고, 우리 에이전트가
 *     쓰는 명령(agent/vuln-inventory-agent.sh 의 collect_integrity)에서 온다.
 *
 *   @param string[] $flagList 화면에 세운 행들의 flags 원문
 *   @return array{tool:string,text:string,title:string} tool 이 '' 면 판정 불가(표기하지 않는다)
 */
function vg_integrity_verify_scope(array $flagList): array {
    $none = ['tool' => '', 'text' => '', 'title' => ''];
    $tool = '';
    $seen = [];        // 실제로 "다름"으로 관측된 항목 — 그 항목은 검사한 것이 확실하다.
    foreach ($flagList as $flags) {
        $flags = trim((string) $flags);
        if ($flags === '' || strcasecmp($flags, 'missing') === 0) { continue; }
        foreach (vg_integrity_diff_items($flags) as $name) { $seen[$name] = true; }
        foreach (array_keys(VG_INTEGRITY_FLAG_SLOTS) as $i) {
            if ($i === VG_INTEGRITY_MD5_SLOT) { continue; }
            if (($flags[$i] ?? '?') !== '?') { $tool = 'rpm'; }
        }
        if ($tool !== 'rpm' && strpos($flags, '?') !== false) { $tool = 'dpkg'; }
    }
    return $tool === '' ? $none : vg_integrity_scope_text($tool, array_keys($seen));
}

/* @param string[] $seen 이번 결과에서 실제로 "다름"으로 관측된 항목 이름 */
function vg_integrity_scope_text(string $tool, array $seen = []): array {
    $all = array_column(VG_INTEGRITY_FLAG_SLOTS, 1);   // 검사 항목 이름은 위 표 하나가 정본이다
    if ($tool === 'dpkg') {
        $checked = ['내용(MD5)'];
        $skipped = array_diff($all, ['내용']);
        $title   = 'dpkg --verify 는 설치 시 기록한 MD5 만 대조합니다. 나머지 항목은 "같다"가 아니라 "안 봤다" 입니다.';
    } else {
        // 제외 항목이 실제로 "다름"으로 관측됐다면 그 항목은 검사한 것이다(옛 에이전트·다른
        //   옵션으로 돌았을 수 있다). 관측된 사실이 우선이라 제외 목록에서 뺀다 — 안 그러면
        //   "수정시각은 검사하지 않았다" 아래 "수정시각 다름" 행이 서는 자기모순이 된다.
        $skipped = array_diff(VG_INTEGRITY_RPM_SKIPPED, $seen);
        $checked = array_diff($all, $skipped);
        $title   = 'rpm -Va --nomtime --nouser --nogroup — 수집 부하를 줄이려고 수정시각·소유자·그룹은 빼고 돌립니다.';
    }
    // 목록 뒤에 조사를 붙이지 않는다("capability은" 같은 말이 생긴다). 항목을 이름표로 나열한다.
    //   화면에 세우는 한 줄(text)은 **무엇으로 검사했는가**만 말한다 — 항목 전수 나열은 툴팁
    //   (title)으로 내린다. 두 줄을 다 펴 놓으면 표보다 안내가 길어져서 정작 "내용만 봤다"는
    //   핵심이 묻힌다(사용자 지적: "이게 뭘 말하는지 모르겠는데"). 안 본 항목을 "같음"으로
    //   흘리지 않는다는 원칙은 그대로다 — 자리를 툴팁으로 옮겼을 뿐 사실은 안 지운다.
    $checked = array_values($checked);
    $short = count($checked) === 1
        ? $checked[0] . '만 검사'
        : implode('·', array_slice($checked, 0, 3)) . ' 등 ' . count($checked) . '개 항목 검사';
    return [
        'tool'  => $tool,
        'text'  => $tool . ' · ' . $short,
        'title' => '검사한 항목: ' . implode('·', $checked)
                   . ($skipped ? ' · 검사하지 않은 항목: ' . implode('·', $skipped) : '')
                   . ' — ' . $title,
    ];
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
