<?php
declare(strict_types=1);

/**
 * 무결성 플래그 파싱 단위 테스트 — server/src/format/labels.php.
 *   rpm -Va / dpkg --verify 의 9자리 플래그는 **자리(position)로 읽어야** 뜻이 맞는다.
 *   특히 '?' 는 "같음"이 아니라 **"검사하지 않음"** 이라, 잘못 읽으면 안 본 항목이
 *   화면에서 "정상"으로 둔갑한다(결과의 범위를 왜곡한다). DB 없이 도는 순수 함수라
 *   스모크 앞단에서 돌린다.
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/integrity_flags_test.php
 */

require_once __DIR__ . '/../server/src/format/labels.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── 차이 항목 풀기 ─────────────────────────────────────────────────────────
//   dpkg --verify 는 md5 자리 하나만 검사한다 → 나머지는 전부 '?'.
$eq('dpkg MD5만',        vg_integrity_flag_label('??5??????'), '내용');
//   rpm 다중: 여러 항목이 켜지면 **전부** 나열한다(하나만 보여주고 자르지 않는다).
$eq('rpm 다중',          vg_integrity_flag_label('S.5....T.'), '크기 · 내용 · 수정시각');
$eq('시각만',            vg_integrity_flag_label('.......T.'), '수정시각');
$eq('권한·소유자·그룹',  vg_integrity_flag_label('.M...UG..'), '권한 · 소유자 · 그룹');
$eq('링크·장치·capability', vg_integrity_flag_label('...DL...P'), '장치번호 · 링크 대상 · capability');
//   전부 같음 / 전부 미검사 — rpm·dpkg 는 걸린 파일만 출력하므로 이 줄이 존재한다는 것 자체가
//   관측이다. "차이 없음"이라고 단정하지 않고 항목만 비운다.
$eq('전부 같음',         vg_integrity_flag_label('.........'), '차이 있음');
$eq('전부 미검사',       vg_integrity_flag_label('?????????'), '차이 있음');
$eq('빈 문자열',         vg_integrity_flag_label(''),          '차이 있음');
$eq('예상 밖 문자',      vg_integrity_flag_label('XYZ!!!!!!'), '차이 있음');
$eq('파일 없음',         vg_integrity_flag_label('missing'),   '파일 없음');
$eq('파일 없음(대문자)', vg_integrity_flag_label('MISSING'),   '파일 없음');
//   자리로 읽는다 — 같은 'S' 라도 크기 자리(1번)가 아니면 크기 차이가 아니다.
$eq('자리 밖 S 는 무시', vg_integrity_flag_label('.S.......'), '차이 있음');
$eq('항목 배열',         vg_integrity_diff_items('S.5....T.'), ['크기', '내용', '수정시각']);
$eq('항목 배열(없음)',   vg_integrity_diff_items('.........'), []);

// ── 검사 범위 판정 ─────────────────────────────────────────────────────────
//   내용 자리를 뺀 나머지가 전부 '?' 면 dpkg(내용만 검사)다.
$dpkg = vg_integrity_verify_scope(['??5??????', '??5??????']);
$eq('dpkg 판정', $dpkg['tool'], 'dpkg');
$eq('dpkg 는 내용(MD5)만 검사', strpos($dpkg['text'], '검사한 항목: 내용(MD5)') !== false, true);
//   ★ 핵심: 안 본 항목을 "같음"으로 흘리지 않는다 — 무엇을 안 봤는지 이름으로 적는다.
$eq('dpkg 미검사 항목 나열', strpos($dpkg['text'], '검사하지 않은 항목: 크기·권한') !== false, true);
$eq('dpkg 미검사에 소유자·수정시각 포함',
    strpos($dpkg['text'], '소유자') !== false && strpos($dpkg['text'], '수정시각') !== false, true);

//   다른 자리에 '?' 아닌 글자('.' 포함)가 있으면 rpm 이다 — rpm 은 검사한 자리를 '.' 로 찍는다.
$eq('rpm 판정',        vg_integrity_verify_scope(['S.5....T.'])['tool'], 'rpm');
$eq('rpm 판정(내용만 다름)', vg_integrity_verify_scope(['..5......'])['tool'], 'rpm');
//   한 행이라도 rpm 근거가 있으면 rpm 이다(섞여 들어와도 낙관하지 않는다).
$eq('혼재 시 rpm 우선', vg_integrity_verify_scope(['??5??????', 'S.5....T.'])['tool'], 'rpm');
//   rpm 은 --nomtime --nouser --nogroup 로 돌리므로 그 셋은 "검사하지 않음"으로 적는다.
$rpm = vg_integrity_verify_scope(['S.5......']);
$eq('rpm 미검사 항목', strpos($rpm['text'], '검사하지 않은 항목: 수정시각·소유자·그룹') !== false, true);
$eq('rpm 검사 항목',   strpos($rpm['text'], '검사한 항목: 크기·권한·내용') !== false, true);
//   단, 제외 항목이 실제로 "다름"으로 관측됐다면 그건 검사한 것이다 — 제외 목록에서 뺀다.
//   (안 그러면 "수정시각은 검사하지 않았다" 밑에 "수정시각 다름" 행이 서는 자기모순이 된다.)
$rpmT = vg_integrity_verify_scope(['S.5....T.']);
$eq('관측된 항목은 미검사에서 뺀다', strpos($rpmT['text'], '검사하지 않은 항목: 소유자·그룹') !== false, true);
$eq('관측된 항목은 검사한 쪽에 선다', strpos($rpmT['text'], '수정시각·capability') !== false, true);

//   판정할 근거가 없으면 아무 말도 하지 않는다("모르는 것은 모른다고 적는다").
$eq('행 없음',   vg_integrity_verify_scope([])['tool'], '');
$eq('missing 만', vg_integrity_verify_scope(['missing'])['tool'], '');
$eq('빈 값만',   vg_integrity_verify_scope(['', '  '])['tool'], '');
$eq('판정 불가 시 문구 없음', vg_integrity_verify_scope([])['text'], '');

if ($fail > 0) { printf("무결성 플래그 테스트 실패 %d건\n", $fail); exit(1); }
echo "무결성 플래그 테스트 통과\n";
