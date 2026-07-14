<?php
declare(strict_types=1);

/**
 * rpmdb 단위 테스트 — rpm 헤더 blob 파서(server/src/rpmdb.php).
 *
 * 왜 중요한가: 이 파서가 틀리면 컨테이너 패키지가 통째로 사라진다(미탐). 데비안 호스트 위의
 *   RHEL 컨테이너는 rpm 바이너리가 없어 **이 경로 말고는 볼 방법이 아예 없다**.
 *
 * 픽스처는 실제 redhat/ubi9 의 rpmdb.sqlite 에서 뽑은 헤더 blob 하나(dbus, 4KB)다.
 *   DB 파일 전체(11~15MB)는 저장소에 넣지 않는다 — 대신 전체 파싱은 실물 대조로 검증했다:
 *   ubi9(sqlite) 188/188, ubi8(BDB) 185/185 로 `rpm -qa` 와 **정확히 일치**(누락·초과 0).
 *
 * 실행: docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/rpmdb_test.php
 */

require_once __DIR__ . '/../server/src/rpmdb.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

$blob = (string) file_get_contents(__DIR__ . '/fixtures/rpmdb/header.blob');
$h    = vg_rpm_header_parse($blob);

$eq('헤더가 파싱된다', is_array($h), true);
$eq('이름',           $h['name'],      'dbus');
$eq('버전',           $h['version'],   '1.12.20');
$eq('릴리스',         $h['release'],   '8.el9');
$eq('아키',           $h['arch'],      'x86_64');
$eq('소스 rpm',       $h['sourcerpm'], 'dbus-1.12.20-8.el9.src.rpm');

// 깨진 입력은 예외가 아니라 null — 헤더 하나가 깨졌다고 스캔 전체를 잃으면 안 된다.
$eq('빈 blob → null',      vg_rpm_header_parse(''), null);
$eq('짧은 blob → null',    vg_rpm_header_parse("\x00\x01"), null);
$eq('쓰레기 blob → null',  vg_rpm_header_parse(str_repeat('A', 64)), null);

// 에이전트 섹션 파싱(cid|gz|base64) — 잘못된 줄은 건너뛰고 나머지를 살린다.
$eq('빈 섹션 → 빈 배열',        vg_ingest_rpmdb_rows(''), []);
$eq('형식 틀린 줄 → 건너뜀',    vg_ingest_rpmdb_rows("깨진줄\n"), []);
$eq('base64 깨짐 → 건너뜀',     vg_ingest_rpmdb_rows("abc|gz|@@@notbase64@@@\n"), []);

if ($fail === 0) {
    echo "rpmdb: 모든 검사 통과\n";
    exit(0);
}
printf("rpmdb: %d 개 실패\n", $fail);
exit(1);
