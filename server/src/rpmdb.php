<?php
declare(strict_types=1);

/**
 * rpmdb.php — 컨테이너의 **rpm 데이터베이스 파일을 중앙이 직접 파싱**한다.
 *
 * 왜: RHEL 계열 컨테이너 안에 `rpm` 바이너리가 없는 경우가 많고(실측: calico UBI8 이미지),
 *   데비안 호스트엔 `rpm` 이 아예 없다. 그래서 그 컨테이너의 패키지가 **통째로 안 보였다**(미탐).
 *   에이전트에 rpm 을 설치하는 건 무설치 원칙 위반이고, 셸로 바이너리 DB 를 파싱할 수도 없다.
 *   Trivy·Grype 가 하는 대로 **DB 파일을 그대로 받아 중앙이 파싱**한다 — 에이전트는 사실(파일)만
 *   나르고 해석은 중앙이 한다는 원칙과 정확히 같다.
 *
 * 두 가지 형식을 지원한다(실물 대조: redhat/ubi8, redhat/ubi9):
 *   · rpm 4.16+ (RHEL9…) : /var/lib/rpm/rpmdb.sqlite  → SQLite. Packages 테이블의 blob 이 헤더다.
 *   · rpm 4.14  (RHEL8…) : /var/lib/rpm/Packages      → Berkeley DB(해시). 값이 헤더 blob.
 *
 * 헤더 blob 형식(rpm 헤더): [il(4, BE)][dl(4, BE)][인덱스 il×16][데이터 dl]
 *   인덱스 항목 = tag(4) type(4) offset(4) count(4). 우리가 쓰는 태그:
 *   NAME 1000 · VERSION 1001 · RELEASE 1002 · EPOCH 1003 · ARCH 1022 · SOURCERPM 1044
 */

const VG_RPM_TAG_NAME      = 1000;
const VG_RPM_TAG_VERSION   = 1001;
const VG_RPM_TAG_RELEASE   = 1002;
const VG_RPM_TAG_EPOCH     = 1003;
const VG_RPM_TAG_ARCH      = 1022;
const VG_RPM_TAG_SOURCERPM = 1044;

/**
 * rpm 헤더 blob 하나 → 패키지 정보. 못 읽으면 null(그 패키지만 건너뛴다).
 * @return array{name:string,version:string,release:string,epoch:?string,arch:string,sourcerpm:string}|null
 */
function vg_rpm_header_parse(string $blob): ?array {
    if (strlen($blob) < 8) { return null; }

    $il = unpack('N', substr($blob, 0, 4))[1];   // 인덱스 개수
    $dl = unpack('N', substr($blob, 4, 4))[1];   // 데이터 길이
    if ($il <= 0 || $il > 100000 || $dl < 0) { return null; }

    $idxStart  = 8;
    $dataStart = 8 + $il * 16;
    if (strlen($blob) < $dataStart + $dl) { return null; }

    $want = [
        VG_RPM_TAG_NAME      => null, VG_RPM_TAG_VERSION => null, VG_RPM_TAG_RELEASE => null,
        VG_RPM_TAG_EPOCH     => null, VG_RPM_TAG_ARCH    => null, VG_RPM_TAG_SOURCERPM => null,
    ];

    for ($i = 0; $i < $il; $i++) {
        $e = unpack('Ntag/Ntype/Noff/Ncount', substr($blob, $idxStart + $i * 16, 16));
        if (!array_key_exists($e['tag'], $want)) { continue; }

        $pos = $dataStart + $e['off'];
        if ($pos < $dataStart || $pos >= $dataStart + $dl) { continue; }

        if ($e['type'] === 4) {                         // INT32 (EPOCH)
            $want[$e['tag']] = (string) unpack('N', substr($blob, $pos, 4))[1];
        } elseif ($e['type'] === 6 || $e['type'] === 8 || $e['type'] === 9) {   // STRING / ARRAY / I18N
            $end = strpos($blob, "\0", $pos);
            if ($end === false) { continue; }
            $want[$e['tag']] = substr($blob, $pos, $end - $pos);
        }
    }

    if (($want[VG_RPM_TAG_NAME] ?? '') === '' || ($want[VG_RPM_TAG_VERSION] ?? '') === '') {
        return null;   // 이름·버전 없으면 패키지가 아니다(헤더 손상)
    }

    return [
        'name'      => (string) $want[VG_RPM_TAG_NAME],
        'version'   => (string) $want[VG_RPM_TAG_VERSION],
        'release'   => (string) ($want[VG_RPM_TAG_RELEASE] ?? ''),
        'epoch'     => $want[VG_RPM_TAG_EPOCH] !== null ? (string) $want[VG_RPM_TAG_EPOCH] : null,
        'arch'      => (string) ($want[VG_RPM_TAG_ARCH] ?? ''),
        'sourcerpm' => (string) ($want[VG_RPM_TAG_SOURCERPM] ?? ''),
    ];
}

/** SQLite rpmdb(rpm 4.16+) → 헤더 blob 목록. */
function vg_rpmdb_blobs_sqlite(string $path): array {
    $pdo = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $out = [];
    foreach ($pdo->query('SELECT blob FROM Packages') as $r) {
        $out[] = (string) $r['blob'];
    }
    return $out;
}

/**
 * Berkeley DB 해시(rpm 4.14, RHEL8) → 헤더 blob 목록.
 *
 * 구조(실물 대조: redhat/ubi8 의 /var/lib/rpm/Packages, 11MB):
 *   · 페이지 0 = 메타. magic(0x00061561) @12, pagesize @20, last_pgno @32  (리틀엔디언)
 *   · 각 페이지 헤더 26바이트: next_pgno @16, entries @20, hf_offset @22, type @25
 *   · 해시 페이지(type 13): 26바이트 뒤에 entries 개의 uint16 오프셋. 키/값이 번갈아 온다
 *     → **홀수 인덱스가 값**(= 헤더 blob).
 *   · rpm 헤더는 페이지보다 커서 항상 오버플로 페이지(type 7)에 저장된다.
 *     값 엔트리(type 3 = HOFFPAGE): pgno @4, 전체 길이 @8 → 그 페이지부터 next 를 따라가며 이어붙인다.
 */
function vg_rpmdb_blobs_bdb(string $path): array {
    $fh = fopen($path, 'rb');
    if ($fh === false) { throw new RuntimeException("rpmdb 열기 실패: $path"); }

    try {
        $meta = fread($fh, 512);
        if ($meta === false || strlen($meta) < 40) { throw new RuntimeException('rpmdb 메타 페이지가 너무 짧다'); }

        $magic = unpack('V', substr($meta, 12, 4))[1];
        if ($magic !== 0x00061561) {
            throw new RuntimeException(sprintf('rpmdb 가 BDB 해시가 아니다(magic=0x%08x)', $magic));
        }
        $pageSize = unpack('V', substr($meta, 20, 4))[1];
        $lastPgno = unpack('V', substr($meta, 32, 4))[1];
        if ($pageSize < 512 || $pageSize > 65536) {
            throw new RuntimeException("rpmdb 페이지 크기가 이상하다: $pageSize");
        }

        $readPage = static function (int $no) use ($fh, $pageSize): string {
            fseek($fh, $no * $pageSize);
            $p = fread($fh, $pageSize);
            return $p === false ? '' : $p;
        };

        $out = [];
        for ($pgno = 1; $pgno <= $lastPgno; $pgno++) {
            $page = $readPage($pgno);
            if (strlen($page) < 26) { continue; }

            $type = ord($page[25]);
            if ($type !== 13) { continue; }                       // 해시 페이지만
            $entries = unpack('v', substr($page, 20, 2))[1];
            if ($entries <= 0 || 26 + $entries * 2 > strlen($page)) { continue; }

            for ($i = 1; $i < $entries; $i += 2) {                // 홀수 = 값
                $off = unpack('v', substr($page, 26 + $i * 2, 2))[1];
                if ($off + 12 > strlen($page)) { continue; }
                if (ord($page[$off]) !== 3) { continue; }         // HOFFPAGE 만(헤더는 항상 오버플로)

                $ovPgno = unpack('V', substr($page, $off + 4, 4))[1];
                $length = unpack('V', substr($page, $off + 8, 4))[1];
                if ($ovPgno === 0 || $length <= 0 || $length > 50_000_000) { continue; }

                // 오버플로 체인을 따라가며 length 바이트를 모은다.
                $blob = '';
                $cur  = $ovPgno;
                while ($cur !== 0 && strlen($blob) < $length) {
                    $ov = $readPage($cur);
                    if (strlen($ov) < 26 || ord($ov[25]) !== 7) { break; }   // 오버플로 페이지가 아니면 중단
                    $next  = unpack('V', substr($ov, 16, 4))[1];
                    $chunk = min($length - strlen($blob), $pageSize - 26);
                    $blob .= substr($ov, 26, $chunk);
                    $cur   = $next;
                }
                if (strlen($blob) === $length) { $out[] = $blob; }
            }
        }
        return $out;
    } finally {
        fclose($fh);
    }
}

/**
 * 에이전트가 올린 rpmdb 섹션(`cid|gz|base64`) → 컨테이너 패키지 행.
 *   반환 행 모양은 에이전트가 보내는 컨테이너 패키지 라인과 **동일**하다:
 *   [cid, 'rpm', 이름, 에포크:버전-릴리스, 소스rpm] → ingest 의 기존 저장 경로를 그대로 탄다.
 *
 *   한 컨테이너가 깨져도 나머지는 살린다(그 컨테이너만 건너뛴다) — 수집 하나 때문에
 *   스캔 전체를 잃는 게 더 나쁘다.
 */
function vg_ingest_rpmdb_rows(string $text): array {
    if (trim($text) === '') { return []; }

    $rows = [];
    foreach (preg_split('/\r?\n/', $text) as $line) {
        if ($line === '') { continue; }
        $f = explode('|', $line, 3);
        if (count($f) < 3) { continue; }
        [$cid, $enc, $b64] = $f;
        if ($cid === '' || $b64 === '') { continue; }

        $bin = base64_decode($b64, true);
        if ($bin === false) { error_log("[rpmdb] base64 디코드 실패: $cid"); continue; }
        if ($enc === 'gz') {
            $bin = @gzdecode($bin);
            if ($bin === false) { error_log("[rpmdb] gzip 해제 실패: $cid"); continue; }
        }

        $tmp = tempnam(sys_get_temp_dir(), 'vgrpmdb');
        if ($tmp === false) { continue; }
        try {
            file_put_contents($tmp, $bin);
            foreach (vg_rpmdb_packages($tmp) as $p) {
                $rows[] = [$cid, 'rpm', $p['name'], $p['version'], $p['source_pkg']];
            }
        } catch (Throwable $e) {
            error_log("[rpmdb] 파싱 실패($cid): " . $e->getMessage());
        } finally {
            @unlink($tmp);
        }
    }
    return $rows;
}

/**
 * rpmdb 파일 → 패키지 목록(에이전트의 rpm -qa 와 같은 모양).
 *   반환 각 행: ['name','version'(=epoch:version-release),'source_pkg','arch']
 *   형식은 파일 시그니처로 자동 판별한다(SQLite 헤더 or BDB magic).
 */
function vg_rpmdb_packages(string $path): array {
    $head = (string) file_get_contents($path, false, null, 0, 16);
    $isSqlite = strncmp($head, "SQLite format 3\0", 16) === 0;

    $blobs = $isSqlite ? vg_rpmdb_blobs_sqlite($path) : vg_rpmdb_blobs_bdb($path);

    $out = [];
    foreach ($blobs as $b) {
        $h = vg_rpm_header_parse($b);
        if ($h === null) { continue; }
        // 에이전트의 rpm -qa --qf "%{EPOCH}:%{VERSION}-%{RELEASE}" 와 같은 표기(에포크 없으면 (none)).
        $evr = ($h['epoch'] ?? '(none)') . ':' . $h['version'] . '-' . $h['release'];
        $out[] = [
            'name'       => $h['name'],
            'version'    => $evr,
            'source_pkg' => $h['sourcerpm'],
            'arch'       => $h['arch'],
        ];
    }
    return $out;
}
