<?php
declare(strict_types=1);

/**
 * ingest_parse.php — ingest.php 가 받는 에이전트 원시 페이로드를 정규화된 배열로
 *   바꾸는 **순수 함수만** 모은다. DB·인증·감사로그는 여기 없다(ingest.php 에 남는다).
 *   모든 함수는 같은 입력엔 같은 출력을 내고 부작용이 없다 — tests/ingest_parse_test.php 참고.
 */

require_once __DIR__ . '/vercmp.php';       // vg_ver_cmp — vg_ingest_parse_kernel 에서 커널 버전 비교용
require_once __DIR__ . '/license_risk.php'; // vg_license_normalize_token — pkg_license 정규화

// ── collected_at (ISO-8601) → MySQL DATETIME ──────────────────────────────
function vg_ingest_parse_collected_at($raw): ?string
{
    if (empty($raw)) { return null; }
    $ts = strtotime((string) $raw);
    if ($ts === false) { return null; }
    return date('Y-m-d H:i:s', $ts);
}

// ── 패키지 목록 (매니저별 TSV) ─────────────────────────────────────────────
//   rpm : name \t epoch:version-release \t arch \t sourcerpm \t vendor
//   dpkg: name \t version \t arch \t source_pkg \t source_version \t status ('ii' 아니면 버림)
function vg_ingest_parse_packages(string $manager, string $list): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $list) as $line) {
        if ($line === '') { continue; }
        $f    = explode("\t", $line);
        $name = trim($f[0] ?? '');
        if ($name === '') { continue; }
        if ($manager === 'rpm') {
            $rows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', '', $f[4] ?? ''];
        } else {
            $st = trim($f[5] ?? '');
            if ($st !== '' && substr($st, 1, 1) !== 'i') { continue; }
            $rows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', $f[4] ?? '', ''];
        }
    }
    return $rows;
}

// ── 패키지 출처(Origin) 라벨 — "name\tOrigin" 줄 목록 ──────────────────────
function vg_ingest_parse_origins(string $originsText): array
{
    $map = [];
    foreach (preg_split('/\r?\n/', $originsText) as $line) {
        $f = explode("\t", trim($line));
        if (count($f) < 2 || $f[0] === '' || $f[1] === '') { continue; }
        $map[$f[0]] = mb_strimwidth($f[1], 0, 128, '');
    }
    return $map;
}

// ── 언어 패키지 (pip/npm/gem/composer) ─────────────────────────────────────
function vg_ingest_parse_langpkgs(array $lang): array
{
    $rows = [];
    // $weak = 선언 파일(go.mod/requirements.txt/pom.xml)에서 읽은 "보충" 값. 설치본이 아니라
    // 선언이라 실제 배포 버전과 다를 수 있고, 스캔 루트에 파일 한 줄만 심어도 만들어낼 수 있다 —
    // 그래서 이미 다른 소스가 잡은 값이 있으면 절대 덮어쓰지 않는다.
    // 그 외 소스(설치본 조회)는 예전 그대로 나중 값이 이긴다.
    $add = static function (string $mgr, string $name, string $ver, bool $weak = false) use (&$rows): void {
        $name = trim($name); $ver = trim($ver);
        if ($name === '' || $ver === '') { return; }
        $key = "$mgr|$name";
        if ($weak && isset($rows[$key])) { return; }
        $rows[$key] = [$mgr, mb_strimwidth($name, 0, 255, ''), mb_strimwidth($ver, 0, 255, '')];
    };
    foreach (preg_split('/\r?\n/', (string) ($lang['pip'] ?? '')) as $line) {
        if (preg_match('/^([A-Za-z0-9._-]+)==(\S+)$/', trim($line), $m)) { $add('pip', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['npm_global'] ?? '')) as $line) {
        $t = trim(preg_replace('/^[\s|`+\x{2500}-\x{257F}-]+/u', '', $line) ?? '');
        if (preg_match('/^(@?[^@\s]+(?:\/[^@\s]+)?)@(\S+)$/', $t, $m)) { $add('npm', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['gem'] ?? '')) as $line) {
        if (preg_match('/^(\S+)\s+\((?:default:\s*)?([^,)]+)/', trim($line), $m)) { $add('gem', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['composer'] ?? '')) as $line) {
        if (preg_match('#^(\S+/\S+)\s+(\S+)#', trim($line), $m)) { $add('composer', $m[1], $m[2]); }
    }
    // inventory: "manager|name|version" (+ 선언 파일 유래면 네 번째 필드 'weak').
    // 필드가 4개인데 마지막이 'weak' 가 아니면 name/version 에 '|' 가 섞여 자리가 밀린 오염 줄이다 → 버린다.
    $invMgrs = ['pip','npm','gem','composer','maven','nuget','cargo','go'];
    foreach (preg_split('/\r?\n/', (string) ($lang['inventory'] ?? '')) as $line) {
        $f = explode('|', trim($line), 4);
        $n = count($f);
        if ($n < 3 || !in_array($f[0], $invMgrs, true)) { continue; }
        if ($n === 4 && $f[3] !== 'weak') { continue; }
        if (!preg_match('/^\S+$/', $f[1]) || !preg_match('/^\S+$/', $f[2])) { continue; }
        $add($f[0], $f[1], $f[2], $n === 4);
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['maven'] ?? '')) as $line) {
        if (preg_match('/^([^:\s]+:[^:\s]+)\s+(\S+)$/', trim($line), $m)) { $add('maven', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['nuget'] ?? '')) as $line) {
        if (preg_match('/^(\S+)\s+(\S+)$/', trim($line), $m)) { $add('nuget', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['cargo'] ?? '')) as $line) {
        if (preg_match('/^(\S+)\s+v([^:\s]+):$/', trim($line), $m)) { $add('cargo', $m[1], $m[2]); }
    }
    return array_values($rows);
}

// ── 언어 패키지 라이선스 — 별도 4필드 스트림("mgr|name|version|spdx") ─────────
//   기존 $lang['inventory'](3필드)에 얹지 않는다. 필드수를 다르게 둬야 자리 밀림(파이프
//   인젝션으로 name/version 에 '|' 가 섞인 오염 줄)이 조용히 4번째 칸을 라이선스로
//   오인하는 사고를 막을 수 있다.
function vg_ingest_parse_pkg_license(string $text): array
{
    $rows = [];
    $mgrs = ['pip', 'npm', 'gem', 'composer', 'maven', 'nuget', 'cargo', 'go'];
    foreach (preg_split('/\r?\n/', $text) as $line) {
        $line = trim($line);
        if ($line === '') { continue; }
        // limit 을 주지 않는다 — limit(4) 이면 name/version 에 '|' 가 섞인 오염 줄이 필드 밀림으로
        //   통과한다(PR#466 과 같은 클래스의 버그). 정확히 4필드가 아니면 엄격히 거부한다.
        $f = explode('|', $line);
        if (count($f) !== 4 || !in_array($f[0], $mgrs, true)) { continue; }
        [$mgr, $name, $ver, $lic] = array_map('trim', $f);
        if ($name === '' || $ver === '' || $lic === '') { continue; }
        // 별칭 정규화(자유서술→SPDX)를 화이트리스트 검증보다 먼저 적용한다 — 순서를 바꾸면
        //   대부분의 자유서술 표기("BSD License" 등)가 정규화 전에 걸려 통째로 버려진다.
        $lic = vg_license_normalize_token($lic);
        // SPDX 표현식 문자셋만 허용 — 저작권 문구·파이프 잔존 등 오염값을 걸러낸다.
        if (!preg_match('/^[A-Za-z0-9.\-+ ()]+$/', $lic)) { continue; }
        $rows["$mgr|$name|$ver"] = [
            $mgr, mb_strimwidth($name, 0, 255, ''), mb_strimwidth($ver, 0, 255, ''), mb_strimwidth($lic, 0, 255, ''),
        ];
    }
    return array_values($rows);
}

// ── langRows(mgr,name,version) 에 라이선스 스트림을 매칭해 4번째 필드로 붙인다 ──
//   매칭 안 되면 4번째 필드는 ''(라이선스 미상). langRows 의 앞 3필드 구조는 그대로라
//   기존 dedup·diff 로직(vg_ingest_build_pkg_map 등)은 건드리지 않는다.
function vg_ingest_attach_pkg_license(array $langRows, array $licenseRows): array
{
    $byKey = [];
    foreach ($licenseRows as $r) { $byKey["{$r[0]}|{$r[1]}|{$r[2]}"] = $r[3]; }
    $out = [];
    foreach ($langRows as $r) {
        $out[] = [$r[0], $r[1], $r[2], $byKey["{$r[0]}|{$r[1]}|{$r[2]}"] ?? ''];
    }
    return $out;
}

// ── 노출 상관 (pipe 구분, 첫 줄 헤더) ──────────────────────────────────────
//   pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
function vg_ingest_parse_exposures(string $correlation): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $correlation) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|proc|proto', 14) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 8) { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 실행 프로세스 (pipe, 첫 줄 헤더) ───────────────────────────────────────
//   pid|comm|user|exe_pkg|loaded_pkgs
function vg_ingest_parse_processes(string $processesText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $processesText) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|user', 13) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 5) { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 재시작 필요(stale libs) (pipe, 첫 줄 헤더) ────────────────────────────
//   pid|comm|pkg|lib
function vg_ingest_parse_stale(string $staleText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $staleText) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|pkg', 12) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 4 || trim($f[2]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── changelog CVE (패키지명 => changelog 텍스트) ──────────────────────────
function vg_ingest_parse_changelog(array $clog): array
{
    $rows = [];
    foreach ($clog as $pkgName => $text) {
        $pkgName = trim((string) $pkgName);
        if ($pkgName === '' || !is_string($text) || $text === '') { continue; }
        foreach (preg_split('/\r?\n/', $text) as $line) {
            if (!preg_match_all('/CVE-\d{4}-\d{4,}/i', $line, $m)) { continue; }
            foreach (array_unique($m[0]) as $cve) {
                $cve = strtoupper($cve);
                $k = $pkgName . '|' . $cve;
                if (isset($rows[$k])) { continue; }   // (패키지,CVE)당 첫 근거 줄만
                $rows[$k] = [$pkgName, $cve, mb_strimwidth(trim($line), 0, 255, '')];
            }
        }
    }
    return array_values($rows);
}

// ── errata CVE — `dnf updateinfo list installed --with-cve` 형식 ─────────
//   "CVE-2022-3715  Moderate/Sec.  bash-5.1.8-6.el9_1.x86_64"
function vg_ingest_parse_errata(string $errataText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $errataText) as $line) {
        if (!preg_match('/^\s*(CVE-\d{4}-\d{4,})\s+\S+\s+(\S+)\s*$/i', $line, $m)) { continue; }
        $cve   = strtoupper($m[1]);
        $nevra = $m[2];
        $base  = preg_replace('/\.(x86_64|i686|aarch64|noarch|ppc64le|s390x)$/', '', $nevra);
        $parts = explode('-', (string) $base);
        if (count($parts) < 3) { continue; }
        array_pop($parts); array_pop($parts);   // name-version-release → name
        $pkgName = implode('-', $parts);
        if ($pkgName === '') { continue; }
        $k = $pkgName . '|' . $cve;
        if (isset($rows[$k])) { continue; }
        $rows[$k] = [$pkgName, $cve, mb_strimwidth(trim($nevra), 0, 255, '')];
    }
    return array_values($rows);
}

// ── debsecan — "CVE-2026-13595 bsdutils" (debsecan --format simple) ──────
function vg_ingest_parse_debsecan(string $debsecanText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $debsecanText) as $line) {
        if (!preg_match('/^\s*(CVE-\d{4}-\d{4,})\s+(\S+)\s*$/i', $line, $m)) { continue; }
        $k = strtoupper($m[1]) . '|' . $m[2];
        $rows[$k] = [strtoupper($m[1]), mb_strimwidth($m[2], 0, 255, '')];
    }
    return array_values($rows);
}

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

/** Parse externally supplied CycloneDX/SPDX SBOM lines: cid|format|base64(json). */
function vg_ingest_parse_sbom(string $text): array
{
    $packages=[]; $meta=[];
    foreach (preg_split('/\r?\n/', $text) as $line) {
        $f=explode('|',$line,3); if(count($f)!==3||$f[0]==='')continue;
        $raw=base64_decode($f[2],true); $doc=$raw!==false?json_decode($raw,true):null; if(!is_array($doc))continue;
        $cid=mb_strimwidth($f[0],0,255,''); $format=strtolower($f[1]); $meta[$cid]=[$format,hash('sha256',$raw)];
        $items=$format==='spdx'?($doc['packages']??[]):($doc['components']??[]);
        foreach($items as $item){
            $name=trim((string)($item['name']??''));$ver=trim((string)($item['version']??$item['versionInfo']??''));$purl=(string)($item['purl']??'');
            if($purl===''&&isset($item['externalRefs']))foreach($item['externalRefs'] as $ref){if(($ref['referenceType']??'')==='purl'){$purl=(string)($ref['referenceLocator']??'');break;}}
            $mgr='';if(preg_match('#^pkg:([^/]+)/([^@?]+)#',$purl,$m)){$type=strtolower($m[1]);$decoded=urldecode($m[2]);if($type==='maven'&&str_contains($decoded,'/')){$pos=strrpos($decoded,'/');$decoded=substr($decoded,0,$pos).':'.substr($decoded,$pos+1);}$name=$decoded?:$name;$mgr=['pypi'=>'pip','npm'=>'npm','gem'=>'gem','composer'=>'composer','maven'=>'maven','nuget'=>'nuget','cargo'=>'cargo','golang'=>'go','deb'=>'dpkg','rpm'=>'rpm','apk'=>'apk'][$type]??'';}
            // 라이선스: CycloneDX 는 licenses[].license.{id,name} 또는 licenses[].expression(복수는
            //   스펙상 동시적용=AND 의미), SPDX 는 licenseConcluded(없으면 declared 로 폴백 — syft/trivy
            //   는 보통 concluded=NOASSERTION 이고 declared 에 실값이 있다).
            $lic='';
            if ($format==='spdx') {
                $lc=(string)($item['licenseConcluded']??'');
                if($lc===''||$lc==='NOASSERTION'||$lc==='NONE'){$lc=(string)($item['licenseDeclared']??'');}
                if($lc!==''&&$lc!=='NOASSERTION'&&$lc!=='NONE'){$lic=$lc;}
            } elseif (isset($item['licenses']) && is_array($item['licenses'])) {
                $parts=[];
                foreach ($item['licenses'] as $l) {
                    if (isset($l['license']['id'])) { $parts[]=(string)$l['license']['id']; }
                    elseif (isset($l['license']['name'])) { $parts[]=(string)$l['license']['name']; }
                    elseif (isset($l['expression'])) { $parts[]=(string)$l['expression']; }
                }
                $lic=implode(' AND ', array_unique(array_filter($parts, static fn($v)=>$v!=='')));
            }
            // dedup 키는 이름까지만(버전 제외) — 버전까지 넣으면 같은 이름의 다중 버전(중첩 jar,
            //   멀티스테이지 이미지)이 전부 별도 행으로 저장돼 tb_container.pkg_count·finding 건수가
            //   부풀려진다. 대신 **병합**한다: 이미 있는 항목의 라이선스가 비어 있을 때만 채운다.
            if($mgr!==''&&$name!==''&&$ver!==''){
                $pkey=$cid.'|'.$mgr.'|'.$name;
                if(!isset($packages[$pkey])){
                    $packages[$pkey]=[$cid,$mgr,mb_strimwidth($name,0,255,''),mb_strimwidth($ver,0,255,''),'',mb_strimwidth($lic,0,255,'')];
                } elseif ($packages[$pkey][5]===''&&$lic!==''){
                    $packages[$pkey][5]=mb_strimwidth($lic,0,255,'');
                }
            }
        }
    }
    return ['packages'=>array_values($packages),'meta'=>$meta];
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

// ── 커널: 실행 중인 커널 vs 설치된 최신 커널 → 재부팅 필요 판정 ───────────
//   반환: ['running' => string, 'latest' => string, 'reboot_needed' => 0|1]
function vg_ingest_parse_kernel(string $manager, string $runningKernel, string $installedKernelsText): array
{
    $kernelLatest = '';
    $kernelReboot = 0;
    $kernelCands  = [];
    foreach (preg_split('/\r?\n/', $installedKernelsText) as $line) {
        $line = trim($line);
        if ($line === '' || stripos($line, 'not installed') !== false) { continue; }
        if ($manager === 'rpm') {
            if (preg_match('/^kernel(?:-core)?-(\d.+)$/', $line, $m)) { $kernelCands[] = $m[1]; }
        } else {
            $f = preg_split('/\s+/', $line);
            if (isset($f[0]) && preg_match('/^linux-image-(\d.+)$/', $f[0], $m)) { $kernelCands[] = $m[1]; }
        }
    }
    if ($kernelCands) {
        // 문자열 비교로는 틀린다(5.14.0-687 vs 5.14.0-70) — 배포판 규칙으로 최신을 고른다.
        $mgrForKernel = $manager === 'rpm' ? 'rpm' : 'dpkg';

        // **같은 flavor 끼리만 비교한다.** 한 호스트에 기종·아키가 다른 커널이 여러 개 깔린다
        //   (라즈베리파이: rpi-2712 = Pi5, rpi-v8 = 그 외). 전부를 한 줄로 세우면 **안 쓰는 기종의
        //   커널이 "더 최신"으로 뽑혀** 실행 중 커널이 낡은 것처럼 보이고, 재부팅 필요가 잘못 붙는다
        //   (실측: 실행 6.18.34+rpt-rpi-2712 인데 설치된 6.18.34+rpt-rpi-v8 을 최신으로 골랐다).
        //   같은 flavor 후보가 하나도 없으면(그 커널이 제거된 경우) 옛 방식대로 전체를 본다 — 여기서
        //   비교를 포기하면 진짜 재부팅 필요를 놓친다(미탐).
        $runFlavor  = vg_kernel_flavor($runningKernel, $mgrForKernel);
        $sameFlavor = $runFlavor === '' ? [] : array_values(array_filter(
            $kernelCands,
            static fn(string $k): bool => vg_kernel_flavor($k, $mgrForKernel) === $runFlavor
        ));
        $pool = $sameFlavor ?: $kernelCands;

        $kernelLatest = $pool[0];
        foreach ($pool as $k) {
            if (vg_ver_cmp($k, $kernelLatest, $mgrForKernel) > 0) { $kernelLatest = $k; }
        }
        if ($runningKernel !== '' && vg_ver_cmp($runningKernel, $kernelLatest, $mgrForKernel) < 0) {
            $kernelReboot = 1;
        }
    }
    return ['running' => $runningKernel, 'latest' => $kernelLatest, 'reboot_needed' => $kernelReboot];
}

/**
 * 커널 릴리스에서 flavor(기종·아키)를 뽑는다. 버전 비교는 **같은 flavor 안에서만** 뜻이 있다.
 *   dpkg : 마지막 '-' 뒤   6.1.0-18-amd64 → amd64 · 6.18.34+rpt-rpi-2712 → 2712 · …-rpi-v8 → v8
 *   rpm  : 마지막 '.' 뒤   5.14.0-503.11.1.el9_5.x86_64 → x86_64
 *          (rpm 은 마이너 릴리스가 el9_4/el9_5 로 문자열에 박히므로 아키만 flavor 로 본다.)
 */
function vg_kernel_flavor(string $release, string $manager): string
{
    $r = trim($release);
    if ($r === '') { return ''; }
    $sep = $manager === 'rpm' ? '.' : '-';
    $pos = strrpos($r, $sep);
    return $pos === false ? '' : substr($r, $pos + 1);
}

// ── 내용 해시 — "바뀔 때만 스냅샷" 판정에 쓰는 정규화 해시 ────────────────
//   PID 는 절대 넣지 않는다 — 재부팅·프로세스 재시작마다 바뀌어서 매번 "변경됨"이 된다.
function vg_ingest_content_hash(
    array $pkgRows,
    string $manager,
    array $langRows,
    array $expRows,
    array $staleRows,
    array $ctrPkgRows,
    array $ctrRows,
    array $ctrExpRows,
    string $runningKernel,
    string $kernelLatest,
    int $kernelReboot,
    array $vm,
    array $sys,
    array $originMap = []
): string {
    $hashParts = [];
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
    foreach ($staleRows as $r) { $hashParts[] = "s|{$r[2]}|{$r[3]}"; }
    foreach ($ctrPkgRows as $r) { $hashParts[] = "c|{$r[0]}|{$r[1]}|{$r[2]}|{$r[3]}|" . ($r[5] ?? ''); }
    foreach ($ctrRows as $r)    { $hashParts[] = "C|{$r[0]}|{$r[2]}|{$r[3]}|{$r[4]}"; }   // cid|image|os
    foreach ($ctrExpRows as $f) { $hashParts[] = 'CE|' . $f[0] . '|' . implode('|', array_slice($f, 2, 7)); }   // pid 제외
    $hashParts[] = 'k|' . $runningKernel . '|' . $kernelLatest . '|' . $kernelReboot;
    $hashParts[] = 'o|' . ($vm['distro_id'] ?? '') . '|' . ($vm['distro_version'] ?? '')
                 . '|' . ($sys['kernel_release'] ?? ($sys['kernel'] ?? ''));
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
