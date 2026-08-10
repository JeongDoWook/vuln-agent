<?php
declare(strict_types=1);

/**
 * purl.php — 설치 패키지 한 건 → Package URL(purl) 문자열.
 *
 *   왜 별도 파일인가: SBOM 산출(sbom.php)뿐 아니라 나중에 화면에서도 같은 표기를 쓴다.
 *   생태계 판정(vg_pkg_ecosystem/vg_osv_ecosystem, distro.php)과는 **다른 어휘**다 —
 *   저쪽은 OSV 조회용 생태계명('PyPI'·'RubyGems'), 여기는 purl 스펙의 type 문자열('pypi'·'gem').
 *   같은 개념이라 헷갈리기 쉬워서 매핑을 여기 하나로 모은다.
 *
 *   모르는 manager 는 null 을 돌려준다 — 억지로 만든 틀린 purl 은 없는 purl 보다 나쁘다.
 */

/**
 * manager → purl type 과 이름 분해 규칙.
 *   ns    : 네임스페이스 출처. 'os'=tb_scan.os_id, 문자열 리터럴, 또는 null(없음)
 *   split : name 에서 네임스페이스를 떼는 구분자. '/'(마지막 슬래시 기준) | ':' | null
 *   arch  : arch 를 qualifier 로 붙일지
 */
const VG_PURL_TYPES = [
    'rpm'      => ['type' => 'rpm',      'ns' => 'os',     'split' => null, 'arch' => true],
    'dpkg'     => ['type' => 'deb',      'ns' => 'os',     'split' => null, 'arch' => true],
    'apk'      => ['type' => 'apk',      'ns' => 'alpine', 'split' => null, 'arch' => true],
    'pip'      => ['type' => 'pypi',     'ns' => null,     'split' => null, 'arch' => false],
    // npm 스코프(@babel/core)는 네임스페이스 '@babel' + 이름 'core' 로 갈린다.
    'npm'      => ['type' => 'npm',      'ns' => null,     'split' => '/',  'arch' => false],
    'gem'      => ['type' => 'gem',      'ns' => null,     'split' => null, 'arch' => false],
    // composer 는 vendor/package, go 는 모듈 경로(github.com/foo/bar) — 둘 다 마지막 슬래시로 가른다.
    'composer' => ['type' => 'composer', 'ns' => null,     'split' => '/',  'arch' => false],
    'go'       => ['type' => 'golang',   'ns' => null,     'split' => '/',  'arch' => false],
    // maven 은 name 이 "group:artifact" 형태로 저장돼 있다.
    'maven'    => ['type' => 'maven',    'ns' => null,     'split' => ':',  'arch' => false],
    'nuget'    => ['type' => 'nuget',    'ns' => null,     'split' => null, 'arch' => false],
    'cargo'    => ['type' => 'cargo',    'ns' => null,     'split' => null, 'arch' => false],
];

/**
 * purl 한 조각 인코딩. rawurlencode 로 전부 인코딩한 뒤, purl 스펙이 해당 구간에서
 * 그대로 두는 문자만 되돌린다. ':' 와 '+' 는 EVR(에포크 1:2.3)·빌드메타(1.0+deb11)에서
 * 흔하고 실제 도구들도 인코딩하지 않는다.
 */
function vg_purl_seg(string $s): string {
    return strtr(rawurlencode($s), ['%3A' => ':', '%2B' => '+']);
}

/**
 * 설치 패키지 → purl 문자열. 매핑에 없는 manager 나 이름이 빈 경우 null.
 *
 * @param string      $manager tb_package.manager (rpm|dpkg|apk|pip|npm|gem|composer|maven|go|nuget|cargo)
 * @param string      $name    tb_package.name (npm 스코프·maven group:artifact 포함 원문)
 * @param string|null $version tb_package.version (EVR 전체)
 * @param string|null $arch    tb_package.arch (OS 패키지만 의미 있음)
 * @param string|null $osId    tb_scan.os_id (rpm/dpkg 네임스페이스)
 */
function vg_purl(string $manager, string $name, ?string $version = null,
                 ?string $arch = null, ?string $osId = null): ?string {
    $m = strtolower(trim($manager));
    $name = trim($name);
    if ($name === '' || !isset(VG_PURL_TYPES[$m])) { return null; }
    $rule = VG_PURL_TYPES[$m];

    // 네임스페이스: 이름에서 떼거나(split), 매핑이 지정한 출처에서 가져온다.
    $ns = [];
    if ($rule['split'] !== null) {
        $pos = strrpos($name, $rule['split']);
        if ($pos !== false && $pos > 0) {
            $ns   = explode('/', substr($name, 0, $pos));   // go 의 다단 경로도 조각 단위로
            $name = substr($name, $pos + 1);
            if ($name === '') { return null; }
        }
    } elseif ($rule['ns'] === 'os') {
        $os = strtolower(trim((string) $osId));
        if ($os === '') { return null; }   // 배포판을 모르면 rpm/deb purl 은 성립하지 않는다
        $ns = [$os];
    } elseif ($rule['ns'] !== null) {
        $ns = [$rule['ns']];
    }

    $purl = 'pkg:' . $rule['type'];
    foreach ($ns as $seg) {
        if ($seg === '') { continue; }
        $purl .= '/' . vg_purl_seg($seg);
    }
    $purl .= '/' . vg_purl_seg($name);

    $version = $version !== null ? trim($version) : '';
    if ($version !== '') { $purl .= '@' . vg_purl_seg($version); }

    $arch = $arch !== null ? trim($arch) : '';
    if ($rule['arch'] && $arch !== '') { $purl .= '?arch=' . vg_purl_seg($arch); }

    return $purl;
}
