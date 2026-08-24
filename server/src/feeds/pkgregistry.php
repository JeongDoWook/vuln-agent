<?php
declare(strict_types=1);

/**
 * feeds/pkgregistry.php — 레지스트리 메타데이터 커넥터.
 *
 *   tb_package_dependency 에 **부모**로 등장하는 패키지들의 설치된 버전보다 높은 버전들만,
 *   업스트림 레지스트리(Packagist/npm/PyPI/Maven Central)에서 "이 버전은 자식을 어떤 제약으로
 *   요구하는가"를 받아 tb_package_registry_meta 로 저장한다.
 *
 *   왜 필요한가: tb_package_dependency 는 *설치된 스냅샷 한 벌*이라 "부모의 어느 버전이 안전한
 *   자식을 끌어오는가"를 모른다(server/src/packagedep.php 의 "버전은 제안하지 않는다" 제약과
 *   같은 이유 — 그 표는 조회 전용이라 여기서 건드리지 않는다). 계산(semver 범위 해석·최소
 *   상향 버전 산출)과 화면 반영은 이 작업 스코프 밖이다 — 여기는 원문 제약 문자열을 그대로
 *   모으기만 한다.
 *
 *   생태계별 차이(버전 목록을 어디서 얻는지, 한 번에 몇 버전을 주는지)는 VgRegistryAdapter
 *   구현체 4개로 흡수한다. 5번째 생태계(gem/cargo/go)가 오면 어댑터 클래스 하나 추가 +
 *   self::adapters() 한 줄이면 끝난다(기존 코드 수정 없음 — OCP).
 *
 *   실패 처리: 레지스트리 하나(또는 부모 하나)가 죽어도 나머지는 계속돈다 — 어댑터 호출을
 *   부모 단위로 try/catch 해 실패를 로그만 남기고 건너뛴다. 폐쇄망이라 전부 실패해도 run() 은
 *   예외를 던지지 않고 fetched=0/upserted=0 으로 조용히 끝난다("메타데이터 없음"으로 저하 —
 *   에러 화면이 아니다).
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/../vercmp.php';   // vg_ver_cmp — 설치버전보다 높은지 판정

// 부모 하나당 받는 버전 상한(설치된 버전보다 높은 것 중 최신 N개만).
//   근거: guzzlehttp/guzzle 류는 레지스트리에 수백 버전이 쌓여 있는데, 운영자가 실제로 올릴
//   후보는 최신 몇 개면 충분하다(그보다 오래된 버전은 지금 버전도 못 올리는 마당에 조치
//   후보가 될 리 없다). 상한이 없으면 부모 하나가 레지스트리에 수백 회 요청을 내 레이트리밋에
//   걸린다. $conn['max_versions'] 로 덮을 수 있다(연결설정에만 있는 숨은 값 — rhunfixed 의
//   max_detail 과 같은 패턴).
const VG_PKGREG_MAX_VERSIONS = 20;

// $conn['max_versions'] 로 사용자가 올릴 수 있는 절대 상한. THIRD-PARTY-NOTICES.md 의 Maven
// Central 대량 다운로드·미러링 금지 준수 근거가 이 값에 의존한다 — 설정값이 이 천장을 넘을 수
// 없어야 그 문서의 법적 주장이 코드로 강제된다.
const VG_PKGREG_MAX_VERSIONS_CEILING = 100;

// 레지스트리 요청 동시성 상한 — npm·PyPI 레이트리밋을 존중한다(요청 폭주 방지).
const VG_PKGREG_CONCURRENCY = 4;

// 부모 패키지 사이 순차 호출 간 최소 간격(마이크로초). 동시성 상한과 별개로, 부모가 많을 때
// 레지스트리를 쉼 없이 두드리지 않게 한다.
const VG_PKGREG_INTER_PARENT_DELAY_US = 150000; // 0.15초

// 각 레지스트리의 기본 호스트. $conn['{ecosystem}_base'] 로 덮을 수 있다 — 실제 운영에서
// 바꿀 일은 없지만(고정 4종 레지스트리) 폐쇄망 모사 테스트가 존재하지 않는 호스트로
// 이 값을 바꿔 "조용한 저하"를 확인할 수 있어야 한다(검증 항목).
const VG_PKGREG_COMPOSER_BASE = 'https://repo.packagist.org';
const VG_PKGREG_NPM_BASE      = 'https://registry.npmjs.org';
const VG_PKGREG_PIP_BASE      = 'https://pypi.org';
const VG_PKGREG_MAVEN_BASE    = 'https://repo1.maven.org/maven2';

/**
 * 생태계 어댑터 계약 — "이름/버전 → 자식 제약 목록"만 안다.
 *   레지스트리마다 "전 버전을 한 번에 주는가"가 달라 메서드를 둘로 나눈다. 한 번에 주는
 *   레지스트리(composer/npm)는 내부에서 응답을 캐시해 두 메서드가 같은 요청을 재사용한다.
 */
interface VgRegistryAdapter {
    /** 이 부모 패키지가 레지스트리에 실제로 낸 버전 문자열 목록(순서 무관). 실패 시 예외. */
    public function listVersions(string $name): array;

    /**
     * $versions 중 조회 가능한 버전들의 자식 제약.
     * 반환: [version => [child_name => constraint 원문, …]]. 개별 버전 조회 실패는 결과에서
     * 빠질 뿐 예외를 던지지 않는다(호출부가 부모 단위로 실패를 다룬다).
     */
    public function fetchDependencies(string $name, array $versions): array;
}

// ─────────────────────────────────────────────────────────────────────────
// composer(Packagist) — p2 API 는 부모 하나의 전 버전 require 를 한 번에 준다.
// ─────────────────────────────────────────────────────────────────────────
final class VgComposerRegistryAdapter implements VgRegistryAdapter {
    private string $base;
    /** @var array<string, array> 이름 => p2 응답의 packages[name] 원본(list<array>) */
    private array $cache = [];

    public function __construct(string $base = VG_PKGREG_COMPOSER_BASE) {
        $this->base = rtrim($base, '/');
    }

    private function load(string $name): array {
        if (array_key_exists($name, $this->cache)) { return $this->cache[$name]; }
        $parts = explode('/', $name, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return $this->cache[$name] = [];
        }
        $url = $this->base . '/p2/' . rawurlencode($parts[0]) . '/' . rawurlencode($parts[1]) . '.json';
        $r = vg_http_json('GET', $url, null, [], 30, 8_000_000);
        if ($r['code'] !== 200 || !is_array($r['json'])) {
            throw new RuntimeException("composer 레지스트리 조회 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $items = $r['json']['packages'][$name] ?? [];
        return $this->cache[$name] = is_array($items) ? $items : [];
    }

    public function listVersions(string $name): array {
        $out = [];
        foreach ($this->load($name) as $item) {
            $v = (string) ($item['version'] ?? '');
            if ($v !== '' && self::isRealVersion($v)) { $out[] = $v; }
        }
        return $out;
    }

    public function fetchDependencies(string $name, array $versions): array {
        $wanted = array_flip($versions);
        $out = [];
        foreach ($this->load($name) as $item) {
            $v = (string) ($item['version'] ?? '');
            if ($v === '' || !isset($wanted[$v])) { continue; }
            $deps = [];
            foreach ((array) ($item['require'] ?? []) as $childName => $constraint) {
                $childName = (string) $childName;
                if (self::isPlatformPackage($childName)) { continue; }
                $deps[$childName] = (string) $constraint;
            }
            if ($deps) { $out[$v] = $deps; }
        }
        return $out;
    }

    // dev-master·9999999-dev-dev·1.0.x-dev 같은 브랜치 별칭은 릴리스가 아니다 —
    //   vg_ver_cmp 의 semver 비교에 섞이면 순서를 예측할 수 없다(버전 문자열이 아니다).
    private static function isRealVersion(string $v): bool {
        $lo = strtolower($v);
        return !str_starts_with($lo, 'dev-') && !str_ends_with($lo, '-dev') && !str_contains($lo, '@dev');
    }

    // php/hhvm/ext-*/lib-*/composer-plugin-api/composer-runtime-api 는 실제 패키지가 아니라
    //   런타임 요구사항이다 — 자식 엣지로 저장하면 tb_package_dependency 에 없는 유령 노드가 된다.
    private static function isPlatformPackage(string $name): bool {
        $lo = strtolower($name);
        return $lo === 'php' || $lo === 'hhvm' || $lo === 'composer-plugin-api' || $lo === 'composer-runtime-api'
            || str_starts_with($lo, 'ext-') || str_starts_with($lo, 'lib-');
    }
}

// ─────────────────────────────────────────────────────────────────────────
// npm — registry.npmjs.org 도 부모 하나의 전 버전 dependencies 를 한 번에 준다.
// ─────────────────────────────────────────────────────────────────────────
final class VgNpmRegistryAdapter implements VgRegistryAdapter {
    private string $base;
    /** @var array<string, array> 이름 => versions 맵(버전 => 메타) */
    private array $cache = [];

    public function __construct(string $base = VG_PKGREG_NPM_BASE) {
        $this->base = rtrim($base, '/');
    }

    private function load(string $name): array {
        if (array_key_exists($name, $this->cache)) { return $this->cache[$name]; }
        // 스코프 패키지(@scope/name)의 '/' 만 인코딩한다 — 나머지는 vg_pkg_ident_valid 로
        //   이미 안전한 문자셋만 통과한 값이라 추가 이스케이프가 필요 없다.
        $url = $this->base . '/' . str_replace('/', '%2f', $name);
        // vg_http_json 은 기본 Accept 헤더를 항상 덧붙여 축약 응답 협상이 안 되므로(둘 다 실려
        //   보내면 서버 동작이 불명확) vg_http_raw + 수동 디코드를 쓴다. 축약(install-v1) 응답은
        //   버전별로 우리가 쓰는 필드(dependencies)만 담아 전체 응답의 몇 분의 1이다.
        $r = vg_http_raw('GET', $url, ['Accept: application/vnd.npm.install-v1+json'], 30, 8_000_000);
        if ($r['code'] !== 200 || $r['body'] === '') {
            throw new RuntimeException("npm 레지스트리 조회 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $json = json_decode($r['body'], true);
        $versions = $json['versions'] ?? null;
        if (!is_array($versions)) {
            throw new RuntimeException('npm 레지스트리 응답 파싱 실패(versions 없음)');
        }
        return $this->cache[$name] = $versions;
    }

    public function listVersions(string $name): array {
        return array_keys($this->load($name));
    }

    public function fetchDependencies(string $name, array $versions): array {
        $wanted = array_flip($versions);
        $out = [];
        foreach ($this->load($name) as $v => $meta) {
            if (!isset($wanted[$v])) { continue; }
            $deps = [];
            foreach ((array) ($meta['dependencies'] ?? []) as $childName => $constraint) {
                $deps[(string) $childName] = (string) $constraint;
            }
            if ($deps) { $out[$v] = $deps; }
        }
        return $out;
    }
}

// ─────────────────────────────────────────────────────────────────────────
// pip(PyPI) — 목록(releases)은 한 번에 오지만, 버전별 requires_dist 는 버전마다 따로 받는다.
// ─────────────────────────────────────────────────────────────────────────
final class VgPipRegistryAdapter implements VgRegistryAdapter {
    private string $base;
    /** @var array<string, array> 이름 => releases 맵(버전 => 파일목록) */
    private array $releaseCache = [];

    public function __construct(string $base = VG_PKGREG_PIP_BASE) {
        $this->base = rtrim($base, '/');
    }

    private function releases(string $name): array {
        if (array_key_exists($name, $this->releaseCache)) { return $this->releaseCache[$name]; }
        $url = $this->base . '/pypi/' . rawurlencode($name) . '/json';
        $r = vg_http_json('GET', $url, null, [], 30, 4_000_000);
        if ($r['code'] !== 200 || !isset($r['json']['releases']) || !is_array($r['json']['releases'])) {
            throw new RuntimeException("pip 레지스트리 조회 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        return $this->releaseCache[$name] = $r['json']['releases'];
    }

    public function listVersions(string $name): array {
        return array_keys($this->releases($name));
    }

    public function fetchDependencies(string $name, array $versions): array {
        $urlToVer = [];
        foreach ($versions as $v) {
            $urlToVer[$this->base . '/pypi/' . rawurlencode($name) . '/' . rawurlencode($v) . '/json'] = $v;
        }
        if (!$urlToVer) { return []; }
        $resp = vg_http_get_many(array_keys($urlToVer), VG_PKGREG_CONCURRENCY, 30, [], 4_000_000);

        $out = [];
        foreach ($urlToVer as $url => $v) {
            $body = ($resp[$url]['code'] ?? 0) === 200 ? $resp[$url]['body'] : '';
            if ($body === '') { continue; }   // 이 버전만 건너뛴다 — 나머지는 계속
            $json = json_decode($body, true);
            $deps = [];
            foreach ((array) ($json['info']['requires_dist'] ?? []) as $entry) {
                $parsed = vg_pip_parse_requirement((string) $entry);
                if ($parsed === null) { continue; }
                [$childName, $constraint] = $parsed;
                $deps[$childName] = $constraint;
            }
            if ($deps) { $out[$v] = $deps; }
        }
        return $out;
    }
}

/**
 * PEP 508 requirement 문자열 → [자식이름, 제약 원문]. 파싱 불가면 null.
 *   예: "urllib3 (>=1.21.1,<1.27)" · "certifi>=2017.4.17" ·
 *       "PySocks!=1.5.7,>=1.5.6; extra == 'socks'"
 *   버전 스펙 뒤의 환경 마커(`; extra == …`)까지 포함해 **나머지 전부를 원문 그대로** 제약으로
 *   저장한다(파싱해서 쪼개지 않는다 — 이 작업의 원칙). 제약이 없으면(이름뿐인 의존성) '*'.
 */
function vg_pip_parse_requirement(string $entry): ?array {
    $entry = trim($entry);
    if ($entry === '') { return null; }
    // PEP 508 이름 규칙(대소문자·숫자·.·_·-) 뒤에 선택적 extras([...])가 붙고, 그 뒤 나머지가 제약.
    if (!preg_match('/^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/', $entry, $m)) {
        return null;
    }
    $name = $m[1];
    $constraint = trim($m[2]);
    return [$name, $constraint === '' ? '*' : $constraint];
}

// ─────────────────────────────────────────────────────────────────────────
// maven(Maven Central) — 목록은 maven-metadata.xml, 버전별 의존은 그 버전의 pom 을 따로 받는다.
// ─────────────────────────────────────────────────────────────────────────
final class VgMavenRegistryAdapter implements VgRegistryAdapter {
    private string $base;

    public function __construct(string $base = VG_PKGREG_MAVEN_BASE) {
        $this->base = rtrim($base, '/');
    }

    // parent_name 형식은 "groupId:artifactId" — server/src/purl.php 의 maven split=':' 과
    //   server/src/ingest/sbom.php 가 purl 에서 재조합하는 형식이 같다(적재 쪽 정본과 일치).
    private function groupPath(string $name): ?array {
        $parts = explode(':', $name, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') { return null; }
        return [str_replace('.', '/', $parts[0]), $parts[1]];
    }

    public function listVersions(string $name): array {
        $g = $this->groupPath($name);
        if ($g === null) { return []; }
        [$groupPath, $artifact] = $g;
        $url = "{$this->base}/{$groupPath}/{$artifact}/maven-metadata.xml";
        $r = vg_http_raw('GET', $url, [], 30, 2_000_000);
        if ($r['code'] !== 200 || $r['body'] === '') {
            throw new RuntimeException("maven 메타데이터 조회 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $prev = libxml_use_internal_errors(true);
        $xml = @simplexml_load_string($r['body']);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        if ($xml === false) { return []; }

        $out = [];
        foreach (($xml->versioning->versions->version ?? []) as $v) {
            $out[] = (string) $v;
        }
        return $out;
    }

    public function fetchDependencies(string $name, array $versions): array {
        $g = $this->groupPath($name);
        if ($g === null) { return []; }
        [$groupPath, $artifact] = $g;

        $urlToVer = [];
        foreach ($versions as $v) {
            $urlToVer["{$this->base}/{$groupPath}/{$artifact}/{$v}/{$artifact}-{$v}.pom"] = $v;
        }
        if (!$urlToVer) { return []; }
        $resp = vg_http_get_many(array_keys($urlToVer), VG_PKGREG_CONCURRENCY, 30, [], 2_000_000);

        $out = [];
        foreach ($urlToVer as $url => $v) {
            $body = ($resp[$url]['code'] ?? 0) === 200 ? $resp[$url]['body'] : '';
            if ($body === '') { continue; }
            $deps = vg_maven_parse_pom_deps($body);
            if ($deps) { $out[$v] = $deps; }
        }
        return $out;
    }
}

/**
 * pom.xml <dependencies> 직계 자식 → [자식이름(group:artifact) => 제약 원문(<version> 텍스트)].
 *   scope=test/provided 는 런타임 의존이 아니라 버린다 — server/src/ingest/sbom.php 의
 *   vg_ingest_parse_pom_deps() 와 같은 기준이다(그쪽은 에이전트가 올린 pom, 여기는 레지스트리에서
 *   받은 후보 버전의 pom — 소스만 다르고 규칙은 같다). ${…} 미해석 프로퍼티 버전도 같은 이유로
 *   버린다(best-effort — mvn 을 직접 부르지 않으므로 부모 POM 의 프로퍼티까지는 못 푼다).
 */
function vg_maven_parse_pom_deps(string $xml): array {
    $prev = libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    // LIBXML_NONET: 외부 네트워크 참조 금지. 엔티티 확장(LIBXML_NOENT)은 켜지 않는다(XXE 방지).
    $ok = @$doc->loadXML($xml, LIBXML_NONET);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
    if (!$ok) { return []; }

    $xpath = new DOMXPath($doc);
    $nodes = $xpath->query('/*[local-name()="project"]/*[local-name()="dependencies"]/*[local-name()="dependency"]');
    if ($nodes === false) { return []; }

    $out = [];
    foreach ($nodes as $node) {
        $g = ''; $a = ''; $v = ''; $scope = '';
        foreach ($node->childNodes as $child) {
            if ($child->nodeType !== XML_ELEMENT_NODE) { continue; }
            switch ($child->localName) {
                case 'groupId':    $g = trim($child->textContent); break;
                case 'artifactId': $a = trim($child->textContent); break;
                case 'version':    $v = trim($child->textContent); break;
                case 'scope':      $scope = trim($child->textContent); break;
            }
        }
        if ($g === '' || $a === '' || $v === '') { continue; }
        if (str_contains($g, '${') || str_contains($a, '${') || str_contains($v, '${')) { continue; }
        if ($scope === 'test' || $scope === 'provided') { continue; }
        $out["$g:$a"] = $v;
    }
    return $out;
}

// ─────────────────────────────────────────────────────────────────────────
// 대상 선정(순수 함수 — 테스트: tests/pkgregistry_test.php)
// ─────────────────────────────────────────────────────────────────────────

/**
 * 부모 버전 비교(레지스트리 후보 선정 전용) — vg_ver_cmp() 를 그대로 쓰지 않는다.
 *   그 함수는 'maven' 케이스가 없어 default(vg_deb_cmp, dpkg 규칙)로 떨어진다. 실측(Maven
 *   Central, com.google.guava:guava): dpkg 규칙으로 비교하면 옛 버전 별칭 "r09" 가
 *   "30.0-jre" 보다 **높다**고 나와, "설치버전보다 높은 최신 N개" 선정이 뒤집힌다(오래된
 *   r09/r08 이 후보로 뽑히고 실제 최신 33.x 는 빠진다). 매처가 쓰는 공유 비교기
 *   (server/src/vercmp.php)는 이 작업 스코프 밖이라 고치지 않는다 — 여기서만 maven 을
 *   언어 패키지(semver 계열)로 보고 vg_lang_cmp 를 직접 쓴다(version_compare 로
 *   "r09" < "30.0-jre" · "3.20.0" > "3.10" 이 실측으로 맞게 나온다). composer·npm·pip 는
 *   원래도 vg_ver_cmp 가 vg_lang_cmp 로 위임하므로 동작이 그대로다.
 */
function vg_pkgregistry_ver_cmp(string $a, string $b, string $manager): int {
    return $manager === 'maven' ? vg_lang_cmp($a, $b) : vg_ver_cmp($a, $b, $manager);
}

/**
 * tb_package_dependency 에 부모로 등장하는 (manager, name)과 그 최저 설치버전.
 *   여러 스캔에 걸쳐 설치버전이 다르면(호스트 A 는 2.5.0, 호스트 B 는 2.7.0) 가장 낮은 것을
 *   기준으로 잡는다 — 2.5.0 초과 목록은 2.7.0 초과도 포함하므로, 최저값 기준이라야 어느 쪽
 *   설치본에도 유효한 상향 후보를 놓치지 않는다.
 * @param string[] $managers
 * @return list<array{0:string,1:string,2:string}> [manager, name, floorVersion]
 */
function vg_pkgregistry_targets(PDO $pdo, array $managers): array {
    if (!$managers) { return []; }
    $in = implode(',', array_fill(0, count($managers), '?'));
    $st = $pdo->prepare(
        "SELECT DISTINCT parent_manager, parent_name, parent_version
           FROM tb_package_dependency
          WHERE parent_manager IN ($in) AND parent_name IS NOT NULL AND parent_version IS NOT NULL"
    );
    $st->execute(array_values($managers));

    $floors = [];   // "manager|name" => 최저 버전
    foreach ($st->fetchAll() as $r) {
        $mgr = (string) $r['parent_manager'];
        $key = $mgr . '|' . $r['parent_name'];
        $ver = (string) $r['parent_version'];
        if (!isset($floors[$key]) || vg_pkgregistry_ver_cmp($ver, $floors[$key], $mgr) < 0) {
            $floors[$key] = $ver;
        }
    }
    $out = [];
    foreach ($floors as $key => $ver) {
        [$mgr, $name] = explode('|', $key, 2);
        $out[] = [$mgr, $name, $ver];
    }
    return $out;
}

/**
 * 레지스트리 버전 목록에서 "설치버전보다 높은 것 중 최신 N개"만 고른다.
 * @param string[] $available
 * @return string[] 최신순(내림차순)
 */
function vg_pkgregistry_pick_versions(array $available, string $floor, string $manager, int $max): array {
    $higher = array_values(array_filter(
        array_unique($available),
        static fn(string $v): bool => $v !== '' && vg_pkgregistry_ver_cmp($v, $floor, $manager) > 0
    ));
    usort($higher, static fn(string $a, string $b): int => vg_pkgregistry_ver_cmp($b, $a, $manager));
    return array_slice($higher, 0, max(0, $max));
}

// ─────────────────────────────────────────────────────────────────────────
// 커넥터
// ─────────────────────────────────────────────────────────────────────────
final class VgPkgRegistryConnector implements VgFeedConnector {
    /** @return array<string, VgRegistryAdapter> manager => 어댑터. $conn 의 *_base 로 호스트를 덮을 수 있다. */
    private function adapters(array $conn): array {
        return [
            'composer' => new VgComposerRegistryAdapter((string) ($conn['composer_base'] ?? VG_PKGREG_COMPOSER_BASE)),
            'npm'      => new VgNpmRegistryAdapter((string) ($conn['npm_base'] ?? VG_PKGREG_NPM_BASE)),
            'pip'      => new VgPipRegistryAdapter((string) ($conn['pip_base'] ?? VG_PKGREG_PIP_BASE)),
            'maven'    => new VgMavenRegistryAdapter((string) ($conn['maven_base'] ?? VG_PKGREG_MAVEN_BASE)),
        ];
    }

    public function run(PDO $pdo, array $conn): array {
        $maxVersions = max(1, min((int) ($conn['max_versions'] ?? VG_PKGREG_MAX_VERSIONS), VG_PKGREG_MAX_VERSIONS_CEILING));
        $adapters    = $this->adapters($conn);
        $targets     = vg_pkgregistry_targets($pdo, array_keys($adapters));

        $ins = $pdo->prepare(
            'INSERT INTO tb_package_registry_meta
                (manager, parent_name, parent_version, child_name, child_constraint, collected_at)
             VALUES (?,?,?,?,?,NOW())
             ON DUPLICATE KEY UPDATE child_constraint = VALUES(child_constraint), collected_at = NOW()'
        );

        $fetched = 0; $upserted = 0; $failed = 0;
        foreach ($targets as $i => [$manager, $name, $floor]) {
            if ($i > 0) { usleep(VG_PKGREG_INTER_PARENT_DELAY_US); }   // 레이트리밋 존중

            $adapter = $adapters[$manager] ?? null;
            if ($adapter === null) { continue; }   // 미등록 생태계 — 5번째가 등록되기 전까지 조용히 건너뜀

            try {
                $versions = $adapter->listVersions($name);
            } catch (Throwable $e) {
                // 폐쇄망·레지스트리 장애 — 이 부모만 건너뛴다(반드시 지킬 것 #1). 전부 실패해도
                // 여기서 던지지 않으므로 run() 전체는 fetched=0 로 조용히 끝난다(#2).
                error_log("[pkgregistry] $manager/$name 버전 목록 조회 실패: " . $e->getMessage());
                $failed++;
                continue;
            }
            $candidates = vg_pkgregistry_pick_versions($versions, $floor, $manager, $maxVersions);
            if (!$candidates) { continue; }

            try {
                $depsByVersion = $adapter->fetchDependencies($name, $candidates);
            } catch (Throwable $e) {
                error_log("[pkgregistry] $manager/$name 의존관계 조회 실패: " . $e->getMessage());
                $failed++;
                continue;
            }

            foreach ($depsByVersion as $ver => $deps) {
                foreach ($deps as $childName => $constraint) {
                    $fetched++;
                    $childName = mb_strimwidth((string) $childName, 0, 255, '');
                    if ($childName === '') { continue; }
                    $ins->execute([
                        $manager,
                        mb_strimwidth($name, 0, 255, ''),
                        mb_strimwidth((string) $ver, 0, 255, ''),
                        $childName,
                        mb_strimwidth((string) $constraint, 0, 500, ''),
                    ]);
                    $upserted++;
                }
            }
        }
        if ($failed > 0) {
            error_log("[pkgregistry] 부모 {$failed}건 조회 실패(레지스트리 접근 불가 또는 오류) — 나머지는 정상 수집됨");
        }
        return ['fetched' => $fetched, 'upserted' => $upserted];
    }

    // 미리보기: 대상 중 첫 부모 하나만 실제로 조회해 보여준다(저장 안 함).
    public function preview(PDO $pdo, array $conn): array {
        $adapters = $this->adapters($conn);
        $targets  = vg_pkgregistry_targets($pdo, array_keys($adapters));
        if (!$targets) {
            return ['ok' => true, 'count' => 0, 'sample' => [], 'note' => 'tb_package_dependency 에 부모 패키지가 없다'];
        }
        [$manager, $name, $floor] = $targets[0];
        $adapter = $adapters[$manager];
        try {
            $versions   = $adapter->listVersions($name);
            $candidates = vg_pkgregistry_pick_versions($versions, $floor, $manager, min(3, VG_PKGREG_MAX_VERSIONS));
            $deps       = $candidates ? $adapter->fetchDependencies($name, $candidates) : [];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage(), 'target' => "$manager:$name"];
        }
        $items = [];
        foreach ($deps as $ver => $childMap) {
            foreach ($childMap as $childName => $constraint) {
                $items[] = ['parent' => "$name $ver", 'child' => $childName, 'constraint' => $constraint];
                if (count($items) >= 10) { break 2; }
            }
        }
        return ['ok' => true, 'target' => "$manager:$name (> $floor)", 'count' => count($items), 'items' => $items];
    }
}
