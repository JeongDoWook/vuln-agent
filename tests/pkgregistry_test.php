<?php
declare(strict_types=1);

/**
 * pkgregistry 단위 테스트 — 레지스트리 메타데이터 커넥터(feeds/pkgregistry.php)의 순수 함수들.
 *   네트워크·MySQL 없이 도는 것만 검사한다(대상 선정은 SQLite 인메모리 DB 로 대체).
 *
 * 실행: docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/pkgregistry_test.php
 */

require_once __DIR__ . '/../server/src/feeds.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── 버전 선정 — 설치버전보다 높은 것 중 최신 N개, 내림차순 ─────────────────
$available = ['1.0.0', '2.5.0', '2.6.0', '2.7.0', '3.0.0', '0.9.0', '2.6.0'];   // 2.6.0 중복 포함
$eq('설치 2.6.0 초과만, 내림차순',
    vg_pkgregistry_pick_versions($available, '2.6.0', 'composer', 10),
    ['3.0.0', '2.7.0']);
$eq('상한 1개',
    vg_pkgregistry_pick_versions($available, '0.9.0', 'composer', 1),
    ['3.0.0']);
$eq('설치버전이 최신 → 후보 없음',
    vg_pkgregistry_pick_versions($available, '3.0.0', 'composer', 10),
    []);
$eq('빈 문자열 버전은 무시',
    vg_pkgregistry_pick_versions(['', '1.0.0', '2.0.0'], '1.0.0', 'npm', 10),
    ['2.0.0']);

// ── maven 은 vg_ver_cmp() 의 dpkg 기본값이 아니라 semver 계열로 비교한다 ───
//   실측(Maven Central, com.google.guava:guava): dpkg 규칙으로 비교하면 옛 버전 별칭
//   "r09" 가 "30.0-jre" 보다 높다고 나와 최신 후보 선정이 뒤집힌다(회귀 방지).
$eq('maven: r09 는 30.0-jre 보다 낮다(dpkg 기본값이면 반대로 나온다)',
    vg_pkgregistry_ver_cmp('r09', '30.0-jre', 'maven') < 0, true);
$eq('maven 버전 목록에서 옛 별칭(r09/r08)이 아니라 최신이 뽑힌다',
    vg_pkgregistry_pick_versions(['r08', 'r09', '30.0-jre', '33.0-jre'], '30.0-jre', 'maven', 2),
    ['33.0-jre']);

// ── 대상 선정 — 여러 스캔에 걸친 설치버전 중 최저값을 기준으로 삼는다 ──────
//   (MySQL 문법이 아니라 표준 SQL 만 쓰므로 SQLite 로도 같은 결과가 나와야 한다)
$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('CREATE TABLE tb_package_dependency (
    parent_manager VARCHAR(16), parent_name VARCHAR(255), parent_version VARCHAR(255),
    child_manager VARCHAR(16), child_name VARCHAR(255), child_version VARCHAR(255)
)');
$ins = $pdo->prepare(
    'INSERT INTO tb_package_dependency (parent_manager, parent_name, parent_version, child_manager, child_name, child_version)
     VALUES (?,?,?,?,?,?)'
);
// 같은 부모(composer/opis/json-schema)가 두 스캔에서 다른 버전으로 설치됨 — 최저값 2.5.0 이 떠야 한다.
$ins->execute(['composer', 'opis/json-schema', '2.7.0', 'composer', 'opis/string', '2.0.0']);
$ins->execute(['composer', 'opis/json-schema', '2.5.0', 'composer', 'opis/string', '2.0.0']);
// npm 부모 하나.
$ins->execute(['npm', 'lodash', '4.17.20', 'npm', 'lodash.merge', '4.6.0']);
// 자식 행(parent 가 NULL)은 대상이 아니다 — 부모로 등장한 적 없는 패키지.
$ins->execute([null, null, null, 'maven', 'org.apache.commons:commons-lang3', '3.9']);

$targets = vg_pkgregistry_targets($pdo, ['composer', 'npm', 'pip', 'maven']);
$byKey = [];
foreach ($targets as [$mgr, $name, $floor]) { $byKey["$mgr|$name"] = $floor; }

$eq('대상 2건(부모 없는 자식행 제외)', count($targets), 2);
$eq('composer 부모는 최저 설치버전(2.5.0)을 floor 로', $byKey['composer|opis/json-schema'] ?? null, '2.5.0');
$eq('npm 부모 floor', $byKey['npm|lodash'] ?? null, '4.17.20');
$eq('필터에 없는 manager(maven)는 대상 없음', isset($byKey['maven|org.apache.commons:commons-lang3']), false);

// ── pip PEP 508 requirement 파싱 — 원문 제약을 그대로 보존한다 ─────────────
$eq('버전 스펙(괄호)',
    vg_pip_parse_requirement('urllib3 (>=1.21.1,<1.27)'), ['urllib3', '(>=1.21.1,<1.27)']);
$eq('버전 스펙(괄호 없음)',
    vg_pip_parse_requirement('certifi>=2017.4.17'), ['certifi', '>=2017.4.17']);
$eq('extras 는 제약에서 빠지고 마커는 남는다',
    vg_pip_parse_requirement("PySocks!=1.5.7,>=1.5.6; extra == 'socks'"),
    ['PySocks', "!=1.5.7,>=1.5.6; extra == 'socks'"]);
$eq('제약 없는 이름뿐인 의존성 → *',
    vg_pip_parse_requirement('typing'), ['typing', '*']);
$eq('빈 문자열은 무시', vg_pip_parse_requirement(''), null);
$eq('빈 문자열(공백) 은 무시', vg_pip_parse_requirement('   '), null);

// ── maven pom.xml 파싱 — scope=test/provided 제외, 미해석 프로퍼티 버전 제외 ──
$pom = <<<'XML'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.2</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.9.0</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>jakarta.servlet</groupId>
      <artifactId>jakarta.servlet-api</artifactId>
      <version>5.0.0</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>unresolved-prop</artifactId>
      <version>${some.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>no-version</artifactId>
    </dependency>
  </dependencies>
</project>
XML;
$deps = vg_maven_parse_pom_deps($pom);
$eq('런타임 의존 1건만 남는다', count($deps), 1);
$eq('runtime 의존의 자식/제약',
    $deps['com.fasterxml.jackson.core:jackson-databind'] ?? null, '2.15.2');
$eq('test scope 제외', isset($deps['org.junit.jupiter:junit-jupiter']), false);
$eq('provided scope 제외', isset($deps['jakarta.servlet:jakarta.servlet-api']), false);
$eq('미해석 프로퍼티 제외', isset($deps['org.example:unresolved-prop']), false);
$eq('버전 없음 제외', isset($deps['org.example:no-version']), false);

$eq('깨진 XML 은 빈 배열', vg_maven_parse_pom_deps('not xml'), []);

if ($fail === 0) {
    echo "pkgregistry: 모든 검사 통과\n";
    exit(0);
}
printf("pkgregistry: %d 개 실패\n", $fail);
exit(1);
