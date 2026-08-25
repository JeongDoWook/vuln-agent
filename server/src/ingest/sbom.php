<?php
declare(strict_types=1);

/**
 * ingest/sbom.php — 외부에서 올라온 SBOM 문서(CycloneDX/SPDX)와 pom.xml 을 읽어
 *   패키지 목록 + **의존성 그래프 엣지**로 바꾼다. 다른 파서와 달리 입력이 base64(JSON/XML)라
 *   신뢰 경계가 여기 있다 — 저장 상한(DoS)·식별자 문자셋(저장형 XSS)·XXE 방어가 전부 이 파일에 모인다.
 *   그래서 vg_pkg_ident_valid()와 상한 상수도 여기 둔다(유일한 호출부가 이 파일이다).
 *
 * ingest_parse.php 가 require 한다.
 */

// ── SBOM 예약 cid — 호스트 자신 ────────────────────────────────────────────
//   SBOM 파일명이 곧 cid 다(agent/vuln-inventory-agent.sh 의 collect_sbom). 이 값만은
//   컨테이너가 아니라 **호스트 자신**(container_id = 0, db/01-schema.sql 규약)을 가리킨다.
//   밑줄로 시작하는 이름은 docker/podman 이름 규칙(`[a-zA-Z0-9][a-zA-Z0-9_.-]*`)상 만들 수 없어
//   실제 컨테이너와 충돌이 구조적으로 불가능하다. 매핑은 vg_ingest_ctr_ids_with_host() 한 곳에서만 한다.
const VG_SBOM_HOST_CID = '_host';

// ── 패키지 의존성 그래프(tb_package_dependency) 저장 상한 ──────────────────
//   PR#399 리뷰: dedup/상한 없는 SBOM dependencies 배열이 자원 소진(DoS)로 실측됨.
//   스캔(컨테이너 SBOM 1개 또는 호스트 pom.xml 전체) 당 상한 — 초과분은 버리고 로그만 남긴다.
const VG_SBOM_DEP_EDGE_MAX = 5000;
const VG_POM_DEP_EDGE_MAX  = 2000;

// ── SPDX relationshipType 중 "의존 엣지"로 채택하는 것 ─────────────────────
//   SPDX 2.3 은 관계 종류가 40여 개다. **전부 엣지로 삼으면 그래프가 의미를 잃는다** —
//   특히 syft/trivy 가 컨테이너 이미지 SBOM 에 쏟아내는 CONTAINS(이미지→모든 패키지)를 엣지로
//   보면 설치된 패키지 전부가 루트의 "직접 의존"이 되어 직접/전이 구분이 통째로 사라진다.
//   그래서 **의존 관계를 직접 뜻하는 것만** 채택한다.
//     · 정방향 DEPENDS_ON        : A 가 B 에 의존 → parent=A, child=B
//     · 역방향 DEPENDENCY_OF     : A 가 B 의 의존 → parent=B, child=A (같은 사실의 반대 표기)
//              RUNTIME_DEPENDENCY_OF : 런타임 의존. pom 경로가 scope=test/provided 만 버리고
//                                      런타임 의존은 담는 것과 같은 기준이다.
//   버리는 것과 이유:
//     · CONTAINS/CONTAINED_BY          — 파일·아카이브 포함 관계. 위 이유로 그래프를 망친다.
//     · DESCRIBES/DESCRIBED_BY         — 문서가 무엇을 기술하는지. 엣지가 아니라 **루트 표식**이라
//                                        아래에서 루트 표식행 생성에만 쓴다.
//     · BUILD_/DEV_/TEST_/OPTIONAL_DEPENDENCY_OF — 런타임에 적재되지 않는 의존. pom 경로가
//                                        scope=test/provided 를 버리는 것과 같은 기준.
//     · GENERATED_FROM·PATCH_FOR·그 외 — 의존이 아니다.
const VG_SPDX_REL_FORWARD = ['DEPENDS_ON'];
const VG_SPDX_REL_REVERSE = ['DEPENDENCY_OF', 'RUNTIME_DEPENDENCY_OF'];

// ── 패키지 의존성 그래프 그룹/이름/버전 문자셋 검증 ─────────────────────────
//   PR#399 리뷰: 문자셋 검증 없이 저장하면 저장형 XSS 사전조건이 된다. vg_h() 출력 이스케이프는
//   유지하되 저장 단계에서부터 거른다 — 첫 글자는 영숫자 또는 npm 스코프 패키지(@babel/core 등)의
//   선행 `@` 만 허용한다(이슈 #481). 그 외 문자 제한은 그대로 — 특수문자로 시작하는 값은 계속 배제한다.
function vg_pkg_ident_valid(string $s): bool
{
    return $s !== '' && strlen($s) <= 255 && preg_match('/^[A-Za-z0-9@][A-Za-z0-9._\-\/:+@]*$/', $s) === 1;
}

/** Parse externally supplied CycloneDX/SPDX SBOM lines: cid|format|base64(json). */
function vg_ingest_parse_sbom(string $text): array
{
    $packages=[]; $meta=[]; $deps=[]; $depsSeen=[]; $depsDropped=0; $depsUnresolved=0;
    // 엣지 하나를 검증·dedup·상한 확인 후 담는다. CycloneDX 루트 표식 / CycloneDX dependencies /
    //   SPDX relationships 세 곳이 같은 규칙을 쓰므로 여기 한 곳에 둔다(DRY — 3번째에 추출).
    //   $parent 가 null 이면 루트 표식행(parent 3필드 전부 NULL) — DB 규약은
    //   db/migrations/20260806141456_package_dependency_graph.sql 주석 참고.
    $pushEdge = static function (string $cid, ?array $parent, array $child)
        use (&$deps, &$depsSeen, &$depsDropped): void {
        foreach ($parent === null ? $child : array_merge($parent, $child) as $v) {
            if (!vg_pkg_ident_valid($v)) { return; }   // 정체를 알 수 없는 부모/자식은 저장하지 않는다
        }
        $k = $cid . '|' . ($parent === null ? 'root' : implode('|', $parent)) . '|' . implode('|', $child);
        if (isset($depsSeen[$k])) { return; }
        if (count($deps) >= VG_SBOM_DEP_EDGE_MAX) { $depsDropped++; return; }
        $depsSeen[$k] = true;
        $deps[] = $parent === null
            ? [$cid, null, null, null, $child[0], $child[1], $child[2]]
            : [$cid, $parent[0], $parent[1], $parent[2], $child[0], $child[1], $child[2]];
    };
    foreach (preg_split('/\r?\n/', $text) as $line) {
        $f=explode('|',$line,3); if(count($f)!==3||$f[0]==='')continue;
        $raw=base64_decode($f[2],true); $doc=$raw!==false?json_decode($raw,true):null; if(!is_array($doc))continue;
        $cid=mb_strimwidth($f[0],0,255,''); $format=strtolower($f[1]); $meta[$cid]=[$format,hash('sha256',$raw)];
        $items=$format==='spdx'?($doc['packages']??[]):($doc['components']??[]);
        // 참조 → [manager,name,version] — 엣지의 양끝을 실제 패키지로 되짚는 매핑.
        //   CycloneDX 는 dependencies[].ref(bom-ref, 없으면 purl), SPDX 는 relationships 의
        //   SPDXID(SPDXRef-…) 로 참조한다.
        $refMap=[];
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
                // CycloneDX: dependencies[].ref 는 보통 bom-ref, 없으면 컴포넌트 자신의 purl.
                // SPDX:      relationships 는 패키지의 SPDXID 로 참조한다.
                $ref = $format === 'spdx' ? (string) ($item['SPDXID'] ?? '') : (string) ($item['bom-ref'] ?? $purl);
                if ($ref !== '') { $refMap[$ref] = [$mgr, mb_strimwidth($name,0,255,''), mb_strimwidth($ver,0,255,'')]; }
            }
        }
        // metadata.component — BOM 이 기술하는 대상(스캔된 프로젝트/이미지) 자신. components[] 에는
        //   안 들어 있으므로 dependencies[] 의 루트 참조를 풀려면 refMap 에 따로 등록해야 한다.
        if ($format !== 'spdx' && isset($doc['metadata']['component']) && is_array($doc['metadata']['component'])) {
            $rc = $doc['metadata']['component'];
            $rname = trim((string) ($rc['name'] ?? ''));
            $rver  = trim((string) ($rc['version'] ?? ''));
            $rpurl = (string) ($rc['purl'] ?? '');
            $rmgr = '';
            if (preg_match('#^pkg:([^/]+)/([^@?]+)#', $rpurl, $m)) {
                $type = strtolower($m[1]); $decoded = urldecode($m[2]);
                if ($type === 'maven' && str_contains($decoded, '/')) { $pos = strrpos($decoded, '/'); $decoded = substr($decoded, 0, $pos) . ':' . substr($decoded, $pos + 1); }
                $rname = $decoded ?: $rname;
                $rmgr = ['pypi'=>'pip','npm'=>'npm','gem'=>'gem','composer'=>'composer','maven'=>'maven','nuget'=>'nuget','cargo'=>'cargo','golang'=>'go','deb'=>'dpkg','rpm'=>'rpm','apk'=>'apk'][$type] ?? '';
            }
            $rref = (string) ($rc['bom-ref'] ?? $rpurl);
            if ($rref !== '' && $rmgr !== '' && $rname !== '' && $rver !== '') {
                $refMap[$rref] = [$rmgr, mb_strimwidth($rname, 0, 255, ''), mb_strimwidth($rver, 0, 255, '')];
            }
        }
        // CycloneDX dependencies[] → 부모→자식 엣지. ref 가 refMap 에 없는(문자셋/미완성) 컴포넌트를
        //   가리키면 그 엣지는 버린다(정체를 알 수 없는 부모/자식을 저장하지 않는다).
        if ($format !== 'spdx' && isset($doc['dependencies']) && is_array($doc['dependencies'])) {
            $rootRef = (string) ($doc['metadata']['component']['bom-ref'] ?? $doc['metadata']['component']['purl'] ?? '');
            if ($rootRef !== '' && isset($refMap[$rootRef])) { $pushEdge($cid, null, $refMap[$rootRef]); }
            foreach ($doc['dependencies'] as $dep) {
                $ref = (string) ($dep['ref'] ?? '');
                if ($ref === '' || !isset($refMap[$ref])) { continue; }
                foreach ((array) ($dep['dependsOn'] ?? []) as $childRef) {
                    $childRef = (string) $childRef;
                    if (!isset($refMap[$childRef])) { continue; }
                    $pushEdge($cid, $refMap[$ref], $refMap[$childRef]);
                }
            }
        }
        // SPDX relationships → 부모→자식 엣지. 채택/기각한 relationshipType 과 그 근거는
        //   VG_SPDX_REL_FORWARD/REVERSE 상수 위 주석에 있다. 루트 표식행은 CycloneDX 경로와
        //   **같은 규약**(parent 3필드 전부 NULL)으로 만든다 — 같은 화면이 둘 다 읽는다.
        if ($format === 'spdx' && (isset($doc['relationships']) || isset($doc['documentDescribes']))) {
            $rels = is_array($doc['relationships'] ?? null) ? $doc['relationships'] : [];
            // 루트: documentDescribes[] 또는 DESCRIBES/DESCRIBED_BY 관계가 가리키는 요소.
            //   CycloneDX 의 metadata.component 자리다. 패키지로 되짚을 수 없으면(예: syft 가
            //   이미지 자체를 기술할 때) 루트 표식행은 만들지 않는다 — 없는 게 틀린 것보다 낫다.
            $described = [];
            foreach ((array) ($doc['documentDescribes'] ?? []) as $r) {
                if (is_string($r) && $r !== '') { $described[$r] = true; }
            }
            foreach ($rels as $rel) {
                if (!is_array($rel)) { continue; }
                $type = strtoupper(trim((string) ($rel['relationshipType'] ?? '')));
                if ($type === 'DESCRIBES')    { $described[(string) ($rel['relatedSpdxElement'] ?? '')] = true; }
                if ($type === 'DESCRIBED_BY') { $described[(string) ($rel['spdxElementId'] ?? '')]      = true; }
            }
            foreach (array_keys($described) as $rootId) {
                if (isset($refMap[$rootId])) { $pushEdge($cid, null, $refMap[$rootId]); }
            }
            foreach ($rels as $rel) {
                if (!is_array($rel)) { continue; }
                $type = strtoupper(trim((string) ($rel['relationshipType'] ?? '')));
                $fwd  = in_array($type, VG_SPDX_REL_FORWARD, true);
                if (!$fwd && !in_array($type, VG_SPDX_REL_REVERSE, true)) { continue; }
                $from = (string) ($rel['spdxElementId'] ?? '');
                $to   = (string) ($rel['relatedSpdxElement'] ?? '');
                // 되짚을 수 없는 SPDXRef(문서 자신·외부문서 참조 DocumentRef-…·NOASSERTION·
                //   packages[] 에 없는 id)는 엣지를 버리되 **조용히 삼키지 않고** 집계한다.
                if (!isset($refMap[$from]) || !isset($refMap[$to])) { $depsUnresolved++; continue; }
                // 역방향 타입은 "A 는 B 의 의존" 이므로 부모/자식을 뒤집어야 같은 사실이 된다.
                $pushEdge($cid, $fwd ? $refMap[$from] : $refMap[$to], $fwd ? $refMap[$to] : $refMap[$from]);
            }
        }
    }
    return ['packages'=>array_values($packages),'meta'=>$meta,'deps'=>$deps,
            'deps_dropped'=>$depsDropped,'deps_unresolved'=>$depsUnresolved];
}

/**
 * 붙을 곳이 없어 버려질 SBOM 을 집계한다 — 예약 cid(_host)도 아니고 수집된 컨테이너 목록에도
 *   없는 cid. 이런 SBOM 은 저장 단계에서 패키지도 엣지도 통째로 버려지는데, 그 실패가
 *   "0건이라 안전"으로 보이면 안 된다(미지원 배포판 경고와 같은 취지). 매칭 실패를 호스트로
 *   떨어뜨리는 폴백은 **만들지 않는다** — 사라진 컨테이너의 SBOM 이 호스트 것으로 둔갑한다.
 *   반환: cid => ['packages'=>n, 'edges'=>m] (버려질 것이 없으면 빈 배열)
 */
function vg_ingest_sbom_dropped(array $sbom, array $ctrRows): array
{
    $dropped = [];
    foreach (array_keys($sbom['meta'] ?? []) as $cid) {
        if ($cid === VG_SBOM_HOST_CID || isset($ctrRows[$cid])) { continue; }
        $dropped[$cid] = ['packages' => 0, 'edges' => 0];
    }
    if (!$dropped) { return []; }
    foreach ($sbom['packages'] ?? [] as $r) {
        if (isset($dropped[$r[0]])) { $dropped[$r[0]]['packages']++; }
    }
    foreach ($sbom['deps'] ?? [] as $r) {
        if (isset($dropped[$r[0]])) { $dropped[$r[0]]['edges']++; }
    }
    return $dropped;
}

// ── pom.xml 최상위 <dependencies> 직접 선언 (best-effort, mvn 미호출) ────────
//   에이전트가 올린 형식: path|base64(pom.xml 원문). 옛 PR#399 는 awk 한 줄 파싱으로
//   <exclusions> 블록·한 줄 <parent> 를 잘못 잡아 오탐/0건이 났다 — DOMDocument 로 실제
//   XML 트리를 따라가 "루트 <project> 의 직계 자식인 <dependencies> 의 직계 자식 <dependency>"
//   만 골라낸다. <parent>·<dependencyManagement>·<exclusions> 안에 같은 태그가 있어도
//   경로가 다르므로 XPath 가 구조적으로 걸러낸다(한 줄 <parent> 형태도 자식 엘리먼트가
//   없어 애초에 매칭되지 않는다).
function vg_ingest_parse_pom_deps(string $text): array
{
    $rows = []; $seen = []; $dropped = 0;
    foreach (preg_split('/\r?\n/', $text) as $line) {
        if ($line === '') { continue; }
        $f = explode('|', $line, 2);
        if (count($f) !== 2 || trim($f[0]) === '' || $f[1] === '') { continue; }
        $xml = base64_decode($f[1], true);
        if ($xml === false || trim($xml) === '') { continue; }

        $prevErrors = libxml_use_internal_errors(true);
        $doc = new DOMDocument();
        // LIBXML_NONET: 외부 네트워크 참조 금지. 엔티티 확장(LIBXML_NOENT)은 절대 켜지 않는다(XXE 방지).
        $ok = @$doc->loadXML($xml, LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($prevErrors);
        if (!$ok) { continue; }

        $xpath = new DOMXPath($doc);
        $deps = $xpath->query('/*[local-name()="project"]/*[local-name()="dependencies"]/*[local-name()="dependency"]');
        if ($deps === false) { continue; }

        foreach ($deps as $depNode) {
            $g = ''; $a = ''; $v = ''; $scope = '';
            foreach ($depNode->childNodes as $child) {
                if ($child->nodeType !== XML_ELEMENT_NODE) { continue; }
                switch ($child->localName) {
                    case 'groupId':    $g = trim($child->textContent); break;
                    case 'artifactId': $a = trim($child->textContent); break;
                    case 'version':    $v = trim($child->textContent); break;
                    case 'scope':      $scope = trim($child->textContent); break;
                }
            }
            if ($g === '' || $a === '' || $v === '') { continue; }         // 버전 없음(부모/BOM 관리) → 해석 불가, 버림
            if (str_contains($g, '${') || str_contains($a, '${') || str_contains($v, '${')) { continue; } // 미해석 프로퍼티
            if ($scope === 'test' || $scope === 'provided') { continue; }   // 런타임 의존이 아님
            $name = "$g:$a";
            if (!vg_pkg_ident_valid($name) || !vg_pkg_ident_valid($v)) { continue; }
            $k = "$name|$v";
            if (isset($seen[$k])) { continue; }
            if (count($rows) >= VG_POM_DEP_EDGE_MAX) { $dropped++; continue; }
            $seen[$k] = true;
            $rows[] = ['maven', mb_strimwidth($name, 0, 255, ''), mb_strimwidth($v, 0, 255, '')];
        }
    }
    return ['rows' => $rows, 'dropped' => $dropped];
}
