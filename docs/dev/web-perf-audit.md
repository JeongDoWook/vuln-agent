# 전 화면 응답시간 감사 — 55개 화면을 재고, 두 곳만 고쳤다

> 측정일 2026-08-16 · 워크트리 `wt/perf-web-audit` · 포트 8091 ·
> 공용 dev DB(`vulnagent-db-dev`, MySQL 8.0.46) · Windows 11 · Docker Desktop
> 조치 대상은 **인덱스 2개 + 중복 질의 1개 제거**다. 쿼리 리라이트는 하나도 하지 않았다.

## 요약 (결론 먼저)

1. **55개 화면 중 사람이 체감할 만큼 느린 것은 하나였다 — `vendor.php` 761ms.**
   2위(`compliance.php` 280ms)의 2.7배이고, 전체 median(약 60ms)의 12배다.
2. **그 761ms 중 SQL 이 575~655ms(약 85%)였고, 그중 두 자리가 원인이었다.**
   ① 릴리스 필터 셀렉트를 채우려고 **56만 행을 훑어 값 2개**를 얻는 `DISTINCT`(163ms)
   ② `$total` 을 내려고 **바로 아래에서 이미 센 것과 똑같은 COUNT 를 한 번 더** 던지는 질의(187~227ms)
3. **같은 ①번 패턴이 `activity.php` 에도 있었다** — `DISTINCT scope` 하나가 그 화면 SQL 의 73%(86ms).
   두 화면의 병이 같아서 **인덱스 마이그레이션 하나로 같이 고쳤다.**
4. 조치 결과(전부 dev 실측, 아래 §5 에 원본):

   | | 조치 전 | 조치 후 | |
   |---|---:|---:|---|
   | `vendor.php` HTTP median | **760.8 ms** | **277.6 ms** | −64% |
   | `vendor.php` SQL 합계 | 575~655 ms | **212 ms** | −2.8배 |
   | `activity.php` HTTP median | **242.3 ms** | **52.9 ms** | −78% |
   | `activity.php` SQL 합계 | 119~121 ms | **38 ms** | −3.1배 |
   | 릴리스 옵션 질의(5-way UNION) | 167.5 ms | **1.30 ms** | **129배** |
   | `DISTINCT scope` | 85.6 ms | **17.0 ms** | 5.0배 |

   **화면 출력은 바이트 단위로 같다** — 필터 10조합에 대해 조치 전 코드와 `diff` 로 대조했다(§4-3).
5. **나머지 53개 화면은 손대지 않았다.** 재보니 손댈 곳이 없어서다. 다만 재는 중에
   **고칠 수 있지만 지금은 안 하기로 한 것 하나**를 찾았고(`tb_finding` 의 퇴화 인덱스,
   compliance.php 를 2.5배 늦추고 있다), 근거를 전부 §6 에 적어 다음 사람에게 넘긴다.

---

## 1. 측정 방법

### 1-1. 어디서 재나 — 컨테이너 내부

`docker exec` 로 **web 컨테이너 안에서 `curl http://localhost/...`** 를 친다. Caddy·TLS 와
Windows 의 호스트↔컨테이너 왕복을 빼서, 재는 대상이 **PHP + SQL** 만 남게 한다.

> 호스트에서 재면 왕복이 섞인다. `docs/dev/archive/packages-screen-profiling.md` 가
> 정적 파일 `app.css` 하나에 48ms 를 실측했고, 그건 화면이 어떻게 해도 못 줄이는 몫이다.
> 컨테이너 안에서 같은 파일이 **28~38ms** 다 — 이 문서의 모든 수치에서 그만큼이 바닥값이다.

### 1-2. 몇 번 재나 — 워밍업 1회 후 3회 median

1회 측정은 파일·버퍼풀 캐시 상태에 휘둘린다(이 저장소가 이미 겪은 것: `smoke-timing-profiling.md`
의 cold 9.3초 / warm 0.4초). 각 URL마다 **워밍업 1회 → 측정 3회 → median** 을 쓴다.

### 1-3. 무엇을 재나

- 목록 화면은 **1페이지와 깊은 페이지 양쪽**(OFFSET 이 큰 쪽이 느린 게 흔하다).
- 상세 화면은 **데이터가 가장 많은 대상**을 고른다 — `host_id=4391`(탐지 111,265건),
  `CVE-2023-44487`(탐지 462건), `kernel`(연관 CVE 3,249건).
- 로그인이 필요한 화면이 대부분이라 **이 워크트리 전용 계정**(`admin-perf-web-audit`)으로
  세션을 만든다. 공용 admin 을 쓰면 다른 워크트리의 스모크가 세션을 걷어차 302 가 섞인다
  (`tests/smoke.sh` 가 같은 이유로 워크트리별 계정을 만든다).

### 1-4. 화면 안을 어떻게 가르나 — PHP 시간 / SQL 시간

`server/src/db.php` 의 `vg_pdo()` 가 `function_exists()` 가드 안에 있다는 점을 이용해,
**계측판 `vg_pdo()` 를 먼저 정의해 두고** 화면 파일을 `require` 하는 CLI 프로파일러를 썼다.
`PDO::query()/exec()` 와 `PDOStatement::execute()` 를 감싸 질의별 경과를 모은다.

- 이 프로파일러는 **저장소에 남기지 않았다**(측정 후 삭제). 다시 필요하면 위 한 줄이 방법 전부다.
- **CLI 총시간은 믿지 않는다.** 같은 페이지가 198 / 1078 / 837 ms 로 튄다(opcache 없이 매번
  수십 개 파일을 파싱하는 CLI 특성). **질의별 SQL 시간만 안정적**이라 그것만 인용한다.
  화면 총시간은 §2 의 HTTP median 을 쓴다.
- `performance_schema.events_statements_summary_by_digest` 도 시도했으나 이 환경에서 웹
  컨테이너의 질의가 digest 에 잡히지 않아 접었다(원인은 캐지 않았다 — 위 방법으로 충분했다).

### 1-5. dev 데이터 규모 (측정 시점)

| 테이블 | 행 수 | | 테이블 | 행 수 |
|---|---:|---|---|---:|
| `tb_cve_affected_package` | 897,593 | | `tb_activity_log` | 77,333 |
| `tb_vendor_errata` | 569,803 | | `tb_debian_tracker` | 64,522 |
| `tb_ubuntu_oval` | 352,959 | | `tb_kernel_cve_fix` | 58,155 |
| `tb_finding` | 118,544 | | `tb_package_summary` | 38,213 |
| `tb_cve` | 30,784 | | `tb_cce_finding` | 8,529 |
| `tb_package` | 3,891 | | `tb_scan` | 237 · `tb_host` 11 |

---

## 2. 전 화면 응답시간 (조치 전)

워밍업 1회 후 3회 median. 컨테이너 내부 `curl`.

| 화면 | URL | median(ms) | 비고 |
|---|---|---:|---|
| **벤더 에라타** | `/vendor.php` | **760.8** | ← 1위. §3 에서 분해 |
| 컴플라이언스 | `/compliance.php` | 279.7 | SQL 272ms 중 236ms 이 SLA 집계 하나(§6) |
| 활동 로그 깊은p | `/activity.php?page=500` | 296.2 | ← §3-2 |
| 활동 로그 1p | `/activity.php` | 242.3 | ← §3-2 |
| 탐지결과 노출 | `/findings.php?tab=exposure` | 223.8 | SQL 80ms · 나머지는 렌더 |
| 의존성 그래프 | `/depgraph.php?id=4391` | 156.1 | 재현 안 됨(2차 31ms) — 노이즈 |
| 자산 상세 관리 | `/host.php?id=4391&tab=manage` | 139.4 | |
| 탐지결과 CVE 1p | `/findings.php` | 134.4 | |
| 탐지결과 CCE | `/findings.php?tab=cce` | 133.7 | |
| 탐지 이력 | `/finding_history.php?id=…&cve=…&pkg=kernel` | 133.5 | |
| 탐지결과 CVE 깊은p | `/findings.php?page=500` | 132.5 | 1p 와 같다 — 깊은 OFFSET 영향 없음 |
| 패키지 OS 1p | `/packages.php` | 126.8 | |
| 탐지결과 호스트필터 | `/findings.php?host=4391` | 121.6 | |
| 변경 추적 | `/changes.php` | 106.8 | |
| 자산 상세 취약점 | `/host.php?id=4391` | 99.1 | 본문 118KB(최대) |
| 자산 상세 런타임 | `/host.php?id=4391&tab=runtime` | 88.0 | |
| 대시보드 | `/index.php` | 84.6 | #617 이후 이미 잡혀 있다 |
| 자산 상세 계정 | `/host.php?id=4391&tab=accounts` | 85.2 | |
| 자산 상세 취약점 깊은p | `/host.php?id=4391&page=500` | 92.3 | |
| 자산 상세 보안설정 | `/host.php?id=4391&tab=cce` | 82.7 | |
| 자산 상세 스캔이력 | `/host.php?id=4391&tab=scans` | 81.8 | |
| 사용자 목록 | `/users.php` | 81.8 | |
| 패키지 OS 깊은p | `/packages.php?page=3000` | 80.6 | 38K행 카탈로그의 끝 |
| 자산 상세 억제 | `/host.php?id=4391&tab=suppressed` | 76.5 | |
| 보안설정 규칙상세 | `/cce-rule.php?code=CCE-SSH-ROOT` | 73.7 | |
| 통제 상세 | `/control.php?fw=KISA_U&control=U-01` | 69.6 | |
| 컴플라이언스 규칙목록 깊은p | `/compliance_rules.php?page=200` | 67.9 | |
| CVE 목록 깊은p | `/cves.php?page=500` | 66.9 | 1p(59.6)와 사실상 같다 |
| CVE 상세 | `/cve.php?cve=CVE-2023-44487` | 63.7 | 탐지 462건짜리 |
| 자산 상세 패키지 | `/host.php?id=4391&tab=packages` | 62.1 | |
| CVE 목록 1p | `/cves.php` | 59.6 | |
| 통제 매핑 | `/control_mapping.php` | 55.1 | |
| 미조치 패키지 | `/nofix-packages.php` | 53.6 | |
| 컴플라이언스 규칙상세 | `/compliance_rule.php?rule=account_…` | 53.7 | |
| 자산 목록 1p / 깊은p | `/assets.php` · `?page=2` | 50.8 / 50.0 | |
| 권한 | `/permissions.php` | 45.2 | |
| 컴플라이언스 규칙목록 1p | `/compliance_rules.php` | 41.8 | |
| 스타일가이드 | `/styleguide.php` | 39.8 | |
| 보안공지 목록 | `/advisories.php` | 39.1 | |
| 자산별 패키지 | `/asset-packages.php?host=4391` | 38.5 | |
| 설정 | `/settings.php` | 38.0 | |
| 패키지 언어탭 | `/packages.php?tab=lang` | 37.6 | dev 는 요약테이블 0행 — §6-4 |
| 수집 토큰 | `/agent-tokens.php` | 37.6 | |
| 패키지 상세 | `/package.php?name=kernel` | 35.5 | |
| 프로필 | `/profile.php` | 33.1 | |
| 보안설정 규칙목록 | `/cce-rules.php` | 32.1 | |
| 컨테이너 상세 | `/container.php?id=4391&cid=api` | 31.7 | |
| 사용자 상세 | `/user.php?id=1` | 28.8 | |
| 수집 제어 현황 | `/agent-command-overview.php` | 28.5 | |
| 보안공지 상세 | `/advisory.php?id=57` | 26.5 | |
| 커넥터 | `/connectors.php` | 21.5 | |
| **기준선** 정적 `app.css` | `/assets/app.css` | **28.3** | 144KB · PHP 무관 |
| **기준선** 로그인 GET | `/login.php` | 18.4 | 302 |

**읽는 법 하나**: 정적 파일 하나가 이미 28ms 다. 즉 표의 30~60ms 대 화면들은 사실상
**"PHP·SQL 이 거의 아무 일도 안 한다"** 는 뜻이고, 거기서 더 줄일 것은 없다.

`/sbom.php?host=4391` 은 404 다(정상 — `scan_id`·`cid` 가 필요한 내보내기 엔드포인트라
호스트만으로는 대상이 정해지지 않는다). 성능 대상이 아니라 표에서 뺐다.

---

## 3. 1·2위를 분해했다

### 3-1. `vendor.php` 760.8ms — SQL 이 85%

질의별 median(3회 실행의 대표값, 워밍업 후):

| 질의 | median | 하는 일 |
|---|---:|---|
| **총건수 5-way `UNION ALL COUNT`** | **186~227 ms** | `$total` |
| **릴리스 옵션 5-way `UNION DISTINCT`** | **167~226 ms** | 필터 셀렉트 채우기 |
| `COUNT(*) tb_vendor_errata` | 80~87 ms | 소스 탭 뱃지 |
| `COUNT(*) tb_ubuntu_oval` | 50~62 ms | 〃 |
| `COUNT(*)` 커널 CNA(JOIN) | 45~52 ms | 〃 |
| `COUNT(*) tb_debian_tracker` | 10~12 ms | 〃 |
| 목록 5-way UNION(갈래별 LIMIT) | **1.07 ms** | 표 본문 — 이미 잘 돼 있다 |
| `COUNT(*) tb_vendor_unfixed` | 0.71 ms | |
| **SQL 합계** | **575~655 ms** | 페이지의 약 85% |

목록 질의가 1ms 라는 데 주목한다 — **이 화면의 표를 그리는 부분은 이미 최적이다**(PR #280·#307
이 갈래별 LIMIT + 커버링 인덱스로 만들어 둔 구조가 정확히 제 일을 한다). 느린 것은 전부
**표 위쪽의 필터·뱃지를 채우는 곁다리 질의**였다.

#### ① 릴리스 옵션 — 56만 행을 읽어 값 2개

```sql
SELECT DISTINCT release_codename FROM tb_debian_tracker
UNION SELECT DISTINCT release_major   FROM tb_vendor_errata     -- ← 여기
UNION SELECT DISTINCT release_major   FROM tb_vendor_unfixed
UNION SELECT DISTINCT release_codename FROM tb_ubuntu_oval
UNION SELECT DISTINCT stream          FROM tb_kernel_cve_fix
ORDER BY rel
```

`EXPLAIN` 이 다섯 갈래의 운명을 그대로 보여준다:

```
tb_debian_tracker   type=range  key=uq_debtracker           rows=2       Using index for group-by
tb_vendor_errata    type=index  key=idx_vendor_errata_cve   rows=564541  Using index; Using temporary   ← 혼자 다르다
tb_vendor_unfixed   type=index  key=idx_vendor_unfixed_cve  rows=1772    Using index; Using temporary
tb_ubuntu_oval      type=range  key=uq_ubuntu_oval          rows=3       Using index for group-by
tb_kernel_cve_fix   type=range  key=idx_kcve_fix_stream     rows=41      Using index for group-by
```

세 갈래는 **느슨한 인덱스 스캔**(`Using index for group-by`)으로 값 목록만 훑어 rows 2~41 이다.
`tb_vendor_errata` 만 **56만 행 전체 스캔 + 임시테이블**이다. 이유는 인덱스 부재가 아니라
**컬럼의 위치**다:

```
uq_vendor_errata       seq=1 vendor(card 1)  seq=2 release_major  seq=3 pkg_name  seq=4 cve_id  seq=5 fixed_evr
idx_vendor_errata_cve  seq=1 cve_id          seq=2 pkg_name       seq=3 is_deleted seq=4 release_major
```

`release_major` 는 어느 인덱스에서도 **선두가 아니다**. 데비안·우분투는 자기 유니크 인덱스의
선두가 릴리스 컬럼이라 공짜였고, 에라타만 아니었다.

**`EXPLAIN ANALYZE` 로 확인한 실제 비용** — 전체 191ms 중 189ms 가 이 한 갈래다:

```
-> Sort: rel  (actual time=191..191 rows=51 loops=1)
    -> Union materialize with deduplication  (actual time=191..191 rows=51 loops=1)
        -> Covering index skip scan on tb_debian_tracker      (actual time=0.057..0.071 rows=1)
        -> Temporary table with deduplication                 (actual time=189..189 rows=2)     ← 189ms
            -> Covering index scan on tb_vendor_errata
               using idx_vendor_errata_cve  (actual time=0.124..89.2 rows=569803 loops=1)       ← 56.9만 행
        -> Temporary table with deduplication                 (actual time=0.668..0.669 rows=2)
        -> Covering index skip scan on tb_ubuntu_oval         (actual time=0.018..0.041 rows=3)
        -> Covering index skip scan on tb_kernel_cve_fix      (actual time=0.009..0.144 rows=45)
```

**569,803행을 읽어 값 2개를 얻는다.** 전체 결과는 51개짜리 셀렉트다.

#### ② 총건수 — 방금 센 것을 한 번 더 센다

`vendor.php` 는 `$total`(페이저용)과 `$srcCounts`(소스 탭 뱃지용)를 **따로** 구했다.

```php
// (구) $total — 5갈래 UNION ALL COUNT 한 방       ... 186~227ms
$stmt = $pdo->prepare('SELECT SUM(n) FROM (' . implode(' UNION ALL ', $countParts) . ') c');
// 바로 아래에서 같은 WHERE 로 5갈래를 다시 센다  ... 합계 약 200ms
foreach (VG_VENDOR_SRC as $srcKey => $srcDef) { /* COUNT(*) 5회 */ }
```

두 블록의 `WHERE` 는 **같은 함수 `vg_vendor_where($def, $q, $rel, …)` 로 만든다.** 그리고
`$active` 는 정의상 `src` 가 비면 5종 전부, 고르면 그 하나다. 따라서

- `src === ''` → `$total` = `array_sum($srcCounts)`
- `src !== ''` → `$total` = `$srcCounts[$src]`

가 **항상** 성립한다. 즉 같은 COUNT 를 두 번 센 것이고, 그 한 번이 186~227ms 였다.
`tb_vendor_errata` 는 56만 행이고 `COUNT` 에는 조기 종료가 없어 전건을 세야 한다.

### 3-2. `activity.php` 242.3ms — 한 질의가 SQL 의 73%

| 질의 | median |
|---|---:|
| **`SELECT DISTINCT scope FROM tb_activity_log WHERE is_deleted = 0 ORDER BY scope`** | **85.6 ms** |
| `COUNT(*) FROM tb_activity_log WHERE is_deleted = 0` | 18.6 ms |
| 사용자별 접속 현황(`tb_user`) | 3.9 ms |
| 목록 본문 `ORDER BY activity_log_id DESC LIMIT 10` | **0.40 ms** |
| SQL 합계 | 119~121 ms |

**①과 똑같은 병이다.**

```
tb_activity_log  type=index  key=idx_activity_scope  rows=76189  filtered=10  Using where
```

`idx_activity_scope` 는 `(scope, scope_id)` 라 **`is_deleted` 가 없다.** 그래서 인덱스를 끝까지
훑은 뒤 행마다 원본에서 `is_deleted` 를 다시 본다(`filtered=10%`). **76,189행을 읽어 값 15개**를 얻는다.

여기서도 목록 본문 질의는 0.40ms 다. 느린 건 필터 셀렉트를 채우는 곁다리다.

---

## 4. 조치

### 4-1. (a) 인덱스 — `db/migrations/20260816230500_perf_distinct_lookup_indexes.sql`

쿼리를 한 글자도 안 건드리는, 되돌리기가 `DROP INDEX` 두 줄인 조치다.

| 인덱스 | 노리는 것 |
|---|---|
| `tb_activity_log (is_deleted, scope)` | 조건이 인덱스 안에서 끝나게 |
| `tb_vendor_errata (release_major, is_deleted)` | `release_major` 를 **선두**로 올려 느슨한 인덱스 스캔 |

전후 실측:

| | 조치 전 | 조치 후 | 배수 | EXPLAIN 변화 |
|---|---:|---:|---:|---|
| `DISTINCT release_major`(에라타 단독) | 162.53 ms | **0.38 ms** | **428배** | `type=index rows=564541` → `type=range rows=2` `Using index for group-by` |
| 릴리스 옵션 5-way UNION 전체 | 167.54 ms | **1.30 ms** | **129배** | |
| `DISTINCT scope` | 85.59 ms | **16.99 ms** | 5.0배 | `type=index Using where` → `type=ref Using index` |
| `COUNT(*) tb_activity_log` | 18.61 ms | **11.35 ms** | 1.6배 | 새 인덱스가 덤으로 커버 |

`DISTINCT scope` 가 428배가 아니라 5배인 이유: MySQL 이 이 형태에서는 느슨한 인덱스 스캔이
아니라 `is_deleted = 0` 범위 `ref` 스캔(38,094행)을 골랐다. 그래도 원본 조회가 사라져
5배다. 더 짜내려면 질의를 `GROUP BY` 형태로 바꿔 봐야 하는데, **5배를 얻은 뒤의 15ms 를
위해 질의를 건드릴 이유가 없어** 하지 않았다.

**시도했다가 버린 인덱스 2개** (실측으로 효과 없음을 확인하고 마이그레이션에서 뺐다):

| 후보 | 결과 |
|---|---|
| `tb_vendor_errata (is_deleted, release_major)` — 순서 반대 | `DISTINCT` 162.53 → **159.62 ms**(개선 없음). `is_deleted` 조건이 없는 질의라 선두가 못 쓰인다. **순서가 전부다.** |
| `tb_ubuntu_oval (release_codename, is_deleted)` | `DISTINCT` 0.25 → 0.33 ms. 이미 `uq_ubuntu_oval` 선두가 릴리스라 **얻을 게 없다.** |
| `tb_finding (scan_id, severity, is_deleted)` | 옵티마이저가 **아예 안 골랐다**(§6-1). |

### 4-2. (c 아님) 중복 질의 제거 — `server/public/vendor.php`

`$total` 을 별도 질의로 세지 않고 **`$srcCounts` 의 부분합**으로 낸다.

```php
// 총건수는 위 5개를 더해서 낸다 — 세는 질의를 따로 던지지 않는다.
$total = 0;
foreach ($active as $srcKey => $_def) { $total += $srcCounts[$srcKey]; }
```

**이것은 SQL 리라이트가 아니다.** 남는 질의는 원래 있던 것 그대로이고, 없앤 질의는 그것들과
같은 값을 다시 계산하던 것뿐이다. `$active`/`$srcCounts` 가 같은 `vg_vendor_where()` 로
조건을 만든다는 사실이 동치성의 근거이고, 아래 §4-3 이 그것을 기계로 확인한다.

**효과: −186~227 ms** (질의 11개 → 10개).

### 4-3. 출력이 안 바뀌었는지 — 바이트 비교

인덱스는 결과를 바꾸면 안 되고, 바뀌면 버그다. 조치 전 코드를 `git show HEAD:… > _vendor_old.php`
로 나란히 띄우고(파일명이 링크에 박히므로 비교 전 정규화) 같은 세션으로 두 URL 을 받아 `diff` 했다.

```
동일  ?                          동일  ?q=CVE-2024          동일  ?page=3
동일  ?src=rhoval                동일  ?q=openssl           동일  ?src=rhoval&page=2&rel=9
동일  ?src=debtracker            동일  ?rel=9
동일  ?src=kcve                  동일  ?src=ubuntuoval&q=openssl
```

**10개 필터 조합 전부 바이트 단위로 동일.** 총건수·소스 탭 뱃지·페이저·표 본문이 모두 같다.

---

## 5. 조치 전후 — 전 화면

바뀐 화면만. 나머지 53개는 코드도 스키마도 안 건드렸으므로 §2 표가 그대로 유효하다.

| 화면 | 조치 전 | 조치 후 | |
|---|---:|---:|---|
| `/vendor.php` | **760.8 ms** | **277.6 ms** | −64% |
| `/activity.php` | **242.3 ms** | **52.9 ms** | −78% |
| `/activity.php?page=500` | 296.2 ms | 263.8 ms | −11% (§6-3) |

SQL 만 따로 보면(CLI 프로파일러, 워밍업 후 3회):

| | 조치 전 | 조치 후 |
|---|---|---|
| `vendor.php` SQL 합계 | 575.0 / 591.0 / 654.4 ms | **212.0 / 214.8 ms** |
| `activity.php` SQL 합계 | 119.1 / 120.6 ms | **37.6 / 39.0 ms** |

`vendor.php` 에 남은 212ms 는 **소스 탭 뱃지용 `COUNT(*)` 5개**(에라타 78ms + 우분투 50ms +
커널 50ms + 데비안 10ms + 미수정 0.7ms)다. `is_deleted` 는 값이 사실상 하나뿐인 컬럼이라
어떤 인덱스를 붙여도 **56만 행을 다 세야 한다** — 인덱스로 없앨 수 있는 비용이 아니다.
없애려면 뱃지를 사전집계하거나 화면에서 빼야 하는데, 둘 다 이 화면의 존재 이유(“소스별로
얼마나 있나”가 진입점, PR #307)를 건드리므로 **하지 않았다.**

> **절대값 주의**: 공용 dev DB 는 다른 워크트리와 공유한다. 최종 측정 시점에 web 컨테이너가
> 4개 떠 있었다(다른 워커 3개). 그래서 §5 의 “조치 후” 절대값에는 경합이 섞여 있고,
> 실제 개선폭은 여기 적힌 것보다 크면 컸지 작지 않다. **경합에 안 흔들리는 지표는
> §4-1 의 질의별 median 과 EXPLAIN 계획**이라 판단 근거는 그쪽에 뒀다.

---

## 6. 하지 않기로 한 것 — 그리고 그 이유

### 6-1. `compliance.php` 280ms — 원인은 찾았지만 조치는 넘긴다 ★

**2위 화면이고, 원인이 명확하며, 고치면 2.5~3배다.** 그런데도 이번에 안 넣었다.

SQL 272ms 중 **236~255ms 가 SLA 경과일 집계 하나**다(`server/src/compliance/patch.php:174`,
`server/src/finding_sla.php` 와 `server/src/findings/queries.php` 도 같은 형태를 쓴다):

```sql
SELECT s2.host_id, COALESCE(c2.cid,'') AS cid, f2.cve_id, f2.package_name,
       MIN(COALESCE(s2.received_at, s2.collected_at)) AS first_seen, DATEDIFF(…) AS days_since
  FROM tb_finding f2
  JOIN tb_scan s2 ON s2.scan_id = f2.scan_id AND s2.is_deleted = 0
  LEFT JOIN tb_container c2 ON c2.container_id = f2.container_id AND c2.is_deleted = 0
 WHERE f2.scan_id IN (250개) AND f2.severity IN ('CRITICAL','HIGH') AND f2.is_deleted = 0
 GROUP BY s2.host_id, cid, f2.cve_id, f2.package_name
```

`EXPLAIN` 이 이상하다 — **딱 맞는 인덱스를 두고 쓸모없는 인덱스를 고른다:**

```
f2  type=ref  key=idx_findings_is_deleted  rows=60534  filtered=34.8%  Using where; Using temporary
```

`idx_findings_is_deleted` 는 **`is_deleted` 한 컬럼짜리 인덱스이고 카디널리티가 1** 이다.
값이 하나뿐인 컬럼의 인덱스라 거르는 힘이 0 인데, 옵티마이저는 이쪽을 골라 60,534행을 훑는다.
`idx_find_scan_sev (scan_id, severity)` 는 이 `WHERE` 에 정확히 맞고 **498행**이면 된다.

실측 4종(결과 행 수는 넷 다 540 으로 동일 — 계획만 다르다):

| 조건 | median | `f2` 계획 |
|---|---:|---|
| 현재 | **205.98 ms** | `key=idx_findings_is_deleted rows=60534` |
| `FORCE INDEX (idx_find_scan_sev)` | **72.98 ms** | `key=idx_find_scan_sev rows=498` |
| 새 인덱스 `(scan_id, severity, is_deleted)` 추가 | 207.58 ms | **안 골랐다** — 여전히 is_deleted |
| `idx_findings_is_deleted` **삭제** | **85.82 ms** | `type=ALL`(풀스캔인데도 2.4배 빠르다) |
| `idx_findings_is_deleted` 삭제 + `eq_range_index_dive_limit=1000` | **72.19 ms** | `key=idx_find_scan_sev rows=21330` |

`eq_range_index_dive_limit`(기본 200 < 레인지 500개)만 올리는 것으로는 **계획이 안 바뀌었다**
(215.03 → 206.24ms). #617 마이그레이션이 남긴 “남은 것” 과는 **다른 원인**이라는 뜻이다.

**즉 근본 원인은 `idx_findings_is_deleted` 라는 퇴화 인덱스가 옵티마이저를 오도하는 것**이고,
고치는 방법은 그 인덱스를 지우는 것이다. 회귀 여부도 실제로 쟀다 — tb_finding 을 무겁게
쓰는 화면 8개 × 3회, 인덱스 있음/없음 SQL 합계 median:

| 화면 | 인덱스 있음 | 인덱스 없음 |
|---|---:|---:|
| `compliance.php` | 271.7 ms | **152.6 ms** |
| `index.php` | 91.4 | 93.9 |
| `findings.php` | 110.8 | 118.2 |
| `findings.php?host=4391` | 48.5 | 51.3 |
| `host.php?id=4391` | 30.4 | 33.9 |
| `cves.php` | 15.9 | 10.2 |
| `changes.php` | 39.4 | 33.8 |
| `assets.php` | 35.3 | 21.1 |

**한 화면만 크게 좋아지고 나머지는 노이즈 범위(±10ms)다. 나빠진 화면은 없었다.**
코드에 `FORCE INDEX(idx_findings_is_deleted)` 같은 참조도 없다(정의는 `db/02-matcher.sql:110`
한 곳뿐).

**그럼 왜 안 넣나.**

1. **`DROP INDEX` 는 `ADD` 와 위험 등급이 다르다.** 되돌릴 수는 있지만(한 줄), 되돌리는 동안
   운영 최대 테이블(143만 행)에 인덱스를 다시 만들어야 한다.
2. **이 저장소는 dev 수치가 운영에서 뒤집힌 전례가 있다.** #617 이 dev 0.65ms / 운영 1,554ms
   로 **2,392배** 차이였다. 여기 dev 는 118,544행이고 운영은 143만 행 — 12배다. 옵티마이저의
   인덱스 선택은 통계에 좌우되고, 통계는 행 수에 좌우된다. **운영에서 같은 계획을 고르는지
   확인 없이 최대 테이블의 인덱스를 지우는 것은 이 작업의 지시(“위험도 낮은 순”)를 벗어난다.**
3. 이 브랜치의 조치 2개는 **`ADD` 뿐이라 서로 독립**이다. 이걸 같이 넣으면 문제가 났을 때
   무엇을 되돌려야 하는지가 흐려진다.

**넘기는 절차(운영에서 사람이 확인할 것)** — 운영 접속은 이 작업의 범위 밖이다.

```sql
-- ① 운영에서 지금 계획이 dev 와 같은지부터 본다(읽기만 한다)
EXPLAIN <위 SLA 집계 질의>;      -- key 가 idx_findings_is_deleted 면 dev 와 같은 병이다
-- ② 같다면 힌트로 이득을 먼저 확인한다(스키마 변경 없음)
EXPLAIN ANALYZE SELECT … FROM tb_finding f2 FORCE INDEX (idx_find_scan_sev) …;
-- ③ ②에서 이득이 확인되면 그때 인덱스를 지우는 마이그레이션을 별도 PR 로 낸다
--    DROP INDEX idx_findings_is_deleted ON tb_finding;
--    되돌리기: CREATE INDEX idx_findings_is_deleted ON tb_finding (is_deleted);
```

**`FORCE INDEX` 를 코드에 박는 길은 택하지 않는다** — 이 저장소가 이미 “옵티마이저 강제 힌트는
데이터 분포가 바뀌면 발목을 잡는다, 구조적 개선이 안전하다”로 결론 낸 자리다(PR #354).
②는 어디까지나 **측정용**이지 넣자는 제안이 아니다.

### 6-2. `findings.php?tab=exposure` 223.8ms — SQL 은 80ms, 나머지는 렌더

이 화면의 SQL 합계는 **80.0~82.9ms 로 안정적**이고, 그중 최대가 CVE 탭 목록 41~53ms 다.
나머지는 PHP 렌더인데, CLI 로 3회 재보니 198 / 1078 / 838 ms 로 튀어서(opcache 없는 CLI 특성)
**의미 있는 렌더 병목을 특정하지 못했다.** HTTP 재측정에서도 223.8 → 152.1 → 128.9 → 221.9ms
로 흔들린다. **재현되지 않는 것은 고치지 않는다.**

덧붙여 이 화면은 **손대지 말라고 명시된 자리**다 — 세 탭을 UNION 하면 인덱스가 죽어 235ms 가
42초가 된 운영 실측이 있다(#555). 쿼리층 `server/src/findings/queries.php` 는 이 브랜치 기간에
다른 워커가 만지고 있어 애초에 범위 밖이다.

### 6-3. 깊은 OFFSET — 재봤더니 문제가 아니었다

목록 화면은 전부 1페이지와 깊은 페이지를 나란히 쟀다.

| 화면 | 1p | 깊은 p | |
|---|---:|---:|---|
| `/findings.php` | 134.4 | 132.5 (page=500) | **차이 없음** |
| `/cves.php` | 59.6 | 66.9 (page=500) | 차이 없음 |
| `/assets.php` | 50.8 | 50.0 (page=2) | 차이 없음 |
| `/packages.php` | 126.8 | 80.6 (page=3000) | 오히려 빠름 |
| `/compliance_rules.php` | 41.8 | 67.9 (page=200) | +26ms |
| `/activity.php` | 242.3 | 296.2 (page=500) | +54ms |

`activity.php` 깊은 페이지만 남는다(조치 후 52.9 vs 263.8). `ORDER BY activity_log_id DESC
LIMIT 10 OFFSET 4990` 이 버리는 4,990행 몫이다. keyset 페이징으로 상수화할 수는 있으나,
**감사로그 500페이지로 이동하는 사용자가 있는가**가 먼저다 — 이 화면에는 기간·사용자·IP·
수행업무 필터가 이미 다 있어서 깊이 파고들 이유가 좁혀진다. 근거 없이 복잡도만 늘리므로 안 한다.
(같은 판단이 `packages-screen-profiling.md` 안 F 에도 있다.)

### 6-4. 언어 패키지 탭 — dev 로는 “빠르다”고 말할 수 없다

`/packages.php?tab=lang` 이 37.6ms 지만, dev 의 `tb_package_license_summary` 가 **0행**이라
**이 숫자는 무의미하다.** 이건 새 발견이 아니라 `packages-screen-profiling.md` §6-3 이 이미
적어 둔 것이고, 이번 측정도 그 상태 그대로다. **운영에서 다시 재야 한다.**

### 6-5. 이미 최적이라 결론난 자리 — 확인만 하고 지나갔다

측정 결과가 “이미 잡혀 있다”는 기존 결론과 일치했다. 아무것도 안 했다.

| 자리 | 이번 측정 | 근거 |
|---|---|---|
| 대시보드 대응 우선순위 쿼리 | `/index.php` 84.6ms — 상위권 아님 | 파생테이블 리라이트가 235ms→42초를 만들었다 |
| `findings.php` 세 탭 | SQL 80ms · 탭별 질의 하나씩 | UNION 하면 인덱스가 죽는다(#555) |
| `changes.php` 벌크로드 | 106.8ms | SQL 페이징으로 바꾸면 30초+(#292) |
| `host.php`·`assets.php` 탭 지연 로딩 | 탭별 45~110ms | 합치지 않는다(#579) |
| `tb_package_summary` 사전집계 | `/packages.php` 126.8ms, 상세 35.5ms | 8s→0.05s 로 이미 잡힘 |
| `tb_finding STATS_SAMPLE_PAGES=200` | 대시보드 84.6ms | #617 로 이미 적용 |

---

## 7. 남는 것

- **필터 셀렉트를 채우는 `DISTINCT` 는 이 저장소의 반복 패턴이다.** 두 화면에서 같은 모양으로
  나왔고 둘 다 같은 처방(그 컬럼을 선두로 둔 인덱스)으로 고쳐졌다. 새 화면에 필터 셀렉트를
  붙일 때는 **그 컬럼이 어느 인덱스의 선두인지**를 먼저 본다. 아니면 `EXPLAIN` 의
  `Using index for group-by` 가 사라지고 테이블 크기만큼 읽는다.
- **곁다리 질의가 본 질의보다 비쌀 수 있다.** `vendor.php` 는 표 본문이 1.07ms 인데 필터·뱃지가
  600ms 였고, `activity.php` 는 본문 0.40ms 에 필터가 86ms 였다. 화면을 프로파일할 때
  “목록 쿼리”부터 보는 습관이 두 번 다 헛다리였다.
- **`compliance.php` 는 원인까지만 갔다**(§6-1). 운영에서 `EXPLAIN` 한 번이면 판단이 끝나고,
  맞으면 `DROP INDEX` 한 줄짜리 후속 PR 이다.
