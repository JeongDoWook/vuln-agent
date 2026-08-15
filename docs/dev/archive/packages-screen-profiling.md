# 패키지 카탈로그 화면 프로파일링 — 스모크 `[패키지 서브탭]` 14초의 실제 출처

> 측정일 2026-08-12 · 워크트리 `wt/packages-profile` · dev 공용 DB(`vulnagent-db-dev`, MySQL 8.0.46)
> **이 문서는 측정과 제안까지다. 쿼리·인덱스·스키마를 바꾸지 않았다**(`git diff --stat` 0).

## 요약 (결론 먼저)

세 줄로 줄이면:

1. **`packages.php` 는 느리지 않다.** OS 탭 median **91 ms**, 언어 탭 **102 ms**, 상세 **62 ms**.
   14초와는 두 자릿수 차이다.
2. **`[패키지 서브탭]` 이라는 이름이 잘못됐다.** 그 구간은 smoke.sh **650–865행, 129개 명령**으로
   host.php·depgraph.php·findings.php·cve.php·agent-progress.php 까지 전부 들어 있다.
   패키지 화면 3개 요청은 그 구간의 **약 0.3초**, 즉 **2.6%** 뿐이다.
3. **구간 11.4초 중 7.0초(61%)가 서버와 무관한 `assert_*` 의 `grep` 프로세스 스폰이다.**
   Windows git-bash 에서 fork 한 번이 44–48 ms 인데 그게 65번 돈다. DB 도 PHP 도 아니다.

그래서 **지금 이 화면에 쿼리·인덱스 변경을 넣을 근거가 없다.** 그럼에도 실측 중
운영에서 문제가 될 수 있는 지점 하나(정렬 타이브레이크로 인한 풀스캔+filesort)를 찾았고,
**참조 카탈로그 화면이라 우선순위는 낮게** 잡는 것이 이 문서의 추천이다.

---

## 1. 측정 방법

### 1-1. 환경

| 항목 | 값 |
|---|---|
| 스택 | `wt/packages-profile` 전용 web+scheduler (`vulnagent-web-dev-packages-profile`), 포트 8090 |
| DB | 공용 dev DB `vulnagent-db-dev` · MySQL **8.0.46** |
| 계정 | `admin-packages-profile` (스모크가 만드는 워크트리 전용 계정 — 세션 격리) |
| 측정 | 워밍업 1회 후 **12회**, **median**·min·max 병기 |

### 1-2. 도구

- **HTTP 응답 시간**: 로그인 세션(cookie jar)으로 `curl -w '%{time_total}'`, 12회 median.
- **구간 내부 분해**: `tests/smoke.sh` 사본에 `DEBUG` trap 을 걸어 **최상위 명령별 경과**를 기록.
  `$EPOCHREALTIME` + 순수 bash 산술만 써서 계측 자체가 프로세스를 스폰하지 않게 했다.
  DEBUG trap 은 명령 **직전**에 발화하므로 기록된 경과는 **앞 명령**의 것이다 — 후처리에서 한 칸 밀어 보정했다.
- **SQL**: `server/bin/` 에 임시 스크립트를 두고 컨테이너 PHP 로 실행(`PDO`, 12회 median) +
  `EXPLAIN` / `EXPLAIN ANALYZE` / `SHOW INDEX`. **읽기와 EXPLAIN 만 했고, 측정 후 파일은 삭제했다.**

### 1-3. 데이터 규모 (dev, 측정 시점)

| 테이블 | 행 수 |
|---|---:|
| `tb_cve_affected_package` (원본) | 895,636 |
| `tb_package_summary` (사전집계) | **21,370** |
| `tb_package_license_summary` | **0** ← 주의, 아래 §5 |
| `tb_package` | 3,345 |
| `tb_scan` | 210 |
| `tb_host` | 12 |

---

## 2. 어느 요청이 느린가 — 전부 아니다

`[패키지 서브탭]` 구간이 실제로 치는 모든 URL 을 각 12회 재고 median 을 냈다.

| 요청 | median | min | max | 응답 크기 |
|---|---:|---:|---:|---:|
| `/packages.php` (OS 탭) | **0.091 s** | 0.057 | 0.163 | 22 KB |
| `/packages.php?tab=lang` | **0.102 s** | 0.056 | 0.137 | 19 KB |
| `/packages.php?tab=zzz` (OS 폴백) | 0.103 s | 0.074 | 0.124 | 22 KB |
| `/packages.php?q=glibc` | 0.079 s | 0.066 | 0.306 | 24 KB |
| `/package.php?name=glibc` (상세) | **0.062 s** | 0.045 | 0.123 | 12 KB |
| `/package.php?name=kernel` | 0.069 s | 0.051 | 0.135 | 12 KB |
| `/language-packages.php?q=test` (302) | 0.022 s | 0.010 | 0.036 | – |
| `/host.php?id=W1` (취약점 탭) | 0.128 s | 0.094 | 0.198 | 113 KB |
| `/host.php?id=W1&tab=manage` | 0.104 s | 0.077 | 0.279 | 30 KB |
| `/host.php?id=W1&tab=scans` | 0.115 s | 0.101 | 0.273 | 48 KB |
| `/host.php?id=W1&tab=packages` | 0.093 s | 0.053 | 0.216 | 18 KB |
| `/host.php?id=W1&tab=runtime` | 0.108 s | 0.073 | 0.237 | 19 KB |
| `/host.php?id=W2&tab=suppressed` | 0.089 s | 0.074 | 0.204 | 37 KB |
| `/depgraph.php?id=W1` | 0.077 s | 0.049 | 0.122 | 13 KB |
| `/findings.php` | 0.111 s | 0.088 | 0.209 | 35 KB |
| `/findings.php?host=W1` | 0.098 s | 0.059 | 0.174 | 35 KB |
| `/cve.php?cve=CVE-2023-4911&per_page=100` | 0.081 s | 0.053 | 0.172 | 29 KB |
| `/assets.php?q=web01` | 0.078 s | 0.070 | 0.187 | 25 KB |
| **기준선** `/assets/app.css` (정적, PHP 무관) | **0.048 s** | 0.031 | 0.090 | 135 KB |
| **기준선** `/login.php` GET | 0.032 s | 0.015 | 0.099 | – |

**이 구간의 어떤 요청도 0.15초를 넘지 않는다.** 34번의 curl 을 전부 합쳐도 **2.92초**다.

정적 파일 하나가 이미 48 ms 라는 점에 주목한다 — Windows Docker 의 HTTP 왕복 자체가
그만큼이다. 즉 `packages.php` 의 91 ms 중 **절반은 페이지가 아니라 왕복 비용**이다.

## 3. 그럼 14초는 어디서 오나 — `grep` 프로세스 스폰

DEBUG trap 으로 구간 129개 명령을 분해한 결과(off-by-one 보정 후):

| 분류 | 합계 | 건수 | 평균 | 비중 |
|---|---:|---:|---:|---:|
| **`assert_*` (grep 스폰)** | **6.96 s** | 65 | 107 ms | **61.1 %** |
| `curl` (HTTP 요청) | 2.92 s | 34 | 86 ms | 25.6 % |
| 기타 외부명령(grep/sed/mktemp) | 0.84 s | 8 | 105 ms | 7.4 % |
| 순수 bash | 0.56 s | 18 | 31 ms | 4.9 % |
| `docker exec` | 0.11 s | 3 | 37 ms | 1.0 % |
| **합계** | **11.38 s** | 128 | | |

계측 오버헤드(trap 자체)가 얹혀 이 실행은 11.4초였고, 계측 없는 실행에서 14.0초로 보고됐다.
**어느 쪽이든 결론은 같다 — 단일 병목이 없다.** 가장 느린 한 줄이 677 ms 이고, 그 다음이
532 ms 다. 나머지는 100–250 ms 짜리가 100개 넘게 늘어선 롱테일이다.

가장 느린 15줄:

```
    677 ms  cancel_check=$(curl_ -s -X POST .../agent-progress.php ...)
    532 ms  supbody=$(curl_ -s -b "$JAR" ".../host.php?id=$WEB02_ID&tab=suppressed")
    497 ms  progress_resp=$(curl_ -s -X POST .../agent-progress.php ...)
    307 ms  grep -q 'nginx' <<< "$supbody"
    257 ms  assert_contains "$body" "올바르지 않습니다" ...
    245 ms  assert_not_contains "$hostvuln" 'name="action" value="agent_run_now"' ...
    241 ms  assert_contains "$body" "패키지 DB 가 없는 이미지" ...
    231 ms  body=$(curl_ ... --data-urlencode "password=WRONG" ".../login.php")
    220 ms  assert_contains "$body" "판정 불가" ...
    218 ms  assert_contains "$body" "최고 위험도" ...
    192 ms  assert_contains "$hostvuln" 'tab=manage' ...
    183 ms  assert_contains "$body" "redis" ...
    182 ms  assert_contains "$frombody" '이 패키지를 끌어온 경로' ...
    178 ms  assert_contains "$langtabbody" "언어 패키지" ...
    175 ms  assert_contains "$upbody" "upsvc" ...
```

`assert_contains` 는 서버를 치지 않는다 — 이미 받아둔 문자열에 `grep -q` 를 돌릴 뿐이다:

```sh
assert_contains() { if grep -q "$2" <<<"$1"; then ok "$3"; else no "$3  ('$2' 없음)"; fi; }
```

이 호스트에서 `grep` **한 번 스폰 비용**을 따로 쟀다:

| | 평균 |
|---|---:|
| `grep -q` 스폰 — 11바이트 문자열 | **44 ms** |
| `grep -q` 스폰 — 113 KB 문자열 | **48 ms** |
| bash 내장 `[[ "$big" == *needle* ]]` — 113 KB | **1.3 ms** |

**본문 크기와 거의 무관하다.** 44 ms 는 전부 Windows 의 `fork`/`CreateProcess` 비용이다.
즉 `[패키지 서브탭]` 구간의 61%는 **서버 성능이 아니라 스모크 하니스의 프로세스 스폰**이다.

## 4. 그래도 쿼리를 다 봤다 — 정렬 타이브레이크가 풀스캔을 부른다

화면이 빠르다고 쿼리가 건강한 건 아니다. `packages.php` 가 실제로 던지는 쿼리를 전부 쟀다.

### 4-1. OS 탭 (`tab=os`, 무필터, 1페이지) — SQL 합계 ≈ 29.6 ms

| # | 쿼리 | median | 계획 |
|---|---|---:|---|
| Q1 | `SELECT DISTINCT ecosystem … ORDER BY ecosystem` | **8.36 ms** | `type=index` · `Using temporary; Using filesort` · rows=20825 |
| Q2 | `SELECT MAX(updated_at)` | 4.19 ms | |
| Q3 | `SELECT COUNT(*) … WHERE 1=1` | 2.36 ms | `type=index` · `Using index` (커버링) |
| Q4 | 목록 `ORDER BY cve_cnt DESC, package_name ASC LIMIT 50` | **14.58 ms** | **`type=ALL` · `Using filesort`** |
| Q4b | 목록 `ORDER BY max_epss DESC, package_name ASC` | 14.47 ms | 동일(풀스캔+filesort) |
| Q4c | 목록 `ORDER BY package_name …` | **0.35 ms** | PRIMARY 사용 |
| Q5 | `q=glibc` COUNT (`LIKE '%glibc%'`) | 5.69 ms | 커버링 인덱스 스캔, filtered 11.1% |
| Q6 | `q=glibc` 목록 | 9.79 ms | |
| Q7 | 마지막 페이지 `OFFSET 21000` | **58.88 ms** | 깊은 OFFSET |

### 4-2. 주범 확정 — 원인은 인덱스 부재가 아니라 **타이브레이크**

`idx_psum_cve (cve_cnt)` 는 **이미 있다.** 그런데 Q4 는 그걸 안 쓴다. 왜인지 실측했다.

```
현재 쿼리 (ORDER BY cve_cnt DESC, package_name ASC)      median = 14.57 ms
-> Limit: 50 row(s)  (cost=2133 rows=50) (actual time=15.8..15.8 rows=50 loops=1)
    -> Sort: cve_cnt DESC, package_name, limit input to 50 row(s) per chunk
             (cost=2133 rows=20825) (actual time=15.8..15.8 rows=50 loops=1)
        -> Table scan on tb_package_summary
             (cost=2133 rows=20825) (actual time=0.0355..7.41 rows=21370 loops=1)

타이브레이크 제거 (ORDER BY cve_cnt DESC 만)             median =  0.35 ms
-> Limit: 50 row(s)  (cost=0.133 rows=50) (actual time=0.023..0.0959 rows=50 loops=1)
    -> Index scan on tb_package_summary using idx_psum_cve (reverse)
             (cost=0.133 rows=50) (actual time=0.0225..0.0928 rows=50 loops=1)

FORCE INDEX(idx_psum_cve) + 타이브레이크                  median = 14.24 ms
    ...여전히 Table scan + Sort (강제해도 옵티마이저가 인덱스를 못 살린다)

FORCE INDEX(idx_psum_cve), 타이브레이크 없음              median =  0.39 ms
    -> Index scan using idx_psum_cve (reverse)
```

**결론: `package_name ASC` 타이브레이크 하나가 14.6 ms 중 14.2 ms 를 만든다(41배).**
단일 컬럼 인덱스 `(cve_cnt)` 로는 2차 정렬을 줄 수 없어 MySQL 이 21,370행을 통째로 읽고 정렬한다.
`FORCE INDEX` 로도 안 되는 건, 인덱스를 써도 어차피 전체를 정렬해야 하기 때문이다.

같은 이유로 `sort=epss`(`max_epss DESC, package_name ASC`)도 14.5 ms 다.
`sort=package` 만 PRIMARY 를 타서 0.35 ms 다.

> 타이브레이크는 **없애면 안 된다.** 동점이 흔한 데이터(상위 8종이 전부 3,246건)라
> 타이브레이크 없이는 페이지를 넘길 때 행이 중복·누락된다. 화면은 이미 `same_agg` 로
> "동일 집계"를 표시할 만큼 동점이 많다는 걸 전제하고 있다.

### 4-3. `ecosystem` 에는 인덱스가 없다

```
--- SHOW INDEX FROM tb_package_summary ---
  PRIMARY        seq=1 col=package_name   card=13295
  PRIMARY        seq=2 col=ecosystem      card=20825
  idx_psum_cve   seq=1 col=cve_cnt        card=189
  idx_psum_epss  seq=1 col=max_epss       card=1268
```

`ecosystem` 은 PRIMARY 의 **두 번째** 컬럼이라 선두가 아니다 → `WHERE ecosystem = ?` 도,
Q1 의 `DISTINCT ecosystem` 도 인덱스를 못 쓴다.

```
eco 필터 (Debian:12, 29행 = 0.1%)     median =  7.80 ms   → Table scan 21,370행 후 Filter
eco 필터 (Ubuntu:24.04, 9,665행 = 45%) median = 11.62 ms   → Table scan 21,370행 후 Filter
```

**배포판 분포가 극단적으로 치우쳐 있다** — 이게 §6 위험 판단의 핵심이다:

| ecosystem | 행 수 | 비중 |
|---|---:|---:|
| Ubuntu:24.04 | 9,665 | 45.2 % |
| Oracle Linux:8 | 4,487 | 21.0 % |
| Red Hat:8 | 4,312 | 20.2 % |
| Red Hat:9 | 2,864 | 13.4 % |
| Debian:12 | 29 | 0.1 % |
| Rocky Linux:9 / PyPI / Alpine / Go / Bitnami | 11 | ~0 % |

### 4-4. 언어 탭 (`tab=lang`) — dev 수치를 믿으면 안 되는 구간

| # | 쿼리 | median |
|---|---|---:|
| L1 | `MAX(updated_at) FROM tb_package_license_summary` | 0.27 ms |
| L2 | `SELECT risk, SUM(pkg_count) … GROUP BY risk` | 0.57 ms |
| L3 | `COUNT(*)` 5-way JOIN | 1.69 ms |
| L4 | 목록 `ORDER BY p.name, h.fqdn, p.version, p.package_id LIMIT 50` | 1.65 ms |

빠르지만 **이 숫자는 무의미하다** — dev 의 `tb_package_license_summary` 가 **0행**이고
`tb_package` 가 3,345행뿐이다. L4 의 계획을 보면 구조적 위험이 보인다:

```
h            type=ALL      rows=12     Using where; Using temporary; Using filesort   ← 드라이빙 테이블
<derived2>   type=ref      rows=11     <auto_key0>                                    ← vg_latest_scan_subq()
s            type=eq_ref   rows=1
p            type=ref      rows=16     key=idx_pkg_scan   filtered=34.5%
c            type=eq_ref   rows=1
sm           type=eq_ref   rows=1      key_len=2110                                   ← (manager,name,license) PK
DERIVED      tb_scan       rows=210    key=idx_scans_is_deleted   Using temporary
```

- `Using temporary; Using filesort` 가 **드라이빙 테이블에** 붙어 있다 → 정렬이
  `LIMIT` 전에 **조인 결과 전체**에 걸린다. 지금은 그 전체가 3천 행이라 안 아프다.
- `sm` 조인 키가 **2110바이트**다. 요약 테이블이 비어 있어 지금은 공짜지만,
  운영에서 행이 차면 이 폭의 키로 인스턴스마다 eq_ref 를 한다.
- 파생 서브쿼리 `vg_latest_scan_subq()` 가 `Using temporary` + `<auto_key0>` 다 —
  스캔 수가 늘면 여기가 먼저 무너진다(dev 210행).

## 5. 개선안 비교

| # | 안 | 얻는 것 | 비용·위험 | dev 실측 근거 |
|---|---|---|---|---|
| **A** | `tb_package_summary` 에 **복합 내림차순 인덱스** `(cve_cnt DESC, package_name ASC)` + `(max_epss DESC, package_name ASC)` 추가 | Q4·Q4b 를 filesort 없이 index scan 으로. 14.6 ms → **0.4 ms 수준 기대** | 인덱스 2개 추가 = 요약 재구성(`DELETE`+`INSERT` 21K행) 쓰기 비용 소폭 증가. OSV 커넥터 직후 **한 번만** 도는 배치라 체감 영향 거의 없음. 되돌리기 = `DROP INDEX` 한 줄. **MySQL 8.0 이상 필수**(내림차순 인덱스). 운영 8.0.x 확인 필요 | 타이브레이크 제거 시 0.35 ms / `FORCE INDEX` 만으로는 14.2 ms — 즉 **정확히 이 복합 인덱스가 없어서** 생기는 비용 |
| **B** | `(ecosystem, cve_cnt DESC, package_name)` 복합 인덱스 | 배포판 필터 + 정렬을 한 번에 | **분포가 치우쳐 있어 효과가 배포판마다 뒤집힌다.** Debian:12(0.1%)엔 큰 이득, Ubuntu:24.04(45%)엔 거의 무의미(어차피 절반을 읽는다). 인덱스 3개째 | eco 필터 실측 7.8 / 11.6 ms · 분포표 §4-3 |
| **C** | 쿼리 재작성 (파생테이블·`GROUP BY` 재구성 등) | – | **권하지 않는다.** 대시보드 대응 우선순위에서 이 방식이 dev 235 ms → 운영 42초(180배)로 뒤집힌 전례가 있다. 지금 쿼리는 단일 테이블 조회라 재작성으로 얻을 게 없다 | `docs`/메모리의 `dashboard-urgent-query-leave-alone` |
| **D** | 사전집계 확장 | – | **이미 충분하다.** 화면이 원본 `tb_cve_affected_package`(89.6만 행)를 다시 훑는 부분은 **없다.** 4개 쿼리 전부 21K행 요약만 읽는다. 더할 것이 없다 | §4-1 EXPLAIN 전부 `table=tb_package_summary` |
| **E** | 화면 쪽 (기본 페이지 크기·컬럼 접기) | – | **효과 없음.** per_page 10→100 (행 10배)에서 91→112 ms 로 사실상 평탄하다. 렌더는 병목이 아니다 | 아래 표 |
| **F** | 깊은 OFFSET 대응 (keyset 페이징) | 마지막 페이지 59 ms → 상수 | 21,370행 / 50 = 428페이지. **참조 카탈로그에서 400페이지로 가는 사용자가 있는가**가 먼저다. 근거 없이 복잡도만 는다 | Q7 58.9 ms · `page=400` 요청 146 ms |
| **G** | 스모크 `assert_*` 를 bash 내장 매칭으로 | 스모크 전체 **약 7초 단축**(구간의 61%) | 이 화면과 무관한 별개 작업. `grep` 정규식 문법을 쓰는 호출부가 있어 일괄 치환은 불가 — 리터럴 검사만 골라야 한다 | `grep` 44 ms vs `[[ == * ]]` 1.3 ms |

**렌더 확장성 실측** (안 E 의 근거):

| per_page | median | 응답 크기 |
|---:|---:|---:|
| 10 | 0.101 s | 22 KB |
| 20 | 0.101 s | 31 KB |
| 40 | 0.091 s | 49 KB |
| 60 | 0.094 s | 67 KB |
| 100 | 0.112 s | 99 KB |

행이 10배가 되고 본문이 4.5배가 되는 동안 응답 시간은 **11% 늘었다.**
"4만 행을 그리는 게 문제일 수도 있다"는 가설은 **기각**된다.

**응답 시간 분해** (OS 탭 91 ms):

| 성분 | 추정 | 근거 |
|---|---:|---|
| HTTP 왕복 + Docker(Windows) | ~48 ms | 정적 `app.css` median |
| SQL 4개 | ~30 ms | §4-1 합계 |
| PHP 렌더·세션·부트스트랩 | ~13 ms | 잔차 · per_page 평탄성 |

**SQL 비중 약 33%, 렌더 비중 약 14%.** 나머지 절반은 페이지가 어떻게 해도 못 줄이는 왕복이다.

## 6. dev 수치가 운영에서 뒤집힐 수 있는 지점 (반드시 짚을 것)

`tb_package_summary` 는 **호스트·스캔이 아니라 피드 카탈로그**에서 나온다. dev 21,370행과
운영의 행 수는 같은 OSV 데이터를 보므로 **자릿수가 비슷할 것**으로 본다 — 이 점에서
OS 탭은 dev↔운영 괴리가 상대적으로 작다. 그래도 아래는 뒤집힐 수 있다.

1. **배포판 분포 (안 B 직격).** dev 는 Ubuntu:24.04 가 45%다. 운영의 자산 구성이 다르면
   선두 컬럼 `ecosystem` 의 선택도가 완전히 달라지고, 옵티마이저가 인덱스를 쓸지 말지도
   달라진다. **안 B 는 운영 분포를 확인하기 전에는 넣지 않는다.**
2. **`cve_cnt` 카디널리티 189.** 동점이 매우 많다(21,370행에 189개 값). 안 A 의 복합
   인덱스는 이 동점 구간을 `package_name` 으로 정렬해 주는 것이 요점이라 **동점이 많을수록
   이득이 크다.** 운영에서 동점이 더 많으면 효과가 커지는 방향이지, 뒤집히는 방향이 아니다
   — 이것이 안 A 를 안 B 보다 안전하다고 보는 이유다.
3. **언어 탭은 dev 수치가 아예 무효다.** `tb_package_license_summary` 0행 · `tb_package`
   3,345행 · `tb_host` 12 · `tb_scan` 210. 운영은 자산 수·스캔 이력이 훨씬 크고,
   §4-4 의 `Using temporary; Using filesort`(드라이빙 테이블) + 2110바이트 조인 키 +
   `Using temporary` 파생 서브쿼리가 그때 처음 드러난다.
   **언어 탭에 대해서는 이 문서가 "빠르다"고 말하지 않는다 — 측정하지 못했다고 말한다.**
   운영에서 다시 재야 한다.
4. **`OFFSET 21000` (안 F).** 요약 행 수에 선형이다. 운영 카탈로그가 커지면 마지막
   페이지 비용은 dev 의 59 ms 보다 비례해서 는다.

## 7. 추천 — 지금은 **아무것도 바꾸지 않는다**

### 7-1. 왜

- 화면이 **91 ms** 다. 사용자가 체감할 수 있는 수준이 아니다.
- 14초는 이 화면 탓이 아니었다 — **61%가 스모크 하니스의 프로세스 스폰**이고,
  패키지 화면 3요청은 그 구간의 **2.6%(약 0.3초)** 다.
- 이 화면은 최근 정보구조 검토에서 **"업무 화면이 아니라 참조 카탈로그"** 로 분류돼
  사이드바 `데이터` 그룹으로 내려갔다(PR #580). 하루에도 몇 번씩 여는 대시보드·탐지 결과와
  급이 다르다. **참조 화면의 91 ms 를 40 ms 로 줄이는 데 운영 리스크를 걸 이유가 없다.**
- 이 화면은 **이미 한 번 크게 고쳐진 자리**다(8초 → 0.05초, 사전집계 도입).
  그때 얻은 구조는 지금도 정확히 제 역할을 한다 — 4개 쿼리 전부 21K행 요약만 읽고,
  89.6만 행 원본은 건드리지 않는다. **여기에 더 손댈 여지가 없다는 것이 측정 결과다.**

### 7-2. 그럼에도 하나를 고른다면 — **안 A**

승인이 떨어진다면 **안 A(복합 내림차순 인덱스 2개)만** 한다. 이유:

- **원인이 실측으로 확정됐다.** 타이브레이크 제거 시 14.57 → 0.35 ms(41배),
  `FORCE INDEX` 로는 안 고쳐짐 — 즉 "이 복합 인덱스의 부재"가 유일한 원인이다.
- **되돌리기가 가장 싸다.** `DROP INDEX` 한 줄. 쿼리·스키마 의미는 그대로다.
- **운영 분포에 안 흔들린다.** §6-2 — 동점이 많을수록 이득이 커지는 방향이라
  운영에서 뒤집히는 시나리오가 없다. 안 B 와 결정적으로 다른 점이다.
- 쓰기 비용은 OSV 커넥터 직후 배치 1회(21K행 재삽입)에만 붙고, 웹 요청 경로엔 없다.

**단, 안 A 도 지금 하자는 뜻은 아니다.** 이득은 Q4 하나에서 약 14 ms(14.6 → 0.4 ms),
페이지 전체로는 **91 → 약 77 ms** 다. 나머지 SQL(Q1 8.4 · Q2 4.2 · Q3 2.4 ms)은 그대로고,
왕복 48 ms 는 어차피 못 줄인다. 사용자가 느끼는 몫은 사실상 없다 —
**다른 화면 작업의 곁다리로 얹을 때** 하는 것이 맞다.

전제 조건: 운영 MySQL 이 **8.0 이상**이어야 한다(내림차순 인덱스). dev 는 8.0.46.

### 7-3. 우선순위가 실제로 높은 것 — 안 G

이 조사에서 나온 **가장 큰 실질 이득은 화면이 아니라 스모크에 있다.**
`assert_*` 65회 × 약 107 ms = **7.0초**. `grep` 을 bash 내장 매칭으로 바꾸면
이 구간뿐 아니라 스모크 전체(1분 27초)에서 두 자릿수 초가 빠진다 —
전체 assert 수를 세면 이 구간의 65개는 일부일 뿐이다.

다만 **범위 밖이고 별개 작업**이다. 주의할 점:
`assert_contains` 는 `grep` 정규식으로 검사하는 호출부가 섞여 있어
(`'class="on" href="?tab=os">OS 패키지'` 처럼 메타문자가 든 리터럴 포함)
일괄 치환은 안 된다. 리터럴 검사만 골라 내장 매칭으로 돌리는 별도 조사가 필요하다.

### 7-4. 이름부터 고치면 좋을 것

`[패키지 서브탭]` 이라는 섹션 이름이 216행·129명령을 덮고 있어서 이번 오진이 났다.
그 구간에는 host.php 상세 6종, depgraph 5종, findings 5종, cve 상세, agent-progress 3종이
전부 들어 있다. **구간을 실제 내용대로 쪼개면 다음에 같은 오진이 안 난다** — 코드 변경이
아니라 `printf "\n[…]\n"` 몇 줄을 넣는 일이다.

## 8. 하지 않은 것

- 쿼리·인덱스·스키마 변경 **없음**. 마이그레이션 파일 **없음**.
- 운영 DB 접속 **없음**. 모든 측정은 dev 공용 DB.
- 공용 dev DB 에 대량 쓰기·`OPTIMIZE TABLE`·인덱스 생성 **없음** — 읽기와 `EXPLAIN` 만.
  (측정용 임시 PHP 스크립트는 `server/bin/` 에 두고 실행 후 삭제했다.)
