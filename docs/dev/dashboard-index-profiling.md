# 대시보드(`index.php`) 프로파일링 — 1.92초는 어디서 오나

> 측정일 2026-08-16 · 워크트리 `wt/dashboard-perf-measure` · dev 공용 DB(`vulnagent-db-dev`, MySQL 8.0.46)
> **이 문서는 측정까지다. 쿼리·인덱스·스키마를 바꾸지 않았다**(마이그레이션 파일 없음, `server/**` 변경 없음).
> 형식은 `docs/dev/archive/packages-screen-profiling.md` 를 따른다.

## 요약 (결론 먼저)

1. **dev 에서 1.92초는 재현되지 않는다.** 컨테이너 내부에서 직접 친 `index.php` 는 median
   **70 ms**(정적 파일 기준선 22 ms), SQL 13개 합계 **30.5 ms** 다. 운영과 **27배** 차이다.
   이 문서는 dev 숫자로 "느리다/빠르다"를 판정하지 않는다.
2. **대신 비용의 형태를 실측으로 확정했다.** 이 화면의 SQL 시간은 **"최신 스캔에 들어 있는
   `tb_finding` 행 수"에 선형**이다. 같은 쿼리를 모집단만 52배(2,096 → 109,746행) 키우자
   시간이 38배(19.8 → 751 ms)로 늘었다 — **행당 7~9 µs** 로 거의 일정하다.
3. 그래서 운영 1.92초에 대한 **검증 가능한 예측**이 나온다:
   운영의 최신 스캔 finding 행 수는 **약 25만 행**일 것이다(§6 에 확인용 SQL 한 줄).
   맞으면 원인은 "특정 쿼리의 나쁜 계획"이 아니라 **모집단 크기 자체**다.
4. **인덱스로는 못 고친다.** 유일한 인덱스 후보(최신 스캔 서브쿼리용 복합 인덱스)를 실제로
   만들어 A/B/A 로 3라운드 재봤다 — 서브쿼리 단독은 4배 빨라지지만(1.07 → 0.27 ms)
   페이지 전체로는 **약 2.5 ms(7%)** 고, **선형 항을 전혀 건드리지 못한다.** 넣지 않았다(§5).
5. 구조적으로 맞는 답은 **스캔별 사전집계**다(`tb_package_summary` 전례). 다만 갱신 주체·시점
   설계가 필요해 범위가 커지므로 **설계만 적고 멈춘다**(§7) — 지시대로 메인 세션 판단 대상.

---

## 1. 측정 방법

### 1-1. 환경

| 항목 | 값 |
|---|---|
| 스택 | 이 워크트리 전용 web+scheduler (`vulnagent-web-dev-dashboard-perf-measure`), 포트 8091 |
| DB | 공용 dev DB `vulnagent-db-dev` · MySQL **8.0.46** |
| 계정 | `admin-dashboard-perf-measure` (스모크와 같은 워크트리 전용 계정 — 세션 격리) |
| 측정 | 워밍업 1회 후 7~12회, **median** 병기(공용 DB라 max 는 다른 워크트리 경합에 오염된다) |

### 1-2. 도구

- **HTTP 응답 시간**: 로그인 세션(cookie jar)으로 `curl -w '%{time_total}'`.
  운영 실측과 조건을 맞추려고 **컨테이너 내부에서 `http://localhost` 로 직접** 친 값을 정본으로 삼고,
  호스트(Windows)에서 친 값은 참고로만 적는다.
- **쿼리별 분해**: `index.php` 의 SQL 을 **그대로 옮긴** 임시 PHP 스크립트를 컨테이너 `/tmp` 에
  `docker cp` 해서 실행하고 각 쿼리를 `microtime(true)` 로 쟀다.
  **저장소 안(`server/bin/`)에 두지 않았다** — 계측 코드가 커밋에 섞이는 사고를 원천 차단한다.
  측정이 끝난 뒤 `/tmp` 의 스크립트는 전부 지웠다.
- **SQL 계획**: `EXPLAIN` / `EXPLAIN ANALYZE` / `SHOW INDEX`.
- **선형성 확인**: 같은 집계를 "최신 스캔"과 "전체 스캔" 두 모집단에 돌려 비교(§4).
- **인덱스 A/B**: 후보 인덱스를 실제로 `CREATE` → 측정 → `DROP` 을 3라운드 교대로(§5).
  **측정이 끝난 시점에 `tb_scan` 의 인덱스는 원래 4개 그대로다**(확인함).

### 1-3. 데이터 규모 (dev, 측정 시점)

| 테이블 | 행 수 |
|---|---:|
| `tb_finding` (전체) | 109,746 |
| `tb_finding` **중 최신 스캔에 속한 것** | **2,096** ← 이 화면이 실제로 다루는 모집단 |
| `tb_container` | 1,060 |
| `tb_scan` | 220 |
| `tb_host` | 10 |
| `tb_finding_status` | 0 ← 주의(§6-3) |

**dev 는 스캔 이력이 220개(호스트당 22개)나 되는데 최신 스캔 finding 은 2,096행뿐이다.**
즉 dev 는 "이력은 길고 현재 상태는 작은" 데이터다. 운영은 그 반대일 가능성이 높다(§6).

---

## 2. 페이지 응답 시간 — dev 에서는 70 ms

| 측정 위치 | 대상 | median | min | max |
|---|---|---:|---:|---:|
| **컨테이너 내부**(운영 실측과 같은 조건) | `/index.php` | **0.070 s** | 0.058 | 0.099 |
| 컨테이너 내부 | `/assets/app.css` (정적 기준선) | 0.022 s | 0.018 | 0.038 |
| 호스트(Windows Docker) | `/index.php` | 0.088 s | 0.075 | 0.235 |
| 호스트(Windows Docker) | `/assets/app.css` | 0.055 s | 0.025 | 0.127 |
| 호스트(Windows Docker) | `/login.php` | 0.040 s | 0.021 | 0.100 |

**응답 시간 분해** (컨테이너 내부 70 ms 기준):

| 성분 | 값 | 근거 |
|---|---:|---|
| HTTP 왕복 + 정적 처리 | ~22 ms | `app.css` median |
| SQL 13개 | **~30 ms** | §3 합계 |
| PHP 렌더·세션·부트스트랩 | ~18 ms | 잔차 |

**운영 1.92초 대비 27배 빠르다.** 이 화면의 코드는 dev 에서 병목이 아니다 —
바꿔 말하면 **dev 숫자로는 운영 문제를 재현하지도, 반증하지도 못한다.**

---

## 3. 쿼리별 소요시간 (dev)

`index.php` 는 519줄에서 SQL 을 **13번** 친다(지시문의 "FROM 절 11곳"에, PHP 헬퍼가 감춘
`vg_finding_first_seen_map()`·`vg_sev_by_scan_ids()` 두 개가 더 붙는다).

측정 9회 median · 공용 DB · 워밍업 1회 제외:

| # | 줄 | 쿼리 요지 | median(ms) | 전체 대비 | 결과 행 |
|---|---|---|---:|---:|---:|
| Q1 | :30 | `tb_host` COUNT | 0.22 | 0.7 % | 1 |
| Q2 | :34 | `tb_feed_connector` 다음 수집 예정 | 0.23 | 0.7 % | 1 |
| **Q3** | **:63** | **등급별 총합 + KEV**(`tb_finding` GROUP BY severity) | **3.80** | **12.4 %** | 4 |
| Q4 | :93 | KEV 행(기한 계산용) | 0.69 | 2.3 % | 8 |
| **Q5** | :114 | `vg_finding_first_seen_map()` — 최초 발견 시각 | **3.13** | **10.3 %** | 8 |
| **Q6** | **:126** | **주요 취약점 신호 목록**(GROUP BY 7컬럼 + 정렬) | **8.65** | **28.3 %** | 6 |
| **Q7** | **:139** | **신호 총건수**(Q6 과 같은 GROUP BY 를 COUNT) | **4.99** | **16.3 %** | 1 |
| Q8 | :157 | 7일 전 스캔(`MAX(scan_id) GROUP BY host_id`) | 0.66 | 2.1 % | 10 |
| Q9 | :167 | `vg_sev_by_scan_ids()` — 7일 전 등급 집계 | 0.99 | 3.2 % | 10 |
| Q10 | :189 | 추세 스캔 목록(UNION + `MAX(scan_id)` 서브쿼리) | 0.91 | 3.0 % | 10 |
| Q11 | :218 | 추세 스캔별 High 이상 집계 | 0.65 | 2.1 % | 10 |
| Q12 | :243 | 목록 총건수(`EXISTS(tb_scan)`) | 0.23 | 0.8 % | 1 |
| **Q13** | **:260** | **호스트별 현황 한 페이지**(등급 SUM + 정렬) | **5.39** | **17.7 %** | 10 |
| | | **SQL 합계** | **30.54** | 100 % | |

**상위 4개(Q6·Q13·Q7·Q3)가 74.7%** 다. 넷 다 **"최신 스캔의 `tb_finding` 을 훑어 집계"** 라는
같은 일을 한다 — 같은 행들을 **네 번** 읽는다. 특히 **Q6 과 Q7 은 GROUP BY 절이 사실상 같다**
(목록 6건과 그 총건수). 합쳐서 13.6 ms, 전체의 **44.6 %** 다.

> 지시문이 특히 보라고 한 두 곳은 **둘 다 결백했다.**
> - `:198` 의 `MAX(scan_id) GROUP BY host_id` 서브쿼리(Q10 안) — 0.91 ms, 3.0 %.
> - `:244` 의 `EXISTS(tb_scan)`(Q12) — **0.23 ms, 0.8 %.** `Nested loop semijoin` +
>   `FirstMatch(h)` 로 커버링 인덱스 두 개만 탄다. 풀스캔이 아니다.
>
> 의심은 빗나갔고, 실제 몫은 전부 **finding 집계 4형제**에 있었다.

---

## 4. 상위 쿼리 EXPLAIN

### 4-1. 공통 구조 — 최신 스캔 파생테이블

네 쿼리 모두 `vg_latest_scan_subq()`
= `(SELECT host_id, MAX(scan_id) AS mid FROM tb_scan WHERE is_deleted = 0 GROUP BY host_id)`
를 조인한다. 이 파생테이블은 쿼리마다 **따로 materialize** 된다(페이지당 5회).

```
-> Materialize  (actual time=0.435..0.435 rows=10 loops=1)
    -> Table scan on <temporary>  (actual time=0.42..0.421 rows=10 loops=1)
        -> Aggregate using temporary table  (actual time=0.416..0.416 rows=10 loops=1)
            -> Index lookup on tb_scan using idx_scans_is_deleted (is_deleted=0)
                 (cost=25.4 rows=220) (actual time=0.0638..0.371 rows=220 loops=1)
```

`idx_scans_is_deleted (is_deleted)` 는 카디널리티 1짜리라 **비삭제 스캔 전부(220행)를 읽어**
임시 테이블에 집계한다. 여기에 대한 조치는 §5 에서 실측으로 기각했다.

### 4-2. Q6 — 주요 취약점 신호 (8.65 ms, 28.3 %)

```
id=1 PRIMARY  tbl=h           type=ALL    key=                          rows=10   Using where; Using temporary; Using filesort
id=1 PRIMARY  tbl=<derived2>  type=ref    key=<auto_key0>               rows=11   Using where; Using index
id=1 PRIMARY  tbl=s           type=eq_ref key=PRIMARY                   rows=1    Using where
id=1 PRIMARY  tbl=f           type=ref    key=idx_find_scan_kev_runtime rows=492
id=2 DERIVED  tbl=tb_scan     type=ref    key=idx_scans_is_deleted      rows=220  Using temporary
```

```
-> Limit: 6 row(s)  (actual time=9.88..9.88 rows=6 loops=1)
    -> Sort: ((f.in_kev = 1) and (f.runtime_status = 'EXTERNAL')) DESC, f.in_kev DESC,
             field(f.runtime_status,...), field(f.severity,...), finding_id,
             limit input to 6 row(s) per chunk  (actual time=9.88..9.88 rows=6 loops=1)
        -> Table scan on <temporary>  (actual time=9.11..9.51 rows=2072 loops=1)
            -> Aggregate using temporary table  (actual time=9.11..9.11 rows=2072 loops=1)
                -> Nested loop inner join  (cost=5012 rows=5455) (actual time=0.557..3.64 rows=2096 loops=1)
                    ...
                    -> Index lookup on f using idx_find_scan_kev_runtime (scan_id=latest.mid)
                         (cost=401 rows=492) (actual time=0.0302..0.289 rows=210 loops=10)
```

읽는 방식 자체는 건강하다 — `idx_find_scan_kev_runtime (scan_id, in_kev, runtime_status)` 로
호스트당 한 스캔씩만 찍어 2,096행을 가져온다. **비싼 건 그 다음이다:**
`GROUP BY` 7컬럼이 임시 테이블에 2,072행을 만들고(3.64 → 9.11 ms, 약 5.5 ms),
그걸 다시 전량 정렬해 **6행**을 꺼낸다. `LIMIT 6` 은 정렬 앞에서 아무것도 줄이지 못한다.
**인덱스로 없앨 수 있는 종류의 비용이 아니다** — `MIN(finding_id)` 집계와 `FIELD()` 표현식
정렬이라 어떤 인덱스도 이 `GROUP BY`/`Sort` 를 대체하지 못한다.

### 4-3. Q7 — 신호 총건수 (4.99 ms, 16.3 %)

```
id=1 PRIMARY  tbl=<derived2>  type=ALL  key=  rows=5455
id=2 DERIVED  ... (Q6 과 동일한 조인·GROUP BY)
```

```
-> Aggregate: count(0)  (cost=6790..6790 rows=1) (actual time=6.57..6.57 rows=1 loops=1)
    -> Table scan on cf  (cost=6174..6245 rows=5455) (actual time=6.23..6.49 rows=2072 loops=1)
        -> Materialize  (cost=6174..6174 rows=5455) (actual time=6.22..6.22 rows=2072 loops=1)
            -> Table scan on <temporary>  (cost=5558..5628 rows=5455) (actual time=5.34..5.61 rows=2072 loops=1)
                -> Temporary table with deduplication  (cost=5558..5558 rows=5455) (actual time=5.34..5.34 rows=2072 loops=1)
                    -> Nested loop inner join  (cost=5012 rows=5455) (actual time=0.556..3.81 rows=2096 loops=1)
```

**Q6 이 이미 만든 것과 같은 2,072행 그룹을 처음부터 다시 만들어 세기만 한다.**
임시 테이블을 **두 번**(dedup 용 + materialize 용) 만든다. 화면에서 이 값의 쓰임은
"상위 6건 / 총 N건" 한 줄뿐이다(`index.php:380-382`).

### 4-4. Q13 — 호스트별 현황 (5.39 ms, 17.7 %)

```
id=1 PRIMARY  tbl=<derived2>  type=ALL    key=                    rows=220  Using where; Using temporary; Using filesort
id=1 PRIMARY  tbl=s           type=eq_ref key=PRIMARY             rows=1
id=1 PRIMARY  tbl=h           type=eq_ref key=PRIMARY             rows=1    Using where
id=1 PRIMARY  tbl=f           type=ref    key=idx_find_scan_sev   rows=765  Using index
id=2 DERIVED  tbl=tb_scan     type=ref    key=idx_scans_is_deleted rows=220 Using temporary
```

```
-> Limit: 20 row(s)  (actual time=5.78..5.79 rows=10 loops=1)
    -> Sort: sev_critical DESC, sev_high DESC, sev_medium DESC, sev_low DESC,
             s.collected_at DESC, s.scan_id DESC, limit input to 20 row(s) per chunk
        -> Table scan on <temporary>  (actual time=5.75..5.75 rows=10 loops=1)
            -> Aggregate using temporary table  (actual time=5.75..5.75 rows=10 loops=1)
                -> Nested loop left join  (cost=18470 rows=168415) (actual time=0.459..1.25 rows=2099 loops=1)
                    ...
                    -> Covering index lookup on f using idx_find_scan_sev (scan_id=t.mid)
                         (cost=6.93 rows=766) (actual time=0.00721..0.0578 rows=210 loops=10)
```

**이 쿼리는 이미 최적에 가깝다.** `idx_find_scan_sev (scan_id, severity)` 를 **커버링 인덱스**로
타서(`Using index`) 테이블 행을 아예 안 읽고 2,099행을 집계한다. 그런데도 5.4 ms 인 이유는
역시 임시 테이블 집계(1.25 → 5.75 ms) 다. **인덱스는 이미 제 몫을 다 하고 있다.**

### 4-5. Q3 — 등급별 총합 + KEV (3.80 ms, 12.4 %)

```
-> Table scan on <temporary>  (actual time=4.52..4.52 rows=4 loops=1)
    -> Aggregate using temporary table  (actual time=4.52..4.52 rows=4 loops=1)
        -> Nested loop inner join  (cost=5012 rows=5455) (actual time=1.31..3.47 rows=2096 loops=1)
            ...
            -> Index lookup on f using idx_find_scan_kev_runtime (scan_id=latest.mid)
                 (cost=401 rows=492) (actual time=0.0262..0.207 rows=210 loops=10)
```

Q6·Q7 과 **똑같은 2,096행**을 세 번째로 읽는다. `GROUP BY severity` 는 4행만 만들어
집계 자체는 싸다(3.47 → 4.52 ms). 비용의 대부분이 행을 읽는 데 든다.

### 4-6. `SHOW INDEX` — 안 쓰이는 인덱스 확인

```
--- tb_finding ---
  PRIMARY                   seq=1 col=finding_id      card=120312
  uq_find                   seq=1 col=scan_id         card=194
  uq_find                   seq=2 col=container_id    card=904
  uq_find                   seq=3 col=cve_id          card=111890
  uq_find                   seq=4 col=package_name    card=120312
  idx_find_sev              seq=1 col=severity        card=3        ← 이 화면에선 안 쓰임
  idx_findings_is_deleted   seq=1 col=is_deleted      card=1        ← 이 화면에선 안 쓰임
  idx_find_cve              seq=1 col=cve_id          card=487      ← Q5 만 사용
  idx_find_scan_sev         seq=1 col=scan_id         card=180      ← Q13 (커버링)
  idx_find_scan_sev         seq=2 col=severity        card=1032
  idx_find_scan_kev_runtime seq=1 col=scan_id         card=175      ← Q3·Q6·Q7
  idx_find_scan_kev_runtime seq=2 col=in_kev          card=376
  idx_find_scan_kev_runtime seq=3 col=runtime_status  card=1279

--- tb_scan ---
  PRIMARY               seq=1 col=scan_id       card=138
  idx_scans_host_time   seq=1 col=host_id       card=13     ← Q12(커버링)
  idx_scans_host_time   seq=2 col=collected_at  card=13
  idx_scans_received    seq=1 col=received_at   card=138    ← 이 화면에선 안 쓰임
  idx_scans_is_deleted  seq=1 col=is_deleted    card=1      ← 최신스캔 파생테이블(페이지당 5회)
```

**`tb_finding` 쪽에 부족한 인덱스는 없다.** 무거운 세 쿼리가 전부 전용 복합 인덱스를 타고
있고 Q13 은 커버링까지 된다. **이 화면의 비용은 "행을 못 찾아서"가 아니라 "찾은 행이 많아서"** 다.

---

## 5. 인덱스 후보 — 만들어서 재보고 기각했다

의심할 만한 곳은 §4-1 하나뿐이었다: 최신 스캔 파생테이블이 카디널리티 1짜리
`idx_scans_is_deleted` 로 비삭제 스캔 전부를 읽고 임시 테이블에 집계한다(페이지당 5회).

후보: `CREATE INDEX idx_scan_latest_per_host ON tb_scan (is_deleted, host_id, scan_id)`

### 5-1. 서브쿼리 단독 — 계획은 확실히 좋아진다 (4배)

```
[인덱스 없음]  median = 1.073 ms   type=ref  key=idx_scans_is_deleted  rows=220  Using temporary
-> Table scan on <temporary>  (actual time=0.69..0.692 rows=10 loops=1)
    -> Aggregate using temporary table  (actual time=0.687..0.687 rows=10 loops=1)
        -> Index lookup on tb_scan using idx_scans_is_deleted (is_deleted=0) (rows=220)

[인덱스 있음]  median = 0.267 ms   type=ref  key=idx_scan_latest_per_host  rows=220  Using index
-> Group aggregate: max(tb_scan.scan_id)  (cost=44.4 rows=13) (actual time=0.065..0.0711 rows=10 loops=1)
    -> Covering index lookup on tb_scan using idx_scan_latest_per_host (is_deleted=0)
         (cost=22.4 rows=220) (actual time=0.0111..0.0531 rows=220 loops=1)
```

**임시 테이블이 사라지고 스트리밍 그룹 집계 + 커버링 인덱스가 된다.** 1.073 → 0.267 ms.

### 5-2. 스캔이 50,000개여도 효과는 밀리초 단위다

"스캔 이력이 쌓이면 여기가 무너진다"는 가설을 실측으로 확인했다. 별도 스키마
`vulnagent_perf` 에 `tb_scan` 과 같은 구조의 표를 만들어 **50,000행 / 50 호스트**를
합성해 넣고 같은 서브쿼리를 쟀다(측정 후 스키마 통째로 `DROP` — `vulnagent` 는 안 건드렸다).

| 스캔 행 수 | 인덱스 없음 | 인덱스 있음 | 계획 변화 |
|---:|---:|---:|---|
| 220 (dev 실제) | 1.07 ms | 0.27 ms | `Using temporary` → `Using index` |
| **50,000** (합성) | **2.39 ms** | **0.68 ms** | 동일 |

**스캔 227배에 시간은 2.2배다 — 이 서브쿼리는 사실상 선형이 아니다**(대부분이 고정 오버헤드).
50,000 스캔에서도 절약분은 회당 1.7 ms × 5회 = **약 8 ms** 다. 1.92초와 자릿수가 셋 다르다.

### 5-3. 페이지 전체 A/B/A — 약 2.5 ms (7%)

공용 dev DB 는 다른 워크트리 부하가 섞이므로 한 번 재고 판단하면 안 된다.
`CREATE` → 측정 → `DROP` → 측정을 3라운드 교대로 돌렸다(각 9회 median 합):

| 라운드 | 인덱스 없음 | 인덱스 있음 |
|---|---:|---:|
| 1 | 33.59 ms | 31.42 ms |
| 2 | 35.29 ms | 29.62 ms |
| 3 | 33.95 ms | 33.22 ms |
| **median** | **33.95 ms** | **31.42 ms** |

방향은 3/3 라운드 일관되게 개선이지만 **폭이 2.5 ms** 다. 페이지 70 ms 의 3.6 %,
운영 1,920 ms 의 **0.13 %** 다.

> 첫 측정에서 40.81 → 30.54 ms(25%) 로 보였던 것은 **인덱스 효과가 아니라 캐시 워밍/경합
> 노이즈였다.** 인덱스를 지우고 다시 재니 31.68 ms 가 나왔다. 한 번만 재고 PR 에 "25% 개선"
> 이라고 적었으면 거짓말이 될 뻔했다 — 공용 dev DB 에서는 A/B/A 가 필수다.

### 5-4. 판단 — **넣지 않는다**

- 얻는 것이 페이지의 3.6 %, 운영 목표(1.92초)의 0.13 % 다.
- **선형 항(§4)을 전혀 건드리지 못한다.** 운영이 느린 이유가 모집단 크기라면(§6) 이 인덱스는
  아무 답도 아니다.
- `tb_scan` 은 에이전트 수집마다 INSERT 되는 쓰기 경로다. 인덱스 하나당 쓰기 비용이 붙는데,
  읽기 이득이 2.5 ms 라면 교환이 성립하지 않는다.
- `packages-screen-profiling.md` 가 같은 규모의 이득(약 14 ms)을 두고 내린 결론과 같다 —
  **"다른 화면 작업의 곁다리로 얹을 때 하는 것이 맞다."**

**측정 결과 이 인덱스는 만들었다가 지웠다. 저장소에 마이그레이션 파일을 남기지 않았다.**
(측정 종료 시점 `tb_scan` 인덱스 = `PRIMARY`, `idx_scans_host_time`, `idx_scans_received`,
`idx_scans_is_deleted` — 측정 전과 같다.)

---

## 6. 그럼 1.92초는 무엇인가 — 검증 가능한 예측

### 6-1. 비용은 "최신 스캔 finding 행 수"에 선형이다

인덱스가 답이 아니라면 남는 가설은 **모집단 크기**다. 같은 쿼리를 모집단만 바꿔
(최신 스캔 조인을 빼서 전체 스캔이 대상이 되게) 다시 쟀다. 의미는 다르지만 **계획 형태는
똑같다** — `scan_id` 로 `tb_finding` 을 훑고 `GROUP BY` 로 임시 테이블을 만든다.

| 모집단 | 대상 finding 행 | Q3 | Q6 | Q7 | 합계 | 행당 |
|---|---:|---:|---:|---:|---:|---:|
| 최신 스캔 (실제) | 2,096 | 4.66 ms | 8.95 ms | 6.18 ms | **19.78 ms** | 9.44 µs |
| 전체 스캔 (합성 조건) | 109,746 | 204.58 ms | 343.58 ms | 202.87 ms | **751.03 ms** | 6.84 µs |

**행 52배 → 시간 38배.** 행당 비용은 6.8~9.4 µs 로 거의 일정하다. 계획도 안 뒤집힌다:

```
-> Limit: 6 row(s)  (actual time=372..372 rows=6 loops=1)
    -> Sort: ... limit input to 6 row(s) per chunk  (actual time=372..372 rows=6 loops=1)
        -> Table scan on <temporary>  (actual time=372..372 rows=2072 loops=1)
            -> Aggregate using temporary table  (actual time=372..372 rows=2072 loops=1)
                -> Nested loop inner join  (cost=23435 rows=65856) (actual time=0.392..175 rows=109746 loops=1)
                    -> Index lookup on f using uq_find (scan_id=s.scan_id) (actual time=0.109..0.766 rows=499 loops=220)
```

109,746행을 읽는 데 175 ms, 그걸 2,072 그룹으로 집계하는 데 197 ms — **읽기와 집계가 반반**이고
둘 다 행 수에 비례한다. 결과가 6행이든 2,072행이든 상관없다.

### 6-2. 예측: 운영의 최신 스캔 finding 은 약 25만 행

운영 1.92초에서 PHP·왕복(dev 실측 ~40 ms)을 빼면 SQL 이 약 1.88초다.
SQL 합계는 §3 의 상위 4개가 75%를 차지하고 전부 같은 선형 계수를 쓰므로:

```
1,880 ms ÷ 7.5 µs/행 ≈ 250,000 행
```

**운영의 최신 스캔 finding 행 수가 20만~30만이면 이 모델이 맞다.**
dev(2,096행)와 **약 120배** 차이다 — 1.92초 / 70 ms = 27배보다 크지만, dev 는 호스트가
10대뿐이라 고정비 비중이 커서 그렇다(§2 의 22 ms 왕복 + 18 ms PHP).

### 6-3. 운영에서 이 계측을 뜨는 절차

운영 서버에는 접속하지 않았다. 아래는 **운영 담당자가 그대로 실행할 수 있는 순서**다.

**① 먼저 모집단부터 센다 (§6-2 예측의 검증 — 이 한 줄이면 가설이 서거나 죽는다)**

```sql
SELECT COUNT(*) AS latest_findings
  FROM tb_finding f
  JOIN tb_scan s ON s.scan_id = f.scan_id
  JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
  JOIN (SELECT host_id, MAX(scan_id) AS mid FROM tb_scan WHERE is_deleted = 0 GROUP BY host_id) latest
    ON latest.host_id = s.host_id AND latest.mid = s.scan_id;

-- 함께 볼 것
SELECT COUNT(*) FROM tb_finding;          -- 전체(이력 포함)
SELECT COUNT(*) FROM tb_scan;             -- 스캔 이력 길이
SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0;
```

- **20만 이상이면** → 원인은 모집단 크기다. §7 로 간다. 인덱스는 답이 아니다.
- **2만 미만이면** → 이 문서의 모델이 틀렸다. 원인이 SQL 밖(PHP·세션·디스크·네트워크)에
  있을 수 있으니 ②③ 을 반드시 뜬다.

**② 페이지 시간을 Caddy/TLS 없이 다시 확인**

```sh
docker exec -it <운영 web 컨테이너> sh -c '
  J=/tmp/j; rm -f $J
  csrf=$(curl -s -c $J http://localhost/login.php | grep -oE "[a-f0-9]{32}" | head -1)
  curl -s -o /dev/null -b $J -c $J -X POST \
    --data-urlencode "csrf=$csrf" --data-urlencode "username=<계정>" \
    --data-urlencode "password=<암호>" http://localhost/login.php
  curl -s -o /dev/null -b $J http://localhost/index.php     # 워밍업
  for i in $(seq 1 12); do curl -s -o /dev/null -b $J -w "%{time_total}\n" http://localhost/index.php; done
  for i in $(seq 1 12); do curl -s -o /dev/null -b $J -w "%{time_total}\n" http://localhost/assets/app.css; done
'
```

`app.css`(정적) 값이 기준선이다. `index.php − app.css` 가 이 화면이 실제로 쓰는 시간이다.

**③ 쿼리별로 쪼갠다 — `index.php` 를 고치지 말고 별도 스크립트로**

운영 코드에 `microtime()` 을 심지 말 것. 이 조사에서 쓴 방식 그대로:
`index.php` 의 SQL 을 복사한 스크립트를 컨테이너 `/tmp` 에 `docker cp` 하고 실행한 뒤 지운다
(§1-2). 저장소·이미지에 아무것도 남지 않고, 웹 요청 경로도 안 건드린다.
`vg_latest_scan_subq()`·`vg_ui_dashboard_urgent_limit()` 를 쓰므로
`require_once '/var/www/html/src/db.php'` 와 `ui_config.php` 만 붙이면 된다.

**④ 상위 쿼리에 `EXPLAIN ANALYZE`** — 특히 §4-2 의 `Aggregate using temporary table` 이
운영에서 몇 ms 인지. 이 문서의 dev 계획과 **같은 형태인지**를 본다. 형태가 다르면(예: `type=ALL`,
파생테이블이 머지됨) 원인이 다른 것이고, 같은 형태인데 시간만 크면 §6-2 모델이 맞는 것이다.

### 6-4. dev 숫자를 그대로 믿으면 안 되는 지점

1. **`tb_finding_status` 가 dev 에 0행이다.** Q4 의 `LEFT JOIN tb_finding_status` 가 dev 에선
   공짜다. 운영에서 조치 상태가 쌓이면 이 조인(4컬럼 자연키)이 처음 비용을 드러낸다.
2. **Q5(`vg_finding_first_seen_map`)는 dev KEV 키가 8개뿐이라 3.13 ms 다.** 이 쿼리는
   `cve_id IN (...) AND package_name IN (...) AND host_id IN (...)` 로 세 축을 펼치므로
   **KEV 키 개수에 IN 목록 길이가 비례한다.** 운영에서 High 이상 KEV 가 수천 건이면
   IN 목록이 수천 개가 되고, 되짚는 구간도 74일치 스캔 전부다. **dev 수치가 가장 못 미더운
   쿼리가 이것이다** — ③ 에서 반드시 따로 잰다.
3. **dev 는 이력이 길고 현재가 작다**(스캔 220 / 최신 finding 2,096). 운영은 반대일 것이라
   보는 것이 §6-2 의 전제다. ① 이 이 전제를 직접 검증한다.
4. 공용 dev DB 라 다른 워크트리 부하가 섞인다. 이 문서의 median 은 그래서 median 이고,
   max 값은(예: Q10 이 한 번 537 ms) 경합 흔적이라 판단 근거로 쓰지 않았다.

---

## 7. 고친다면 무엇을 — 사전집계 (구현하지 않음, 설계만)

§5 로 인덱스가 답이 아님이 확정됐고 §6 으로 원인이 모집단 크기임이 좁혀졌다.
남는 선택지는 세 개고, 지시문의 위험도 순서 그대로 정리한다.

| # | 안 | 얻는 것 | 비용·위험 | 판단 |
|---|---|---|---|---|
| **a** | 인덱스 추가 | 최신 스캔 서브쿼리 4배 | 쓰기 경로 인덱스 1개 추가 | **기각** — 페이지 2.5 ms(0.13%). §5 실측 |
| **b** | **스캔별 사전집계 테이블** | 상위 4쿼리를 **호스트 수에 비례**로. 선형 항 제거 | 갱신 주체·시점 설계 필요. 범위 큼 | **유일하게 유효.** 아래 설계 |
| **c** | SQL 리라이트 | – | **180배 악화 전례가 있는 자리** | **하지 않는다.** §7-3 |

### 7-1. 안 b 설계 초안 — `tb_scan_severity_summary`

**핵심 관찰: 집계 대상이 불변이다.** `tb_finding` 은 `uq_find (scan_id, container_id, cve_id,
package_name)` 로 **스캔마다 행이 새로 생긴다.** 즉 **한 스캔의 finding 집합은 그 스캔이
저장된 뒤로 바뀌지 않는다.** 그래서 스캔 단위 집계는 **한 번 계산하면 영원히 유효**하다 —
`tb_package_summary`(피드 갱신마다 통째로 재구성)보다 오히려 정합성 부담이 작다.

```sql
-- 스캔 하나당 한 행. 갱신 아닌 '추가' 만 일어난다.
CREATE TABLE IF NOT EXISTS tb_scan_severity_summary (
  scan_id        BIGINT UNSIGNED NOT NULL,
  sev_critical   INT UNSIGNED NOT NULL DEFAULT 0,
  sev_high       INT UNSIGNED NOT NULL DEFAULT 0,
  sev_medium     INT UNSIGNED NOT NULL DEFAULT 0,
  sev_low        INT UNSIGNED NOT NULL DEFAULT 0,
  kev_high_plus  INT UNSIGNED NOT NULL DEFAULT 0,   -- High 이상 중 KEV (퍼널 3번 칸)
  signal_groups  INT UNSIGNED NOT NULL DEFAULT 0,   -- Q7 의 GROUP BY 결과 행수
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (scan_id)
) ...;
```

**누가 언제 갱신하나** (이 질문에 답이 없으면 안 b 는 착수하면 안 된다):

| 시점 | 주체 | 내용 |
|---|---|---|
| 스캔 적재 직후 | `ingest.php` 의 매칭 완료 지점 | 그 `scan_id` 한 건 INSERT. 이미 그 스캔의 finding 을 손에 쥔 자리다 |
| 재매칭·백필 | `server/bin/backfill_*.php` | 해당 scan_id 들 REPLACE |
| 스캔 소프트삭제 | 삭제 처리 지점 | 행 삭제 불필요(최신 스캔 조인에서 이미 빠진다) |
| 누락 복구 | 스케줄러 | 요약이 없는 `scan_id` 만 채우는 멱등 배치 |

**어느 쿼리가 얼마나 줄어드나** (dev 기준, 상위 4개 = 18.8 ms → 호스트 수 비례):

| 쿼리 | 지금 | 사전집계 후 | 비고 |
|---|---|---|---|
| Q3 등급별 총합 | 최신 finding 전량 GROUP BY | 호스트 수만큼 SUM | 완전 대체 |
| Q13 호스트별 현황 | 최신 finding 전량 SUM | 요약 조인 | 완전 대체 |
| Q7 신호 총건수 | 같은 GROUP BY 재실행 | `signal_groups` 합 | **주의**: 호스트 간 중복 제거가 안 됨 → 값 정의가 바뀐다 |
| Q6 신호 목록 | 최신 finding GROUP BY + 정렬 | **대체 불가** | 6건이지만 CVE·패키지 단위라 스캔 요약으로 못 뽑는다 |
| Q9 7일 전 등급 | `vg_sev_by_scan_ids()` | 요약 조회 | 완전 대체 (다른 화면도 같이 이득) |
| Q11 추세 High | scan_id IN(...) 집계 | 요약 조회 | 완전 대체 |

**Q6 이 남는다는 게 이 설계의 한계다.** dev 에서 8.65 ms(28.3%)로 단일 최대이고,
운영 25만 행 가정이면 여기만 500 ms 안팎이 남는다. Q6 까지 없애려면 "최신 스캔 기준 현재
신호" 를 CVE·패키지 단위로 유지하는 별도 요약이 필요한데, 그건 스캔 단위가 아니라
**호스트 단위 현재 상태** 라 갱신 규칙이 완전히 달라진다(스캔이 바뀔 때마다 그 호스트분을
통째로 교체). 범위가 한 단계 더 커진다.

### 7-2. 그래서 여기서 멈춘다

지시문대로 안 b 는 **설계를 적고 메인 세션의 판단을 받는 지점**이다. 판단이 필요한 것 셋:

1. **운영 ①(§6-3)을 먼저 돌릴 것인가.** 25만 행 예측이 빗나가면 안 b 는 헛일이다.
   측정 한 줄이 며칠치 구현을 아낀다.
2. **Q7 의 값 정의를 바꿔도 되는가.** 지금은 (cve, 패키지, 호스트, 등급, 런타임, KEV) 조합의
   전역 distinct 수다. 스캔 요약의 단순 합은 호스트 간 중복을 제거하지 못해 **값이 커진다.**
   화면 문구가 "총 N건"이라 숫자가 바뀌면 사용자에게 보이는 변화다.
3. **Q6 까지 덮을 것인가**(범위 2배) **아니면 남길 것인가**(개선폭 약 70%에서 멈춤).

### 7-3. 안 c(SQL 리라이트)를 하지 않는 이유

이 화면의 "대응 우선순위" 쿼리를 파생테이블로 리라이트했다가 **dev 235 ms → 운영 42초(180배)**
로 뒤집힌 전례가 있다(`dashboard-urgent-query-leave-alone`). 이번 측정은 그 판단을 **뒤집지
않고 강화한다** — §4-2 에서 확인했듯 Q6 의 비용은 조인이나 인덱스 선택이 아니라
`GROUP BY` 임시 테이블 + `FIELD()` 정렬이고, **이건 쿼리를 어떻게 다시 써도 같은 행 수를 같은
방식으로 통과해야 한다.** 리라이트로 얻을 것이 없고 잃을 것(옵티마이저가 dev 와 운영에서
다른 계획을 고를 위험)만 있다.

같은 이유로 `FORCE INDEX`·`STRAIGHT_JOIN` 류의 힌트도 넣지 않았다 —
"옵티마이저 재정렬을 영구히 막는 힌트라 데이터 분포가 바뀌면 오히려 발목을 잡는다"(PR #354).

---

## 8. 곁다리로 발견한 것 (이번엔 고치지 않는다)

- **Q6 과 Q7 은 같은 `GROUP BY` 를 두 번 돈다**(합 13.6 ms, 44.6%). 하나로 합칠 수 있는
  모양이지만 그건 SQL 리라이트라 §7-3 에 걸린다. 안 b 를 할 때 같이 정리할 자리다.
- **`vg_latest_scan_subq()` 가 페이지당 5번 따로 materialize 된다.** 같은 10행을 다섯 번
  만든다. PHP 로 한 번 뽑아 scan_id 목록을 값으로 펼치는 방법이 있지만(추세 쿼리가 이미
  그렇게 한다 — `index.php:185`), 이것도 쿼리 구조 변경이라 안 b 와 같이 판단할 일이다.
- **`index.php:161`·`:193`·`:199` 가 날짜를 SQL 문자열에 직접 박는다**(`'$weekAgoDay'`,
  `'$since'`). 값이 `date()` 생성물이라 주입 위험은 없지만 저장소 규약(prepared statement)과는
  어긋난다. 이번 범위 밖 — **적어만 둔다.**
- **`DATE(s.collected_at) >= '...'` 는 컬럼에 함수를 씌워 인덱스를 못 탄다**(Q8·Q10).
  dev 에선 0.9 ms 라 문제가 아니지만 스캔 이력이 길어지면 여기가 자란다.
  `s.collected_at >= '... 00:00:00'` 으로 바꾸면 되는 형태다 — **이번 범위 밖.**

## 9. 하지 않은 것

- **운영 DB·운영 서버 접속 없음.** 모든 측정은 dev 공용 DB.
- **쿼리·인덱스·스키마 변경 없음. 마이그레이션 파일 없음.** `server/**`·`db/**` 무변경.
- **계측 코드를 저장소에 넣지 않았다.** 임시 스크립트는 컨테이너 `/tmp` 에만 두고 실행 후 삭제.
- 공용 dev DB 의 `vulnagent` 스키마에 쓰기 없음. §5-2 의 합성 데이터는 별도 스키마
  `vulnagent_perf` 에 만들고 통째로 `DROP` 했다. §5 의 인덱스도 만들었다 지웠다
  (측정 종료 시점 `tb_scan` 인덱스 4개 = 측정 전과 동일함을 확인).
