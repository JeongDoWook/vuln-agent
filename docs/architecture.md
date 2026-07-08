# vuln-agent 아키텍처

지금까지 확정·구현된 구조를 그림으로 정리한다. (Mermaid — GitHub에서 바로 렌더링)

관련 문서: 전략·로드맵은 [`../CONTEXT.md`](../CONTEXT.md), 실행법은 [`../README.md`](../README.md).

---

## 1. 시스템 개요 (데이터 흐름)

```mermaid
flowchart LR
    subgraph Servers["수집 대상 서버들 (Linux)"]
        A1["에이전트<br/>vuln-inventory-agent.sh"]
        A2["에이전트"]
        A3["에이전트"]
    end

    subgraph Central["중앙 서버 · Docker"]
        ING["ingest.php<br/>(수신 API · 토큰 인증)"]
        DB[("MySQL<br/>hosts·scans·packages·exposures")]
        MAT["매처 (PHP)<br/>exposure + pkg × CVE"]
        CVE[("CVE 미러<br/>NVD·OSV·KEV·EPSS")]
        WEB["웹 대시보드<br/>우선순위·노출근거·VEX"]
    end

    A1 -->|"매일 1회 / 델타<br/>JSON POST"| ING
    A2 --> ING
    A3 --> ING
    ING --> DB
    DB --> MAT
    CVE --> MAT
    MAT -->|findings| DB
    DB --> WEB

    style A1 fill:#1f6feb,color:#fff
    style ING fill:#238636,color:#fff
    style MAT fill:#a371f7,color:#fff
    style WEB fill:#db6d28,color:#fff
```

**핵심:** 매칭 정확도는 검증된 스캐너/피드에서 상속하고, 우리 기여는 그 위 레이어
(**런타임 노출 상관 · KEV/EPSS 우선순위 · 설명가능성**)에 둔다.

---

## 2. 매처 판정 로직 — "실제로 위험한가"

설치되었다고 전부 올리지 않는다. **런타임 상태(노출·실행·사용) + KEV** 로 우선순위를 가른다.
exposures(포트) + processes(실행/로드) 를 합쳐 5단계 상태를 판정한다.

```mermaid
flowchart TD
    START["패키지 P 에 영향을 주는 CVE"] --> EXT{"외부(0.0.0.0)<br/>오픈 포트로 노출?"}
    EXT -->|예| KEV{"CVE 가 KEV 등재?"}
    KEV -->|예| CRIT["외부노출 + KEV<br/>→ CRITICAL"]
    KEV -->|아니오| HIGH["외부노출<br/>→ HIGH"]
    EXT -->|아니오| USE{"리스닝(로컬)·<br/>실행중·라이브러리 로드<br/>중 하나라도?"}
    USE -->|예| MED["로컬리스닝/실행중/사용중<br/>→ MEDIUM"]
    USE -->|아니오| INS["설치만 됨<br/>→ LOW"]

    style CRIT fill:#da3633,color:#fff
    style HIGH fill:#db6d28,color:#fff
    style MED fill:#9e6a03,color:#fff
    style INS fill:#6e7681,color:#fff
```

> 상태: EXTERNAL > LISTENING > RUNNING > LOADED > INSTALLED. KEV 시 한 단계 상향,
> EPSS·CVSS 는 같은 등급 내 정렬. 각 판정에 근거(어떤 프로세스·포트·라이브러리)가 남는다.
> 백포트 오탐은 OSV 버전필터(배포판 전체버전 대조)가 이미 제거.

---

## 3. CVE 피드 커넥터 (외부 소스 수집)

claude-pipeline 의 Connector/CollectionLog 패턴을 참고. UI에서 소스를 설정·스케줄하면
스케줄러가 주기적으로 당겨와 매처가 재계산한다.

```mermaid
flowchart LR
    subgraph UI["웹 (admin)"]
        CFG["connectors.php<br/>설정·스케줄·지금실행·미리보기"]
    end
    subgraph Sched["scheduler 사이드카"]
        TICK["매 1분<br/>due 커넥터 조회"]
    end
    subgraph Sources["외부 소스"]
        KEV["CISA KEV json"]
        OSV["OSV.dev API"]
        NVD["NVD 2.0 API"]
    end
    DBc[("feed_connectors<br/>feed_collection_logs")]
    CVE[("cves · kev_catalog<br/>cve_affected_packages")]
    MAT["매처 재계산"]

    CFG -->|저장| DBc
    TICK -->|enabled & next_run<=now| DBc
    TICK --> KEV & OSV & NVD
    KEV & OSV & NVD -->|upsert| CVE
    CVE --> MAT
    TICK -->|실행 후| MAT
    CFG -->|지금 실행| MAT
    CFG -.->|미리보기 10건<br/>feed_preview.php| KEV

    style KEV fill:#238636,color:#fff
    style MAT fill:#a371f7,color:#fff
```

커넥터 = `{type(kev/osv/nvd/kisa), connection(url·key·ecosystem), schedule, enabled}`.
스케줄은 **manual / interval(N분) / daily(HH:MM) / cron(5필드 표현식)** 지원 — UI에서 지정하면
스케줄러 사이드카가 매 tick(60s) 판정해 그 시각에 수집·재매칭한다(Quartz 유사, 중앙 실행).
수집 이력·상태는 `feed_collection_logs` 에 남고 커넥터 행에 마지막 상태로 표시된다.

---

## 4. 배포 구성 (dev / prod)

```mermaid
flowchart TB
    subgraph Runner["compose_runner.sh"]
        direction LR
        R1["dev up"]
        R2["prod up"]
    end

    subgraph Files["compose 레이어"]
        F0["compose.yml<br/>(서비스 정의 + secrets)"]
        FC["compose.common.yml<br/>(restart·로깅·pids)"]
        FD["compose.dev.yml<br/>(소스마운트·DB포트노출)"]
        FP["compose.prod.yml<br/>(이미지코드·DB비노출·my.cnf)"]
    end

    subgraph Secrets["Docker Secrets (txt)"]
        S1["mysql_root_password"]
        S2["mysql_password"]
        S3["ingest_token"]
        S4["admin_password"]
    end

    subgraph Stack["실행 컨테이너"]
        WC["web · php:8.3-apache"]
        SCH["scheduler · php-cli<br/>(피드 주기 실행)"]
        DC[("db · mysql:8.0")]
    end

    R1 --> F0 & FC & FD
    R2 --> F0 & FC & FP
    F0 --> Stack
    S2 & S3 & S4 --> WC
    S2 & S3 & S4 --> SCH
    S1 & S2 --> DC
    WC -->|"vulnagent 내부망"| DC
    SCH --> DC

    style WC fill:#238636,color:#fff
    style SCH fill:#a371f7,color:#fff
    style DC fill:#1f6feb,color:#fff
```

> web·scheduler 는 같은 이미지(`vulnagent-app`)를 공유하고, 환경/시크릿은 compose 앵커
> (`x-app-env`/`x-app-secrets`)로 DRY 하게 재사용한다.

| | dev | prod |
|---|---|---|
| 소스 | `./server` 라이브 마운트 | 이미지에 구움(배포=재빌드) |
| DB 포트 | 노출(3307) | 미노출(내부망만) |
| my.cnf | 미적용(기본값) | 적용(charset/보안 튜닝) |
| 프로젝트 | `vulnagent-dev` | `vulnagent` |

---

## 5. 데이터 모델 (ERD)

```mermaid
erDiagram
    hosts ||--o{ scans : "수집 이력"
    scans ||--o{ packages : "설치 패키지"
    scans ||--o{ exposures : "노출 소켓(포트)"
    scans ||--o{ processes : "실행 프로세스"
    scans ||--o{ findings : "매처 판정"
    cves  ||--o{ cve_affected_packages : "영향 패키지"
    cves  ||--o{ findings : "취약점"
    cves  ||--o| kev_catalog : "KEV 등재"
    feed_connectors ||--o{ feed_collection_logs : "수집 이력"

    hosts {
        bigint id PK
        string fqdn UK
        string os_id
    }
    scans {
        bigint id PK
        bigint host_id FK
        datetime collected_at
        int package_count
        int exposure_count
    }
    packages {
        bigint id PK
        bigint scan_id FK
        string name
        string version
        string source_pkg
    }
    exposures {
        bigint id PK
        bigint scan_id FK
        string proc
        int port
        string scope
        string exe_pkg
        text loaded_pkgs
    }
    processes {
        bigint id PK
        bigint scan_id FK
        string comm
        string exe_pkg
        text loaded_pkgs
    }
    findings {
        bigint id PK
        bigint scan_id FK
        string cve_id FK
        string severity
        string runtime_status
        bool in_kev
    }
    cves {
        string cve_id PK
        decimal cvss
    }
    kev_catalog {
        string cve_id PK
        date date_added
    }
    cve_affected_packages {
        bigint id PK
        string cve_id FK
        string package_name
        string fixed_version
    }
    feed_connectors {
        bigint id PK
        string connector_type
        json connection_json
        json schedule_json
        bool enabled
        datetime next_run_at
    }
    feed_collection_logs {
        bigint id PK
        bigint connector_id FK
        string status
        int items_upserted
    }
    advisories {
        bigint id PK
        string source
        string title
        string url UK
        date published
        string cve_ids
    }
    users {
        bigint id PK
        string username UK
        string password_hash
        string role
    }
```

*(cves / kev_catalog / cve_affected_packages / findings 는 2단계 매처, feed_* 는 4a 피드 커넥터,
advisories 는 4b KISA 국내공지, users 는 3단계 인증에서 도입. advisories 는 CVE 와 느슨한 연계
(제목의 CVE best-effort)라 FK 없음)*

---

## 6. 웹 화면 구성 (사이트맵 · 인증)

```mermaid
flowchart TD
    LOGIN["/login.php<br/>세션 로그인 · CSRF"]
    LOGIN -->|인증 성공| DASH

    subgraph Auth["로그인 필요"]
        DASH["/ 대시보드<br/>호스트별 최신스캔 · 심각도 KPI"]
        FIND["/findings.php<br/>취약점 우선순위 · 노출근거"]
        ADV["/advisories.php<br/>국내 보안공지(KISA)"]
    end

    subgraph AdminOnly["admin 전용"]
        CONN["/connectors.php<br/>피드 커넥터 · 미리보기"]
        USERS["/users.php<br/>계정 관리"]
    end

    DASH --> FIND
    DASH -.-> ADV
    DASH -.-> CONN & USERS

    subgraph API["인증: 공유 토큰(에이전트)"]
        ING["/ingest.php<br/>수집 수신"]
        REM["/rematch.php<br/>재매칭"]
    end

    style LOGIN fill:#1f6feb,color:#fff
    style CONN fill:#db6d28,color:#fff
    style USERS fill:#db6d28,color:#fff
    style ING fill:#238636,color:#fff
```

- **세션 인증**(users 테이블) : 대시보드·취약점·국내공지. admin 은 피드·사용자 추가.
- **토큰 인증**(공유 시크릿) : 에이전트가 쓰는 `ingest.php`/`rematch.php` — 사람 로그인과 분리.
- 역할: `admin`(관리) / `viewer`(조회). 최초 admin 은 `secrets/admin_password` 로 부트스트랩.
