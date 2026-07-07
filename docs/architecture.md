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

설치되었다고 전부 올리지 않는다. **노출·로드 여부 + KEV** 로 우선순위를 가른다.

```mermaid
flowchart TD
    START["패키지 P 에 영향을 주는 CVE 발견"] --> LOADED{"P 를 로드한<br/>프로세스가 있나?<br/>(loaded_pkgs/exe_pkg)"}
    LOADED -->|아니오| INSTALLED["설치만 됨<br/>→ LOW<br/>(VEX: 미로드)"]
    LOADED -->|예| EXT{"그 프로세스 소켓이<br/>scope = EXTERNAL?"}
    EXT -->|아니오| LOCAL["로드됨·내부만<br/>→ MEDIUM"]
    EXT -->|예| KEV{"CVE 가<br/>CISA KEV 등재?"}
    KEV -->|아니오| HIGH["외부노출 + 로드됨<br/>→ HIGH"]
    KEV -->|예| CRIT["외부노출 + 로드됨 + KEV<br/>→ CRITICAL"]

    style CRIT fill:#da3633,color:#fff
    style HIGH fill:#db6d28,color:#fff
    style LOCAL fill:#9e6a03,color:#fff
    style INSTALLED fill:#6e7681,color:#fff
```

> 보안 권고로 이미 백포트 패치된 경우 → 해당 없음(VEX 근거 기록). 각 판정에는
> "왜 이 등급인가"의 근거(노출 소켓·로드 라이브러리·KEV 여부)가 함께 남는다.

---

## 3. 배포 구성 (dev / prod)

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
    end

    subgraph Stack["실행 컨테이너"]
        WC["web · php:8.3-apache"]
        DC[("db · mysql:8.0")]
    end

    R1 --> F0 & FC & FD
    R2 --> F0 & FC & FP
    F0 --> Stack
    S2 --> WC
    S3 --> WC
    S1 --> DC
    S2 --> DC
    WC -->|"vulnagent 내부망"| DC

    style WC fill:#238636,color:#fff
    style DC fill:#1f6feb,color:#fff
```

| | dev | prod |
|---|---|---|
| 소스 | `./server` 라이브 마운트 | 이미지에 구움(배포=재빌드) |
| DB 포트 | 노출(3307) | 미노출(내부망만) |
| my.cnf | 미적용(기본값) | 적용(charset/보안 튜닝) |
| 프로젝트 | `vulnagent-dev` | `vulnagent` |

---

## 4. 데이터 모델 (ERD)

```mermaid
erDiagram
    hosts ||--o{ scans : "수집 이력"
    scans ||--o{ packages : "설치 패키지"
    scans ||--o{ exposures : "런타임 노출"
    scans ||--o{ findings : "매처 판정"
    cves  ||--o{ cve_affected_packages : "영향 패키지"
    cves  ||--o{ findings : "취약점"
    cves  ||--o| kev_catalog : "KEV 등재"

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
    findings {
        bigint id PK
        bigint scan_id FK
        string cve_id FK
        string severity
        bool exposed
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
```

*(cves / kev_catalog / cve_affected_packages / findings 는 2단계 매처에서 도입)*
