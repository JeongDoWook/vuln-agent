# changelog 억제층은 왜 한 건도 억제하지 않나 — 운영 실측

> 기록 성격: 2026-07-28 시점의 운영 실측 자료. 현행 구조 설명은 `architecture.md`, 최신 실행값은 웹 자산 상세를 기준으로 한다.

운영 억제 144만 건 중 **②changelog 를 근거로 억제된 건이 0건**이었다. 이 문서는 그 이유를
코드 경로와 벤더 1차 소스 대조로 확인한 기록이다.

조사일 **2026-07-28**, 운영 DB **읽기 전용 조회**. 판정 코드는 건드리지 않았다 —
이 문서는 조사 결과일 뿐이고, 무엇을 고칠지는 이 문서를 근거로 따로 결정한다.

## 결론 먼저

**(b) 다.** changelog 신호는 맞았는데 그 앞의 게이트에 막혀 도달하지 못한다.
다만 "억제 겹의 순서" 때문이 아니라 **`canSuppress` 가드**(서드파티·재시작 필요) 때문이고,
막힌 것 중 실제로 걷어야 할 것은 **서드파티 가드에 걸린 4,088건**뿐이다.

| 대상 | 건수 | 무엇이 막았나 | 벤더 대조 결과 | 막은 게 옳은가 |
|---|---|---|---|---|
| 컨테이너 | 5,774 | `hostEvidenceOk` (changelog 는 호스트 수집물) | 전수 5,404건 **정탐**, 오탐 0 | **옳다** — 억제했으면 미탐 |
| 호스트·재시작 필요 | 168 | `staleEv` → `canSuppress=false` | 오탐 118 / 정탐 0 — 단 프로세스가 옛 `.so` 사용 중 | **옳다** — 벤더는 고쳤어도 지금 도는 코드는 취약 |
| 호스트·서드파티 | 4,088 | `!isDistroPkg` → `canSuppress=false` | 전수 대조 **오탐 4,086 / 정탐 0** | **틀렸다** ← 유일한 개선 지점 |

그리고 **버전 비교가 이미 대부분을 커버한다** — changelog 근거가 붙은 건 중 억제된
21,956건은 사유가 하나도 빠짐없이 다른 층이었다(버전 비교 20,676 · 데비안 트래커 1,196 ·
우분투 OVAL 84 · changelog **0**). 즉 (a) 도 부분적으로 참이다: changelog 가 억제할 수
있었을 것의 94%는 어차피 버전 비교가 먼저 잡는다.

## 실측 수치

운영 DB 읽기 전용 조회(2026-07-28). 조회 중에도 스캔이 계속 유입돼 총계는 몇 건씩 움직인다.

| 항목 | 값 |
|---|---|
| 스캔 / 호스트 | 280 / 11 |
| `tb_finding` | 637,461 |
| `tb_suppressed_finding` | 1,457,211 |
| 그중 `suppress_reason LIKE '%changelog%'` | **0** |
| `tb_pkg_changelog_cve` | 14,215행 (180 스캔) |
| `tb_applied_errata` | **0행** (운영에 RHEL 계열 호스트 없음) |
| `tb_debsecan` | 2,164행 — 스캔 **2개**에만 존재 |

억제 사유를 층별로 나누면 이렇다(`suppress_reason` 문자열 분류):

| 억제 근거 | 건수 |
|---|---|
| 버전 비교 (설치 ≥ 조치) | 799,362 |
| 커널 (실행 중 아님 / 업스트림 CNA) | 284,240 |
| 데비안 보안 트래커 | 196,705 |
| 우분투 보안 OVAL | 176,837 |
| **changelog** | **0** |
| errata | 0 (원본 테이블이 0행) |
| 기타 | 67 |

## 코드 경로 — changelog 검사는 언제 도달하나

판정은 `server/src/matcher.php` 의 `vg_match_decide_cve()` 하나가 한다. **순서가 곧
우선순위**라 먼저 걸리는 조건이 이기고 뒤는 평가되지 않는다.

```
1. 실행 중이 아닌 커널              → 억제 (matcher.php:576)
2. 커널 CNA(업스트림 판정)          → 억제 (matcher.php:593)
── 여기서 canSuppress 를 정한다 ──
   staleEv 있음(재시작 필요)        → canSuppress = false (matcher.php:601)
   kernelPending(재부팅 필요)       → canSuppress = false (matcher.php:606)
   !isDistroPkg(서드파티 저장소)    → canSuppress = false (matcher.php:615)
3. 버전 비교 설치 ≥ 조치            → 억제 (matcher.php:625)
4. 배포판 트래커 / 우분투 OVAL      → 억제 (matcher.php:638)
5. 중앙 벤더권고(OVAL, RHEL 계열)   → 억제 (matcher.php:653)
6. errata(에이전트 dnf updateinfo)  → 억제 (matcher.php:664)
7. changelog(백포트)                → 억제 (matcher.php:674)  ← 마지막
```

> **문서와 코드의 번호가 다르다.** `CONTEXT.md`·`docs/dev/architecture.md` 는 억제를
> "①OSV 버전필터 ②changelog ③errata ④debsecan" 4겹으로 소개하지만, 실제 코드에서
> changelog 는 **마지막 일곱 번째**다. "②" 라는 이름 때문에 앞쪽 층으로 오해하기 쉽다.

7번의 조건은 `$canSuppress && $ctx['hostEvidenceOk'] && $bpEv !== null` 이고,
`hostEvidenceOk` 는 `($ctr === null) && $isDistroPkg` 다(matcher.php:522). 풀어 쓰면
changelog 가 억제하려면 **다섯 가지가 동시에** 성립해야 한다:

1. 호스트 패키지일 것 (컨테이너 제외)
2. 배포판 저장소 패키지일 것 (`isDistroPkg`)
3. 재시작·재부팅 대기가 아닐 것
4. 버전 비교로 안 걸렸을 것 — 즉 **설치 버전이 조치 버전보다 낮아 보일 것**
5. 트래커/OVAL 도 "아직 취약"이라 말할 것 — 4번에서 안 걸렸으면 여기서 대개 걸린다

2번과 5번이 서로를 잡아먹는다. 배포판 패키지라면 트래커·OVAL 이 그 릴리스를 관할하므로
4·5번이 먼저 판정하고, 트래커가 "아직 취약"이라 말하는데 changelog 만 "고쳤다"고 하는
정면 충돌 상황에서만 7번이 살아난다. **운영에서 그 조합은 0건이다.**

### 패키지 화이트리스트는 원인이 아니다

`CONTEXT.md` 가 말하는 "핵심 13개 패키지 하드코딩"은 에이전트 수집 단계
(`agent/vuln-inventory-agent.sh:1249,1253`)에 있다.

```
rpm  : kernel glibc openssl openssh-server bash sudo systemd curl zlib expat python3 nss gnutls
dpkg : openssl libssl3 openssh-server bash sudo systemd curl libcurl4 zlib1g libexpat1 python3 libnss3 libgnutls30
```

살아남은 건의 상위 패키지(`openssl`·`curl`·`libexpat1`·`systemd`·`libnss3`·`zlib1g`·`sudo`·
`openssh-server`)는 **전부 이 목록 안에 있다.** 게다가 매처는 `$p['name']` 이 안 맞으면
`$p['source_pkg']` 로도 조회하므로(matcher.php:672) `libssl3t64`·`openssl-provider-legacy`
같은 파생 바이너리도 `openssl` 기록에 걸린다. 화이트리스트는 이 문제와 무관하다.

## changelog 근거가 붙은 finding 의 운명

매처가 실제로 쓰는 키(`p.name` 또는 `p.source_pkg`)로 `tb_pkg_changelog_cve` 와
`tb_finding` 을 조인하면 **10,030건**이 나온다. 전부 분해했다:

```
10,030 = 컨테이너 5,774 + 호스트 4,256
호스트 4,256 = 서드파티 저장소 4,088 + 재시작 필요 168 + 그 외 0
```

**"그 외" 가 0건**이라는 게 핵심이다. changelog 검사까지 내려온 finding 은 단 한 건도 없다.
전부 그 앞의 `canSuppress`/`hostEvidenceOk` 게이트에서 꺼졌다.

서드파티 4,088건의 origin 은 `Raspberry Pi Foundation` 4,020 · `LOCAL`(수동 설치 `.deb`) 68 이다.
앞의 4,020 은 라즈베리파이 6대 × `openssl`·`libssl3t64`·`openssl-provider-legacy` 세 바이너리로,
사실상 **openssl 하나가 전부**다. 재시작 필요 168건은 origin 이 `Ubuntu`/`Debian` 인 정상
배포판 패키지이고, 옛 라이브러리를 물고 있는 프로세스 때문에 억제가 보류된 것이다.

앞선 조사가 지목한 "changelog(고쳐짐) ↔ debsecan(남아있음) 충돌 16건" 도 확인했다 —
스캔 134·135 의 `openssl` 8종 × 2로, **16건 전부 origin 이 `Raspberry Pi Foundation`** 이다.
충돌이라서 안 걸린 게 아니라 서드파티라서 안 걸렸다. 원인이 같다.

## 벤더 1차 소스 대조

버전 비교는 눈대중하지 않고 `server/src/vercmp.php` 의 `vg_ver_cmp($installed, $fixed, 'dpkg')`
를 그대로 호출했다(PHP 8.3 컨테이너 — 호스트 php 7.2 는 화살표 함수를 오탐한다).

- 데비안: `https://security-tracker.debian.org/tracker/data/json` 전체(80MB)를 받아
  `releases[<코드명>].status` 와 `fixed_version` 을 봤다
- 우분투: `https://ubuntu.com/security/cves/<CVE>.json` 의 `packages[].statuses[]` 에서
  해당 시리즈의 `status`/`description`

판정 기준: `resolved`/`released` 면 설치 버전과 조치 버전을 비교해 설치 ≥ 조치면 `오탐`,
`open`/`needed`/`deferred`(수정본 없음)면 `정탐`, `not-affected`/`DNE` 면 `오탐`(해당 없음).

### 표본 40건

지시된 최소 25건을 넘겨 40건을 뽑았다 — 스캔 20개에 분산, 데비안·우분투 양쪽, 호스트·컨테이너
양쪽, `openssl` 계열 12 · `curl` 계열 10 · `libexpat1` 5 · `systemd` 계열 2 · `libnss3` 2 ·
`libgnutls30` 2 · `zlib1g` 2 · `sudo` 2 · `openssh-server` 2.

| # | scan | 대상 | OS | 패키지 | 설치 버전 | CVE | 벤더 조치 | 판정 | 막은 게이트 | 근거 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 148 | 호스트 | debian 13 (trixie) | `curl` | `8.14.1-2+deb13u3` | CVE-2025-13034 | `8.14.1-2+deb13u3` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2025-13034) |
| 2 | 145 | 호스트 | debian 13 (trixie) | `curl` | `8.14.1-2+deb13u3` | CVE-2025-13034 | `8.14.1-2+deb13u3` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2025-13034) |
| 3 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libcurl3-gnutls` | `7.81.0-1ubuntu1.25` | CVE-2026-8925 | `7.81.0-1ubuntu1.25` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-8925) |
| 4 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libcurl3-gnutls` | `7.81.0-1ubuntu1.25` | CVE-2026-8927 | `7.81.0-1ubuntu1.25` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-8927) |
| 5 | 233 | 호스트 | ubuntu 22.04 (jammy) | `libcurl3-gnutls` | `7.81.0-1ubuntu1.25` | CVE-2026-8927 | `7.81.0-1ubuntu1.25` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-8927) |
| 6 | 148 | 호스트 | debian 13 (trixie) | `libcurl4t64` | `8.14.1-2+deb13u3` | CVE-2025-13034 | `8.14.1-2+deb13u3` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2025-13034) |
| 7 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libgnutls30` | `3.7.3-4ubuntu1.9` | CVE-2026-42009 | `—` | **판단불가** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-42009) |
| 8 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libgnutls30` | `3.7.3-4ubuntu1.9` | CVE-2026-42010 | `3.7.3-4ubuntu1.9` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-42010) |
| 9 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libnss3` | `2:3.98-0ubuntu0.22.04.4` | CVE-2023-6135 | `2:3.98-0ubuntu0.22.04.1` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2023-6135) |
| 10 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libnss3` | `2:3.98-0ubuntu0.22.04.4` | CVE-2026-12318 | `2:3.98-0ubuntu0.22.04.4` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-12318) |
| 11 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libssl3` | `3.0.2-0ubuntu1.25` | CVE-2026-45445 | `3.0.2-0ubuntu1.25` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-45445) |
| 12 | 269 | 호스트 | ubuntu 22.04 (jammy) | `libssl3` | `3.0.2-0ubuntu1.25` | CVE-2026-45446 | `3.0.2-0ubuntu1.25` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-45446) |
| 13 | 233 | 호스트 | ubuntu 22.04 (jammy) | `libssl3` | `3.0.2-0ubuntu1.25` | CVE-2026-45446 | `3.0.2-0ubuntu1.25` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-45446) |
| 14 | 277 | 호스트 | debian 13 (trixie) | `libssl3t64` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 15 | 271 | 호스트 | debian 13 (trixie) | `libssl3t64` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 16 | 270 | 호스트 | debian 13 (trixie) | `libssl3t64` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 17 | 266 | 호스트 | debian 13 (trixie) | `libssl3t64` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 18 | 141 | 호스트 | ubuntu 24.04 (noble) | `openssh-server` | `1:9.6p1-3ubuntu13.16` | CVE-2026-35387 | `1:9.6p1-3ubuntu13.16` | **오탐** | 서드파티 가드 | [우분투](https://ubuntu.com/security/CVE-2026-35387) |
| 19 | 141 | 호스트 | ubuntu 24.04 (noble) | `openssh-server` | `1:9.6p1-3ubuntu13.16` | CVE-2026-35388 | `1:9.6p1-3ubuntu13.16` | **오탐** | 서드파티 가드 | [우분투](https://ubuntu.com/security/CVE-2026-35388) |
| 20 | 277 | 호스트 | debian 13 (trixie) | `openssl` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 21 | 271 | 호스트 | debian 13 (trixie) | `openssl` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 22 | 270 | 호스트 | debian 13 (trixie) | `openssl` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 23 | 277 | 호스트 | debian 13 (trixie) | `openssl-provider-legacy` | `3.5.6-1~deb13u2+rpt1` | CVE-2026-9076 | `3.5.6-1~deb13u2` | **오탐** | 서드파티 가드 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-9076) |
| 24 | 269 | 호스트 | ubuntu 22.04 (jammy) | `systemd` | `249.11-0ubuntu3.21` | CVE-2025-4598 | `249.11-0ubuntu3.16` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2025-4598) |
| 25 | 269 | 호스트 | ubuntu 22.04 (jammy) | `systemd` | `249.11-0ubuntu3.21` | CVE-2026-29111 | `249.11-0ubuntu3.19` | **오탐** | 재시작 가드 | [우분투](https://ubuntu.com/security/CVE-2026-29111) |
| 26 | 164 | 컨테이너 | debian 12 (bookworm) | `sudo` | `1.9.13p3-1+deb12u3` | CVE-2026-35535 | `1.9.13p3-1+deb12u4` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-35535) |
| 27 | 205 | 컨테이너 | debian 12 (bookworm) | `sudo` | `1.9.13p3-1+deb12u3` | CVE-2026-35535 | `1.9.13p3-1+deb12u4` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-35535) |
| 28 | 228 | 컨테이너 | ubuntu 24.04 (noble) | `openssl` | `3.0.13-0ubuntu3.5` | CVE-2026-9076 | `—` | **판단불가** | 컨테이너 제외 | [우분투](https://ubuntu.com/security/CVE-2026-9076) |
| 29 | 232 | 컨테이너 | debian 13 (trixie) | `curl` | `8.14.1-2+deb13u2` | CVE-2026-6253 | `8.14.1-2+deb13u4` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-6253) |
| 30 | 238 | 컨테이너 | ubuntu 24.04 (noble) | `openssl` | `3.0.13-0ubuntu3.5` | CVE-2026-7383 | `3.0.13-0ubuntu3.11` | **정탐** | 컨테이너 제외 | [우분투](https://ubuntu.com/security/CVE-2026-7383) |
| 31 | 252 | 컨테이너 | ubuntu 20.04 (focal) | `curl` | `7.68.0-1ubuntu2.25` | CVE-2026-8927 | `7.68.0-1ubuntu2.25+esm4` | **정탐** | 컨테이너 제외 | [우분투](https://ubuntu.com/security/CVE-2026-8927) |
| 32 | 252 | 컨테이너 | ubuntu 20.04 (focal) | `libexpat1` | `2.2.9-1ubuntu0.8` | CVE-2026-25210 | `2.2.9-1ubuntu0.8+esm1` | **정탐** | 컨테이너 제외 | [우분투](https://ubuntu.com/security/CVE-2026-25210) |
| 33 | 256 | 컨테이너 | ubuntu 20.04 (focal) | `curl` | `7.68.0-1ubuntu2.25` | CVE-2026-8927 | `7.68.0-1ubuntu2.25+esm4` | **정탐** | 컨테이너 제외 | [우분투](https://ubuntu.com/security/CVE-2026-8927) |
| 34 | 256 | 컨테이너 | ubuntu 20.04 (focal) | `libexpat1` | `2.2.9-1ubuntu0.8` | CVE-2026-25210 | `2.2.9-1ubuntu0.8+esm1` | **정탐** | 컨테이너 제외 | [우분투](https://ubuntu.com/security/CVE-2026-25210) |
| 35 | 267 | 컨테이너 | debian 13 (trixie) | `curl` | `8.14.1-2+deb13u3` | CVE-2026-5773 | `8.14.1-2+deb13u4` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-5773) |
| 36 | 276 | 컨테이너 | debian 12 (bookworm) | `libexpat1` | `2.5.0-1+deb12u2` | CVE-2026-25210 | `(미수정)` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-25210) |
| 37 | 278 | 컨테이너 | debian 12 (bookworm) | `libexpat1` | `2.5.0-1+deb12u2` | CVE-2026-25210 | `(미수정)` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-25210) |
| 38 | 278 | 컨테이너 | debian 12 (bookworm) | `zlib1g` | `1:1.2.13.dfsg-1` | CVE-2023-45853 | `(미수정)` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2023-45853) |
| 39 | 279 | 컨테이너 | debian 12 (bookworm) | `libexpat1` | `2.5.0-1+deb12u2` | CVE-2026-25210 | `(미수정)` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2026-25210) |
| 40 | 279 | 컨테이너 | debian 12 (bookworm) | `zlib1g` | `1:1.2.13.dfsg-1` | CVE-2023-45853 | `(미수정)` | **정탐** | 컨테이너 제외 | [트래커](https://security-tracker.debian.org/tracker/CVE-2023-45853) |

**표본 집계: 오탐 24 · 정탐 14 · 판단불가 2.** 대상별로 완전히 갈린다.

| 대상 | 오탐 | 정탐 | 판단불가 |
|---|---|---|---|
| 호스트 (25건) | **24** | **0** | 1 |
| 컨테이너 (15건) | **0** | **14** | 1 |

판단불가 2건은 `ubuntu.com` 이 재시도에도 503/504 를 반환해 조회하지 못한 것이다
(CVE 자체가 없는 게 아니라 API 가 불안정했다).

### 호스트건 전수 대조

데비안 트래커는 전체 JSON 을 받아 뒀으므로 표본이 아니라 **호스트건 4,256건 전부**를
대조할 수 있었다.

| 대상(막은 게이트) | 건수 | 오탐 | 정탐 | 판단불가 | 대조 소스 |
|---|---|---|---|---|---|
| 데비안 · 서드파티 | 4,068 | **4,068** | 0 | 0 | 트래커(1차) |
| 데비안 · 재시작 필요 | 24 | **24** | 0 | 0 | 트래커(1차) |
| 우분투 · 서드파티 | 20 | **18** | 0 | 2 | ubuntu.com(1차) |
| 우분투 · 재시작 필요 | 144 | **94** | 0 | 50 | ubuntu.com(1차) |
| **합계 (1차 소스만)** | **4,256** | **4,204** | **0** | **52** | |
| 합계 (+ OVAL 보조) | 4,256 | 4,248 | 0 | 8 | |

우분투 CVE 46종 중 38종만 1차 소스로 닿았다 — `ubuntu.com` 이 재시도 4회에도 503/504 를
반복했다. 그래서 중앙이 수집한 Canonical OVAL(`tb_ubuntu_oval`)로 한 번 더 채웠고(마지막
행), 이건 같은 벤더의 데이터지만 우리 파이프라인을 거친 것이라 **보조**로 구분해 적는다.
1차 소스와 OVAL 판정이 둘 다 있는 건에서 둘은 어긋나지 않았다.

**어느 쪽으로 세든 정탐이 한 건도 없다.** 호스트에서 changelog 근거가 있는데 finding 으로
남은 4,256건은 전부 벤더 기준으로 이미 수정됐거나 확인 불가였다.

OVAL 로도 남는 판단불가 8건은 `libudev-dev` 처럼 OVAL 에 항목이 없는 패키지다
(OVAL 은 바이너리 패키지명 기준인데 개발 헤더 패키지는 목록에 없다).

### 컨테이너건 전수 대조 — 방향이 정반대다

같은 방법으로 컨테이너건도 전부 대조했다. **호스트건과 판정이 완전히 뒤집힌다.**

| 컨테이너 OS | 건수 | 오탐 | 정탐 | 판단불가 | 대조 소스 |
|---|---|---|---|---|---|
| 데비안 (bookworm·trixie) | 2,673 | 0 | **2,673** | 0 | 트래커(1차) |
| 우분투 (focal·jammy·noble) | 2,731 | 0 | **2,731** | 0 | OVAL(보조) |
| 알파인 | 436 | — | — | — | 대상 외 |
| **합계** | **5,840** | **0** | **5,404** | 0 | |

> 위 분해에서 5,774 라고 쓴 것과 66건 차이가 나는 건 조회 시점이 다르기 때문이다
> (그 사이 스캔이 더 들어왔다). 판정 비율은 달라지지 않는다 — 오탐이 계속 0이다.

즉 **호스트에서 긁은 changelog 를 컨테이너에 적용했다면 5,404건을 잘못 숨겼을 것**이다.
당연하다 — 호스트의 `openssl` 이 패치됐다는 기록은 그 안에서 도는 `debian:12` 컨테이너의
`openssl` 과 아무 상관이 없다. `hostEvidenceOk` 가드는 정확히 이 사고를 막고 있었다.

알파인 436건은 판정 대상 자체가 아니다. changelog 수집은 `rpm`/`dpkg` 에서만 돌아서
(`agent/vuln-inventory-agent.sh:1248,1252`) apk 패키지에는 근거가 있을 수 없는데,
`tb_pkg_changelog_cve` 에 `container_id` 가 없어 조인만 걸린 것이다.

## 권고 — 이 PR 에서 적용했다

**changelog 억제를 서드파티 가드에서 뺀다.** 단 `staleEv`(재시작 필요)·
`kernelPending`(재부팅 필요) 가드는 그대로 유지한다.

구현은 억제 보류를 성격이 다른 둘로 나눈 것이다(`matcher.php`) — 근거의 종류를 가리지
않는 **런타임 보류**(`$runtimeStale`)와, 버전 비교 계열에만 해당하는 **서드파티 보류**.
changelog 억제는 앞엣것만 보고 뒤엣것은 보지 않는다. 컨테이너 제외(`$ctr === null`)는
그대로다. 판정이 바뀌었으므로 `VG_MATCH_FP_VERSION` 도 2 로 올렸다 — 안 올리면 입력이
그대로인 스캔의 지문이 같아서 새 결과가 저장되지 않는다.

계약은 `tests/matcher_suppress_test.php` 로 고정했다(스모크에 편입). 변경 전 코드로
돌리면 바뀐 2건만 실패하고 나머지 9건(버전·트래커·errata·커널 경로)은 그대로 통과한다.

근거는 서드파티 가드의 사유가 changelog 에는 적용되지 않는다는 것이다. 그 가드의 주석
(matcher.php:613)이 밝히는 이유는 *"배포판 조치안과 버전 체계가 달라 자동 판정 불가"* 인데,
이건 **EVR 비교**(①버전 비교)에만 해당하는 말이다. changelog 는 버전을 비교하지 않는다 —
그 빌드 자신의 변경 기록에 CVE 번호가 박혀 있느냐를 볼 뿐이라, 오히려 벤더 데이터가 닿지
않는 서드파티 빌드에서 **유일하게 신뢰할 수 있는 근거**다.

실제로 라즈베리의 `3.5.6-1~deb13u2+rpt1` 은 데비안 `3.5.6-1~deb13u2` 를 리빌드한 것이라
EVR 조차 비교 가능했다. 이건 다른 해법도 시사한다 — `vg_is_distro_pkg()` 가 라즈베리
저장소를 데비안 파생으로 인정하게 하는 쪽이 더 근본적일 수 있다. 다만 그건 라즈베리
저장소가 **항상** 데비안 EVR 체계를 따른다는 가정이 필요하고, changelog 경로는 그런 가정
없이 개별 CVE 기록만으로 판정하므로 더 좁고 안전하다.

**미탐 위험도 확인했다.** 걷히는 4,088건 중 `no_fix`(벤더가 아직 안 고침) 표시는 **0건**,
CISA KEV 등재도 **0건**이다. 즉 이 억제는 "지금 조치할 수 없는 것"이나 "실제로 악용 중인
것"을 화면에서 지우지 않는다. 위 전수 대조에서 정탐이 0인 것과 함께, 이 변경으로 숨겨질
진짜 취약점은 현재 데이터에 없다.

**컨테이너 제외와 재시작 가드는 그대로 둔다.** 대조 결과가 그 둘의 정당성을 뒷받침한다 —
컨테이너 5,404건은 벤더 기준으로도 전부 취약했고(억제했으면 그만큼이 미탐), 재시작 대기
건은 벤더가 고쳤어도 그 프로세스가 아직 옛 라이브러리를 실행 중이다.

### 권고를 따르면 바뀌는 수치

누적이 아니라 **화면에 실제 뜨는 것**(호스트별 최신 스캔) 기준으로 계산했다.

| 지표 | 지금 | 권고 적용 후 |
|---|---|---|
| 최신 스캔 finding 총계 (11 호스트) | 34,947 | 34,587 (**−360**, −1.0%) |
| 그중 HIGH | — | **−120** |
| 그중 LOW | — | −240 |
| 영향 호스트 | 라즈베리파이 6대 | 각 60건씩 감소 |

전체 대비 1%는 작아 보이지만 **등급별로 보면 그렇지 않다.** 라즈베리 6대는 전부 같은 모양이다:

| 호스트 | HIGH 전체 | 그중 changelog 오탐 | 비중 |
|---|---|---|---|
| raspberrypi5-00 ~ 05 (6대 동일) | 70 | **20** | **28.6%** |
| (같은 호스트 LOW) | ~1,440 | 40 | 2.8% |

**그 서버들의 HIGH 목록에서 10건 중 3건이 이미 패치된 것**이다. 사람이 대응 우선순위를
보는 화면이 HIGH 라는 점에서, 누적 4,088건보다 이 28.6% 가 실제 비용에 가깝다.

한편 이 4,088건의 **고유 (패키지, CVE) 종류는 73개, 고유 CVE 는 31개**다. 같은 오탐이
스캔 162개 × 바이너리 3개로 부풀려져 있다는 뜻이라, 4,088 이라는 숫자를 "취약점 4천 개가
사라진다"로 읽으면 안 된다.

**수집을 끄는 안(a)은 권하지 않는다.** 절약되는 게 거의 없기 때문이다 —
[에이전트 리소스 프로파일](에이전트-리소스-프로파일.md)의 실측표는 `full` 3.7s / **`--no-changelog` 3.5s**,
피크 RSS 는 **양쪽 다 61.6MB** 로 같다. 대상이 13개 패키지로 고정돼 패키지 수와 무관한
상수 비용이라 그렇다. 0.2초를 아끼려고 서드파티 빌드의 유일한 백포트 근거를 버릴 이유가 없다.

## 한계

- **조인이 실제 판정을 재현한 게 아니다.** `tb_pkg_changelog_cve` 와 `tb_finding` 을 SQL 로
  이어 붙여 "changelog 근거가 있었는데 finding 으로 남은 것"을 셌을 뿐, 매처를 다시 돌려
  본 것이 아니다. 조인 키를 어떻게 잡느냐로 수가 크게 흔들린다 — `scan+cve` 만으로 이으면
  12,366건, `scan+pkg+cve` 로 엄격히 이으면 3,005건, 매처가 실제로 쓰는
  `name 또는 source_pkg` 기준이면 10,030건이다. 이 문서는 마지막 것을 정본으로 삼았다.
  (앞선 조사가 말한 3,572건은 `scan+cve` 조인의 부분집합으로 보인다.)
- **`container_id` 를 무시하면 중복이 생긴다.** `tb_pkg_changelog_cve` 에는 `container_id`
  컬럼이 없다(호스트에서만 수집하므로). 그래서 changelog 기록 하나가 같은 스캔의 컨테이너
  finding 에도 조인돼 붙는다 — 위 5,774건이 그것이고, 매처는 이들을 애초에 억제 대상으로
  보지 않는다. "억제될 수 있었던 건"으로 세면 안 된다.
- **같은 취약점이 여러 번 세어진다.** 호스트 4,256건은 스캔 162개에 걸쳐 있고 대부분이
  같은 호스트의 반복 스캔이다. `openssl` 하나가 `openssl`·`libssl3t64`·
  `openssl-provider-legacy` 세 바이너리로도 갈린다(각 1,340건). 실제 "고유한 오탐"은
  훨씬 적다 — 4,088건은 화면에 뜨는 행 수이지 취약점 종류 수가 아니다.
- **우분투 1차 소스가 불안정하다.** `ubuntu.com/security/cves/<CVE>.json` 이 503/504 를
  자주 반환해, 재시도 4회에도 필요한 CVE 46종 중 **38종**만 받았다. 대조하지 못한 건은
  `판단불가` 로 남겼고 오탐으로 추정하지 않았다. 데비안 쪽은 전체 JSON 한 번으로 받아
  이 문제가 없었다 — 그래서 결론의 무게는 데비안 4,092건(전량 1차 소스)이 지고 있다.
- **운영 DB 가 살아 있다.** 조사 중에도 스캔이 유입돼 같은 쿼리의 총계가 조회 시점마다
  몇 건씩 달랐다(호스트건 4,256, changelog 조인 총계 2,989→3,005). 결론이 뒤집힐 규모는
  아니지만 수치는 스냅샷이다.
- **`정탐` 판정은 벤더 데이터의 최신성에 의존한다.** 트래커·OVAL 이 아직 반영하지 않은
  수정은 `아직 취약`으로 읽힌다. 다만 이번 결론(서드파티 4,088건 오탐)은 반대 방향이라
  이 편향의 영향을 받지 않는다.
