# vuln-agent 에이전트 — 설치·운영 가이드

> **현행 버전: 3.13** (문서 기준 2026-08-20). 실제 값은 `vuln-inventory-agent.sh` 의
> `SCRIPT_VERSION` 이 정본이다.

| 버전 | 들어간 것 |
|---|---|
| 3.13 | 호스트 **Go 바이너리 buildinfo** 수집, Ruby 앱 의존성(`Gemfile.lock`·vendored `*.gemspec`), Node/Python 보조 lock(`yarn.lock`·`pnpm-lock.yaml`·`poetry.lock`·`Pipfile.lock`·`*.egg-info/PKG-INFO`) |
| 3.12 | 패키지 무결성 검증(`--verify-files`, 기본 꺼짐) |
| 3.11 | **헤더만 있는 섹션 파일도 그대로 전송** — 중앙이 "수집했고 0건"과 "아예 안 왔다"를 구분해 자산등급 제안을 판정불가로 분리한다 |
| 3.10 | meta 3필드(`elapsed_seconds`·`peak_rss_mb`·`cpu_seconds`) 누락 수정 |
| 3.9 | cgroup 재실행 가드 |
| ~3.8 | 기본 경로 IP 보고, 장시간 단계 heartbeat, 웹 중단 요청 |

대상 리눅스 서버에서 **자산·취약노출 정보를 수집해 중앙 서버로 전송**하는 에이전트다.
스캐너를 각 서버에 심는 방식이 아니라, 가벼운 셸 스크립트가 주기적으로 인벤토리를
수집해 중앙(`ingest.php`)으로 push 한다.

## 한 번만 설치하면 된다 (systemd 가 있으면 상시 데몬으로 알아서 돈다)

- 설치기는 **`run.sh` 를 systemd 상시 서비스**(`Type=simple`, `Restart=on-failure`)로 등록해
  `enable --now` 한다. `run.sh` 는 10초마다 중앙 `agent-poll.php` 를 GET 으로 poll 하는 데몬이고,
  **리스닝 포트를 열지 않는 아웃바운드 전용**이라 중앙이 노드로 들어오는 경로는 없다.
- poll 응답의 `poll_schedule_seconds`(정기수집 주기, 초기값은 설치 때 `--schedule`)가 지났으면
  수집·전송한다. 중앙 웹에서 주기를 바꾸면 **다음 poll 에 바로 반영**된다(SSH 재설치 불필요).
  `due_command_id` 가 실려 오면(중앙에서 "지금 수집") 주기와 무관하게 즉시 수집하고 완료 처리한다.
- 네트워크가 잠깐 끊겨도 데몬은 죽지 않는다 — poll 실패가 이어지면 간격을 10초→최대 5분까지
  지수 백오프했다가 성공하면 10초로 복귀한다.
- **systemd 가 없는 노드는 cron 폴백**(정기수집만 가능, 즉시/예약 명령은 지원하지 않는다)
  — `run.sh --once` 를 주기적으로 cron 이 실행한다. 설치 로그에 이 사실이 안내된다.

## 설치

설치 순서는 다음 네 단계다.

1. 중앙의 **에이전트 키** 화면에서 대상 FQDN에 묶인 키를 발급한다.
2. 자산 화면의 "에이전트 설치 안내"에서 스크립트 2개와 중앙의 `caddy-root.crt`를 받는다
   (레포 체크아웃 불필요, `agent-dl.php`).
3. 세 파일을 대상 서버의 같은 디렉터리에 두고 아래 설치기를 실행한다. CA는 자동 등록된다
   (`--ca-file PATH`로도 지정 가능).
4. 설치기의 즉시 1회 전송이 2xx인지 확인하고, 중앙 호스트 상세에서 연결 시각과 첫 스캔을 확인한다.

> **CA 는 배포마다 다르다.** `caddy-root.crt` 는 각 중앙 서버의 Caddy 가 만든 고유값이라 레포에
> 커밋하지 않는다. 자산 화면의 다운로드 버튼이 "아직 준비 안 됨" 이면 중앙 관리자가 최초 1회
> 추출해야 한다 — [`deploy/README.md`](../deploy/README.md) 의 **"에이전트 CA 준비"** 참고.

```bash
sudo bash install-agent.sh
```

```
== vuln-agent 설치 ==
중앙 서버 주소 (예: vulnagent.example.com:8080): <운영-도메인>:8080
전송 토큰 (입력은 화면에 보이지 않습니다): ********      ← 중앙에서 이 호스트용으로 발급한 개별 토큰
수집 주기 [hourly] (daily / '*:0/30'=30분마다): ⏎        ← Enter 치면 hourly
```

- `<운영-도메인>` 은 이 배포의 중앙서버 도메인이다 — 운영 배포 시 정해 `deploy/.env.prod` 의
  `PROD_DOMAIN` 에 넣은 값으로, 저장소에는 실제 값을 두지 않는다. 중앙 관리자에게 받는다.
- 주소는 **도메인만 넣어도 된다.** `https://` 와 `/ingest.php` 는 자동으로 붙는다.
- 토큰은 화면·셸 히스토리에 남지 않는다(입력 숨김).

### 선행 검사 — 설치기가 알아서 한다

설치기는 파일을 깔기 **전에** 전송이 실제로 되는지 확인하고, 막히면 **아무것도 설치하지 않고
중단**한다(예전엔 이 셋을 사람이 미리 손봐야 했고, 안 하면 조용한 실패가 됐다).

| 검사 | 자동 처리 | 수동 지정 |
|---|---|---|
| 전송 수단(`curl` 또는 `wget`) 없음 | **중단**. 설치기는 대상 서버에 아무것도 설치하지 않는다 | — |
| 중앙이 **자체서명**(Caddy `tls internal`) | 스크립트 옆의 `caddy-root.crt` 를 신뢰 저장소에 등록 | `--ca-file PATH` |
| 도메인이 **공인 IP** 로 풀려 내부망에서 못 붙음(헤어핀 NAT) | 중앙의 내부 IP 를 묻고 `/etc/hosts` 에 이름을 묶음 | `--host-ip 10.0.0.200` |

### 대상 서버 요구사항 — 아무것도 설치하지 않는다

에이전트는 **대상 서버에 패키지를 요구하지 않는다.** 현장 폐쇄망 서버엔 `apt` 자체가 없고,
남의 서버에 패키지를 심는 건 승인 사안이다. 그래서 어디에나 이미 있는 것만 쓴다:

| 도구 | 필수인가 | 없으면 |
|---|---|---|
| `bash` · coreutils | 필수 | — |
| `awk` | 필수(POSIX — busybox 에도 있다) | JSON 을 만들 수 없어 중단 |
| `curl` **또는** `wget` | 필수 | HTTPS 전송을 순수 셸로는 못 한다 → 중단 |
| `jq` | **아니오** | awk 로 JSON 을 조립한다(결과 동일 — `tests/agent_json_test.sh` 가 jq 출력과 대조) |
| `openssl` | **아니오**(수집·전송엔 안 쓴다) | 자동 업데이트가 **적용되지 않는다** — 서명을 검증할 도구가 없어 `no_verify_tool` 로 보고하고 구버전에 그대로 머문다(조건별 동작은 아래 **"자동 업데이트가 멈추거나 저하되는 경우"** 표 한 곳에만 적는다). 수집·전송은 그대로 |
| `debsecan` | **아니오** | 중앙이 데비안 보안 트래커를 직접 받아 판정한다 |

루트 CA 는 중앙에서 한 번 꺼내 두고 모든 대상에 재사용한다 — 추출 명령은
[`deploy/README.md`](../deploy/README.md) **"에이전트 CA 준비"** 한 곳에만 둔다. 헤어핀 NAT 는
이름을 IP 로 바꿔서는 못 푼다(Caddy 가 SNI 로 사이트를 고른다) — `/etc/hosts` 로 **이름이
가리키는 곳**을 바꾼다.

자동화(Ansible 등)로 무인 설치할 땐 인자로 넘긴다. **TTY 가 아니면 아무것도 묻지 않으므로**,
세 값을 다 주면 사람 없이 끝난다:

```bash
sudo bash install-agent.sh \
  --server https://<운영-도메인>:8080/ingest.php \
  --token  <중앙 웹의 에이전트 키 화면에서 해당 호스트에 발급한 값> \
  --schedule hourly              # 또는 daily, '*:0/30'(30분마다, systemd)
```

설치 마지막에 **즉시 1회 수집·전송**해 통신을 확인한다. 이 첫 전송이 성공하면
중앙 대시보드의 호스트 목록에 해당 서버가 뜬다.

## 권한 — root 가 필요하다 (chmod / chown)

**설치는 반드시 root(sudo).** `/opt/vuln-agent` 생성, systemd 유닛 작성, cron 등록은
root 아니면 불가능하다. root 가 아니면 설치기가 바로 실패하며 올바른 명령을 알려준다.

수집에도 root 가 필요하다. 옵션이 아니라 **수집 품질** 문제다:

| 항목 | root 없으면 |
|---|---|
| `ss -tulpn` 포트↔프로세스 매핑 | **어느 프로세스가 그 포트를 열었는지 안 보임** → 외부노출 판정 근거 누락 |
| 다른 사용자 프로세스의 `/proc/PID/maps` | 로드된 `.so` 라이브러리를 못 읽음 |
| `dmidecode` | 하드웨어 정보 수집 불가 |
| `/etc/shadow` · `/etc/sudoers` | 계정 정책·sudo 섹션이 아예 안 만들어짐 → 중앙이 `NA`(판정 불가)로 읽는다 |

단, 에이전트 본체(`vuln-inventory-agent.sh`)는 root 가 아니어도 **실패하지 않고 경고만 띄운 뒤
수집 가능한 것만 모은다**(읽기 전용이라 OS·커널·패키지 목록은 그대로 모인다). 누가 실행했는지는
`meta.running_as` 로 실려 중앙이 부분 수집임을 안다. 정상 설치 경로는 root 데몬이라 볼 일은 없다.

**chmod·chown 은 필요 없다** — `bash <파일>` 로 실행하면 되고(`./` 로 실행할 때만 `chmod +x`),
`sudo` 로 돌리면 설치기가 `/opt/vuln-agent/**` 를 root 소유로 만들고 토큰 파일(`etc/agent.env`)은
`600` 으로 잠근다.

### 스크립트를 어디에 두고 실행하나 — `/opt/vuln-agent`

**스크립트 2개를 `/opt/vuln-agent/` 에 두고 거기서 실행한다.** 설치기가 설치물을 두는 곳과
같은 경로라 **외울 경로가 하나뿐**이다(`--prefix` 로 바꾸면 그 경로).

```bash
scp install-agent.sh vuln-inventory-agent.sh caddy-root.crt 대상서버:~/   # 1) 홈으로 전송 (scp 는 root 로 못 붙는 경우가 많다)
ssh 대상서버
sudo mkdir -p /opt/vuln-agent                                            # 2) 제자리로 (root 소유가 된다)
sudo cp ~/install-agent.sh ~/vuln-inventory-agent.sh ~/caddy-root.crt /opt/vuln-agent/
rm -f ~/install-agent.sh ~/vuln-inventory-agent.sh ~/caddy-root.crt      # 3) 홈의 원본은 정리

cd /opt/vuln-agent                                                       # 4) 설치 (CA 는 옆에 있으니 알아서 등록된다)
sudo bash install-agent.sh
```

설치가 끝나면 원본과 설치물이 한 지붕 아래 모인다:

```
/opt/vuln-agent/
├── install-agent.sh          ← 원본. 재설치·주기변경·제거를 여기서 한다
├── vuln-inventory-agent.sh   ← 원본
├── bin/    vuln-inventory-agent.sh · run.sh (설치기가 복사한 것 — 실제로 도는 것)
├── etc/    agent.env (설정·토큰, 600) · agent-update.pub (자동 업데이트 서명 공개키, 600)
└── logs/   last.json (최근 수집 결과) · last_scan_at · poll_interval
```

**왜 아무 데나 두면 안 되나.** `sudo bash install-agent.sh` 는 그 파일 내용을 root 로 실행하므로,
다른 계정이 바꿔칠 수 있는 곳(`/tmp`·`/var/www`·공유 배포 폴더)에 두면 남의 코드가 root 로 도는
셈이다. `/opt` 는 root 소유(`755`)라 안전하고, 3번에서 홈의 원본을 지우는 것도 같은 이유다
(재설치·주기 변경도 같은 경로에서, 멱등). **중앙 서버 자신도 `/opt/vuln-agent` 다** —
`/apps/vulnagent`(중앙 앱 배포 루트)에 깔면 `--uninstall` 이 앱 디렉토리를 통째로 지운다.
`--prefix` 는 `/opt` 를 못 쓰는 진짜 예외에서만 쓴다.

## 갱신 — 지금 즉시 밀어넣기 (`deploy/agent_push.sh`)

`vuln-inventory-agent.sh` 본체는 아래 "자동 업데이트" 로 노드가 스스로 갱신한다. 이 절은 **당장**
밀어넣고 싶을 때와 자동 업데이트가 꺼진 노드용이다. 노드들에 SSH 로 닿는 곳에서 한 줄이면 된다:

```bash
bash deploy/agent_push.sh 10.0.0.100 10.0.0.101 10.0.0.102
```

각 노드의 `<prefix>/bin/vuln-inventory-agent.sh` 를 덮고 **즉시 1회 수집·전송해 결과(HTTP)까지
확인**한다. **토큰·URL·타이머는 건드리지 않는다** — 노드의 `agent.env`(600)에 이미 있으므로
재입력이 필요 없고, 토큰이 이 스크립트를 거쳐 가지도 않는다. 안 깔린 노드는 건너뛰고 알려준다.

| 이 스크립트가 안 하는 것 | 대신 무엇을 하나 |
|---|---|
| 신규 설치·토큰 발급 | 그 서버에서 `install-agent.sh` 를 대화형으로 돌린다(토큰 발급이 사람 판단이라 그렇다) |
| 노드 목록 전체에 일괄 적용 | `deploy/install_staged_agents.sh` — [`deploy/README.md`](../deploy/README.md) "에이전트 일괄 설치·갱신" |
| `install-agent.sh` 자신(타이머·유닛·preflight·자동 업데이트 로직)의 갱신 | 그 노드에서 설치기를 다시 돌린다 |
| 웹 버튼으로 제공 | 하지 않는다 — PHP 컨테이너가 전 노드 root SSH 키를 들면 웹앱 침해가 전 노드 root 장악으로 번진다. **보는 건 웹**(자산 화면의 `meta.agent_version`), **미는 건 CLI** |

**`run.sh` 자신은 설치기를 재실행해야 갱신된다.** 속도 티어 필드(`cpu_quota_percent`·
`packaging_timeout_seconds`·`mem_max_mb`)를 읽는 버전이 아니면 그 노드는 스크립트 기본값
(CPU 10% / 120초 / 300M)으로만 돈다. 재실행은 `daemon-reload` → `enable` → `restart` 라
새 `run.sh` 가 확실히 물린다.

## 자동 업데이트 — poll 이 구버전을 감지하면 스스로 갱신한다 (2026-08-19)

상시 데몬(`run.sh`)이 poll 할 때 자기 `SCRIPT_VERSION` 을 같이 보내고, 서버가 배포된
`agent-src/vuln-inventory-agent.sh` 보다 낮다고 보면 다운로드 경로(`agent-dl.php`)·sha256·서명을
응답에 실어 보낸다. 에이전트는 **HTTPS 확인 → 버전 상향 확인(`sort -V`) → sha256 → Ed25519 서명
→ `bash -n`** 을 모두 통과했을 때만 `.bak` 백업 후 원자적으로 교체하고, 교체 뒤 자기점검
(`bash -n` + `--help`)에 실패하면 롤백한 다음 **그 버전을 기억해 재시도하지 않는다.**
**관리자 승인 게이트 없이 무인**이며, 어느 검증에 걸려도 조용히 넘어가지 않는다 — 결과가 다음
poll 로 보고돼 감사로그(`tb_activity_log`, `agent_auto_update`)에 남는다. 세 겹 검증이 각각 무엇을
막고 못 막는지·공개키 pin 의 설계 근거는
[`docs/dev/architecture.md`](../docs/dev/architecture.md) §4.1.

- 기존 노드의 `run.sh` 는 재설치 전까지 이 로직 자체를 모른다 — 받으려면 설치기를 한 번 더 돌린다.
- 서명 공개키(`<prefix>/etc/agent-update.pub`)는 **최초 설치 때만 고정(pin)** 된다. 이미 핀이 있고
  서버 키가 다르면 설치기는 **경고만 남기고 기존 핀을 유지**한다 — 바꾸려면 그 파일을 지우고 재설치.

### 자동 업데이트가 멈추거나 저하되는 경우 — 보고값으로 찾는다

`run.sh` 가 남기는 **보고값은 전부 여기 있다** — 로그·감사로그에서 본 값을 이 표에서 찾는다.
`ok`·`rollback`·`skipped_known_bad` 는 교체 이후 자기점검 경로이고 아래는 그 앞이다. 적용하지
않은 건은 **다음 poll 에 다시 시도한다**(fail-safe, 백오프 없음).

| 보고값 | 상황 | 적용되나 · 무엇을 확인하나 |
|---|---|---|
| `no_sha_tool` | `sha256sum`·`shasum` 이 둘 다 없음 | **아니오.** 검증 불가는 검증 면제가 아니다 |
| `no_verify_tool` | `openssl` 이 아예 없음(busybox·minimal 컨테이너) | **아니오.** 자동 갱신을 받으려면 그 노드에 `openssl` 을 넣는다 |
| `legacy_openssl_sha256_only` | OpenSSL 3.0 미만(RHEL8·Ubuntu20.04·Debian10 등) | **예 — 서명 검증만 건너뛰고 sha256 만으로 적용.** raw Ed25519 검증이 3.0+ 전용이라 **명시적 저하**다. 이 경로엔 웹 티어 침해 방어가 없으니 3.0+ 로 올리는 게 정공법 |
| `no_pinned_pubkey` · `no_signature` · `no_base64_tool` | 공개키 핀 없음 · 서버 응답에 서명 없음 · `base64` 없음(OpenSSL 3.0 이상 분기에서만 도달) | **아니오.** 핀이 없으면 그 노드에서 설치기를 한 번 더 돌리면 다시 받는다 |
| `checksum_mismatch` | 받은 파일 sha256 이 기대값과 다름 | **아니오.** 재시도해도 계속 나면 손상이 아니라 **중간자·배포본 교체를 의심**한다 |
| `signature_invalid` | Ed25519 서명이 고정 공개키로 검증되지 않음 | **아니오.** sha256 은 맞는데 서명만 틀린 것이라 **웹 티어 침해 시 정확히 이 값이 뜬다** — 배포 파이프라인·서버 침해부터 확인 |
| `syntax_check_failed` | 받은 스크립트가 `bash -n` 실패 | **아니오.** 배포된 정본 자체가 깨진 것이다 |
| `download_failed` · `backup_failed` | 다운로드 실패 · 교체 전 `.bak` 복사(`cp -p`) 실패 | **아니오.** `backup_failed` 는 디스크 가득참·권한을 본다 |
| `downgrade_rejected` | 과거에 정상 서명된 구버전 재전송(재생 공격) | **아니오.** 다운로드 **전에** 버전을 독립 검사한다 — 서명이 유효해 sha256·서명만으로는 못 막는다 |
| (로그만) | `SEND_URL` 이 `https://` 가 아님(레거시·loopback 설치) | **아니오 — 자체 갱신만 꺼진다.** poll·수집은 그대로 돈다. `agent_push.sh` 로 수동 갱신하거나 HTTPS 로 재설치 |

**의도적 다운그레이드(장애 롤백)는 poll 자동 경로로 불가능하다.** `agent_push.sh` 로 노드만
구버전으로 덮으면 다음 poll 에 자동으로 최신으로 되돌아간다 — `agent-src/vuln-inventory-agent.sh`
자체를 그 구버전으로 되돌려 배포한 **뒤에** 밀어넣어야 한다(순서를 반대로 하면 곧바로 되돌린다).

### 유지보수자 — `vuln-inventory-agent.sh` 를 고칠 때마다 서명한다

커밋 전에 `bash deploy/agent_sign.sh ~/agent-signing.key` 를 돌려 **바뀐 스크립트와 갱신된 `.sig`
를 같은 커밋**에 넣는다. 잊으면 에이전트가 `no_signature` 로 업데이트를 건너뛴다(노드가 구버전에
머물 뿐 잘못된 코드가 적용되진 않는다). 개인키는 저장소 밖(홈)에만 두고 커밋하지 않는다.
서명 대상은 자동 업데이트로 원격 교체되는 `vuln-inventory-agent.sh` 뿐이다 — `install-agent.sh`
는 관리자가 SSH 로 직접 전달한다.

```bash
openssl genpkey -algorithm ed25519 -out ~/agent-signing.key                            # 최초 1회
openssl pkey -in ~/agent-signing.key -pubout -out agent/vuln-inventory-agent.pub       # 공개키는 커밋
```

## 속도 티어 — 호스트마다 CPU·메모리·조립 타임아웃을 다르게

호스트 상세의 **수집 제어 카드**에서 4단계 중 하나를 고른다(`tb_host.agent_speed_tier`,
기본 `normal`). 값의 정의처는 **`server/src/agentspeedtier.php` 하나**이고,
`agent-poll.php` 가 poll 응답에 실어 보내면 `run.sh` 가 env 로 넘긴다.

| 티어 | 화면 표기 | `cpu_quota_percent` → `CPU_QUOTA` | `mem_max_mb` → `MEM_MAX` | `packaging_timeout_seconds` → `PACKAGING_TIMEOUT` |
|---|---|---|---|---|
| `very_fast` | 매우 빠름 | 80% | 1024MB | 300초 |
| `fast` | 빠름 | 40% | 512MB | 200초 |
| `normal` | 보통(기본값) | 10% | 300MB | 120초 |
| `slow` | 느림 | 5% | 200MB | 90초 |

- 세 값 모두 커널 cgroup(`systemd-run --scope`)이 강제하는 하드리밋이다. `install-agent.sh` 가
  범위를 검증해(CPU 1~100, 메모리 64~8192MB, 타임아웃 30~3600초) 벗어난 값만 버리고 기본값으로
  돈다 — 중앙이 이상한 값을 줘도 노드가 죽지 않는다.
- 티어를 바꿔도 **이미 설치된 노드의 `run.sh` 가 이 필드를 읽는 버전이어야** 반영된다(위 "갱신").
- `PROC_SCAN_TIMEOUT`(프로세스 스캔 상한, 기본 180초)은 **이 표에 없다** — 중앙이 내려주지 않는
  스크립트 자체 기본값이고, 같은 방식으로 30~3600초를 검증한다.

## 주기 변경 — 상시 데몬 노드는 웹에서, 구버전/cron 폴백 노드는 CLI 로

**상시 데몬 노드(위 "한 번만 설치하면 된다" 방식)는 SSH 가 필요 없다.** 중앙 대시보드의
**호스트 상세 → 수집 제어 카드**에서 주기를 바꾸면 `tb_host.poll_schedule_seconds` 가 갱신되고,
그 노드의 다음 poll(최대 10초 이내)에 바로 반영된다. 즉시 1회 실행·예약 실행도 같은 카드에서
된다. 아래 CLI 는 **웹에서 바꿀 수 없는 노드**를 위한 보조 수단이다.

```bash
bash deploy/agent_schedule.sh daily 10.0.0.100 10.0.0.101 10.0.0.102   # 셋 다 daily
bash deploy/agent_schedule.sh hourly 10.0.0.100 10.0.0.101='*:0/30'  # 노드별로 다르게
```

첫 인자가 기본 주기, 뒤는 노드 목록이다. `<노드>=<주기>` 로 주면 그 노드만 개별 주기를 쓴다.
노드 종류에 따라 다르게 동작한다:

| 노드 | `agent_schedule.sh` 의 동작 |
|---|---|
| 상시 데몬(레거시 타이머 파일 없음) | **건드리지 않고 건너뛴다.** 웹에서 바꾸라고 안내만 한다 |
| 레거시 systemd-timer(데몬 전환 전) | `OnCalendar` 를 새 값으로 바꿔 재무장 |
| cron 폴백(systemd 자체가 없음) | crontab 의 `run.sh --once` 항목을 새 주기로 재등록. `hourly`/`daily` 만 되고 커스텀 `OnCalendar`(`*:0/30` 등)는 cron 으로 표현 불가라 건너뛴다 |
| 안 깔린 노드(`agent.env` 없음) | 건너뛴다 |

어느 경우든 `agent.env` 의 `SCHEDULE` 도 같이 갱신되고, 다음 수집이 `meta.schedule` 로 실어 보내
중앙 화면이 바뀐 주기를 보여준다(3.8 이전 노드는 이 값을 안 보내 "실행 당시 주기"가 빈다).
**토큰·URL 은 안 건드린다.** `agent_push.sh` 와 같은 보안 모델이다(사람의 SSH 키로 CLI, 웹 버튼 아님).

## 주의점

| # | 알아둘 것 |
|---|---|
| 1 | **토큰은 파일(600)로만 저장된다.** `install-agent.sh` 가 `<prefix>/etc/agent.env` 에 쓰고 env 로만 전달하므로 `ps` 에 노출되지 않는다. 대화형 설치는 셸 히스토리에도 안 남는다 — `--token` 인자로 넘겼다면 설치 후 히스토리를 지운다 |
| 2 | **토큰에 유효기간이 붙을 수 있다(2026-08-08).** 발급 화면에서 무기한/30일/90일/1년 중 고른다. **기존 토큰은 `expires_at` 이 NULL 이라 그대로 무기한.** 만료된 토큰은 401 이 되고 중앙 감사로그에 `agent_token_expired` 가 남는다 — 그 호스트용 토큰을 새로 발급해 노드의 `agent.env` 를 갱신한다(자동 갱신·재발급은 일부러 두지 않았다). 목록에 만료일·만료임박(잔여 7일) 뱃지가 뜬다 |
| 3 | **HTTP 405/401 은 정상 신호다.** `ingest.php` 는 POST 전용이라 GET 으로 열면 405, 토큰이 틀리면 401 이다. 설치기의 "즉시 1회" 전송이 2xx 였는지로 판단한다 |
| 4 | **주기 변경 경로는 실행 방식에 따라 다르다.** 상시 데몬은 웹, cron 폴백·구버전 노드만 `agent_schedule.sh` 또는 설치기 재실행 |
| 5 | **중앙 코드와 무관하게 독립 동작한다.** 중앙을 재배포해도 노드의 데몬·타이머는 그대로 돈다 |

### 전송 URL(`--server`)은 대상 서버가 실제로 닿는 주소여야 한다

| 대상 | 넣을 주소 | 왜 |
|---|---|---|
| 중앙 서버 자신 | `http://127.0.0.1:8081/ingest.php` | 웹 컨테이너 직결(loopback 전용 포트). Caddy·TLS 를 통째로 건너뛴다 |
| 같은 내부망의 다른 서버 | `<운영-도메인>:8080` | Caddy(HTTPS)를 거친다. 도메인이 공인 IP 로 풀리면 설치기가 `/etc/hosts` 로 내부 IP 에 묶는다 |
| 진짜 외부 서버 | `<운영-도메인>:8080` | 밖에서는 공인 IP 가 정답 |

중앙 자신에 loopback 을 쓰는 이유: 도메인이 **공인 IP(라우터)** 로 풀리는데 내부에서 자기
라우터로 되돌아 들어가는 건(헤어핀 NAT) 대개 막혀 있다(`Connection refused`). IP 로 직접 8080 을
치는 것도 안 된다 — Caddy 가 **SNI 로 사이트를 고른다.** 방화벽에 뚫을 건 **하나뿐이다** —
대상 서버 → 중앙 `WEB_PORT`(기본 8080) **아웃바운드 HTTPS.** 중앙이 대상 서버로 들어가는 경로는
없다. 단, loopback 으로 설치한 중앙 서버 자신은 HTTPS 가 아니라 **자동 업데이트가 꺼진다**
(위 "자동 업데이트가 멈추거나 저하되는 경우" 표).

## 상태 확인

```bash
systemctl status vuln-agent.service      # 데몬 상태(상시 기동인지)
journalctl -u vuln-agent.service -n 20   # 실행 로그(poll·수집 시작·자동 업데이트 결과)
cat <prefix>/logs/last.json              # 최근 수집 결과(로컬 사본)
cat <prefix>/logs/last_scan_at           # 마지막 정기수집 시각(epoch)
cat <prefix>/logs/poll_interval          # 현재 정기수집 주기(초, 중앙에서 바꾸면 갱신됨)
```

## 제거

```bash
cd /opt/vuln-agent
sudo bash install-agent.sh --uninstall [--prefix 설치경로]
```

타이머·유닛·cron 항목과 `bin`/`etc`/`logs` 를 지운다. **원본 스크립트 2개는 남는다**(재설치가
쉬우라고). 흔적까지 지우려면 `sudo rm -rf /opt/vuln-agent`.

## 무엇을 수집하나

이 원자료가 중앙에서 CVE 미러(NVD·OSV·KISA)와 매칭되고, 런타임 노출·EPSS·KEV 가중이 얹혀 최종
우선순위가 된다. 판정 로직·페이로드 스키마·의존성 그래프·오탐 억제 근거는
[`docs/dev/architecture.md`](../docs/dev/architecture.md)(§1 수집 · §2.2·§2.4 억제 · §2.7 계정 ·
§2.9 의존성 그래프), 피드별 역할은 [`docs/dev/피드소스-역할.md`](../docs/dev/피드소스-역할.md).

| 수집 항목 | 어디서 읽나 | 중앙에서 쓰이는 곳 | root |
|---|---|---|---|
| OS·커널·CPE | `/etc/os-release`·`uname`·`dmidecode` | 호스트 기본 정보, 커널 CVE 매칭 | `dmidecode` 만 |
| 설치 패키지 | 호스트 `dpkg`/`rpm` — NEVRA·소스패키지·**출처** | 패키지 CVE 매칭 | 아니오 |
| 컨테이너 내부 패키지 | 실행 중 컨테이너 rootfs 직독(아래) | `container_id` 로 구분 저장 → 호스트 상세 컨테이너 탭 | 예 |
| 실행 프로세스·리스닝 포트 | `/proc` · `ss -tulpn` | **외부노출 판정**, 재시작 필요 판정 | 예(포트↔프로세스 매핑) |
| 보안설정 | sshd·계정·파일권한·SELinux/AppArmor·방화벽·시간동기화·로그·암호화 | 서버가 CCE 점검 | 일부 |
| 언어 패키지 | 전역 CLI 목록 + `PROJECT_SCAN_ROOTS` 아래 **설치본**(`*.dist-info/METADATA`·`*-lock`·`Gemfile.lock`·`Cargo.lock`·`*.jar` · Go 바이너리 buildinfo 등)과 **선언 파일**(`go.mod`·`requirements.txt`·`pom.xml`) — 8개 생태계 | 앱 의존성 CVE 매칭, 라이선스 식별 | 아니오 |
| 계정 인벤토리 | `getent passwd` · `/etc/shadow` · `lastlog` · `sudoers`(아래 — **개인정보성**) | ISMS-P 2.5.x / N2SF AC 계정관리 판정 | 예 |
| 패키지 의존성 그래프 | `pom.xml` 원문 · SBOM 파일(`SBOM_DIR/*.json`, CycloneDX·SPDX) — **에이전트는 파싱하지 않고 원문을 올린다** | 직접/전이 판정, `depgraph.php` | 아니오 |
| 오탐 억제 근거 | changelog 의 CVE 줄 · 적용된 벤더 권고(errata) · `debsecan` · 재시작/재부팅 필요 신호 | 매처가 이미 패치된 건을 억제(재시작·재부팅 필요는 억제하지 않는다) | 일부 |
| 패키지 무결성 검증 | `rpm -Va` / `dpkg --verify` — **`--verify-files` 를 준 실행에서만** | 설치 패키지 탭의 "원본과 다름" | 예 |
| 수집 자체(`meta`) | `running_as`·`agent_version`·`schedule`·`elapsed_seconds`·`peak_rss_mb`·`cpu_seconds` | `tb_scan` 의 소요시간·자원 기록. 3.10 미만 노드는 뒤 세 필드가 빈다 | — |

- **컨테이너 내부도 본다** — 호스트 스캔에서 통째로 빠지던 미탐 영역이다. `collect_containers` 가
  실행 중 컨테이너의 rootfs 를 직접 읽어 내부 패키지 인벤토리를 뜬다(docker CLI 비의존이라
  podman·containerd 도 잡힌다). 함께 오는 k8s 위치·이미지 다이제스트·런타임 상태·SBOM 은
  **호스트 상세 → 컨테이너 탭**, 의존성 엣지는 같은 화면의 `depgraph.php` 가 읽는다. 단
  **프로세스 인벤토리는 호스트 것만** 뜬다(다른 mount namespace 는 건너뛴다).
- **설치본이 먼저 나가고 선언 파일이 뒤에 붙는다** — 예산(`MAX_BYTES`)이 모자라면 고신뢰 쪽이
  남아야 하기 때문이다. 전체 스캔은 `PROJECT_SCAN_TIMEOUT`(300초)·`SCAN_MAX_FILES`(3000)·
  `SCAN_MAX_DEPTH`(8), Go 바이너리는 `GO_BIN_MIN_SIZE`(1M)·`GO_BIN_PROBE_BYTES`(64KB)·
  `GO_BIN_SCAN_MAX`(40개)로 캡핑된다. 의존성 원문은 예산이 따로고(`pom.xml` 128KB · SBOM 2MB/파일).
- **호스트 자신의 SBOM 은 `/opt/vuln-agent/sbom/_host.json` 으로 둔다.** SBOM 은 파일명이 곧
  대상이라 `_host`(예약 이름, docker/podman 이름 규칙상 만들 수 없어 충돌 불가)는 호스트 자신으로
  저장된다. 붙을 곳이 없는 SBOM 은 버리되 `error_log` 와 ingest 응답의 `sbom_dropped` 로 드러난다
  — 호스트로 떨어뜨리는 폴백은 없다(사라진 컨테이너의 SBOM 이 호스트 것으로 둔갑하면 오탐이다).
- **개인정보 고지 — 계정명·홈 경로·마지막 로그인 시각이 중앙 DB(`tb_host_account`)에 스캔별로
  쌓인다.** 중앙은 이 값으로 90일 미로그인·sudo 보유자·공유계정 추정·퇴직자 계정 잔존을 판정하며,
  계정 탭 열람은 감사로그 대상이다. **패스워드 해시는 어떤 형태로도 수집·전송하지 않는다**
  (shadow 는 정책 필드와 잠금 여부 1/0 만). `/etc/shadow`·`sudoers` 를 못 읽으면(비root) 그 섹션을
  **아예 만들지 않는다** — 중앙이 `NA`(판정 불가)로 읽는다. 없는 것을 "정상"으로 위장하지 않는다.

## 실행 옵션

| 옵션 | 뜻 |
|---|---|
| `--send URL` / `--token TOK` | 수집 후 중앙(`ingest.php`)으로 POST (파일 저장도 유지) |
| `-o, --output PATH` | 결과 파일 경로 |
| `--limit` | 기본 적용되는 cgroup 상한을 명시적으로 활성화(기본값은 CPU 한 코어의 10% · 메모리 300M = `normal` 티어. 중앙이 티어를 내려주면 그 값 — 위 "속도 티어" 표). `AGENT_LIMIT=0`일 때만 해제 |
| `--no-changelog` | changelog 수집 생략 — **가장 무거운 단계**. 대신 백포트 억제가 약해진다 |
| `--timeout N` | 명령별 타임아웃 초(기본 20) |
| `--verify-files` | 패키지 무결성 검증(`rpm -Va` / `dpkg --verify`) — **기본 꺼짐**. 아래 설명 |
| `--verify-timeout N` | 무결성 검증 단독 상한 초(기본 300). `--timeout`(20초)로는 무조건 잘린다 |
| `--command-id ID` | 중앙의 즉시/예약 명령 실행임을 표시(페이로드 최상위 `command_id`). `run.sh` 가 붙인다 |

### `--verify-files` — 패키지 무결성 검증 (기본 꺼짐)

패키지 관리자가 설치 때 기록해 둔 파일별 digest·권한·소유자를 지금 디스크와 대조해
**"설치 이후에 파일이 바뀌었다"** 를 잡는다(N2SF 제6장 IN 구성요소 무결성의 근거 데이터).
GPG 서명 검증은 범위가 아니다 — 파일 무결성만 본다.

**왜 기본이 꺼져 있나 — 비용 때문이다.** `rpm -Va` 는 설치된 **모든 패키지의 모든 파일을
해시**해 수 분 + 무거운 디스크 IO 가 든다("대상 서버에 무리를 주지 않는다"는 대전제와 충돌).
`nice 19`·`ionice idle` 은 자식인 rpm/dpkg 도 그대로 상속한다.

| 항목 | 값·동작 |
|---|---|
| 시간 상한 | `--verify-timeout`(기본 300초). 잘리면 결과에 `partial` 을 실어 보내고 화면은 **"부분 결과"** 로 표시한다 — 잘린 결과의 0건을 "깨끗함"으로 읽으면 안 되기 때문 |
| 줄 수 상한 | `VERIFY_MAX_LINES`(기본 500, 환경변수). 넘으면 `truncated` 와 함께 **잘리기 전 전체 건수**를 보낸다 |
| 버리는 것 | 설정파일(`c` 플래그) 줄 — 관리자가 고치는 게 정상이라 전부 노이즈다 |
| 화면 표기 | 자산 상세 → 설치 패키지 탭이 **"미수행 / 정상 / 원본과 다름 N건"** 을 구분한다. 이 플래그 없이 수집한 자산은 "정상"이 아니라 **"미수행"** |
| 어휘 | 잡힌 파일은 "변조됨"이 아니라 **"패키지 원본과 다름(관측)"** — 운영자가 직접 바꾼 파일일 수 있다 |

켜는 길은 두 가지다. **매 수집마다** 켜려면 설치 때 `install-agent.sh --verify-files` 를 준다 —
`<prefix>/etc/agent.env` 에 `VERIFY_FILES=1` 이 들어가 노드 고정값이 된다.

**필요할 때 한 번만**은 중앙에서 켠다: 자산 상세 → 설치 패키지 탭의 **`무결성 검사`** 버튼이
`tb_agent_command.verify_files=1` 로 명령을 큐에 넣고, `agent-poll.php` 가 응답에
`due_command_verify_files` 를 실어 준다. `run.sh` 는 그 값이 1 이면 **그 실행에 한해서만**
`--verify-files --verify-timeout 300` 을 붙인다(노드 고정값과는 OR 관계다). 명령 단위라
다음 정기수집에는 따라붙지 않는다 — 기본 꺼짐이라는 대전제는 그대로다.

설치하지 않고 **그 자리에서 한 번만** 돌려볼 수도 있다(타이머를 등록하지 않는다):

```bash
sudo bash vuln-inventory-agent.sh                       # 수집해서 로컬 파일로만 저장
sudo bash vuln-inventory-agent.sh \
     --send https://<운영-도메인>:8080/ingest.php \
     --token <중앙에서 이 호스트용으로 발급한 토큰>       # 수집 후 전송(파일 저장도 유지)
```

CPU·메모리 cgroup 제한은 기본 적용되고, 에이전트 자체도 `nice 19`·`ionice idle`·명령별 timeout
으로 돈다. **피크 메모리는 실측 61.6MB**(Debian 12 · 91패키지) — 수치·스케일링 규칙·재측정법은
[`docs/dev/에이전트-리소스-프로파일.md`](../docs/dev/에이전트-리소스-프로파일.md) 참고.
