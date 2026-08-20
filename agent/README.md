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

- `install-agent.sh` 가 있는 노드는 **`run.sh` 를 systemd 상시 서비스**(`Type=simple`,
  `Restart=on-failure`)로 등록해 `enable --now` 한다. `run.sh` 는 10초마다 중앙의
  `agent-poll.php` 를 GET 으로 poll 하는 while-loop 데몬이다 — 리스닝 포트를 열지 않는
  **아웃바운드 전용**이라 중앙이 노드로 들어오는 경로는 없다.
- poll 응답에 실린 `poll_schedule_seconds` 가 지났으면(정기수집 주기, 초기값은 설치 때
  `--schedule` 로 정한 값) `vuln-inventory-agent.sh` 를 돌려 수집·전송한다. 중앙 웹에서
  주기를 바꾸면 **다음 poll 에 바로 반영**된다 — SSH 로 재설치할 필요가 없다.
- poll 응답에 `due_command_id` 가 실려 있으면(중앙에서 "지금 수집" 을 누른 경우) 정기
  주기와 무관하게 즉시 수집하고, 그 명령을 완료 처리한다.
- 네트워크가 잠깐 끊겨도 데몬은 죽지 않는다 — poll 실패가 연속되면 poll 간격을 10초→
  최대 5분까지 지수 백오프했다가, 성공하면 10초로 복귀한다.
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
> 커밋하지 않는다(오픈소스라 남의 배포가 내 CA 를 신뢰하면 안 된다). 자산 화면의 다운로드 버튼이
> "아직 준비 안 됨" 이라면, 중앙 관리자가 최초 1회 추출해야 한다 — [`deploy/README.md`](../deploy/README.md)
> 의 **"에이전트 CA 준비"** 참고.

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
중단**한다. 예전엔 이 셋을 사람이 미리 손봐야 했고, 안 하면 "타이머는 도는데 자산은 안 올라오는"
조용한 실패가 됐다.

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
| `openssl` | **아니오**(수집·전송엔 안 쓴다) | 자동 업데이트가 **적용되지 않는다** — 서명을 검증할 도구가 없어 `no_verify_tool` 로 보고하고 구버전에 그대로 머문다(조건별 동작은 아래 **"자동 업데이트의 예외 상황"** 표 한 곳에만 적는다). 수집·전송은 그대로 |
| `debsecan` | **아니오** | 중앙이 데비안 보안 트래커를 직접 받아 판정한다 |

예전엔 `jq` 가 없으면 설치기가 `apt` 로 깔았고, 그마저 실패하면 에이전트가 텍스트를 뱉고
**전송을 조용히 건너뛰었다**(타이머는 매시간 초록불인데 자산은 안 올라왔다).

루트 CA 는 중앙에서 한 번 꺼내 두고 모든 대상에 재사용한다 — 추출 명령은
[`deploy/README.md`](../deploy/README.md) **"에이전트 CA 준비"** 한 곳에만 둔다.
헤어핀 NAT 를 피하려고 이름을 IP 로 바꿔 붙는 건 **안 된다**(Caddy 가 SNI 로 사이트를 고른다)
— 그래서 IP 를 바꾸는 게 아니라 `/etc/hosts` 로 **이름이 가리키는 곳**을 바꾼다.

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

단, 에이전트 본체(`vuln-inventory-agent.sh`)는 root 가 아니어도 **실패하지 않고 경고만
띄운 뒤 수집 가능한 것만 모은다**(읽기 전용이라 OS·커널·패키지 목록은 그대로 모인다).
누가 실행했는지는 페이로드의 `meta.running_as` 에 실려 중앙이 부분 수집임을 알 수 있다.
정상 설치 경로는 root 데몬이라 이 경고를 볼 일은 없다.

**chmod 는 필요 없다** — `bash <파일>` 로 실행하면 된다(`./` 로 실행하고 싶을 때만
`chmod +x install-agent.sh vuln-inventory-agent.sh`). **chown 도 필요 없다** — `sudo` 로
실행하면 설치기가 `/opt/vuln-agent/**` 를 root 소유로 새로 만들고, 토큰 파일
(`etc/agent.env`)은 `600` 으로 잠근다.

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

**왜 아무 데나 두면 안 되나.** `sudo bash install-agent.sh` 는 그 파일의 내용을 root 로
실행한다. 다른 계정이 파일을 바꿔칠 수 있는 곳(`/tmp`·웹 루트 `/var/www`·여러 계정이 공유하는
배포 폴더)에 두면 남의 코드가 root 로 도는 셈이다. `/opt` 는 root 소유(`755`)라 안전하고,
3번에서 홈의 원본을 지우는 것도 같은 이유다. 재설치·주기 변경도 같은 경로에서 한다(멱등).

**어느 호스트든 `/opt/vuln-agent` 로 통일한다 — 중앙 서버 자신도 마찬가지다.**
`/apps/vulnagent` 는 *중앙 앱* 배포 루트(`{app,bin,etc,logs,data,backups}`)라 성격이 다르다 —
에이전트를 거기로 깔면 bin/etc/logs 가 앱과 섞이고 `--uninstall` 이 앱 배포 디렉토리를 통째로
지운다. `--prefix` 는 `/opt` 를 못 쓰는 진짜 예외 상황에서만 쓴다.

## 갱신 — 지금 즉시 밀어넣기 (`deploy/agent_push.sh`)

`vuln-inventory-agent.sh` 본체는 아래 "자동 업데이트" 로 노드가 스스로 갱신한다. 이 절은 그
주기를 기다리지 않고 **당장** 밀어넣고 싶을 때, 그리고 자동 업데이트가 꺼진 노드를 위한 수단이다.

master 처럼 **노드들에 SSH 로 닿는 곳**에서 한 줄이면 된다:

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

- 2026-08-06: `run.sh` 가 poll 응답의 `cpu_quota_percent`·`packaging_timeout_seconds`·
  `mem_max_mb`(호스트별 속도 티어)를 읽어 `vuln-inventory-agent.sh` 에 env(`CPU_QUOTA`·
  `PACKAGING_TIMEOUT`·`MEM_MAX`)로 넘긴다 — **이미 설치된 노드는 재설치 전까지 이 값을 무시하고
  스크립트 자체 기본값(CPU 10% / 120초 / 300M)으로만 돈다.**
- **설치기를 재실행하면 `run.sh` 가 확실히 갱신된다(2026-08-06 수정).** 예전엔 마지막 단계가
  `systemctl enable --now` 여서, 유닛이 이미 active 인 노드에서는 **재시작이 일어나지 않아**
  방금 디스크에 쓴 새 `run.sh` 를 옛 프로세스가 계속 메모리에 물고 돌았다(속도 티어를 넣어도
  반영 안 되는 원인). 지금은 `daemon-reload` → `enable` → `restart`(무조건 재기동) 순서다.

## 자동 업데이트 — poll 이 구버전을 감지하면 스스로 갱신한다 (2026-08-19)

상시 데몬(`run.sh`)이 `agent-poll.php` 를 poll 할 때마다 자기 `SCRIPT_VERSION` 을 같이 보낸다.
서버는 배포된 `agent-src/vuln-inventory-agent.sh` 파일에서 직접 최신 버전·sha256 을 읽어(DB
아님 — `agent_push.sh` 로 배포하면 이 값도 즉시 같이 바뀐다) 구버전이면 응답에 다운로드
경로(`agent-dl.php?f=vuln-inventory-agent.sh`, 이 서버 정본 경로 고정)와 sha256·서명을 실어 보낸다.

`run.sh` 의 `do_update()` 는 그 응답을 받으면:

1. **`SEND_URL` 이 HTTPS 가 아니면 여기서 멈춘다** — 아래 검증 전부가 "다운로드를 HTTPS 로
   안전하게 받았다"는 전제 위에 있으므로, 이게 최소한의 차단선이다.
2. **새 버전이 현재보다 엄격히 높은지** `sort -V` 로 독립 검사한다(재생 공격 방어 — 아래 표).
3. 새 스크립트를 받아 **sha256 검증**.
4. **Ed25519 서명 검증**(아래 "커밋 시점 서명").
5. `bash -n` 문법 검사를 통과하면 기존 스크립트를 `.bak` 으로 백업하고 `mv` 로 원자적 교체.
6. 다음 실행이 시작되기 **전에** 새 스크립트 자기점검(`bash -n` + `--help` 무해 실행)을 한 번
   더 한다 — 롤백 여부는 이 결과로만 정한다. 뒤이은 실제 수집이 중앙 서버 오류·네트워크
   타임아웃으로 실패해도 그건 업데이트 실패로 보지 않는다(정상 운영 중 실패와 분리).
   자기점검에 실패하면 `.bak` 으로 롤백하고, **그 버전 문자열을 기억**해 서버가 같은 버전을
   다시 제안해도 재시도하지 않는다(무한 교체↔롤백 방지, 보고값 `skipped_known_bad`).
7. 적용 결과(성공/실패/롤백/건너뜀)는 `UPDATE_REPORT_FILE` 에 한 줄로 남았다가 다음 poll GET
   에 실려 서버로 보고되고, 서버는 감사로그(`tb_activity_log`, `agent_auto_update`)에 남긴다.

**어느 검증에 걸려도 조용히 넘어가지 않는다.** 적용하지 않고 로그와 다음 poll 보고에 사유를
남기며, 서버가 여전히 구버전이라고 보는 한 자동으로 다시 시도한다(fail-safe).

**관리자 승인 게이트 없이 완전 무인이다** — 이 저장소의 설계 원칙("중앙→노드 인바운드 경로는
만들지 않는다")을 그대로 따라, 서버는 poll 응답에 정보를 실을 뿐이고 실제 다운로드·검증·교체는
전부 에이전트가 자기 토큰으로 능동적으로 pull 해 수행한다. 기존 노드의 `run.sh` 는 재설치
전까지 이 로직 자체를 모르므로, 기능을 받으려면 그 노드에서 `install-agent.sh` 를 한 번 더 돌린다.

**서명 공개키(`agent-update.pub`)는 최초 설치 시에만 고정(pin)된다.** 이미 핀이 있으면 설치기는
서버가 내려준 공개키와 지문을 비교해 같으면 그대로 두고, 다르면 **경고만 남기고 기존 핀을
유지**한다(덮어쓰지 않음). 의도적으로 키를 바꾸려면 노드에서 `<prefix>/etc/agent-update.pub` 를
수동으로 지운 뒤 설치기를 다시 실행해야 한다.

### 자동 업데이트의 예외 상황 — 무엇이 적용되고 무엇이 멈추나

| 상황 | 적용되나 | 동작·보고값 | 왜 그렇게 했나 |
|---|---|---|---|
| **`openssl` 이 아예 없는 노드**(busybox·minimal 컨테이너 등) | **아니오** | `have openssl` 에서 걸려 **적용하지 않고** `no_verify_tool` 로 보고한다. 구버전 그대로 돌면서 다음 poll 에 다시 시도한다 | 서명 검증은 sha256 통과와 **별개로** 반드시 통과해야 한다 — 검증할 수단이 없는 것은 "검증 면제"가 아니라 "검증 불가"다. 조용한 스킵이 아니라 로그·보고로 남긴다(sha256 도구가 없을 때의 `no_sha_tool` 과 같은 패턴). 자동 갱신을 받으려면 그 노드에 `openssl` 을 넣어야 한다 |
| **OpenSSL 3.0 미만 노드**(RHEL8·Ubuntu20.04·Debian10 등 1.1.1 계열) | **예**(서명 검증만 건너뜀) | `run.sh` 가 `openssl version` 으로 major 를 확인해 3 미만이면 **서명 검증만 건너뛰고 sha256 만으로 적용**한다. 보고값 `legacy_openssl_sha256_only` | `openssl pkeyutl -verify -rawin`(raw Ed25519)은 3.0 이상에서만 된다. 감지 없이 돌리면 서명 검증이 **항상** 실패해 자동 업데이트가 영구히 멈춘다. 조용한 폴백이 아니라 로그·보고에 남기는 **명시적 저하**다 — 이 경로에선 아래 "웹 티어 침해" 방어가 사라지므로 OpenSSL 3.0+ 로 올리는 것이 정공법 |
| **OpenSSL 3.0 이상인데 공개키 핀·서명·`base64` 중 하나가 없음** | **아니오** | 각각 `no_pinned_pubkey`(`<prefix>/etc/agent-update.pub` 가 비었거나 없음) · `no_signature`(서버 응답에 서명이 없음 — 아직 서명 안 된 배포이거나 구버전 서버) · `no_base64_tool` 로 보고하고 **적용하지 않는다.** 다음 poll 에 다시 시도한다 | 이 셋은 3.0 이상 분기에서만 도달한다 — 위 두 행과 조건이 정반대라 따로 적는다. 핀이 없을 때는 그 노드에서 `install-agent.sh` 를 한 번 더 돌리면 다시 받는다 |
| **HTTP 로 설치된 노드**(`SEND_URL` 이 `https://` 로 시작하지 않음) | **아니오**(자체 갱신만) | poll·수집은 그대로 돌고 **`vuln-inventory-agent.sh` 자체 갱신만** 건너뛴다. 로그에 이유를 남긴다 | 서명도 sha256 도 다운로드를 HTTPS 로 받았다는 전제 위에 있다. 보통은 도메인만 넣어도 `https://` 가 자동으로 붙으므로 레거시 설정·loopback 설치에서만 생긴다. `agent_push.sh` 로 수동 갱신하거나 HTTPS 로 재설치한다 |
| **재생(replay) 공격** — 과거에 정상 서명된 구버전을 그대로 다시 내려보냄 | **아니오** | `do_update()` 가 다운로드 **전에** `sort -V` 로 새 버전이 현재보다 엄격히 높은지 독립 검사하고, 아니면 `downgrade_rejected` 로 보고하고 거부한다 | `agent-poll.php` 의 버전비교는 웹 티어가 침해되면 그 판단 자체가 공격자 손에 들어간다. 구버전 스크립트는 서명 자체가 유효하므로 sha256·서명 검증만으로는 못 막는다 |
| **관리자의 의도적 다운그레이드**(장애 대응 롤백) | **아니오** | poll 자동 경로로는 **불가능**. `agent_push.sh` 로 노드만 구버전으로 덮으면 다음 poll(수십 초 이내)에 자동으로 최신으로 되돌아간다 | `agent-poll.php` 는 "배포된 `agent-src/vuln-inventory-agent.sh` 보다 낮으면 무조건 갱신 지시"만 한다. 정말 구버전을 유지하려면 **`agent-src/vuln-inventory-agent.sh` 자체를 그 구버전으로 먼저 되돌려 배포**해야 서버가 그걸 "최신"으로 보고 갱신 지시를 멈춘다. 그 뒤에 `agent_push.sh` 로 개별 노드에 밀어넣는다 — 순서를 반대로 하면 자동 업데이트가 곧바로 되돌린다 |

### 커밋 시점 서명 — sha256 이 못 막는 "웹 티어 침해" 를 막는다 (2026-08-20)

sha256 검증은 **다운로드가 중간에 깨지지 않았는지**만 보장한다. 그 값 자체를 같은
`agent-poll.php`(웹앱)가 계산해서 내려주므로, 웹 티어가 침해되면 공격자는 자신이 준비한 악성
스크립트의 해시를 그대로 응답에 실어 "검증 통과"로 만들 수 있다 — sha256 만으로는 **웹 티어
침해 1건이 전체 노드의 root 침해로 번질 수 있었다.**

서명은 출처가 다르다. 유지보수자가 **로컬 머신에만 있는 Ed25519 개인키**로 `vuln-inventory-agent.sh`
를 고칠 때마다 커밋 전에 서명해 `.sig`(64바이트, raw 서명)를 스크립트와 함께 커밋한다. 배포는
기존과 동일(git pull + compose 재기동) — `.sig` 도 스크립트와 같은 ro 마운트(`agent-src/`)로
자동 배포된다. **PHP 는 이 파일을 읽기만 할 뿐 서명을 절대 만들지 않는다** — 웹 티어가 뚫려도
유효한 서명을 위조할 수 없다. 공개키(`agent/vuln-inventory-agent.pub`)는 비밀이 아니므로
레포에 커밋하고, 에이전트가 최초 설치 시 `agent-dl.php` 로 받아 `<prefix>/etc/agent-update.pub`
(권한 600)에 고정한다 — **이후 poll 응답으로 이 키를 바꾸는 경로는 없다**(그 경로가 있으면
서명 체계 자체가 무의미해진다).

**유지보수자 체크리스트 — `vuln-inventory-agent.sh` 를 고칠 때마다:**

1. 최초 1회만: Ed25519 키쌍 생성(개인키는 저장소 밖 홈 디렉터리에만 둔다, 커밋 금지 —
   `.gitignore` 의 `*.key` 가 실수 커밋을 막지만, 애초에 저장소 안에 만들지 않는다):
   ```bash
   openssl genpkey -algorithm ed25519 -out ~/agent-signing.key
   openssl pkey -in ~/agent-signing.key -pubout -out agent/vuln-inventory-agent.pub
   ```
2. 스크립트를 고칠 때마다 커밋 전에:
   ```bash
   bash deploy/agent_sign.sh ~/agent-signing.key
   ```
3. **바뀐 `vuln-inventory-agent.sh` 와 갱신된 `.sig` 를 같은 커밋에 넣는다.** 잊으면
   `agent-poll.php` 가 서명 없음(`signature: null`)으로 응답하고, 에이전트는 `no_signature`
   로 자동 업데이트를 건너뛴다(노드가 구버전에 멈춰 있을 뿐 잘못된 코드가 적용되진 않는다).

**대상 범위**: `vuln-inventory-agent.sh`(자동 업데이트로 원격 교체되는 파일)만 검증한다.
`install-agent.sh` 는 최초 설치 시 SSH/scp 로 관리자가 직접 전달하고 자동 업데이트 대상이
아니라 넣지 않았다 — 설치기 무결성은 전달 경로(SSH)의 신뢰에 의존한다.
**뺀 것(YAGNI)**: 키 순환 절차·다중 서명자·별도 서명 서버/HSM(1인 유지보수 레포에서 불필요),
poll 응답으로 공개키를 바꾸는 기능(설계 원칙과 정면 충돌).

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

- 세 값 모두 커널 cgroup(`systemd-run --scope`)이 강제하는 하드리밋이다. `mem_max_mb` 는
  나중에 붙었다(2026-08-06) — 그전엔 메모리 상한이 **항상 300M 고정**이라 여유가 빠듯한
  호스트(실측 `peak_rss` 350.2MB)가 cgroup 상한에 걸렸다.
- `install-agent.sh` 는 받은 값을 범위 검증한다(CPU 1~100, 메모리 64~8192MB, 타임아웃
  30~3600초). 벗어나면 그 값만 버리고 스크립트 기본값으로 돈다 — 중앙이 이상한 값을 줘도
  노드가 죽지 않는다.
- 티어를 바꿔도 **이미 설치된 노드의 `run.sh` 가 이 필드를 읽는 버전이어야** 반영된다
  (위 "갱신" 절 참고).
- `PROC_SCAN_TIMEOUT`(프로세스 스캔 상한, 기본 180초)은 **이 표에 없다** — 중앙이 내려주지
  않고 `vuln-inventory-agent.sh` 자체 기본값 고정이다. 위 세 값과 같은 패턴으로 스크립트
  안에서 숫자·범위(30~3600초)를 검증한다. 티어 연동은 필요해지면 네 번째 열로 추가한다.

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

어느 경우든 `agent.env` 의 `SCHEDULE` 도 같은 값으로 갱신한다 — 다음 수집이 `meta.schedule` 로
실어 보내 중앙의 자산 상세 수집 제어 영역이 바뀐 주기를 그대로 보여준다.
**토큰·URL 은 안 건드린다**(주기 변경엔 필요 없다). `agent_push.sh` 와 같은 보안 모델이다
(사람의 SSH 키로 CLI, 웹 버튼 아님). 3.8 이전 노드는 `meta.schedule` 을 안 보내 수집 이력의
"실행 당시 주기"가 비어 보인다 — 본체를 올리면 다음 수집부터 채워진다.

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

중앙 자신에 loopback 을 쓰는 이유: 도메인은 **공인 IP(라우터)** 로 풀리는데, 내부에서 자기
라우터로 되돌아 들어가는 건(헤어핀 NAT) 대개 막혀 있다. `Connection refused` 가 그것이다.
IP 로 직접 8080 을 치는 것도 안 된다 — Caddy 가 **SNI 로 사이트를 고르므로** 이름이어야 한다.
방화벽에 뚫을 건 **하나뿐이다** — 대상 서버 → 중앙 `WEB_PORT`(기본 8080) **아웃바운드 HTTPS**
(운영은 Caddy 가 앞단에서 TLS 를 받는다). 중앙이 대상 서버로 들어가는 경로는 없다.
단, loopback(`http://127.0.0.1:8081`)으로 설치한 중앙 서버 자신은 HTTPS 가 아니라
**자동 업데이트가 꺼진다**(위 "자동 업데이트의 예외 상황" 표).

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

이 원자료가 중앙에서 CVE 미러(NVD·OSV·KISA)와 매칭되고, 런타임 노출·EPSS·KEV 가중이 얹혀
최종 우선순위가 된다. 피드 소스별 역할은
[`docs/dev/피드소스-역할.md`](../docs/dev/피드소스-역할.md) 참고.

| 수집 항목 | 어디서 읽나 | 중앙에서 쓰이는 곳 | root |
|---|---|---|---|
| OS·커널·CPE | `/etc/os-release`·`uname`·`dmidecode` | 호스트 기본 정보, 커널 CVE 매칭 | `dmidecode` 만 |
| 설치 패키지 | 호스트 `dpkg`/`rpm` — NEVRA·소스패키지·**출처** | 패키지 CVE 매칭 | 아니오 |
| 컨테이너 내부 패키지 | 실행 중 컨테이너 rootfs 직독(아래) | `container_id` 로 구분 저장 → 호스트 상세 컨테이너 탭 | 예 |
| 실행 프로세스·리스닝 포트 | `/proc` · `ss -tulpn` | **외부노출 판정**, 재시작 필요 판정 | 예(포트↔프로세스 매핑) |
| 보안설정 | sshd·계정·파일권한·SELinux/AppArmor·방화벽·시간동기화·로그·암호화 | 서버가 CCE 점검 | 일부 |
| 언어 패키지 | pip/npm/gem/composer/maven/nuget/cargo/go 8개 생태계(아래) | 앱 의존성 CVE 매칭 | 아니오 |
| 계정 인벤토리 | `getent`·`/etc/shadow`·`lastlog`·`sudoers`(아래 — **개인정보성**) | ISMS-P 2.5.x / N2SF AC 계정관리 판정 | 예 |
| 패키지 의존성 그래프 | `pom.xml` 원문 · SBOM 파일(아래) | 직접/전이 판정, `depgraph.php` | 아니오 |
| 패키지 무결성 검증 | `rpm -Va` / `dpkg --verify` — **`--verify-files` 를 준 실행에서만** | 설치 패키지 탭의 "원본과 다름" | 예 |

**컨테이너 내부도 본다** — 호스트 스캔에서 통째로 빠지던 미탐 영역이다. `collect_containers` 가
실행 중인 컨테이너의 rootfs 를 직접 읽어 **내부 패키지 인벤토리**를 뜬다(dpkg·apk 는 텍스트 DB 라
어디서든, rpm 은 호스트에 rpm 이 있을 때만). docker CLI 에 의존하지 않아 podman·containerd 도
잡힌다(이름·이미지만 CLI 로 보강). 함께 보내는 k8s 위치(네임스페이스/파드/컨테이너)·워크로드
참조·이미지 다이제스트·런타임 상태·SBOM 은 **호스트 상세 → 컨테이너 탭**에서 보고, 의존성
엣지는 같은 화면에서 들어가는 **의존성 그래프**(`depgraph.php`)가 읽는다.

> **프로세스 인벤토리는 호스트 것만** 뜬다(`collect_processes` 는 다른 mount namespace 를
> 건너뛴다) — 컨테이너 오버레이 경로를 `dpkg -S`/`rpm -qf` 로 전수조사하다 멈추는 문제 때문.
> "컨테이너를 안 본다"는 뜻이 아니다. 패키지는 위처럼 따로 수집한다.

### 언어 패키지 — 어디서 읽나 (설치본 우선, 선언 파일은 보충)

전역 CLI 목록(`pip3 list`·`npm ls -g`·`gem list`·`composer global show`·`cargo install --list`·
`dotnet tool list -g`)에 더해 `PROJECT_SCAN_ROOTS` 아래를 훑는다. **설치본이 먼저 나가고 선언
파일이 뒤에 붙는다** — 예산(`MAX_BYTES`)이 모자라면 고신뢰 쪽이 남아야 하기 때문이다.

| 신뢰도 | 읽는 것 | 생태계 |
|---|---|---|
| 설치본 | `site-packages/*.dist-info/METADATA` · `composer/installed.json` · `Cargo.lock` · `package-lock.json` · `*.deps.json` · `*.jar/war/ear` | pip · composer · cargo · npm · nuget · maven |
| 설치본 | `Gemfile.lock`(GEM 섹션의 해결된 버전) · vendored `specifications/*.gemspec`(파일명만 — 본문은 루비 코드다) | gem |
| 설치본 | `yarn.lock`(v1 Classic·v2+ Berry 두 형식) · `pnpm-lock.yaml`(v5/v6/v9 키 표기) — yarn·pnpm 프로젝트엔 `package-lock.json` 이 아예 없어서, 이 둘이 없으면 앱 의존성이 통째로 0건이 된다 | npm |
| 설치본 | `poetry.lock`(`[[package]]` 블록) · `Pipfile.lock`(`default` 만 — `develop` 은 배포본에 없어 오탐이 된다) · `*.egg-info/PKG-INFO`(구식 setuptools 메타 — `METADATA` 와 필드 구조가 같아 같은 분기로 처리, 라이선스도 함께 나간다) | pip |
| 설치본 | **Go 바이너리 buildinfo**(`collect_go_binary_deps`) — `go.mod` 가 없는 배포 바이너리에서 모듈·버전을 직접 뽑는다 | go |
| 선언 | `go.mod` · `requirements.txt` · `pom.xml` | go · pip · maven |

Go 바이너리 탐색은 비용이 커서 3중으로 캡핑한다 — `GO_BIN_MIN_SIZE`(기본 1M, 이보다 작으면 Go
바이너리가 아니다) 로 후보를 거르고, 앞 `GO_BIN_PROBE_BYTES`(기본 64KB)만 읽어 Go 표식을 찾고,
실제 buildinfo 추출은 `GO_BIN_SCAN_MAX`(기본 40개)까지만 한다.

### 계정 인벤토리 — 계정명·마지막 로그인이 중앙으로 간다 (개인정보 고지)

ISMS-P 2.5.x / N2SF AC 계정관리 판정을 위해 **실제 계정 목록**을 보낸다(그전엔 설정 정책만
봤다). 원자료는 `vuln-inventory-agent.sh` 의 `cap users account_*` 네 키다 — 전부 읽기 전용이고
`getent`/`awk` 수준이라 가볍다(파일시스템 전수 `find` 는 하지 않는다).

| 페이로드 키 | 무엇을 읽나 | 무엇을 보내나 |
|---|---|---|
| `users.account_passwd` | `getent passwd` | 사용자명 · uid · gid · 로그인셸 · 홈 디렉터리 |
| `users.account_shadow` | `/etc/shadow`(root 만 읽힌다) | 사용자명 · 마지막 변경일(epoch일) · min/max/warn/inactive · 만료일 · 잠금여부(1/0) |
| `users.account_lastlog` | `lastlog`(`LC_ALL=C`) | 사용자명 · **마지막 로그인 시각 문자열** 또는 `NEVER` |
| `users.account_sudoers` | `/etc/sudoers`·`/etc/sudoers.d/*`(0440) | 주석·빈 줄을 뺀 유효 라인 |

- **패스워드 해시는 어떤 형태로도 수집·전송하지 않는다** — shadow 에서는 정책 필드와
  "해시가 `!`/`*` 로 시작하는가"만 `1/0` 으로 환산해 보낸다.
- **숨기지 않고 적는다: 계정명·홈 경로·마지막 로그인 시각은 개인 식별로 이어질 수 있는 값이고,
  중앙 DB(`tb_host_account`)에 스캔별로 쌓인다.** 중앙은 이 값으로 90일 미로그인·sudo 보유자·
  공유계정 추정·퇴직자 계정 잔존 추정을 판정하며, 계정 탭 열람은 감사로그 대상이다.
- `/etc/shadow`·`sudoers` 를 못 읽으면(비root 실행) 그 섹션을 **아예 만들지 않는다** — 중앙이
  `NA`(판정 불가)로 읽는다. 없는 것을 "정상"으로 위장하지 않는다.

### 패키지 의존성 그래프 — 직접·전이 의존을 함께 보낸다

무엇이 무엇을 끌어오는지(직접/전이)를 중앙 `tb_package_dependency` 에 쌓는다. 출처는 둘이고,
**에이전트는 파싱하지 않고 원문을 올린다** — 구조 파싱은 중앙 PHP(`ingest_parse.php`)가 한다.

| 페이로드 키 | 수집 함수 | 보내는 것 |
|---|---|---|
| `langpkg.pom_deps` | `collect_pom_direct_deps` | `PROJECT_SCAN_ROOTS` 아래 `pom.xml` 을 `경로\|base64` 로. 파일당 128KB(`POM_DEP_FILE_MAX_BYTES`) 초과분은 건너뛴다 |
| `containers.sbom` | `collect_sbom` | `/opt/vuln-agent/sbom/*.json`(CycloneDX·SPDX)을 `이름\|형식\|base64` 로. 파일당 2MB 상한. 파일명이 대상이다 — `_host.json` 은 호스트 자신, 그 외는 컨테이너 cid/이름 |

- **호스트 자신의 SBOM 은 `/opt/vuln-agent/sbom/_host.json` 으로 둔다.** SBOM 파일명이 곧 대상이라
  예전에는 컨테이너에만 붙일 수 있었고, 호스트를 기술하는 SBOM 은 붙을 곳이 없어 **조용히 버려졌다**
  (docker 가 없는 노드는 통째로). `_host` 는 예약 이름이라 중앙이 `container_id = 0`(호스트 자신)으로
  저장한다 — 밑줄로 시작하는 이름은 docker/podman 이름 규칙상 만들 수 없어 실제 컨테이너와 충돌이
  **구조적으로** 불가능하다. 예약어도 아니고 수집된 컨테이너도 아닌 이름은 여전히 버려지지만, 이제는
  `error_log` 와 ingest 응답의 `sbom_dropped`(cid·패키지/엣지 건수)로 **드러난다**. 매칭 실패를
  호스트로 떨어뜨리는 폴백은 없다 — 사라진 컨테이너의 SBOM 이 호스트 것으로 둔갑하면 그게 오탐이다.
- pom 은 왜 원문인가: 옛 awk 한 줄 파싱이 `<exclusions>`·`<dependencyManagement>`·한 줄
  `<parent>` 를 구조적으로 구분하지 못해 오탐/0건이 났다. 중앙이 DOMDocument·XPath 로 최상위
  `<dependencies>` 만 골라낸다.
- 전이 의존은 CycloneDX 의 `dependencies[]` 와 SPDX 의 `relationships` 에서 온다(부모→자식 엣지).
  SPDX 는 `DEPENDS_ON`(정방향)·`DEPENDENCY_OF`/`RUNTIME_DEPENDENCY_OF`(역방향)만 채택한다 —
  `CONTAINS` 까지 엣지로 보면 이미지의 모든 패키지가 루트의 직접 의존이 되어 직접/전이 구분이 사라진다.
- 중앙은 이 엣지로 그래프 화면만 그리는 게 아니라 **취약점 행이 전이 의존성인지** 판정해 조치
  문구를 "직접 조치 불가 — X 가 끌어옴"으로 바꾸고, **부모별로 묶어 "이 하나를 올리면 N건 해결"**
  을 자산 상세 취약점 탭에 올린다. SBOM·pom 을 안 올리는 노드는 이 판정 자체가 생기지 않는다
  (화면엔 아무것도 안 뜬다 — "모름"으로 도배하지 않는다).
- 언어패키지 인벤토리와 **예산이 분리돼 있다**(원문 전송이 요약 스트림보다 무거워 서로를
  갉아먹지 않게). 전체 스캔은 `PROJECT_SCAN_TIMEOUT`(300초)·`SCAN_MAX_FILES`(3000)·
  `SCAN_MAX_DEPTH`(8)로 캡핑된다.

### 오탐을 억제할 근거도 함께 보낸다

중앙 매처는 "버전이 낮다"만으로 취약하다고 하지 않고, 아래 근거로 이미 패치된 건을 걸러낸다
(자세한 판정은 [`docs/dev/architecture.md`](../docs/dev/architecture.md) §2):

| 수집물 | 매처가 쓰는 방식 |
|---|---|
| 패키지 changelog 의 **CVE 줄** | "이 빌드엔 이미 그 CVE 수정이 들어갔다" → 억제 (핵심 13개 패키지) |
| **적용된 벤더 권고(errata)** | 벤더가 "이 설치 빌드에서 고쳤다"고 확인한 것 → 억제 (시스템 전체) |
| **debsecan** (데비안 전용) | "이 버전에 아직 남은 CVE" 목록 → **여기 없으면** 백포트로 고쳐진 것 → 억제 |
| **재시작 필요**(옛 `.so` 를 물고 있는 프로세스) | 패치됐어도 **억제하지 않는다** — 그 프로세스는 여전히 옛 코드를 실행 중 |
| **커널 재부팅 필요** | 커널을 패치해도 재부팅 전엔 옛 커널이 돈다 → 억제하지 않는다(조치는 재부팅) |

## 전송 포맷 — 페이로드의 `meta` 자기계측 필드

최종 JSON 은 `{ "<섹션>": { "<키>": "<원문>" }, "meta": { … } }` 꼴이고, `meta` 에는 수집
자체에 대한 값이 들어간다 — `running_as`·`agent_version`·`schedule` 외에 조립이 끝난 뒤
주입되는 **`elapsed_seconds`·`peak_rss_mb`·`cpu_seconds`** 세 필드가 있다(중앙의
`tb_scan.elapsed_seconds` 등이 여기서 채워진다). `--command-id` 를 받았으면 최상위에
`command_id` 도 얹는다.

> **3.10 미만 노드는 이 세 필드가 비어 있다(2026-08-06 수정).** 조립 2단계 `jq` 호출에 `-c`
> 가 빠져 `"meta": {` 처럼 콜론 뒤 공백이 들어갔고, 뒤이어 주입하는 `awk sub()` 정규식이
> 공백 없는 패턴만 매칭해 **조용히 아무것도 못 바꿨다**(awk `sub` 은 매치 실패해도 오류가
> 없다). jq 가 깔린 거의 모든 호스트에서 재현됐고 운영 DB 에서 해당 필드가 전부 NULL 로
> 확인됐다. 지금은 `jq -sc` + 공백을 허용하는 정규식 양쪽으로 막았다. 값이 계속 비는 노드는
> `agent_push.sh` 로 본체를 올리면 다음 수집부터 채워진다.

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

패키지 관리자는 설치할 때 파일마다 digest·권한·소유자를 기록해 둔다. 그걸 지금 디스크와
대조하면 **"설치 이후에 파일이 바뀌었다"** 를 잡는다(N2SF 제6장 IN 구성요소 무결성 /
비인가 구성요소 식별의 근거 데이터). GPG 서명 검증은 범위가 아니다 — 파일 무결성만 본다.

**왜 기본이 꺼져 있나 — 비용 때문이다.** `rpm -Va` 는 설치된 **모든 패키지의 모든 파일을
해시**한다. 시스템에 따라 수 분 + 무거운 디스크 IO 라 이 에이전트의 대전제("대상 서버에
무리를 주지 않는다")와 정면으로 부딪힌다. `nice 19` · `ionice idle` 은 에이전트 프로세스에
이미 걸려 있어 자식인 rpm/dpkg 도 그대로 상속한다.

| 항목 | 값·동작 |
|---|---|
| 시간 상한 | `--verify-timeout`(기본 300초). 잘리면 결과에 `partial` 을 실어 보내고 화면은 **"부분 결과"** 로 표시한다 — 잘린 결과의 0건을 "깨끗함"으로 읽으면 안 되기 때문 |
| 줄 수 상한 | `VERIFY_MAX_LINES`(기본 500, 환경변수). 넘으면 `truncated` 와 함께 **잘리기 전 전체 건수**를 보낸다 |
| 버리는 것 | 설정파일(`c` 플래그) 줄 — 관리자가 고치는 게 정상이라 전부 노이즈다 |
| 화면 표기 | 자산 상세 → 설치 패키지 탭이 **"미수행 / 정상 / 원본과 다름 N건"** 을 구분한다. 이 플래그 없이 수집한 자산은 "정상"이 아니라 **"미수행"** |
| 어휘 | 잡힌 파일은 "변조됨"이 아니라 **"패키지 원본과 다름(관측)"** — 운영자가 직접 바꾼 파일일 수 있다 |

설치할 때 이 옵션을 켜려면 `install-agent.sh --verify-files` 를 준다(기본 꺼짐). 그러면
`<prefix>/etc/agent.env` 에 `VERIFY_FILES=1` 이 들어가 매 수집마다 적용된다.

설치하지 않고 **그 자리에서 한 번만** 돌려볼 수도 있다(타이머를 등록하지 않는다):

```bash
sudo bash vuln-inventory-agent.sh                       # 수집해서 로컬 파일로만 저장
sudo bash vuln-inventory-agent.sh \
     --send https://<운영-도메인>:8080/ingest.php \
     --token <중앙에서 이 호스트용으로 발급한 토큰>       # 수집 후 전송(파일 저장도 유지)
```

CPU·메모리 cgroup 제한은 기본 적용된다. 에이전트 자체도 `nice 19` ·
`ionice idle` · 명령별 timeout 으로 동작한다. **피크 메모리는 실측 61.6MB**(Debian 12 · 91패키지,
jq 로 전 섹션을 한 번에 조립하는 마지막 단계가 1등 요인) — 수치·스케일링 규칙·재측정법은
[`docs/dev/에이전트-리소스-프로파일.md`](../docs/dev/에이전트-리소스-프로파일.md) 참고.
