# vuln-agent 에이전트 — 설치·운영 가이드

대상 리눅스 서버에서 **자산·취약노출 정보를 수집해 중앙 서버로 전송**하는 에이전트다.
스캐너를 각 서버에 심는 방식이 아니라, 가벼운 셸 스크립트가 주기적으로 인벤토리를
수집해 중앙(`ingest.php`)으로 push 한다.

## 한 번만 설치하면 된다 (계속 켜둘 필요 없음)

이게 가장 자주 나오는 오해다.

- 에이전트 본체(`vuln-inventory-agent.sh`)는 **데몬이 아니다.** 한 번 실행하면
  수집 → 전송 → **종료**한다(`flock` 으로 중복 실행 방지).
- `install-agent.sh` 가 **systemd 타이머**(`Type=oneshot`, 기본 `OnCalendar=hourly`,
  `Persistent=true`)를 등록한다. systemd 가 없으면 cron 으로 대체.
- 그래서 **설치 한 번이면 OS 가 매시간 알아서 재실행**한다. 백그라운드로 계속 돌리거나
  수동으로 켜둘 필요가 없다.
- `Persistent=true` 라 서버가 꺼져 있던 동안 놓친 실행은 부팅 후 한 번 따라잡는다.

## 설치

파일 3개(스크립트 2개 + 중앙의 루트 CA `caddy-root.crt`)를 대상 서버에 두고 **인자 없이 실행하면
물어본다.** 세 파일 모두 **중앙 대시보드의 자산 화면 → “에이전트 설치 안내”** 에서 버튼으로 받는다
(레포 체크아웃 불필요, `agent-dl.php`). `caddy-root.crt` 는 자체서명 Caddy(HTTPS) 신뢰용으로,
`install-agent.sh` 옆에 두면 설치 시 자동 등록된다(`--ca-file PATH` 로도 지정 가능).

> **CA 는 배포마다 다르다.** `caddy-root.crt` 는 각 중앙 서버의 Caddy 가 만든 고유값이라 레포에
> 커밋하지 않는다(오픈소스라 남의 배포가 내 CA 를 신뢰하면 안 된다). 자산 화면의 다운로드 버튼이
> "아직 준비 안 됨" 이라면, 중앙 관리자가 최초 1회 추출해야 한다 — [`deploy/README.md`](../deploy/README.md)
> 의 **“에이전트 CA 준비”** 참고.

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
| 도메인이 **공인 IP** 로 풀려 내부망에서 못 붙음(헤어핀 NAT) | 중앙의 내부 IP 를 묻고 `/etc/hosts` 에 이름을 묶음 | `--host-ip 10.3.142.200` |

### 대상 서버 요구사항 — 아무것도 설치하지 않는다

에이전트는 **대상 서버에 패키지를 요구하지 않는다.** 현장 폐쇄망 서버엔 `apt` 자체가 없고,
남의 서버에 패키지를 심는 건 승인 사안이다. 그래서 어디에나 이미 있는 것만 쓴다:

| 도구 | 필수인가 | 없으면 |
|---|---|---|
| `bash` · coreutils | 필수 | — |
| `awk` | 필수(POSIX — busybox 에도 있다) | JSON 을 만들 수 없어 중단 |
| `curl` **또는** `wget` | 필수 | HTTPS 전송을 순수 셸로는 못 한다 → 중단 |
| `jq` | **아니오** | awk 로 JSON 을 조립한다(결과 동일 — `tests/agent_json_test.sh` 가 jq 출력과 대조) |
| `debsecan` | **아니오** | 중앙이 데비안 보안 트래커를 직접 받아 판정한다 |

예전엔 `jq` 가 없으면 설치기가 `apt` 로 깔았고, 그마저 실패하면 에이전트가 텍스트를 뱉고
**전송을 조용히 건너뛰었다**(타이머는 매시간 초록불인데 자산은 안 올라왔다).

루트 CA 는 중앙에서 이렇게 꺼낸다(한 번 꺼내 두고 모든 대상에 재사용):

```bash
sudo docker cp vulnagent-caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

이름을 IP 로 바꿔 붙는 건 **안 된다** — Caddy 가 SNI 로 사이트를 고르므로 도메인이어야 하고,
그래서 IP 를 바꾸는 게 아니라 `/etc/hosts` 로 **이름이 가리키는 곳**을 바꾼다.

자동화(Ansible 등)로 무인 설치할 땐 인자로 넘긴다 — 예전 방식 그대로다. **TTY 가 아니면
아무것도 묻지 않으므로**, 세 값을 다 주면 사람 없이 끝난다:

```bash
sudo bash install-agent.sh \
  --server https://<운영-도메인>:8080/ingest.php \
  --token  <중앙 웹의 에이전트 키 화면에서 해당 호스트에 발급한 값> \
  --schedule hourly              # 또는 daily, '*:0/30'(30분마다, systemd)
```

설치물은 `--prefix`(기본 `/opt/vuln-agent`) 아래 한 곳에 모인다:

```
<prefix>/bin/{vuln-inventory-agent.sh,run.sh}   실행 파일
<prefix>/etc/agent.env                          설정(토큰 등, 권한 600)
<prefix>/logs/last.json                         최근 수집 결과
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

단, 에이전트 본체(`vuln-inventory-agent.sh`)는 root 가 아니어도 **실패하지 않고 경고만
띄운 뒤 수집 가능한 것만 모은다**(읽기 전용이라 OS·커널·패키지 목록은 그대로 모인다).
누가 실행했는지는 페이로드의 `meta.running_as` 에 실려 중앙이 부분 수집임을 알 수 있다.
정상 설치 경로는 root 타이머라 이 경고를 볼 일은 없다.

**chmod:** 실행 권한은 신경 쓸 필요 없다. `bash <파일>` 로 실행하면 되기 때문이다.

```bash
sudo bash install-agent.sh          # chmod 불필요 (권장)

chmod +x install-agent.sh vuln-inventory-agent.sh   # ./ 로 실행하고 싶다면
sudo ./install-agent.sh
```

**chown 은 필요 없다.** `sudo` 로 실행하면 설치기가 `/opt/vuln-agent/**` 를 root 소유로
새로 만들고, 토큰 파일(`etc/agent.env`)은 `600` 으로 잠근다.

### 스크립트를 어디에 두고 실행하나 — `/opt/vuln-agent`

**스크립트 2개를 `/opt/vuln-agent/` 에 두고 거기서 실행한다.** 설치기가 설치물을 두는 곳과
같은 경로라 **외울 경로가 하나뿐**이다.

중앙 자산 화면의 “에이전트 설치 안내” 에서 두 스크립트를 받아(브라우저 다운로드) 대상 서버로 옮긴다.
`caddy-root.crt` 도 같이 받는다 — `install-agent.sh` 옆에 있으면 설치가 자동 등록한다.

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
├── bin/    설치기가 복사한 실행 파일(실제로 도는 것)
├── etc/    agent.env (토큰, 600)
└── logs/   last.json
```

**왜 아무 데나 두면 안 되나.** `sudo bash install-agent.sh` 는 그 파일의 내용을 root 로
실행한다. 다른 계정이 파일을 바꿔칠 수 있는 곳에 두면 남의 코드가 root 로 도는 셈이다.
`/opt` 는 root 소유(`755`)라 안전하다. **`/tmp`, 웹 루트(`/var/www`), 여러 계정이 공유하는
배포 폴더는 피한다.** 3번에서 홈의 원본을 지우는 것도 같은 이유다 — sudo 로 실행할 파일이
root 소유 폴더 한 곳에만 남는다.

재설치·주기 변경도 같은 경로에서 하면 된다(설치기는 멱등하다).

**에이전트는 어느 호스트든 `/opt/vuln-agent` 로 통일한다 — 중앙 서버 자신도 마찬가지다.**
`/apps/vulnagent` 는 *중앙 앱* 배포 루트(`{app,bin,etc,logs,data,backups}`)라 성격이 다르다.
에이전트를 거기로 깔면 그 bin/etc/logs 가 앱과 섞이고, `--uninstall` 이 앱 배포 디렉토리를
통째로 지운다. 그래서 에이전트는 앱 루트에 끼워 넣지 않는다. `--prefix` 는 `/opt` 를 못 쓰는
진짜 예외 상황에서만 쓴다.

## 갱신 — 에이전트를 고쳤을 때 (`deploy/agent_push.sh`)

**에이전트는 자기를 갱신하지 않는다.** 중앙은 노드에 아무것도 내려보내지 않는다(노드가 밀어
올리기만 한다). 그래서 `vuln-inventory-agent.sh` 를 고치면 노드마다 새 사본을 넣어줘야 한다.

master 처럼 **노드들에 SSH 로 닿는 곳**에서 한 줄이면 된다:

```bash
bash deploy/agent_push.sh 10.3.142.100 10.3.142.101 10.3.142.102
```

각 노드의 `<prefix>/bin/vuln-inventory-agent.sh` 를 덮고 **즉시 1회 수집·전송해 결과(HTTP)까지
확인**한다. **토큰·URL·타이머는 건드리지 않는다** — 노드의 `agent.env`(600)에 이미 있으므로
재입력이 필요 없고, 토큰이 이 스크립트를 거쳐 가지도 않는다. 안 깔린 노드는 건너뛰고 알려준다.

- 신규 설치는 **하지 않는다.** 토큰 발급이 사람 판단이라 그렇다 — 정석은 그 서버에 들어가
  `install-agent.sh` 를 대화형으로 돌리는 것이고, 이 스크립트는 그걸 대체하지 않는다.
- `install-agent.sh` 자체가 바뀐 경우(타이머·유닛·preflight)는 대상이 아니다. 그건 노드에서
  설치기를 다시 돌려야 한다.
- **웹에서 누르는 버튼으로 만들지 않는다.** 그러려면 PHP 컨테이너가 전 노드에 root 로 설치할 수
  있는 SSH 키를 들어야 하고, 웹앱이 한 번 뚫리면 전 노드 root 장악으로 번진다. 보는 건 웹(자산
  화면의 `meta.agent_version`), 미는 건 CLI.

## 주기 변경 — 일괄 (`deploy/agent_schedule.sh`)

수집 주기(`OnCalendar`)는 설치 때 각 노드의 로컬 systemd 타이머에 박힌다. 여러 노드의 주기를
한 번에 바꾸려면 master 처럼 **노드들에 SSH 로 닿는 곳**에서:

```bash
bash deploy/agent_schedule.sh daily 10.3.142.100 10.3.142.101        # 셋 다 daily
bash deploy/agent_schedule.sh hourly 10.3.142.100 10.3.142.101='*:0/30'  # 노드별로 다르게
```

첫 인자가 기본 주기, 뒤는 노드 목록이다. `<노드>=<주기>` 로 주면 그 노드만 개별 주기를 쓴다.
각 노드에서 (1) systemd 타이머의 `OnCalendar` 를 새 값으로 바꿔 재무장하고, (2) `agent.env` 의
`SCHEDULE` 을 같은 값으로 갱신한다 — 다음 수집이 `meta.schedule` 로 실어 보내 **중앙 화면
(`assets.php` 의 "주기" 열)이 바뀐 주기를 그대로 보여준다**(중앙은 읽기전용으로 볼 뿐, 변경은
언제나 여기 CLI 로). **토큰·URL 은 안 건드린다** — 주기 변경엔 필요 없다.

- `agent_push.sh` 와 같은 보안 모델이다(사람의 SSH 키로 CLI, 웹 버튼 아님).
- 안 깔린 노드(`agent.env` 없음)는 건너뛴다. cron 폴백 노드는 `hourly`/`daily` 만 되고,
  커스텀 `OnCalendar`(`*:0/30` 등)는 cron 으로 표현 불가라 건너뛴다.
- 주기 열이 채워지려면 노드가 `meta.schedule` 을 보내는 에이전트(2.4+)여야 한다. 옛 에이전트는
  주기 열이 비어 보인다 — `agent_push.sh` 로 본체를 올리면 다음 수집부터 채워진다.

## 주의점

1. **토큰은 파일(600)로만 저장된다.** `install-agent.sh` 가 토큰을 `<prefix>/etc/agent.env`
   에 `600` 으로 쓰고 env 로만 전달하므로 `ps` 에 노출되지 않는다. 대화형으로 설치하면
   토큰이 셸 히스토리에도 남지 않는다. `--token` 인자로 넘긴 경우엔 명령이 히스토리에
   남으니, 신경 쓰이면 설치 후 히스토리를 지운다.

2. **전송 URL(--server)은 대상 서버가 실제로 닿는 주소여야 한다.** 서버마다 다르다.

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

3. **HTTP 405/401 은 정상 신호다.** `ingest.php` 는 POST 전용이라 GET 으로 열면 405,
   토큰이 틀리면 401 이 온다. 설치기의 "즉시 1회" 전송이 성공(2xx)했는지로 판단한다.

4. **주기 변경은 재설치.** `--schedule` 을 바꾸려면 같은 명령을 다시 실행하면 된다
   (멱등하게 유닛을 덮어쓴다).

5. **중앙 코드와 무관하게 독립 동작.** 에이전트는 중앙의 웹/DB 배포와 별개다.
   중앙을 재배포해도 에이전트 타이머는 그대로 돈다.

## 상태 확인

```bash
systemctl status vuln-agent.timer        # 다음 실행 예정
systemctl list-timers vuln-agent.timer   # 최근/다음 실행
journalctl -u vuln-agent.service -n 20   # 실행 로그
cat <prefix>/logs/last.json              # 최근 수집 결과(로컬 사본)
```

## 제거

```bash
cd /opt/vuln-agent
sudo bash install-agent.sh --uninstall [--prefix 설치경로]
```

타이머·유닛·cron 항목과 `bin`/`etc`/`logs` 를 지운다. **원본 스크립트 2개는 남는다**(재설치가
쉬우라고). 흔적까지 지우려면 `sudo rm -rf /opt/vuln-agent`.

## 무엇을 수집하나

OS/커널/CPE, 설치 패키지(dpkg/rpm — NEVRA·소스패키지·**출처**), 실행 중 프로세스와
리스닝 포트(외부노출 판정), 보안설정(sshd·계정·SELinux/AppArmor·방화벽 → 서버가 CCE 점검),
언어 패키지(pip/npm). 이 원자료가 중앙에서 CVE 미러(NVD·OSV·KISA)와 매칭되고, 런타임
노출·EPSS·KEV 가중이 얹혀 최종 우선순위가 된다. 피드 소스별 역할은
[`docs/dev/피드소스-역할.md`](../docs/dev/피드소스-역할.md) 참고.

**컨테이너 내부도 본다.** `collect_containers` 가 실행 중인 컨테이너의 rootfs 를 직접 읽어
**내부 패키지 인벤토리**를 뜬다(호스트 패키지와 `container_id` 로 구분해 저장). docker CLI 에
의존하지 않으므로 podman·containerd 도 잡힌다(이름·이미지만 CLI 로 보강). 컨테이너 안은
호스트 스캔에서 통째로 빠지던 미탐 영역이었다.

> **프로세스 인벤토리는 호스트 것만** 뜬다(`collect_processes` 는 다른 mount namespace 를
> 건너뛴다) — 컨테이너 오버레이 경로를 `dpkg -S`/`rpm -qf` 로 전수조사하다 멈추는 문제 때문.
> "컨테이너를 안 본다"는 뜻이 아니다. 패키지는 위처럼 따로 수집한다.

**오탐을 억제할 근거도 함께 보낸다.** 중앙 매처는 "버전이 낮다"만으로 취약하다고 하지 않고,
아래 근거로 이미 패치된 건을 걸러낸다(자세한 판정은 [`docs/dev/architecture.md`](../docs/dev/architecture.md) §2):

| 수집물 | 매처가 쓰는 방식 |
|---|---|
| 패키지 changelog 의 **CVE 줄** | "이 빌드엔 이미 그 CVE 수정이 들어갔다" → 억제 (핵심 13개 패키지) |
| **적용된 벤더 권고(errata)** | 벤더가 "이 설치 빌드에서 고쳤다"고 확인한 것 → 억제 (시스템 전체) |
| **debsecan** (데비안 전용) | "이 버전에 아직 남은 CVE" 목록 → **여기 없으면** 백포트로 고쳐진 것 → 억제 |
| **재시작 필요**(옛 `.so` 를 물고 있는 프로세스) | 패치됐어도 **억제하지 않는다** — 그 프로세스는 여전히 옛 코드를 실행 중 |
| **커널 재부팅 필요** | 커널을 패치해도 재부팅 전엔 옛 커널이 돈다 → 억제하지 않는다(조치는 재부팅) |

## 실행 옵션

| 옵션 | 뜻 |
|---|---|
| `--send URL` / `--token TOK` | 수집 후 중앙(`ingest.php`)으로 POST (파일 저장도 유지) |
| `-o, --output PATH` | 결과 파일 경로 |
| `--limit` | cgroup 으로 CPU/메모리 상한(기본 CPU 25% · 메모리 300M). sudo 필요 |
| `--no-changelog` | changelog 수집 생략 — **가장 무거운 단계**. 대신 백포트 억제가 약해진다 |
| `--timeout N` | 명령별 타임아웃 초(기본 20) |
| `--qf FMT` | rpm 질의 포맷 재정의(디버깅용) |

설치하지 않고 **그 자리에서 한 번만** 돌려볼 수도 있다(타이머를 등록하지 않는다):

```bash
sudo bash vuln-inventory-agent.sh                       # 수집해서 로컬 파일로만 저장
sudo bash vuln-inventory-agent.sh \
     --send https://<운영-도메인>:8080/ingest.php \
     --token <중앙에서 이 호스트용으로 발급한 토큰>       # 수집 후 전송(파일 저장도 유지)
```

부하가 걱정되면 `--limit` 을 쓴다(끄는 것보다 낫다). 에이전트 자체가 이미 `nice 19` ·
`ionice idle` · 명령별 timeout 으로 동작한다. **피크 메모리는 실측 61.6MB**(Debian 12 · 91패키지,
jq 로 전 섹션을 한 번에 조립하는 마지막 단계가 1등 요인) — 수치·스케일링 규칙·재측정법은
[`docs/dev/에이전트-리소스-프로파일.md`](../docs/dev/에이전트-리소스-프로파일.md) 참고.
