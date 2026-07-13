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

스크립트 2개 + **중앙 루트 CA(`caddy-root.crt`)** 를 대상 서버에 복사하고, **인자 없이 실행하면 물어본다.**

```bash
sudo bash install-agent.sh
```

```
== vuln-agent 설치 ==
중앙 서버 주소 (예: ost-server.duckdns.org:8080): ost-server.duckdns.org:8080
전송 토큰 (입력은 화면에 보이지 않습니다): ********      ← 중앙에서 이 호스트용으로 발급한 개별 토큰
수집 주기 [hourly] (daily / '*:0/30'=30분마다): ⏎        ← Enter 치면 hourly
```

- 주소는 **도메인만 넣어도 된다.** `https://` 와 `/ingest.php` 는 자동으로 붙는다.
- 토큰은 화면·셸 히스토리에 남지 않는다(입력 숨김).

### 선행 검사 — 설치기가 알아서 한다

설치기는 파일을 깔기 **전에** 전송이 실제로 되는지 확인하고, 막히면 **아무것도 설치하지 않고
중단**한다. 예전엔 이 셋을 사람이 미리 손봐야 했고, 안 하면 "타이머는 도는데 자산은 안 올라오는"
조용한 실패가 됐다.

| 검사 | 자동 처리 | 수동 지정 |
|---|---|---|
| `jq`·`curl` 없음 | 패키지 관리자로 설치(apt/dnf/yum/apk/zypper). 실패하면 중단 | — |
| 중앙이 **자체서명**(Caddy `tls internal`) | 스크립트 옆의 `caddy-root.crt` 를 신뢰 저장소에 등록 | `--ca-file PATH` |
| 도메인이 **공인 IP** 로 풀려 내부망에서 못 붙음(헤어핀 NAT) | 중앙의 내부 IP 를 묻고 `/etc/hosts` 에 이름을 묶음 | `--host-ip 10.3.142.200` |

루트 CA 는 중앙에서 이렇게 꺼낸다(한 번 꺼내 두고 모든 대상에 재사용):

```bash
sudo docker cp vulnagent-caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

이름을 IP 로 바꿔 붙는 건 **안 된다** — Caddy 가 SNI 로 사이트를 고르므로 도메인이어야 하고,
그래서 IP 를 바꾸는 게 아니라 `/etc/hosts` 로 **이름이 가리키는 곳**을 바꾼다.

자동화(Ansible 등)로 무인 설치할 땐 인자로 넘긴다 — 예전 방식 그대로다:

```bash
sudo bash install-agent.sh \
  --server https://ost-server.duckdns.org:8080/ingest.php \
  --token  <중앙의 secrets/ingest_token.txt 값> \
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

```bash
scp -r agent/ caddy-root.crt 대상서버:~/      # 1) 홈으로 전송 (scp 는 root 로 못 붙는 경우가 많다)
ssh 대상서버
sudo mkdir -p /opt/vuln-agent                # 2) 제자리로 (root 소유가 된다)
sudo cp ~/agent/*.sh ~/caddy-root.crt /opt/vuln-agent/
rm -rf ~/agent ~/caddy-root.crt              # 3) 홈의 원본은 정리

cd /opt/vuln-agent                           # 4) 설치 (CA 는 옆에 있으니 알아서 등록된다)
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

재설치·주기 변경도 같은 경로에서 하면 된다(설치기는 멱등하다). 다른 경로에 설치하려면
`--prefix` 를 쓴다(운영 서버는 `/apps/vulnagent`).

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

## 주의점

1. **토큰은 파일(600)로만 저장된다.** `install-agent.sh` 가 토큰을 `<prefix>/etc/agent.env`
   에 `600` 으로 쓰고 env 로만 전달하므로 `ps` 에 노출되지 않는다. 대화형으로 설치하면
   토큰이 셸 히스토리에도 남지 않는다. `--token` 인자로 넘긴 경우엔 명령이 히스토리에
   남으니, 신경 쓰이면 설치 후 히스토리를 지운다.

2. **전송 URL(--server)은 대상 서버가 실제로 닿는 주소여야 한다.** 서버마다 다르다.

   | 대상 | 넣을 주소 | 왜 |
   |---|---|---|
   | 중앙 서버 자신 | `http://127.0.0.1:8081/ingest.php` | 웹 컨테이너 직결(loopback 전용 포트). Caddy·TLS 를 통째로 건너뛴다 |
   | 같은 내부망의 다른 서버 | `ost-server.duckdns.org:8080` | Caddy(HTTPS)를 거친다. 도메인이 공인 IP 로 풀리면 설치기가 `/etc/hosts` 로 내부 IP 에 묶는다 |
   | 진짜 외부 서버 | `ost-server.duckdns.org:8080` | 밖에서는 공인 IP 가 정답 |

   중앙 자신에 loopback 을 쓰는 이유: 도메인은 **공인 IP(라우터)** 로 풀리는데, 내부에서 자기
   라우터로 되돌아 들어가는 건(헤어핀 NAT) 대개 막혀 있다. `Connection refused` 가 그것이다.
   IP 로 직접 8080 을 치는 것도 안 된다 — Caddy 가 **SNI 로 사이트를 고르므로** 이름이어야 한다.

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
[`docs/피드소스-역할.md`](../docs/피드소스-역할.md) 참고.

**컨테이너 내부도 본다.** `collect_containers` 가 실행 중인 컨테이너의 rootfs 를 직접 읽어
**내부 패키지 인벤토리**를 뜬다(호스트 패키지와 `container_id` 로 구분해 저장). docker CLI 에
의존하지 않으므로 podman·containerd 도 잡힌다(이름·이미지만 CLI 로 보강). 컨테이너 안은
호스트 스캔에서 통째로 빠지던 미탐 영역이었다.

> **프로세스 인벤토리는 호스트 것만** 뜬다(`collect_processes` 는 다른 mount namespace 를
> 건너뛴다) — 컨테이너 오버레이 경로를 `dpkg -S`/`rpm -qf` 로 전수조사하다 멈추는 문제 때문.
> "컨테이너를 안 본다"는 뜻이 아니다. 패키지는 위처럼 따로 수집한다.

**오탐을 억제할 근거도 함께 보낸다.** 중앙 매처는 "버전이 낮다"만으로 취약하다고 하지 않고,
아래 근거로 이미 패치된 건을 걸러낸다(자세한 판정은 [`docs/architecture.md`](../docs/architecture.md) §2):

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

부하가 걱정되면 `--limit` 을 쓴다(끄는 것보다 낫다). 에이전트 자체가 이미 `nice 19` ·
`ionice idle` · 명령별 timeout 으로 동작한다. **피크 메모리는 실측 61.6MB**(Debian 12 · 91패키지,
jq 로 전 섹션을 한 번에 조립하는 마지막 단계가 1등 요인) — 수치·스케일링 규칙·재측정법은
[`docs/에이전트-리소스-프로파일.md`](../docs/에이전트-리소스-프로파일.md) 참고.
