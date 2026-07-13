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

`agent/` 폴더(스크립트 2개)를 대상 서버에 복사하고, **인자 없이 실행하면 물어본다.**

```bash
sudo bash install-agent.sh
```

```
== vuln-agent 설치 ==
중앙 서버 주소 (예: ost-server.duckdns.org:8080): ost-server.duckdns.org:8080
전송 토큰 (입력은 화면에 보이지 않습니다): ********      ← 중앙의 secrets/ingest_token.txt 값
수집 주기 [hourly] (daily / '*:0/30'=30분마다): ⏎        ← Enter 치면 hourly
```

- 주소는 **도메인만 넣어도 된다.** `https://` 와 `/ingest.php` 는 자동으로 붙는다.
- 토큰은 화면·셸 히스토리에 남지 않는다(입력 숨김).

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
scp -r agent/ 대상서버:~/                    # 1) 홈으로 전송 (scp 는 root 로 못 붙는 경우가 많다)
ssh 대상서버
sudo mkdir -p /opt/vuln-agent                # 2) 제자리로 (root 소유가 된다)
sudo cp ~/agent/*.sh /opt/vuln-agent/
rm -rf ~/agent                               # 3) 홈의 원본은 정리

cd /opt/vuln-agent                           # 4) 설치
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

## 주의점

1. **토큰은 파일(600)로만 저장된다.** `install-agent.sh` 가 토큰을 `<prefix>/etc/agent.env`
   에 `600` 으로 쓰고 env 로만 전달하므로 `ps` 에 노출되지 않는다. 대화형으로 설치하면
   토큰이 셸 히스토리에도 남지 않는다. `--token` 인자로 넘긴 경우엔 명령이 히스토리에
   남으니, 신경 쓰이면 설치 후 히스토리를 지운다.

2. **전송 URL(--server)은 대상 서버가 실제로 닿는 주소여야 한다.**
   - 중앙 서버 자신에 설치하면 loopback(`http://127.0.0.1:8081/ingest.php`)이 가장 단순.
   - **다른 서버**에서 보낼 때는 중앙의 Caddy(HTTPS, 8080)를 거친다. Caddy 가
     `tls internal`(자체서명) + SNI 도메인을 쓰므로, IP 직접 접속은 실패한다.
     `https://ost-server.duckdns.org:8080/ingest.php` 처럼 **도메인**으로 보내야 하고,
     그 도메인이 대상 서버에서 중앙 IP 로 풀려야 한다(필요하면 `/etc/hosts` 매핑).
     자체서명이라 에이전트가 인증서 검증을 건너뛰어야 할 수 있다.

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

호스트 자신의 인벤토리만 수집한다(컨테이너 등 다른 mount namespace 는 건너뛴다).
OS/커널/CPE, 설치 패키지(dpkg/rpm), 실행 중 프로세스와 리스닝 포트(외부노출 판정),
보안설정(sshd·계정·SELinux/AppArmor·방화벽 → 서버가 CCE 점검), 언어 패키지 등.
이 원자료가 중앙에서 CVE 미러(NVD·OSV·KISA)와 매칭되고, 런타임 노출·EPSS·KEV 가중이
얹혀 최종 우선순위가 된다. 피드 소스별 역할은
[`docs/피드소스-역할.md`](../docs/피드소스-역할.md) 참고.

**패키지 changelog(백포트 근거)** 도 기본으로 수집한다 — `rpm -q --changelog` / dpkg changelog
에서 **CVE 줄만** 뽑는다. 중앙 매처가 "버전은 낮아 보여도 이 빌드엔 이미 그 CVE 수정이
들어갔다"를 증명해 오탐을 억제하는 데 쓴다.

## 실행 옵션

| 옵션 | 뜻 |
|---|---|
| `--send URL` / `--token TOK` | 수집 후 중앙(`ingest.php`)으로 POST (파일 저장도 유지) |
| `-o, --output PATH` | 결과 파일 경로 |
| `--limit` | cgroup 으로 CPU/메모리 상한(기본 CPU 25% · 메모리 300M). sudo 필요 |
| `--no-changelog` | changelog 수집 생략 — **가장 무거운 단계**. 대신 백포트 억제가 약해진다 |

부하가 걱정되면 `--limit` 을 쓴다(끄는 것보다 낫다). 에이전트 자체가 이미 `nice 19` ·
`ionice idle` · 명령별 timeout 으로 동작해 피크 메모리가 수 MB 수준이다.
