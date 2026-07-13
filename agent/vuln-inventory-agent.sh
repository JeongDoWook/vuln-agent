#!/usr/bin/env bash
#
# vuln-inventory-agent.sh  (v2.1)
# ==================================================================
# Linux 취약점 매핑용 정밀 인벤토리 수집 에이전트
#
#  설계 목표
#   1) 서버에 무리 안 가게: nice/ionice 최저 우선순위, 명령별 timeout,
#      출력 바이트 상한, (옵션) cgroup CPU/메모리 하드 리밋, 중복실행 방지
#   2) 오탐을 줄이는 "메타데이터"까지 수집:
#      릴리스번호(NEVRA) · 소스패키지 · 적용된 보안권고 · CVE changelog · CPE
#   3) 읽기 전용 — 시스템을 절대 변경하지 않음
#
#  출력: jq 있으면 구조화 JSON, 없으면 섹션 텍스트
#
#  사용법:
#    ./vuln-inventory-agent.sh                 # 기본(안전+포괄), /tmp 에 저장
#    ./vuln-inventory-agent.sh -o /path.json   # 출력 경로 지정
#    sudo ./vuln-inventory-agent.sh --limit    # cgroup 으로 CPU/메모리 상한
#    ./vuln-inventory-agent.sh --no-changelog  # 가장 무거운 단계 생략
#    ./vuln-inventory-agent.sh --timeout 10    # 명령별 타임아웃(초)
#    ./vuln-inventory-agent.sh \
#        --send http://SERVER:8080/ingest.php \
#        --token 공유토큰                       # 수집 후 중앙 서버로 전송(파일 저장은 유지)
# ==================================================================

set -uo pipefail

# ---------- 기본 설정 (환경변수로 덮어쓰기 가능) ----------
SCRIPT_VERSION="2.1"
CMD_TIMEOUT="${CMD_TIMEOUT:-20}"      # 명령 하나당 최대 실행 시간(초)
MAX_BYTES="${MAX_BYTES:-524288}"      # 섹션당 출력 상한 (512KB)
CPU_QUOTA="${CPU_QUOTA:-25%}"         # --limit 시 CPU 상한
MEM_MAX="${MEM_MAX:-300M}"            # --limit 시 메모리 상한
DO_CHANGELOG=1                        # 핵심 패키지 CVE changelog 수집 여부
DO_LIMIT=0                            # cgroup 리밋 사용 여부
OUT=""
SEND_URL="${SEND_URL:-}"             # --send : 중앙 수신 API(ingest.php) URL
SEND_TOKEN="${SEND_TOKEN:-}"         # --token: 서버와 공유하는 인증 토큰

# ---------- 인자 파싱 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output)     OUT="$2"; shift 2 ;;
    --limit)         DO_LIMIT=1; shift ;;
    --no-changelog)  DO_CHANGELOG=0; shift ;;
    --timeout)       CMD_TIMEOUT="$2"; shift 2 ;;
    --send)          SEND_URL="$2"; shift 2 ;;
    --token)         SEND_TOKEN="$2"; shift 2 ;;
    -h|--help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

# ---------- 파일 → 소속 패키지 (조회 캐시) ----------
# 노출·프로세스·재시작필요 세 곳에서 쓴다. 예전엔 함수마다 복사본(_file_to_pkg/_f2p2)이
# 따로 있었는데, 세 번째 사용처가 생겨 하나로 합쳤다(캐시도 공유되어 조회가 줄어든다).
PKGMGR="none"
have dpkg-query && PKGMGR="dpkg"
have rpm        && PKGMGR="rpm"
declare -A LIBPKG
file_to_pkg() {
  local f="$1" rp p=""
  [ -z "$f" ] && { echo ""; return; }
  rp=$(realpath "$f" 2>/dev/null); [ -z "$rp" ] && rp="$f"   # 삭제된 파일은 realpath 실패 → 원 경로
  if [ -n "${LIBPKG[$rp]+x}" ]; then echo "${LIBPKG[$rp]}"; return; fi
  case "$PKGMGR" in
    dpkg)
      p=$(dpkg -S "$rp" 2>/dev/null | cut -d: -f1 | head -1)
      # usr-merge: /lib 는 /usr/lib 심볼릭 링크인데 **dpkg DB 는 옛 경로(/lib/…)로 기록**한다.
      #   프로세스 maps 는 실경로(/usr/lib/…)로 보이므로 그대로 조회하면 못 찾는다
      #   (실측: libexpat1 → dpkg DB 는 /lib/x86_64-linux-gnu/libexpat.so.1.8.10).
      #   이걸 놓치면 로드된 라이브러리가 통째로 누락돼 런타임 노출 판정이 헐거워진다.
      if [ -z "$p" ]; then
        case "$rp" in
          /usr/lib/*|/usr/bin/*|/usr/sbin/*) p=$(dpkg -S "${rp#/usr}" 2>/dev/null | cut -d: -f1 | head -1) ;;
          /lib/*|/bin/*|/sbin/*)             p=$(dpkg -S "/usr$rp"    2>/dev/null | cut -d: -f1 | head -1) ;;
        esac
      fi
      ;;
    rpm)  p=$(rpm -qf "$rp" 2>/dev/null | grep -v 'not owned' | head -1) ;;
  esac
  LIBPKG[$rp]="$p"; echo "$p"
}

# root 가 아니어도 실패시키지 않는다 — 읽기 전용이라 OS/커널/패키지 같은 핵심 재료는 그대로
# 모인다. 다만 아래 항목이 빠져 결과가 부분적이 되므로 경고한다(누가 돌렸는지는 meta.running_as
# 로 페이로드에도 실려 중앙이 판단할 수 있다). 정상 설치 경로는 root 타이머라 여기 안 걸린다.
is_root || cat >&2 <<EOF
>> [경고] root 가 아닙니다. 다음이 수집되지 않아 결과가 부분적입니다:
   - 리스닝 포트를 연 프로세스(ss -tulpn) → 외부노출 판정 근거 누락
   - 다른 사용자 프로세스가 로드한 라이브러리(/proc/PID/maps)
   - 하드웨어 정보(dmidecode)
   전체 수집: sudo bash $0
EOF

# ---------- (옵션) cgroup 스코프로 재실행: CPU/메모리 하드 리밋 ----------
# root + systemd-run 이 있을 때만. 없으면 아래 nice/ionice 로 대체됨.
if [ "$DO_LIMIT" = 1 ] && [ -z "${_RELAUNCHED:-}" ] && is_root && have systemd-run; then
  export _RELAUNCHED=1
  echo ">> cgroup 리밋 적용(CPU=$CPU_QUOTA, MEM=$MEM_MAX) 후 재실행" >&2
  # 재실행 커맨드에 옵션을 그대로 실어야 한다. 예전엔 ${OUT:+…} ${DO_CHANGELOG:+} 만 붙여
  # --no-changelog·--send·--token 이 유실됐고, 특히 `--limit --send URL` 이면 전송이 통째로
  # 사라졌다(${DO_CHANGELOG:+} 는 항상 빈 문자열). 파싱된 값으로 인자를 배열로 재구성한다.
  # (--limit 은 다시 넘기지 않는다 — _RELAUNCHED 가드로 재진입이 막히고, 스코프는 이미 적용됨.)
  relaunch_args=(--timeout "$CMD_TIMEOUT")
  [ -n "$OUT" ]                && relaunch_args+=(-o "$OUT")
  [ "$DO_CHANGELOG" = 0 ]      && relaunch_args+=(--no-changelog)
  [ -n "$SEND_URL" ]           && relaunch_args+=(--send "$SEND_URL")
  [ -n "$SEND_TOKEN" ]         && relaunch_args+=(--token "$SEND_TOKEN")
  exec systemd-run --scope --quiet \
      -p "CPUQuota=$CPU_QUOTA" -p "MemoryMax=$MEM_MAX" \
      -p CPUWeight=10 -p IOWeight=10 \
      "$0" "${relaunch_args[@]}"
fi

# ---------- 자원 우선순위 최저로: 다른 프로세스에 항상 양보 ----------
renice -n 19 -p $$        >/dev/null 2>&1 || true
have ionice && ionice -c3 -p $$ >/dev/null 2>&1 || true

# ---------- 중복 실행 방지 (cron 겹침 대비) ----------
#   주의: 예전엔 `{ exec 9>…; } 2>/dev/null` 로 열고 flock 했는데, sudo 등 일부 환경에서
#   fd 9 가 안 열린 채 flock 이 "9: Bad file descriptor" 로 실패 → 오탐으로
#   "이미 실행 중"으로 종료됐다. → 열기 성공을 확인하고, 못 열면 락 없이 진행(중단 X).
LOCK="/tmp/.vuln-inventory-agent.lock"
if have flock; then
  if exec 9>"$LOCK"; then
    flock -n 9 || { echo ">> 이미 실행 중입니다. 종료합니다." >&2; exit 0; }
  else
    echo ">> 락 파일 열기 실패($LOCK) — 락 없이 진행합니다." >&2
  fi
fi

# ---------- 준비 ----------
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-/tmp/vulninv-${HOSTNAME_SHORT}-${STAMP}.json}"
TMP="$(mktemp -d /tmp/vulninv.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
START_TS=$SECONDS

echo ">> 수집 시작: $HOSTNAME_SHORT ($(date -Is)) / timeout=${CMD_TIMEOUT}s" >&2

# cap <category> <key> <command-string>
#   - timeout 으로 시간 상한, head -c 로 바이트 상한 → CPU/메모리 폭주 방지
#   - 결과가 비면 파일 삭제 → 출력에는 존재하는 값만 남김
cap() {
  local cat="$1" key="$2"; shift 2
  timeout -k 2 "$CMD_TIMEOUT" bash -c "$*" 2>/dev/null \
    | head -c "$MAX_BYTES" > "$TMP/${cat}__${key}.txt" || true
  [ -s "$TMP/${cat}__${key}.txt" ] || rm -f "$TMP/${cat}__${key}.txt"
}
# put <category> <key> <string>  : 계산된 값을 직접 기록
put() { printf '%s' "$3" > "$TMP/${1}__${2}.txt"; }

# ---------- 방화벽: 허용 포트 집합 (노출 판정 보정) ----------
# 0.0.0.0 바인딩이라도 방화벽이 그 포트를 막고 있으면 외부 노출이 아니다.
# 판정 원칙: **확신이 있을 때만 강등한다.** 방화벽 종류를 모르거나 파싱이 애매하면
# 허용으로 간주해 EXTERNAL 을 유지한다 — 여기서 틀리면 진짜 노출을 놓친다(미탐).
#   firewalld: 모든 zone 의 ports + services 를 합집합으로(인터페이스별 zone 을 놓치면
#              허용된 포트를 차단으로 오판하므로, 넓게 잡는 쪽이 안전하다).
#   ufw:       ALLOW/LIMIT 규칙의 포트. DENY/REJECT 는 허용 아님.
#   그 외(iptables/nft 직접 운용): 판정하지 않는다(규칙 해석이 어렵고 오판 비용이 크다).
FW_KIND="none"; FW_ALLOW=""
fw_detect() {
  if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    FW_KIND="firewalld"
    local zones ports svcs s
    zones=$(timeout "$CMD_TIMEOUT" firewall-cmd --list-all-zones 2>/dev/null)
    ports=$(echo "$zones" | awk '/^[[:space:]]*ports:/{ $1=""; print }')
    svcs=$(echo "$zones"  | awk '/^[[:space:]]*services:/{ $1=""; print }' | tr ' ' '\n' | sort -u)
    for s in $svcs; do
      [ -z "$s" ] && continue
      # 서비스명(ssh, http …)은 포트로 풀어야 비교할 수 있다: "ports: 22/tcp"
      ports="$ports $(timeout "$CMD_TIMEOUT" firewall-cmd --info-service="$s" 2>/dev/null \
                      | awk '/^[[:space:]]*ports:/{ $1=""; print }')"
    done
    FW_ALLOW=$(echo "$ports" | tr ' ' '\n' | grep -E '^[0-9]+(-[0-9]+)?/(tcp|udp)$' | sort -u | paste -sd' ' -)
  elif have ufw && ufw status 2>/dev/null | head -n1 | grep -qi 'status: active'; then
    FW_KIND="ufw"
    # "22/tcp   ALLOW   Anywhere" / "80/tcp (v6)  ALLOW  Anywhere (v6)" / "6000:6007/tcp ..."
    FW_ALLOW=$(ufw status 2>/dev/null | grep -E 'ALLOW|LIMIT' | awk '{print $1}' \
               | grep -E '^[0-9]+(:[0-9]+)?(/(tcp|udp))?$' | sort -u | paste -sd' ' -)
  fi
}

# fw_port_allowed <포트> <proto> — 방화벽이 이 포트를 외부에 열어두었나?
#   방화벽을 판정할 수 없으면(FW_KIND=none) 0(허용)을 돌려 강등을 막는다.
fw_port_allowed() {
  local p="$1" proto="$2" e pp lo hi
  [ "$FW_KIND" = "none" ] && return 0
  for e in $FW_ALLOW; do
    pp="${e#*/}"
    if [ "$pp" = "$e" ]; then pp="$proto"; else e="${e%%/*}"; fi   # 프로토콜 생략 = 양쪽 다
    [ "$pp" != "$proto" ] && continue
    case "$e" in
      *-*|*:*) lo="${e%%[-:]*}"; hi="${e##*[-:]}" ;;
      *)       lo="$e"; hi="$e" ;;
    esac
    [ "$p" -ge "$lo" ] 2>/dev/null && [ "$p" -le "$hi" ] 2>/dev/null && return 0
  done
  return 1
}

# collect_exposure : 런타임 노출 상관 데이터 수집 (차별점 ①)
#   "취약 라이브러리 → 로드한 프로세스 → 외부 포트" 사슬을 잇는 원천 데이터.
#   리스닝 소켓의 PID만 대상 + lib→패키지 조회 캐시 → 가볍다.
#   출력: pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs(,)
collect_exposure() {
  local rows pids
  rows=$(ss -tulpnH 2>/dev/null)
  if [ -n "$rows" ]; then
    pids=$(echo "$rows" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
  else
    pids=$(for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
             grep -ql '\.so' /proc/$p/maps 2>/dev/null && echo "$p"; done | head -20)
  fi
  local pid comm exe exepkg loaded socks proto addr bind port scope
  for pid in $pids; do
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    exe=$(realpath /proc/$pid/exe 2>/dev/null)
    exepkg=$(file_to_pkg "$exe"); [ -z "$exepkg" ] && exepkg="UNPACKAGED"
    loaded=$(awk '/\.so/{print $6}' /proc/$pid/maps 2>/dev/null | sort -u | while read -r lib; do
               file_to_pkg "$lib"; done | grep -v '^$' | sort -u | paste -sd, -)
    socks=$(echo "$rows" | grep "pid=$pid," | awk '{print $1"|"$5}')
    [ -z "$socks" ] && socks="proc||"
    while IFS='|' read -r proto addr; do
      port="${addr##*:}"; bind="${addr%:*}"
      case "$bind" in
        0.0.0.0|"[::]"|"*"|"::") scope="EXTERNAL" ;;
        127.0.0.1|"[::1]")        scope="LOCAL"    ;;
        "")                        scope="-"        ;;
        *)                         scope="BOUND"    ;;
      esac
      # 전체 인터페이스에 떠 있어도 방화벽이 그 포트를 막으면 외부 도달 불가 → FILTERED.
      #   이게 없으면 "방화벽 뒤의 내부 서비스"가 전부 외부노출(HIGH/CRITICAL)로 뜬다.
      if [ "$scope" = "EXTERNAL" ] && ! fw_port_allowed "$port" "$proto"; then
        scope="FILTERED"
      fi
      echo "${pid}|${comm}|${proto}|${bind}|${port}|${scope}|${exepkg}|${loaded}"
    done <<< "$socks"
  done
}

# collect_processes : 실행 중인 "모든" 프로세스 + 소속 패키지 + 로드한 라이브러리 패키지
#   리스닝 소켓이 없어도(포트 미개방) 실행 중이면 잡는다 →
#   "설치만 vs 실행중 vs 사용중(라이브러리 로드)"을 정밀 구분하기 위한 원천 데이터.
#   .so 를 로드한 프로세스만(=실제 사용자 프로그램, 커널스레드 제외). 조회 결과 캐시 → 가볍다.
#   출력: pid|comm|user|exe_pkg|loaded_pkgs(,)
# collect_stale : 삭제된 라이브러리를 아직 메모리에 물고 있는 프로세스 (재시작 필요)
#   패키지를 업데이트하면 옛 .so 는 unlink 되고(=maps 에 "(deleted)") 새 파일이 깔린다.
#   하지만 이미 뜬 프로세스는 **옛 코드를 계속 실행**한다. 그래서 "패치됨"으로 보이지만
#   실제로는 여전히 취약하다 — 오탐이 아니라 **미탐**이라 더 위험하다.
#   출력: pid|comm|pkg|lib
collect_stale() {
  local pid comm f pkg pns HOST_NS
  HOST_NS=$(readlink /proc/self/ns/mnt 2>/dev/null)
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    pns=$(readlink /proc/$pid/ns/mnt 2>/dev/null)
    [ -n "$pns" ] && [ "$pns" != "$HOST_NS" ] && continue   # 컨테이너 제외(호스트 자신만)
    grep -q '(deleted)' /proc/$pid/maps 2>/dev/null || continue
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    awk 'NF>=6 && $6 ~ /\.so/ && /\(deleted\)$/ {print $6}' /proc/$pid/maps 2>/dev/null \
      | sort -u | while read -r f; do
          pkg=$(file_to_pkg "$f"); [ -z "$pkg" ] && continue
          echo "${pid}|${comm}|${pkg}|${f}"
        done
  done
}

collect_processes() {
  local pid comm user exe exepkg loaded pns
  # 컨테이너(쿠버네티스/도커) 프로세스는 다른 mount namespace → 호스트 자신만 인벤토리한다.
  #   (컨테이너 라이브러리는 오버레이 경로라 dpkg -S 가 매번 DB 전체스캔 = 수백~수천회로 멈춤.
  #    컨테이너는 각자 에이전트가 스캔해야 함.) + 안전장치: 오래 걸리면 중단.
  local HOST_NS start; HOST_NS=$(readlink /proc/self/ns/mnt 2>/dev/null); start=$SECONDS
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ $((SECONDS - start)) -gt 90 ] && break
    pns=$(readlink /proc/$pid/ns/mnt 2>/dev/null)
    [ -n "$pns" ] && [ "$pns" != "$HOST_NS" ] && continue      # 다른 ns(컨테이너) 제외
    grep -ql '\.so' /proc/$pid/maps 2>/dev/null || continue   # 실제 프로그램만
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    user=$(stat -c '%U' /proc/$pid 2>/dev/null)
    exe=$(realpath /proc/$pid/exe 2>/dev/null)
    exepkg=$(file_to_pkg "$exe"); [ -z "$exepkg" ] && exepkg="UNPACKAGED"
    loaded=$(awk '/\.so/{print $6}' /proc/$pid/maps 2>/dev/null | sort -u | while read -r lib; do
               file_to_pkg "$lib"; done | grep -v '^$' | sort -u | paste -sd, -)
    echo "${pid}|${comm}|${user}|${exepkg}|${loaded}"
  done
}

# ==================================================================
# 1) 메타 / 시스템 식별 + 취약점 매핑 힌트
# ==================================================================
cap meta hostname_fqdn 'hostname -f 2>/dev/null || hostname'
cap meta collected_at  'date -Is'
cap meta agent_version "echo $SCRIPT_VERSION"
cap meta running_as    'id -un'
cap meta loadavg       'cat /proc/loadavg'
cap meta nproc         'nproc'

cap system os_release     'cat /etc/os-release'
cap system redhat_release 'cat /etc/redhat-release'
cap system debian_version 'cat /etc/debian_version'
cap system kernel         'uname -a'
cap system kernel_release 'uname -r'
cap system arch           'uname -m'
cap system uptime         'uptime'
cap system boot_time      'uptime -s 2>/dev/null || who -b'
cap system timezone       'timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null'

# --- 매핑 힌트: 어떤 OVAL/보안트래커로 대조할지 자기설명적으로 기록 ---
OS_ID="$( . /etc/os-release 2>/dev/null; echo "${ID:-unknown}" )"
OS_CPE="$( . /etc/os-release 2>/dev/null; echo "${CPE_NAME:-}" )"
OS_VID="$( . /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}" )"
case "$OS_ID" in
  rhel|centos|rocky|almalinux|fedora) FAMILY="rpm"; OVAL="Red Hat OVAL / RHSA errata" ;;
  debian|ubuntu)                       FAMILY="deb"; OVAL="Debian/Ubuntu Security Tracker (USN/DSA)" ;;
  sles|opensuse*)                      FAMILY="rpm"; OVAL="SUSE OVAL" ;;
  *)                                   FAMILY="unknown"; OVAL="unknown" ;;
esac
put vuln_mapping distro_id      "$OS_ID"
put vuln_mapping distro_version "$OS_VID"
put vuln_mapping cpe_name       "$OS_CPE"
put vuln_mapping package_family "$FAMILY"
put vuln_mapping recommended_source "$OVAL"
put vuln_mapping note "패키지 비교는 업스트림 버전이 아니라 배포판 전체버전(릴리스번호 포함)으로 대조할 것. 소스패키지·적용된 보안권고를 함께 사용하면 오탐(백포트 미인식)이 감소함."

# ==================================================================
# 2) 하드웨어 / 가상화 / CPU 취약점 완화 상태
# ==================================================================
cap hardware cpu            'lscpu 2>/dev/null || grep -m1 "model name" /proc/cpuinfo'
cap hardware memory         'free -h'
cap hardware disk           'lsblk 2>/dev/null; echo; df -hT'
cap hardware virtualization 'systemd-detect-virt 2>/dev/null'
if is_root && have dmidecode; then
  cap hardware product 'dmidecode -s system-product-name; dmidecode -s system-manufacturer; dmidecode -s bios-version'
fi
# CPU 사이드채널(Spectre/Meltdown 등) 완화 상태 — 커널 CVE 매핑에 유용
cap hardware cpu_vulnerabilities \
  'for f in /sys/devices/system/cpu/vulnerabilities/*; do [ -e "$f" ] && echo "$(basename "$f"): $(cat "$f")"; done'
cap hardware microcode 'grep -m1 microcode /proc/cpuinfo'

# ==================================================================
# 3) 설치 패키지 전체 (릴리스번호 + 소스패키지 + 벤더까지)
#    ★ 취약점 매핑의 핵심 데이터
# ==================================================================
if have rpm; then
  put pkg manager "rpm"
  # 이름 \t 에포크:버전-릴리스 \t 아키 \t 소스RPM \t 벤더
  cap pkg list "rpm -qa --qf '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\n' | sort"
  cap pkg count  'rpm -qa | wc -l'
  cap pkg recent 'rpm -qa --last | head -n 50'
  cap pkg gpg_keys 'rpm -q gpg-pubkey --qf "%{SUMMARY}\n" 2>/dev/null'
elif have dpkg-query; then
  put pkg manager "dpkg"
  # 이름 \t 버전 \t 아키 \t 소스패키지 \t 소스버전 \t 상태
  cap pkg list "dpkg-query -W -f='\${Package}\t\${Version}\t\${Architecture}\t\${source:Package}\t\${source:Version}\t\${db:Status-Abbrev}\n' | sort"
  cap pkg count  'dpkg-query -W 2>/dev/null | wc -l'
  cap pkg recent 'grep -E " (install|upgrade) " /var/log/dpkg.log 2>/dev/null | tail -n 50'
  cap pkg holds  'apt-mark showhold 2>/dev/null'
fi

# ==================================================================
# 4) 패치 상태 + 이미 적용된 보안 권고(errata) ★ 오탐 감소 핵심
#    네트워크는 캐시만 사용(-C) → 서버/네트워크 부하 최소화
# ==================================================================
#    --with-cve 가 핵심이다. 그냥 `updateinfo list installed` 는 권고 ID 만 준다
#    (RLSA-2023:0340 …) → CVE 를 모르니 억제에 못 쓴다. --with-cve 를 붙이면
#    "CVE-2022-3715  Moderate/Sec.  bash-5.1.8-6.el9_1.x86_64" 처럼 CVE↔설치 NEVRA 가 나온다.
#    = "이 CVE 는 이 빌드에서 이미 고쳐졌다"는 벤더 확인서. changelog(13개 하드코딩)와 달리
#    시스템 전체를 덮는다.
if have dnf; then
  cap updates available            'dnf -q -C check-update 2>/dev/null'
  cap updates advisories_pending   'dnf -q -C updateinfo list security 2>/dev/null'
  cap updates advisories_installed 'dnf -q -C updateinfo list installed 2>/dev/null'
  cap updates errata_cves          'dnf -q -C updateinfo list installed --with-cve 2>/dev/null'
elif have yum; then
  cap updates available            'yum -q -C check-update 2>/dev/null'
  cap updates advisories_pending   'yum -q -C updateinfo list security 2>/dev/null'
  cap updates errata_cves          'yum -q -C updateinfo list installed --with-cve 2>/dev/null'
elif have apt-get; then
  cap updates available 'apt list --upgradable 2>/dev/null'
  cap updates security  'apt list --upgradable 2>/dev/null | grep -i security'
  # debsecan: 데비안 보안 트래커가 **이 호스트의 설치 버전에 실제로 해당한다고 판정한** CVE 목록.
  #   백포트가 이미 반영된 권위 있는 판정이라, 중앙이 "여기 없는 deb CVE = 백포트로 수정됨"으로
  #   억제할 수 있다(RHEL 의 errata 에 대응하는 데비안판).
  #   --format simple 은 "CVE-2026-13595 bsdutils" 처럼 한 줄에 CVE·패키지만 준다.
  #   예전엔 --format detail 을 head -200 으로 잘랐는데, **목록이 잘리면 중앙이 "취약하지 않다"고
  #   오판해 미탐이 난다.** 잘리지 않는 형식으로 전량을 보낸다(수백 줄이라 가볍다).
  have debsecan && cap updates debsecan 'debsecan --format simple 2>/dev/null'
fi

# 재부팅 필요 여부 (실행 커널 vs 설치 커널)
cap updates running_kernel 'uname -r'
have needs-restarting && cap updates needs_reboot 'needs-restarting -r 2>/dev/null'
cap updates reboot_required_flag 'test -f /var/run/reboot-required && cat /var/run/reboot-required* 2>/dev/null'
if have rpm; then
  cap updates installed_kernels 'rpm -q kernel kernel-core 2>/dev/null'
elif have dpkg-query; then
  cap updates installed_kernels 'dpkg -l "linux-image-*" 2>/dev/null | grep "^ii" | awk "{print \$2\"\t\"\$3}"'
fi

# ==================================================================
# 5) 핵심 패키지 CVE changelog (백포트 근거) — 가장 무거운 단계라 옵션화
#    대상 패키지를 소수로 한정해 CPU 부담을 억제
# ==================================================================
if [ "$DO_CHANGELOG" = 1 ]; then
  if have rpm; then
    for p in kernel glibc openssl openssh-server bash sudo systemd curl zlib expat python3 nss gnutls; do
      cap changelog "$p" "rpm -q --changelog $p 2>/dev/null | grep -i CVE | head -n 20"
    done
  elif have dpkg-query; then
    for p in openssl libssl3 openssh-server bash sudo systemd curl libcurl4 zlib1g libexpat1 python3 libnss3 libgnutls30; do
      cap changelog "$p" "zcat /usr/share/doc/$p/changelog.Debian.gz 2>/dev/null | grep -iE 'CVE-[0-9]' | head -n 20"
    done
  fi
fi

# ==================================================================
# 6) 언어 런타임 패키지 (각각 자체 CVE 존재) — 전부 로컬 조회
# ==================================================================
have pip3 && cap langpkg pip 'pip3 list --format=freeze --disable-pip-version-check 2>/dev/null'
have npm  && cap langpkg npm_global 'npm ls -g --depth=0 2>/dev/null'
have gem  && cap langpkg gem 'gem list 2>/dev/null'
have composer && cap langpkg composer 'composer global show 2>/dev/null'

# ==================================================================
# 7) 컨테이너 이미지 (이미지별 CVE 매핑)
# ==================================================================
have docker && cap containers docker_images 'docker images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}" 2>/dev/null'
have docker && cap containers docker_running 'docker ps --format "{{.Image}}\t{{.Names}}\t{{.Status}}" 2>/dev/null'
have podman && cap containers podman_images 'podman images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}" 2>/dev/null'

# ==================================================================
# 8) 핵심 서버 제품 실제 버전 (패키지 밖 설치 대비)
# ==================================================================
cap products openssl  'openssl version -a 2>/dev/null'
cap products openssh  'ssh -V 2>&1'
cap products glibc    'ldd --version 2>/dev/null | head -n1'
cap products nginx    'nginx -v 2>&1'
cap products apache   'httpd -v 2>/dev/null || apache2 -v 2>/dev/null'
cap products mysql    'mysqld --version 2>/dev/null || mysql --version 2>/dev/null'
cap products postgres 'postgres --version 2>/dev/null || psql --version 2>/dev/null'
cap products php      'php -v 2>/dev/null | head -n1'
cap products java     'java -version 2>&1 | head -n1'
cap products node     'node -v 2>/dev/null'
cap products redis    'redis-server --version 2>/dev/null'
cap products docker   'docker --version 2>/dev/null'

# ==================================================================
# 9) 커널 모듈 / 네트워크 (공격 표면)
# ==================================================================
cap kernel modules 'lsmod'
cap kernel cmdline 'cat /proc/cmdline'
# 커널 라이브패치 — 실행 커널 버전만 보면 취약해 보여도 라이브패치로 이미 막힌 CVE 가 있다.
#   지금은 근거로 수집만 한다(억제엔 안 쓴다). kpatch list 는 CVE 를 주지 않아 CVE 매핑이
#   없고, 잘못 억제하면 미탐이 되기 때문이다. 매핑 근거(kpatch-patch 패키지 changelog)를
#   확보한 뒤 억제로 넘긴다.
cap kernel livepatch 'kpatch list 2>/dev/null; canonical-livepatch status 2>/dev/null; ls /sys/kernel/livepatch/ 2>/dev/null'
cap net interfaces 'ip -o addr 2>/dev/null || ifconfig -a'
cap net routes     'ip route 2>/dev/null || route -n'
cap net listening  'ss -tulpnH 2>/dev/null || netstat -tulpn 2>/dev/null'
cap net established_count 'ss -tanH state established 2>/dev/null | wc -l'
cap net dns   'cat /etc/resolv.conf'
cap net hosts 'cat /etc/hosts'

# ==================================================================
# 10) 서비스 / 프로세스
# ==================================================================
if have systemctl; then
  cap services running_units 'systemctl list-units --type=service --state=running --no-pager --no-legend'
  cap services enabled_units 'systemctl list-unit-files --state=enabled --no-pager --no-legend'
  cap services failed_units  'systemctl --failed --no-pager --no-legend'
fi
cap services processes 'ps aux --sort=-%mem 2>/dev/null | head -n 60'

# ==================================================================
# 10-b) 런타임 노출 상관 (차별점 ①) — 취약 라이브러리↔프로세스↔외부 포트
#   cap 는 서브셸(bash -c)이라 함수를 못 봄 → 직접 실행해 결과 파일로 기록
# ==================================================================
fw_detect   # 방화벽 허용 포트 집합 — collect_exposure 의 scope 판정에 쓴다
put exposure firewall "$FW_KIND${FW_ALLOW:+ (허용: $FW_ALLOW)}"
{
  echo "pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs"
  collect_exposure
} > "$TMP/exposure__correlation.txt" 2>/dev/null || true
# 헤더만 있고 데이터 없으면(2줄 미만) 제거
[ "$(wc -l < "$TMP/exposure__correlation.txt" 2>/dev/null || echo 0)" -ge 2 ] \
  || rm -f "$TMP/exposure__correlation.txt"

# 10-c) 실행 프로세스 인벤토리 (실행중/사용중 구분용) — 포트 없어도 잡음
{
  echo "pid|comm|user|exe_pkg|loaded_pkgs"
  collect_processes
} > "$TMP/runtime__processes.txt" 2>/dev/null || true
[ "$(wc -l < "$TMP/runtime__processes.txt" 2>/dev/null || echo 0)" -ge 2 ] \
  || rm -f "$TMP/runtime__processes.txt"

# 재시작 필요 — 업데이트로 교체된 옛 라이브러리를 아직 물고 있는 프로세스
{
  echo "pid|comm|pkg|lib"
  collect_stale
} > "$TMP/runtime__stale.txt" 2>/dev/null || true
[ "$(wc -l < "$TMP/runtime__stale.txt" 2>/dev/null || echo 0)" -ge 2 ] \
  || rm -f "$TMP/runtime__stale.txt"

# ==================================================================
# 11) 리포지토리 설정
# ==================================================================
if have dnf || have yum; then
  cap repos list    'ls -1 /etc/yum.repos.d/ 2>/dev/null'
  cap repos enabled 'dnf -C repolist 2>/dev/null || yum -C repolist 2>/dev/null'
  have subscription-manager && cap repos subscription 'subscription-manager status 2>/dev/null'
elif have apt-get; then
  cap repos sources 'cat /etc/apt/sources.list 2>/dev/null; cat /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null'
fi

# ==================================================================
# 12) 보안 자세 (SELinux / 방화벽 / FIPS)
# ==================================================================
cap security selinux 'getenforce 2>/dev/null; sestatus 2>/dev/null'
have aa-status && cap security apparmor 'aa-status 2>/dev/null | head -n 5'
cap security fips 'cat /proc/sys/crypto/fips_enabled 2>/dev/null'
if is_root; then
  cap security firewalld 'firewall-cmd --list-all 2>/dev/null'
  cap security iptables  'iptables -S 2>/dev/null | head -n 100'
  cap security nftables  'nft list ruleset 2>/dev/null | head -n 100'
  have ufw && cap security ufw 'ufw status verbose 2>/dev/null'
fi

# ==================================================================
# 13) 사용자 / 인증 / 예약작업 / 파일시스템
# ==================================================================
cap users accounts     'getent passwd | awk -F: "{print \$1\"\t\"\$3\"\t\"\$7}"'
cap users interactive  'getent passwd | awk -F: "\$3>=1000 && \$7!~/nologin|false/ {print \$1}"'
cap users sudo_group   'getent group sudo wheel 2>/dev/null'
cap users logged_in    'who'
cap users last_logins  'last -n 20 2>/dev/null'
if is_root; then
  cap users sshd_effective 'sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication|x11forwarding|ciphers|macs"'
else
  cap users sshd_config 'grep -iE "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config 2>/dev/null'
fi
cap scheduled crontab_system 'cat /etc/crontab 2>/dev/null; cat /etc/cron.d/* 2>/dev/null'
cap scheduled cron_users 'for u in $(cut -d: -f1 /etc/passwd); do o=$(crontab -l -u "$u" 2>/dev/null); [ -n "$o" ] && { echo "== $u =="; echo "$o"; }; done'
have systemctl && cap scheduled timers 'systemctl list-timers --all --no-pager --no-legend 2>/dev/null'
cap filesystem mounts 'findmnt -A 2>/dev/null || mount'
cap filesystem fstab  'cat /etc/fstab'

# ==================================================================
# 결과 조립
# ==================================================================
ELAPSED=$(( SECONDS - START_TS ))
put meta elapsed_seconds "$ELAPSED"

if have jq; then
  # 각 섹션을 한 줄 JSON 으로 인코딩 후 최종 reduce (O(n), 저부하)
  for f in "$TMP"/*.txt; do
    [ -e "$f" ] || continue
    base="$(basename "$f" .txt)"
    jq -Rs -c --arg c "${base%%__*}" --arg k "${base#*__}" \
      '{c:$c,k:$k,v:(sub("\n+$";""))}' "$f"
  done > "$TMP/_flat.jsonl"
  jq -s 'reduce .[] as $x ({}; .[$x.c][$x.k] = $x.v)' "$TMP/_flat.jsonl" > "$OUT"
  OUTPUT_IS_JSON=1
  echo ">> JSON 저장 완료: $OUT" >&2
else
  OUTPUT_IS_JSON=0
  OUT="${OUT%.json}.txt"
  {
    for f in "$TMP"/*.txt; do
      [ -e "$f" ] || continue
      base="$(basename "$f" .txt)"
      echo "===== [${base%%__*}] ${base#*__} ====="
      cat "$f"; echo
    done
  } > "$OUT"
  echo ">> jq 미설치 → 텍스트 저장 완료: $OUT" >&2
fi

# ---------- 요약 ----------
echo "----------------------------------------" >&2
echo " 호스트   : $HOSTNAME_SHORT" >&2
[ -f "$TMP/pkg__count.txt" ] && echo " 패키지 수: $(cat "$TMP/pkg__count.txt")" >&2
echo " 소요시간 : ${ELAPSED}s (nice 19 / ionice idle)" >&2
echo " 출력파일 : $OUT" >&2
echo "----------------------------------------" >&2

# ==================================================================
# 전송: 중앙 수신 API(ingest.php)로 JSON POST  (--send URL --token TOK)
#   - 파일 저장은 위에서 이미 끝남. 전송은 순수 추가 동작(옵션).
#   - jq 없이 텍스트로 저장된 경우엔 서버가 파싱 못 하므로 전송 생략.
# ==================================================================
if [ -n "$SEND_URL" ]; then
  if [ "${OUTPUT_IS_JSON:-0}" != 1 ]; then
    echo ">> 전송 생략: jq 미설치로 JSON 이 아님(텍스트 출력은 서버가 파싱 못 함)." >&2
  elif ! have curl; then
    echo ">> 전송 생략: curl 이 없습니다." >&2
  else
    echo ">> 전송 시작 → $SEND_URL" >&2
    HTTP_CODE=$(curl -sS -m 30 \
      -o "$TMP/_ingest_resp.json" -w '%{http_code}' \
      -X POST "$SEND_URL" \
      -H 'Content-Type: application/json' \
      ${SEND_TOKEN:+-H "X-Agent-Token: $SEND_TOKEN"} \
      --data-binary @"$OUT" 2>"$TMP/_ingest_err.txt") || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
      echo ">> 전송 성공(HTTP 200): $(cat "$TMP/_ingest_resp.json" 2>/dev/null)" >&2
    else
      echo ">> 전송 실패(HTTP $HTTP_CODE): $(cat "$TMP/_ingest_resp.json" 2>/dev/null)$(cat "$TMP/_ingest_err.txt" 2>/dev/null)" >&2
    fi
  fi
fi
