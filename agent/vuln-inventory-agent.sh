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

# ---------- (옵션) cgroup 스코프로 재실행: CPU/메모리 하드 리밋 ----------
# root + systemd-run 이 있을 때만. 없으면 아래 nice/ionice 로 대체됨.
if [ "$DO_LIMIT" = 1 ] && [ -z "${_RELAUNCHED:-}" ] && is_root && have systemd-run; then
  export _RELAUNCHED=1
  echo ">> cgroup 리밋 적용(CPU=$CPU_QUOTA, MEM=$MEM_MAX) 후 재실행" >&2
  exec systemd-run --scope --quiet \
      -p "CPUQuota=$CPU_QUOTA" -p "MemoryMax=$MEM_MAX" \
      -p CPUWeight=10 -p IOWeight=10 \
      "$0" ${OUT:+-o "$OUT"} ${DO_CHANGELOG:+} --timeout "$CMD_TIMEOUT"
fi

# ---------- 자원 우선순위 최저로: 다른 프로세스에 항상 양보 ----------
renice -n 19 -p $$        >/dev/null 2>&1 || true
have ionice && ionice -c3 -p $$ >/dev/null 2>&1 || true

# ---------- 중복 실행 방지 (cron 겹침 대비) ----------
LOCK="/tmp/.vuln-inventory-agent.lock"
{ exec 9>"$LOCK"; } 2>/dev/null || true
if have flock && ! flock -n 9; then
  echo ">> 이미 실행 중입니다. 종료합니다." >&2
  exit 0
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

# collect_exposure : 런타임 노출 상관 데이터 수집 (차별점 ①)
#   "취약 라이브러리 → 로드한 프로세스 → 외부 포트" 사슬을 잇는 원천 데이터.
#   리스닝 소켓의 PID만 대상 + lib→패키지 조회 캐시 → 가볍다.
#   출력: pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs(,)
collect_exposure() {
  local PKGMGR="none"
  command -v dpkg-query >/dev/null 2>&1 && PKGMGR="dpkg"
  command -v rpm        >/dev/null 2>&1 && PKGMGR="rpm"
  declare -A LIBPKG
  _file_to_pkg() {
    local f="$1" rp p=""
    [ -z "$f" ] && { echo ""; return; }
    rp=$(realpath "$f" 2>/dev/null); [ -z "$rp" ] && rp="$f"
    if [ -n "${LIBPKG[$rp]+x}" ]; then echo "${LIBPKG[$rp]}"; return; fi
    case "$PKGMGR" in
      dpkg) p=$(dpkg -S "$rp" 2>/dev/null | cut -d: -f1 | head -1) ;;
      rpm)  p=$(rpm -qf "$rp" 2>/dev/null | grep -v 'not owned' | head -1) ;;
    esac
    LIBPKG[$rp]="$p"; echo "$p"
  }
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
    exepkg=$(_file_to_pkg "$exe"); [ -z "$exepkg" ] && exepkg="UNPACKAGED"
    loaded=$(awk '/\.so/{print $6}' /proc/$pid/maps 2>/dev/null | sort -u | while read -r lib; do
               _file_to_pkg "$lib"; done | grep -v '^$' | sort -u | paste -sd, -)
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
      echo "${pid}|${comm}|${proto}|${bind}|${port}|${scope}|${exepkg}|${loaded}"
    done <<< "$socks"
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
if have dnf; then
  cap updates available            'dnf -q -C check-update 2>/dev/null'
  cap updates advisories_pending   'dnf -q -C updateinfo list security 2>/dev/null'
  cap updates advisories_installed 'dnf -q -C updateinfo list installed 2>/dev/null'
elif have yum; then
  cap updates available            'yum -q -C check-update 2>/dev/null'
  cap updates advisories_pending   'yum -q -C updateinfo list security 2>/dev/null'
elif have apt-get; then
  cap updates available 'apt list --upgradable 2>/dev/null'
  cap updates security  'apt list --upgradable 2>/dev/null | grep -i security'
  # debsecan: Debian 보안 트래커 기반으로 현재 버전에 영향 주는 CVE 목록 (있으면)
  have debsecan && cap updates debsecan 'debsecan --format detail 2>/dev/null | head -n 200'
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
{
  echo "pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs"
  collect_exposure
} > "$TMP/exposure__correlation.txt" 2>/dev/null || true
# 헤더만 있고 데이터 없으면(2줄 미만) 제거
[ "$(wc -l < "$TMP/exposure__correlation.txt" 2>/dev/null || echo 0)" -ge 2 ] \
  || rm -f "$TMP/exposure__correlation.txt"

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
