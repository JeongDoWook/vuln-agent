#!/usr/bin/env bash
#
# vuln-inventory-agent.sh  (v2.1)
# ==================================================================
# Linux 취약점 매핑용 정밀 인벤토리 수집 에이전트
#
#  설계 목표
#   1) 서버에 무리 안 가게: nice/ionice 최저 우선순위, 명령별 timeout,
#      출력 바이트 상한, 기본 cgroup CPU/메모리 하드 리밋, 중복실행 방지
#   2) 오탐을 줄이는 "메타데이터"까지 수집:
#      릴리스번호(NEVRA) · 소스패키지 · 적용된 보안권고 · CVE changelog · CPE
#   3) 읽기 전용 — 시스템을 절대 변경하지 않음
#
#  출력: jq 있으면 구조화 JSON, 없으면 섹션 텍스트
#
#  사용법:
#    ./vuln-inventory-agent.sh                 # 기본(안전+포괄), /tmp 에 저장
#    ./vuln-inventory-agent.sh -o /path.json   # 출력 경로 지정
#    sudo ./vuln-inventory-agent.sh            # cgroup CPU/메모리 상한이 기본 적용
#    ./vuln-inventory-agent.sh --no-changelog  # 가장 무거운 단계 생략
#    ./vuln-inventory-agent.sh --timeout 10    # 명령별 타임아웃(초)
#    ./vuln-inventory-agent.sh \
#        --send http://SERVER:8080/ingest.php \
#        --token 호스트별토큰                   # 수집 후 중앙 서버로 전송(파일 저장은 유지)
#    ./vuln-inventory-agent.sh --send ... --token ... --command-id 42
#        # run.sh(데몬)가 agent-poll.php 의 due_command_id 를 넘길 때 사용 — POST 바디
#        # 최상위에 command_id 필드가 실려 그 명령이 완료 처리된다.
# ==================================================================

set -uo pipefail

# ---------- 기본 설정 (환경변수로 덮어쓰기 가능) ----------
SCRIPT_VERSION="3.8"
CMD_TIMEOUT="${CMD_TIMEOUT:-20}"      # 명령 하나당 최대 실행 시간(초)
PACKAGING_TIMEOUT="${PACKAGING_TIMEOUT:-120}" # JSON 조립 전체 상한(초)
MAX_BYTES="${MAX_BYTES:-524288}"      # 섹션당 출력 상한 (512KB)
CPU_QUOTA="${CPU_QUOTA:-10%}"         # 기본 CPU 상한(4코어 호스트 전체 기준 최대 약 2.5%)
MEM_MAX="${MEM_MAX:-300M}"             # 기본 메모리 상한
SBOM_DIR="${SBOM_DIR:-/opt/vuln-agent/sbom}" # 선택적 CycloneDX/SPDX 입력 디렉터리
PROJECT_SCAN_ROOTS="${PROJECT_SCAN_ROOTS:-/opt /srv /app /usr/local /var/lib/tomcat* /usr/share/tomcat*}"
DO_CHANGELOG=1                        # 핵심 패키지 CVE changelog 수집 여부
DO_LIMIT="${AGENT_LIMIT:-1}"          # 기본 cgroup 리밋 사용(AGENT_LIMIT=0 으로만 해제)
OUT=""
SEND_URL="${SEND_URL:-}"             # --send : 중앙 수신 API(ingest.php) URL
SEND_TOKEN="${SEND_TOKEN:-}"         # --token: 중앙에서 이 호스트에 발급한 인증 토큰
COMMAND_ID=""                        # --command-id: agent-poll.php 의 due_command_id (완료 처리용)
PAGESIZE="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

# ---------- 인자 파싱 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output)     OUT="$2"; shift 2 ;;
    --limit)         DO_LIMIT=1; shift ;;
    --no-changelog)  DO_CHANGELOG=0; shift ;;
    --timeout)       CMD_TIMEOUT="$2"; shift 2 ;;
    --send)          SEND_URL="$2"; shift 2 ;;
    --token)         SEND_TOKEN="$2"; shift 2 ;;
    --command-id)    COMMAND_ID="$2"; shift 2 ;;
    -h|--help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

if [ -n "$COMMAND_ID" ]; then
  case "$COMMAND_ID" in
    ''|*[!0-9]*) echo "--command-id 는 숫자여야 합니다: $COMMAND_ID" >&2; exit 1 ;;
  esac
fi

have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

# ---------- 자기계측: 이 실행이 쓴 피크 메모리·CPU 를 잰다 (담당자 안심용) ----------
#   1순위: 이번 실행 전용 systemd scope의 cgroup(memory.peak·cpu.stat).
#          상시 vuln-agent.service cgroup은 데몬 수명 동안 값이 누적되므로 절대 쓰지 않는다.
#          이를 한 번의 수집값으로 읽으면 CPU가 실행할 때마다 불어나 수천 %로 보인다.
#   2순위: cgroup 을 못 쓰면(cron·수동·cgroup v1) 초경량 샘플러로 폴백한다.
SELF_CG=""; SAMPLER_PID=""
measure_start() {
  local path
  path="$(sed -n 's/^0::\(.*\)$/\1/p' /proc/self/cgroup 2>/dev/null | head -1)"
  case "$path" in
    *.scope)
      [ -r "/sys/fs/cgroup${path}/memory.peak" ] && SELF_CG="/sys/fs/cgroup${path}" ;;
  esac
  [ -n "$SELF_CG" ] && return                         # cgroup 으로 잴 수 있으면 샘플러 불필요
  # 폴백 샘플러: 0.5초마다 프로세스 트리 RSS 합의 최댓값을 파일에 기록(overwrite).
  #   awk 로 /proc/*/stat 를 한 번 스캔 → ppid 로 자손 모아 rss(pages) 합산. jq·dpkg 피크 포착.
  local parent=$$
  ( peak=0
    while kill -0 "$parent" 2>/dev/null; do
      rss="$(awk -v root="$parent" -v pg="$PAGESIZE" '
        { pid=$1; rest=$0; sub(/^[0-9]+ \(.*\) /,"",rest); split(rest,f," ")
          ppid[pid]=f[2]; rssp[pid]=f[22] }
        END { d[root]=1; c=1
              while(c){ c=0; for(p in ppid) if(!(p in d)&&(ppid[p] in d)){ d[p]=1; c=1 } }
              t=0; for(p in d) t+=rssp[p]*pg; printf "%d", t/1024 }' /proc/[0-9]*/stat 2>/dev/null)"
      [ -n "$rss" ] && [ "$rss" -gt "$peak" ] 2>/dev/null && { peak="$rss"; echo "$peak" > "$TMP/_peak_kb"; }
      sleep 0.5
    done ) &
  SAMPLER_PID=$!
}
# measure_finish → PEAK_RSS_MB, CPU_SECONDS 를 채운다(못 재면 빈 문자열).
measure_finish() {
  PEAK_RSS_MB=""; CPU_SECONDS=""
  if [ -n "$SELF_CG" ]; then
    local pb uu
    pb="$(cat "$SELF_CG/memory.peak" 2>/dev/null)"
    [ -n "$pb" ] && PEAK_RSS_MB="$(awk -v b="$pb" 'BEGIN{printf "%.1f", b/1048576}')"
    uu="$(awk '/^usage_usec/{print $2}' "$SELF_CG/cpu.stat" 2>/dev/null)"
    [ -n "$uu" ] && CPU_SECONDS="$(awk -v u="$uu" 'BEGIN{printf "%.2f", u/1000000}')"
  else
    [ -n "$SAMPLER_PID" ] && { kill "$SAMPLER_PID" 2>/dev/null; wait "$SAMPLER_PID" 2>/dev/null; }
    local pk line rest
    pk="$(cat "$TMP/_peak_kb" 2>/dev/null)"
    [ -n "$pk" ] && PEAK_RSS_MB="$(awk -v k="$pk" 'BEGIN{printf "%.1f", k/1024}')"
    # CPU: 자신 + 이미 회수한 자식 (utime+stime+cutime+cstime)
    # /proc/self 를 cat으로 읽으면 self는 cat 프로세스가 되어 CPU가 0에 가깝게 나온다.
    # 현재 에이전트 셸의 stat을 직접 지정해야 자식 누적 시간(cutime/cstime)까지 측정된다.
    line="$(cat "/proc/$$/stat" 2>/dev/null)"; rest="${line#*) }"
    # shellcheck disable=SC2086
    set -- $rest
    CPU_SECONDS="$(awk -v j="$(( ${12:-0} + ${13:-0} + ${14:-0} + ${15:-0} ))" -v t="$CLK_TCK" \
                    'BEGIN{printf "%.2f", j/t}')"
  fi
}

# ---------- 파일 → 소속 패키지 (조회 캐시) ----------
# 노출·프로세스·재시작필요 세 곳에서 쓴다. 예전엔 함수마다 복사본(_file_to_pkg/_f2p2)이
# 따로 있었는데, 세 번째 사용처가 생겨 하나로 합쳤다(캐시도 공유되어 조회가 줄어든다).
PKGMGR="none"
have dpkg-query && PKGMGR="dpkg"
have rpm        && PKGMGR="rpm"
declare -A LIBPKG
file_to_pkg() {
  local f="$1" rp p="" cache
  [ -z "$f" ] && { echo ""; return; }
  rp=$(realpath "$f" 2>/dev/null); [ -z "$rp" ] && rp="$f"   # 삭제된 파일은 realpath 실패 → 원 경로
  if [ -n "${LIBPKG[$rp]+x}" ]; then echo "${LIBPKG[$rp]}"; return; fi

  # collect_exposure/collect_processes 는 명령 치환과 파이프라인 안에서 이 함수를 부른다.
  # Bash associative array는 그 서브셸마다 복사되어 결과가 부모와 다음 프로세스에 남지 않는다.
  # 실행 전용 TMP 파일에도 결과를 기록해, 같은 libc/libssl 경로를 프로세스마다 dpkg -S로
  # 수백 번 다시 조회하지 않는다. 소유 패키지가 없는 경로(빈 값)도 캐시해야 실패 조회도 반복되지 않는다.
  cache="$TMP/.file-to-pkg.cache"
  if [ -f "$cache" ]; then
    if p=$(awk -F '\t' -v k="$rp" '
        $1 == k { pos=index($0,"\t"); print substr($0,pos+1); found=1; exit }
        END { exit(found ? 0 : 1) }
      ' "$cache" 2>/dev/null); then
      LIBPKG[$rp]="$p"; echo "$p"; return
    fi
  fi
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
  LIBPKG[$rp]="$p"
  printf '%s\t%s\n' "$rp" "$p" >> "$cache"
  echo "$p"
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

# ---------- cgroup 스코프로 재실행: CPU/메모리 하드 리밋 ----------
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
  [ -n "$COMMAND_ID" ]         && relaunch_args+=(--command-id "$COMMAND_ID")
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
measure_start   # 자기계측 시작(cgroup 우선, 없으면 샘플러) — 수집 전체 구간을 덮는다

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

# 명령 큐로 실행된 경우에만 중앙에 단계 기반 진행률을 보고한다. 실패해도 수집은 계속한다.
# 토큰은 curl 인자 대신 600 권한 헤더 파일로 넘겨 로컬 ps에 노출하지 않는다.
progress_report() {
  [ -n "$COMMAND_ID" ] && [ -n "$SEND_URL" ] && [ -n "$SEND_TOKEN" ] && have curl || return 0
  local stage="$1" percent="$2" message="$3" state="${4:-running}" response
  local url="${SEND_URL%ingest.php}agent-progress.php" hdr="$TMP/.progress-header"
  if [ ! -f "$hdr" ]; then
    : > "$hdr"; chmod 600 "$hdr"; printf 'X-Agent-Token: %s\r\n' "$SEND_TOKEN" > "$hdr"
  fi
  response="$(curl -sS -m 5 -H @"$hdr" -X POST "$url" \
    --data-urlencode "command_id=$COMMAND_ID" --data-urlencode "stage=$stage" \
    --data-urlencode "percent=$percent" --data-urlencode "message=$message" \
    --data-urlencode "state=$state" 2>/dev/null || true)"
  case "$response" in *'"cancel_requested":true'*) : > "$TMP/.cancel-requested" ;; esac
}

cancel_if_requested() {
  [ -f "$TMP/.cancel-requested" ] || return 0
  progress_report cancelled 100 '사용자 요청으로 수집을 중단했습니다.' cancelled
  echo '>> 사용자 요청으로 수집을 중단합니다.' >&2
  exit 130
}

progress_heartbeat() {
  local now last=0
  now=$(date +%s); [ -f "$TMP/.progress-heartbeat" ] && read -r last < "$TMP/.progress-heartbeat"
  if [ $((now - last)) -ge 5 ]; then
    printf '%s' "$now" > "$TMP/.progress-heartbeat"
    progress_report exposure 74 '프로세스와 네트워크 노출을 분석하고 있습니다.'
  fi
  cancel_if_requested
}

progress_report initializing 5 '에이전트가 명령을 수신했습니다.'

# ---------- JSON 조립 (jq 없이도 돈다) ----------
# 에이전트는 **대상 서버에 아무것도 요구하지 않는다.** 예전엔 jq 가 없으면 텍스트를 뱉고 전송을
# 통째로 건너뛰어서(=조용한 실패), 설치기가 대신 apt 로 jq 를 깔았다. 둘 다 틀렸다 —
# 현장 폐쇄망 서버엔 apt 자체가 없고, 남의 서버에 패키지를 심는 건 승인 사안이다.
# awk 는 POSIX 필수라 busybox 에도 있다. jq 가 있으면 더 빠르니 그쪽을 쓰고, 없으면 이걸로 만든다.
#
# 이스케이프를 gsub 으로 하지 않는 이유: awk 구현마다 치환문자열의 역슬래시 처리가 갈린다
# (\\ 가 하나로 줄기도, 둘로 남기도 한다). 문자 단위로 이어붙이면 그 해석이 개입하지 않는다.
vg_json_escape_file() {
  awk '
    # 제어문자(0x00~0x1f)는 JSON 에 날것으로 못 넣는다 → jq 와 **똑같이** 이스케이프한다.
    #   awk 엔 ord() 가 없으므로 문자→코드 표를 만들어 둔다.
    BEGIN { for (i = 0; i < 32; i++) { ord[sprintf("%c", i)] = i } }
    {
      s = $0; out = ""; n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if      (c == "\\") { out = out "\\\\" }
        else if (c == "\"") { out = out "\\\"" }
        else if (c == "\t") { out = out "\\t"  }
        else if (c == "\r") { out = out "\\r"  }
        else if (c == "\b") { out = out "\\b"  }
        else if (c == "\f") { out = out "\\f"  }
        else if (c in ord)  { out = out sprintf("\\u%04x", ord[c]) }
        else                { out = out c }        # UTF-8 은 그대로 통과(jq 도 날것으로 낸다)
      }
      lines[++cnt] = out
    }
    END {
      while (cnt > 0 && lines[cnt] == "") { cnt-- }        # 끝의 빈 줄 제거(jq 의 sub("\n+$";"") 와 동일)
      for (i = 1; i <= cnt; i++) { printf "%s%s", (i > 1 ? "\\n" : ""), lines[i] }
    }
  ' "$1"
}

# 컨테이너 RPM DB 폴백은 `cid|gz|base64`만 담는다. Base64에는 JSON 이스케이프가 필요한
# 따옴표·역슬래시·제어문자가 없으므로 수 MB짜리 한 줄을 문자마다 이어 붙일 이유가 없다.
# 기존 범용 AWK는 `out = out c`가 긴 한 줄에서 O(n²)가 되어 Pi에서 100분 넘게 걸렸다.
vg_json_escape_rpmdb_file() {
  LC_ALL=C awk 'BEGIN{first=1} { if (!first) printf "\\n"; printf "%s", $0; first=0 }' "$1"
}

vg_json_is_rpmdb_safe() {
  [ -s "$1" ] && ! LC_ALL=C grep -qvE '^[A-Za-z0-9_.:@/-]+\|gz\|[A-Za-z0-9+/=]+$' "$1"
}

# $TMP/<섹션>__<키>.txt 들을 {"섹션":{"키":"값"}} 으로 조립한다.
#   파일명이 `섹션__키` 라 glob 정렬이 곧 섹션별 묶음이 된다(같은 섹션이 연속).
vg_json_build() {
  local f base c k prev='' first_key=1
  printf '{'
  for f in "$TMP"/*.txt; do
    [ -e "$f" ] || continue
    base="$(basename "$f" .txt)"
    c="${base%%__*}"; k="${base#*__}"
    if [ "$c" != "$prev" ]; then
      [ -n "$prev" ] && printf '},'
      printf '"%s":{' "$c"
      prev="$c"; first_key=1
    fi
    [ "$first_key" = 1 ] || printf ','
    if [ "$base" = "containers__rpmdb" ] && vg_json_is_rpmdb_safe "$f"; then
      printf '"%s":"%s"' "$k" "$(vg_json_escape_rpmdb_file "$f")"
    else
      printf '"%s":"%s"' "$k" "$(vg_json_escape_file "$f")"
    fi
    first_key=0
  done
  [ -n "$prev" ] && printf '}'
  printf '}\n'
}

# ---------- 방화벽: 허용 포트 집합 (노출 판정 보정) ----------
# 0.0.0.0 바인딩이라도 방화벽이 그 포트를 막고 있으면 외부 노출이 아니다.
# 판정 원칙: **확신이 있을 때만 강등한다.** 방화벽 종류를 모르거나 파싱이 애매하면
# 허용으로 간주해 EXTERNAL 을 유지한다 — 여기서 틀리면 진짜 노출을 놓친다(미탐).
#   firewalld: 모든 zone 의 ports + services 를 합집합으로(인터페이스별 zone 을 놓치면
#              허용된 포트를 차단으로 오판하므로, 넓게 잡는 쪽이 안전하다).
#   ufw:       ALLOW/LIMIT 규칙의 포트. DENY/REJECT 는 허용 아님.
#   nftables:  base input chain 의 policy 가 **drop 임을 확인했을 때만** 신뢰한다. 그 체인의
#              단순 dport accept 만 FW_ALLOW 로 뽑는다. policy accept·input chain 없음·하위 체인
#              jump/goto(따라갈 수 없음)면 **강등하지 않는다**(FW_KIND 를 none 으로 남겨 EXTERNAL 유지).
#   iptables:  `-P INPUT DROP` 기본 정책일 때만 신뢰. 단순 dport accept 만 뽑고, -s/-m state 로
#              조건이 붙은 accept·미지의 커스텀 체인 jump 는 "외부 전체 허용"이 아니므로 강등 안 함.
#   공통 원칙: 애매하면 EXTERNAL 유지 — "닫혔다 착각해 강등"보다 "열렸다 보고 유지"가 항상 안전(미탐 방지).
FW_KIND="none"; FW_ALLOW=""

# fw_parse_nft : stdin=`nft list ruleset` → 신뢰 시 "22/tcp 80/tcp …", 아니면 "@@UNTRUSTED@@".
#   신뢰 조건: base input chain(type filter hook input) 중 policy drop 인 게 하나라도 있고,
#   그 drop 체인들이 하위 체인으로 jump/goto 하지 않아 accept 를 전부 눈으로 확인할 수 있을 때.
#   그 조건에서 **단순 dport accept**(`tcp dport 22 accept`, `tcp dport {22,80} accept`,
#   `tcp dport 6000-6007 accept`)만 뽑는다. drop 체인이 없거나 jump 가 섞이면 강등 불가로 판단.
fw_parse_nft() {
  awk '
    BEGIN{ inchain=0; sawInputDrop=0; distrust=0; allow="" }
    /^[[:space:]]*chain [^ ]+[[:space:]]*[{]/ { inchain=1; isinput=0; isdrop=0; chainjump=0; chainunacc=0; ctok=""; next }
    inchain && /^[[:space:]]*[}]/ {
      if (isinput && isdrop) { sawInputDrop=1; if (chainjump || chainunacc) distrust=1; else allow=allow ctok }
      inchain=0; next
    }
    inchain {
      if ($0 ~ /type[[:space:]]+filter[[:space:]]+hook[[:space:]]+input/) isinput=1
      if ($0 ~ /policy[[:space:]]+drop/) isdrop=1
      if ($0 ~ /(^|[[:space:]])(jump|goto)([[:space:]]|$)/) chainjump=1
      t=$0; gsub(/^[[:space:]]+/,"",t); gsub(/[[:space:]]+$/,"",t)
      # 정책 선언 라인(type ...; policy ...;)은 accept 규칙이 아니다 → 계정 대상에서 제외
      if (t ~ /(^|[[:space:]])policy[[:space:]]/) next
      # 2) 단순 dport accept (끝의 comment "..." 접미사 허용) → 포트 추출
      if (t ~ /^(tcp|udp) dport ([{][^}]*[}]|[0-9]+(-[0-9]+)?) accept( comment "[^"]*")?$/) {
        proto=substr(t,1,3); spec=t
        sub(/^(tcp|udp) dport /,"",spec); sub(/ accept( comment "[^"]*")?$/,"",spec)
        gsub(/[{}]/,"",spec); gsub(/,/," ",spec)
        n=split(spec,arr," ")
        for(i=1;i<=n;i++) if(arr[i]!="") ctok=ctok arr[i]"/"proto" "
        next
      }
      # accept 규칙(verb accept 로 끝나거나 포함)인가?
      if (t ~ /(^|[[:space:]])accept([[:space:]]|$)/) {
        # 1) 무시해도 안전한 accept — 외부 신규연결을 여는 게 아님
        if (t ~ /(^|[[:space:]])(iif|iifname)[[:space:]]+"?lo"?([[:space:]]|$)/) next             # 루프백
        if (t ~ /(^|[[:space:]])ct[[:space:]]+state/ && t !~ /(^|[[:space:],:])new([,[:space:]]|$)/) next  # est/rel/invalid 만
        if (t ~ /(^|[[:space:]])icmp(v6)?([[:space:]]|$)/) next                                   # icmp/icmpv6
        # 3) 그 외 accept → 눈으로 계정 불가 → 이 체인 신뢰 불가
        chainunacc=1
        next
      }
      next
    }
    END {
      if (!sawInputDrop || distrust) { print "@@UNTRUSTED@@"; exit }
      print allow
    }
  '
}

# fw_parse_ipt : stdin=`iptables -S INPUT`(호출부가 -P INPUT DROP/REJECT 확인 후 넘김) →
#   단순 dport accept("22/tcp …"), 아니면 "@@UNTRUSTED@@".
#   INPUT 이 ACCEPT/DROP/REJECT/LOG/RETURN 이 아닌 커스텀 체인으로 jump(-j)하면(calico 등)
#   accept 가 그 안에 숨어 따라갈 수 없으니 강등 불가. -s(소스한정)·-m state/conntrack(연결추적)
#   조건이 붙은 accept 는 "외부 전체 허용"이 아니므로 제외.
fw_parse_ipt() {
  awk '
    BEGIN{ untrusted=0; allow="" }
    /^-A INPUT / {
      jt=""
      for(i=1;i<=NF;i++) if($i=="-j"){ jt=$(i+1); break }
      if (jt!="" && jt!="ACCEPT" && jt!="DROP" && jt!="REJECT" && jt!="LOG" && jt!="RETURN") untrusted=1
      if (jt=="ACCEPT") {
        if ($0 ~ /(^| )-s /) next                 # 소스 한정 → 외부 전체 허용 아님
        if ($0 ~ /-m (state|conntrack)/) next     # 연결추적 → 외부 신규 아님
        if ($0 ~ /(^| )-i lo( |$)/) next          # 루프백
        proto=""
        if ($0 ~ /-p tcp/) proto="tcp"; else if ($0 ~ /-p udp/) proto="udp"
        got=0
        if (match($0, /--dport [0-9]+(:[0-9]+)?/)) {
          d=substr($0,RSTART+8,RLENGTH-8); sub(/:/,"-",d)
          allow = allow d (proto!="" ? "/"proto : "") " "; got=1
        }
        if (match($0, /--dports [0-9,:]+/)) {
          d=substr($0,RSTART+9,RLENGTH-9); gsub(/,/," ",d); gsub(/:/,"-",d)
          n=split(d,arr," ")
          for(k=1;k<=n;k++) if(arr[k]!="") { allow = allow arr[k] (proto!="" ? "/"proto : "") " "; got=1 }
        }
        # 포트를 특정하지 못한 광범위 accept(예: -p tcp -j ACCEPT, 조건 없는 -j ACCEPT) → 신뢰 불가
        if (!got) untrusted=1
      }
    }
    END {
      if (untrusted) { print "@@UNTRUSTED@@"; exit }
      print allow
    }
  '
}

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
  elif have nft || have iptables; then
    # nftables 를 먼저 본다(iptables-nft 백엔드면 여기서 룰이 다 보인다). 못 잡으면 iptables 시도.
    local _fwout
    if have nft && nft list ruleset >/dev/null 2>&1; then
      _fwout=$(timeout "$CMD_TIMEOUT" nft list ruleset 2>/dev/null | fw_parse_nft)
      if [ "$_fwout" != "@@UNTRUSTED@@" ]; then
        FW_KIND="nftables"
        FW_ALLOW=$(printf '%s\n' "$_fwout" | tr ' ' '\n' \
                   | grep -E '^[0-9]+(-[0-9]+)?/(tcp|udp)$' | sort -u | paste -sd' ' -)
      fi
    fi
    if [ "$FW_KIND" = "none" ] && have iptables && iptables -S INPUT >/dev/null 2>&1; then
      local _iptdump _iptpol
      _iptdump=$(timeout "$CMD_TIMEOUT" iptables -S INPUT 2>/dev/null)
      _iptpol=$(printf '%s\n' "$_iptdump" | awk '/^-P INPUT /{print $3; exit}')
      if [ "$_iptpol" = "DROP" ] || [ "$_iptpol" = "REJECT" ]; then
        _fwout=$(printf '%s\n' "$_iptdump" | fw_parse_ipt)
        if [ "$_fwout" != "@@UNTRUSTED@@" ]; then
          FW_KIND="iptables"
          FW_ALLOW=$(printf '%s\n' "$_fwout" | tr ' ' '\n' \
                     | grep -E '^[0-9]+(-[0-9]+)?/(tcp|udp)$' | sort -u | paste -sd' ' -)
        fi
      fi
    fi
  fi
}

# fw_port_allowed <포트> <proto> — 방화벽이 이 포트를 외부에 열어두었나?
#   방화벽을 판정할 수 없으면(FW_KIND=none) 0(허용)을 돌려 강등을 막는다.
fw_port_allowed() {
  # proto 는 기본 tcp. set -u 라 "$2" 를 그냥 쓰면, 호출부가 인자를 빠뜨렸을 때
  # 이 함수가 **에이전트 전체를 죽인다**(실제로 그렇게 죽었다). 기본값으로 그 사고를 막는다.
  local p="$1" proto="${2:-tcp}" e pp lo hi
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
      # 링크로컬 멀티캐스트 전용 프로토콜(mDNS 5353 · LLMNR 5355 · SSDP 1900 · WS-Discovery 3702)은
      #   0.0.0.0 에 떠 있어도 멀티캐스트(224.0.0.251/ff02::fb)라 **라우터를 넘지 못한다** → 인터넷
      #   노출이 아니라 같은 세그먼트 한정(LAN). 방화벽 판정보다 먼저 본다(라우팅 자체가 안 되니까).
      #   실측: avahi mDNS 5353 하나가 라이브러리 HIGH 130여 건을 만들었다.
      if [ "$scope" = "EXTERNAL" ] && [ "$proto" = "udp" ]; then
        case "$port" in 5353|5355|1900|3702) scope="LAN" ;; esac
        # avahi 는 5353(멀티캐스트) 말고도 **랜덤 고포트**로 유니캐스트 mDNS 응답을 받는다
        #   (실측: avahi-daemon udp 33257·54564). 포트가 랜덤이라 번호로는 못 잡으니 데몬 이름으로
        #   잡는다 — avahi 는 mDNS 전용 데몬이라 그 소켓은 전부 로컬 세그먼트 한정이다.
        case "$comm" in avahi-daemon) scope="LAN" ;; esac
      fi
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
# collect_pkg_origins : 패키지 출처(Origin 라벨) — 서드파티 저장소 패키지를 가려낸다.
#   rpm 은 VENDOR 를 주는데 dpkg 는 안 준다. 이게 없으면 중앙이 서드파티(PPA·Docker·NodeSource)
#   패키지를 배포판 기준(debsecan/errata)으로 "이미 수정됨" 처리해 **진짜 취약점을 숨긴다**(미탐).
#   URL 이 아니라 **라벨**(o=Debian / o=Docker / o=LP-PPA-…)로 판정한다 — URL 로 보면 사내
#   미러(mirror.company.com)가 서드파티로 오판된다.
#   출력: 패키지<TAB>라벨   (LOCAL = 어느 저장소에도 없음 = 수동 .deb 설치, UNKNOWN = 매핑 실패)
#
#   **설치된 버전 줄만 보면 안 된다.** 보안 업데이트가 나와 설치본이 뒤처지면 그 버전은 더 이상
#   인덱스에 없어서 소스가 `/var/lib/dpkg/status` 하나뿐이다 — 그걸 LOCAL 로 읽었다.
#     curl:  *** 8.14.1-2+deb13u3 100 → /var/lib/dpkg/status   (설치본: 인덱스에 없음)
#                8.14.1-2+deb13u4 500 → deb.debian.org trixie  (저장소가 지금 주는 것)
#   실측(raspberrypi5-00): 이렇게 LOCAL 로 잘못 찍힌 데비안 패키지가 findings 237건을 만들었다.
#   중앙은 서드파티를 "자동 판정 불가" 로 두므로 **억제도, 조치 가능 여부도 못 붙는다** —
#   하필 "지금 apt 로 고칠 수 있는" 패키지들이 통째로 그렇게 됐다.
#   그래서 **그 패키지의 다른 버전 줄**에 저장소가 있으면 그 저장소가 출처다(설치본이 낡았을 뿐).
collect_pkg_origins() {
  have apt-cache || return 0
  {
    timeout "$CMD_TIMEOUT" apt-cache policy 2>/dev/null
    echo "@@@SPLIT@@@"
    timeout "$CMD_TIMEOUT" apt-cache policy $(dpkg-query -W -f='${Package}\n' 2>/dev/null) 2>/dev/null
  } | awk '
    BEGIN { phase = 1 }
    /^@@@SPLIT@@@$/ { phase = 2; next }
    phase == 1 {
      # " 500 http://deb.debian.org/debian bookworm/main amd64 Packages"
      if ($1 ~ /^[0-9]+$/ && $2 ~ /^(http|https|ftp|file|copy|cdrom)/) { lastkey = $2 " " $3 " " $4; next }
      # "     release v=12.15,o=Debian,a=oldstable,…"
      if ($1 == "release" && lastkey != "") {
        o = ""
        if (match($0, /o=[^,]+/)) { o = substr($0, RSTART + 2, RLENGTH - 2) }
        if (o != "") { repo[lastkey] = o; nrepo++ }
        lastkey = ""
      }
      next
    }
    phase == 2 {
      # "curl:" — 앞 패키지를 마감하고 새로 시작한다. 경고 줄(N:/W:/E: …)은 패키지가 아니다.
      if ($0 ~ /^[^ \t]/) {
        flush(); star = 0; inst = ""; any = ""
        if ($0 ~ /^[^ \t:]+:$/) { pkg = $0; sub(/:$/, "", pkg) } else { pkg = "" }
        next
      }
      if (pkg == "") { next }

      if ($0 ~ /^ \*\*\*/) { star = 1; next }                 # 설치된 버전 줄
      if ($1 !~ /^[0-9]+$/) { star = 0; next }                # 다른 버전 줄(설치본 아님)

      # 소스 줄: "        500 http://deb.debian.org/debian trixie/main arm64 Packages"
      if ($2 ~ /^(http|https|ftp|file)/) {
        k = $2 " " $3 " " $4
        o = (k in repo) ? repo[k] : "UNKNOWN"
        if (star == 1) { if (inst == "") inst = o }           # 설치본의 저장소 — 가장 정확
        else           { if (any  == "") any  = o }           # 저장소가 지금 주는 버전의 출처
      }
      # /var/lib/dpkg/status 는 저장소가 아니다 — 여기서 LOCAL 을 단정하지 않는다.
    }
    END { flush() }

    # 설치본의 저장소가 있으면 그것, 없으면 그 패키지를 파는 저장소, 둘 다 없어야 LOCAL(수동 설치).
    #
    # **저장소를 하나도 모르면(nrepo==0) 아무것도 말하지 않는다.** 도커 이미지·폐쇄망 서버는
    #   apt 인덱스(/var/lib/apt/lists)가 비어 있어 모든 패키지의 소스가 dpkg/status 뿐이다.
    #   그걸 LOCAL(수동 설치)로 읽으면 **시스템 전체가 서드파티**가 되고, 중앙은 서드파티를
    #   "자동 판정 불가" 로 두므로 **벤더 판정이 통째로 꺼진다**(실측 ubuntu:24.04: 억제 0건,
    #   우리 281 vs Trivy 34). 모르는 것은 모른다고 해야 한다 — 출처를 안 보내면 중앙은
    #   "정보 없음 → 배포판 패키지로 취급" 으로 안전하게 판정한다.
    function flush() {
      if (pkg == "") { return }
      if (nrepo == 0) { pkg = ""; return }
      print pkg "\t" (inst != "" ? inst : (any != "" ? any : "LOCAL"))
      pkg = ""
    }'
}

# collect_containers : 컨테이너 **내부** 패키지 인벤토리
#   컨테이너 프로세스는 다른 mount namespace 라 호스트 스캔에서 제외해 왔다(그게 맞다 —
#   오버레이 경로를 dpkg -S 로 훑으면 멈춘다). 그래서 컨테이너 안 패키지는 통째로 미탐이었다.
#   여기서는 컨테이너 rootfs(/proc/<pid>/root)를 직접 읽어 패키지 DB 를 파싱한다.
#     · docker CLI 에 의존하지 않는다 → podman/containerd 도 잡힌다(이름·이미지만 CLI 로 보강).
#     · dpkg·apk 는 텍스트 DB 라 어디서든 파싱된다. rpm 은 바이너리라 호스트에 rpm 이 있을 때만.
#     · distroless/scratch 처럼 패키지 DB 가 없는 이미지는 건너뛴다(수집할 게 없다).
#   os-release 는 **source 하지 않고 grep 으로 읽는다** — 컨테이너 안 파일을 셸로 실행하면
#   컨테이너가 호스트 root 코드를 실행시킬 수 있다.
#   패키지는 stdout 으로, 컨테이너 목록은 $TMP/containers__list.txt 로 나간다(한 번만 순회).
# 그 pid 가 속한 컨테이너의 키. **cgroup 경로에 런타임이 박아 둔 컨테이너 ID**(64자리 hex)를 쓴다:
#   …/docker-<id>.scope, …/cri-containerd-<id>.scope, /docker/<id> …
# mount namespace 를 키로 쓰면 안 된다 — 컨테이너 **안에서** systemd 가 도는 이미지(centos7 등)는
# 그 안의 PrivateTmp 서비스가 또 자기 mount ns 를 파서, 한 컨테이너가 여러 개로 갈라져 중복 집계된다
# (실측: `web` 컨테이너 하나가 이름 붙은 것 + ns 로 갈라진 것, 2건으로 잡혔다).
# cgroup 컨테이너 ID 는 그 컨테이너의 **모든** 프로세스가 똑같이 갖는다.
ctr_key() {
  local k
  # `head -1` 이 필수다. cgroup 한 줄에 ID 가 **두 번** 박히는 경우가 있다(컨테이너 안에서 systemd 가
  # 도는 centos7 이미지: `/docker/<id>/docker/<id>`). `grep -m1 -o` 는 첫 "줄"까지라 매칭을 둘 다
  # 뱉고, 그러면 키가 개행 섞인 두 줄이 되어 이름 매칭이 통째로 빗나간다.
  k=$(grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | head -1 | cut -c1-12)
  [ -z "$k" ] && k=$(readlink "/proc/$1/ns/mnt" 2>/dev/null)   # ID 를 못 찾는 런타임 대비
  printf '%s' "$k"
}

# Go 바이너리 하나의 buildinfo 의존성. strings가 PCRE grep보다 대형 바이너리를 빠르게
# 순차 스캔한다(운영 calico-node 149MB: 1.34초 vs 2.21초, 결과 288개 동일).
go_deps_from_binary() {   # $1=파일 $2=cid
  local file="$1" cid="$2"
  if have strings; then
    timeout "$CMD_TIMEOUT" strings -a "$file" 2>/dev/null \
      | awk -F'\t' -v c="$cid" '$1=="dep" && NF>=3 && $2 ~ /\// { print c"|go|"$2"|"$3"|" }'
  else
    # binutils가 없는 최소 호스트는 기존 방식으로 정확도를 유지한다.
    timeout "$CMD_TIMEOUT" grep -aoP 'dep\t[^\t\x00\n]+\t[^\t\x00\n]+' "$file" 2>/dev/null \
      | awk -F'\t' -v c="$cid" 'NF==3 && $2 ~ /\// { print c"|go|"$2"|"$3"|" }'
  fi
}

# ctr_go_deps : Go 바이너리에 박힌 의존 모듈 목록(buildinfo) → "cid|go|모듈|버전|"
#   Go 는 빌드할 때 "dep<TAB>모듈<TAB>버전<TAB>해시" 줄들을 바이너리에 심는다. `go version -m` 이
#   읽는 게 이것인데, 대상 서버에 Go 툴체인이 있을 리 없으니 직접 뽑는다.
#   `strings -w` 가 아니라 grep 을 쓴다 — -w(공백 보존)는 새 binutils 에만 있고, grep 은 어디에나
#   있다. 실측으로 두 방법의 결과가 168개로 동일했다.
#   비용도 확인했다: 80MB 바이너리에 0.5초.
#   컨테이너의 **모든 프로세스**를 본다. 메인 프로세스가 Go 가 아닌 경우가 있다 —
#   calico-node 는 runit(runsvdir)이 PID 1 이고 진짜 Go 바이너리는 그 자식이다. 메인만 보면
#   이런 컨테이너가 통째로 0개로 남는다(실측: calico-node·whisker).
ctr_go_deps() {   # $1=대표pid $2=cid
  local pid="$1" cid="$2" pidns p exe seen=""
  pidns=$(readlink "/proc/$pid/ns/pid" 2>/dev/null)
  [ -z "$pidns" ] && return 0
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(readlink "/proc/$p/ns/pid" 2>/dev/null)" = "$pidns" ] || continue
    exe=$(readlink "/proc/$p/exe" 2>/dev/null); exe=${exe% (deleted)}
    [ -z "$exe" ] && continue
    case "$seen" in *"|$exe|"*) continue ;; esac      # 같은 바이너리를 두 번 읽지 않는다
    seen="$seen|$exe|"
    [ -r "/proc/$p/root$exe" ] || continue
    # 모듈 경로엔 "/" 가 반드시 들어간다(github.com/...) → 헬퍼가 그걸로 잡음을 거른다.
    go_deps_from_binary "/proc/$p/root$exe" "$cid"
  done | sort -u
}

# ctr_upstream_bins : 패키지 DB 도 Go 도 없는 이미지에서 **업스트림 데몬의 버전**을 뽑는다.
#   → "cid|upstream|앱|버전|"  (서버가 OSV 의 Bitnami 생태계로 조회한다)
#
#   범용 탐지는 하지 않는다(KISS). 바이너리마다 버전을 박는 방식이 제각각이라 범용 규칙은
#   오탐만 만든다. **실제로 만난 것만** 넣는다. 지금은 nginx 하나다(calico whisker).
#   nginx 는 "nginx/1.28.2" 를 그대로 박아 둔다.
ctr_upstream_bins() {   # $1=대표pid $2=cid
  local pid="$1" cid="$2" pidns p exe base ver seen=""
  pidns=$(readlink "/proc/$pid/ns/pid" 2>/dev/null)
  [ -z "$pidns" ] && return 0
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(readlink "/proc/$p/ns/pid" 2>/dev/null)" = "$pidns" ] || continue
    exe=$(readlink "/proc/$p/exe" 2>/dev/null); exe=${exe% (deleted)}
    [ -z "$exe" ] && continue
    base=$(basename "$exe")
    case "$seen" in *"|$base|"*) continue ;; esac
    seen="$seen|$base|"
    [ -r "/proc/$p/root$exe" ] || continue
    case "$base" in
      nginx)
        ver=$(timeout "$CMD_TIMEOUT" grep -aoP 'nginx/\d+\.\d+\.\d+' "/proc/$p/root$exe" 2>/dev/null \
              | head -1 | cut -d/ -f2)
        [ -n "$ver" ] && printf '%s|upstream|nginx|%s|\n' "$cid" "$ver"
        ;;
    esac
  done | sort -u
}

# Optional offline SBOM import. Filename (without .json) must match container cid/name.
collect_sbom() {
  [ -d "$SBOM_DIR" ] || return 0
  local f cid format size
  for f in "$SBOM_DIR"/*.json; do
    [ -f "$f" ] || continue
    size=$(stat -c%s "$f" 2>/dev/null || echo 0)
    [ "$size" -gt 0 ] && [ "$size" -le 2097152 ] || continue
    cid=$(basename "$f" .json)
    case "$cid" in *'|'*|*'/'*) continue;; esac
    if grep -q '"SPDXID"' "$f" 2>/dev/null; then format=spdx; else format=cyclonedx; fi
    printf '%s|%s|' "$cid" "$format"
    base64 -w0 "$f" 2>/dev/null || base64 "$f" 2>/dev/null | tr -d '\n'
    printf '\n'
  done
}
collect_containers() {
  is_root || return 0
  local HOST_PIDNS pid key pidns root cid name image digest k8sns k8spod k8sctr workload osid osver mgr pkgs gopkgs binpkgs cnt line MAP KEYMAP p n i d k osrel f
  HOST_PIDNS=$(readlink /proc/self/ns/pid 2>/dev/null)
  declare -A SEEN

  # pid → 이름·이미지 매핑(있으면).
  MAP=""
  if have docker; then
    MAP=$(timeout "$CMD_TIMEOUT" docker ps -q 2>/dev/null \
          | xargs -r timeout "$CMD_TIMEOUT" docker inspect -f '{{.State.Pid}}|{{.Name}}|{{.Config.Image}}|{{.Image}}' 2>/dev/null)
  fi
  if [ -z "$MAP" ] && have podman; then
    MAP=$(timeout "$CMD_TIMEOUT" podman ps --format '{{.Pid}}|{{.Names}}|{{.Image}}' 2>/dev/null)
  fi

  # docker 가 주는 pid 는 컨테이너의 **메인 프로세스(PID 1)** 다. 그런데 아래 /proc 순회에서 그
  # 컨테이너를 대표하게 되는 pid 는 먼저 만나는 **아무 자식**일 수 있다. pid 로 맞추면 매칭이
  # 빗나가 이름이 통째로 비었다(운영 실측: 32개 중 1개만 이름이 붙었다).
  # → 컨테이너 키로 바꿔 둔다. 같은 컨테이너면 자식도 같은 키다.
  KEYMAP=""
  if [ -n "$MAP" ]; then
    while IFS='|' read -r p n i d; do
      [ -z "$p" ] && continue
      k=$(ctr_key "$p")
      [ -z "$k" ] && continue
      KEYMAP="${KEYMAP}${k}|${n#/}|${i}|${d}||||
"
    done <<< "$MAP"
  fi

  # 쿠버네티스(containerd/CRI) 컨테이너는 docker 가 모른다 → crictl 로 이름을 붙인다.
  #   **docker 와 배타가 아니라 덧붙인다**: 한 호스트에 dockerd 와 containerd 가 같이 사는 게
  #   보통이다(운영 실측: docker 컨테이너 1개 + k8s 컨테이너 22개).
  #   crictl 은 **컨테이너 ID 를 직접 준다** — 그게 곧 우리 키(cgroup ID 앞 12자)라 pid 조회가 없다.
  #   이름은 파드까지 붙여 구분한다(같은 컨테이너 이름이 파드마다 또 있다).
  #   이미지는 .image.image 가 sha256 다이제스트라 사람이 못 읽는다 → userSpecifiedImage 를 쓴다.
  #   jq 가 없으면 건너뛴다(이름 없이 ID 로만 잡힌다 — 지금까지의 동작).
  if have crictl && have jq; then
    while IFS='|' read -r k n i d ns pod ctr workload; do
      [ -z "$k" ] && continue
      KEYMAP="${KEYMAP}${k}|${n#/}|${i}|${d}|${ns}|${pod}|${ctr}|${workload}
"
    done <<< "$(timeout "$CMD_TIMEOUT" crictl ps -o json 2>/dev/null \
                | jq -r '.containers[]? |
                    "\(.id[0:12])|\(.labels["io.kubernetes.pod.name"] // "")/\(.metadata.name)|\(.image.userSpecifiedImage // .image.image)|\(.image.image // "")|\(.labels["io.kubernetes.pod.namespace"] // "")|\(.labels["io.kubernetes.pod.name"] // "")|\(.metadata.name // "")|\(.labels["io.kubernetes.container.name"] // "")"' \
                  2>/dev/null)"
  fi

  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    progress_heartbeat
    # **mount namespace 가 다르다고 컨테이너가 아니다.** systemd 의 PrivateTmp/ProtectSystem
    # 서비스도 별도 mount namespace 를 갖는다. 이걸 컨테이너로 오인하면 호스트 rootfs 를 그대로
    # 다시 읽어 **호스트 패키지·CVE 가 통째로 복제된다** — 운영 실측에서 그런 서비스 9개가
    # 각각 호스트와 똑같은 패키지 801개를 물고 와 CVE 15,957건(1,773×9)이 LOW 로 부풀었다.
    # 진짜 컨테이너는 **PID namespace 도 따로 갖는다**(docker/podman 기본) → 그것으로 가른다.
    #   한계: `--pid=host` 로 띄운 컨테이너는 여기서 걸러진다. 드물고, 그걸 살리자고 systemd
    #   서비스를 전부 컨테이너로 세는 쪽이 훨씬 나쁘다.
    pidns=$(readlink /proc/$pid/ns/pid 2>/dev/null)
    if [ -z "$pidns" ] || [ "$pidns" = "$HOST_PIDNS" ]; then continue; fi

    key=$(ctr_key "$pid")
    [ -z "$key" ] && continue
    [ -n "${SEEN[$key]+x}" ] && continue               # 같은 컨테이너의 다른 프로세스
    SEEN[$key]=1
    root="/proc/$pid/root"
    # 배포판은 /etc/os-release 가 /usr/lib/os-release 의 심볼릭 링크지만 **distroless 는 링크를 안 만든다**
    # (gcr.io/distroless, 즉 k8s 의 etcd/kube-* 가 여기 해당). /etc 만 보면 통째로 건너뛰어 미탐이 된다.
    osrel=""
    for f in "$root/etc/os-release" "$root/usr/lib/os-release"; do
      [ -r "$f" ] && { osrel="$f"; break; }
    done
    [ -n "$osrel" ] || continue                        # OS 를 모르면 CVE 생태계도 못 정한다

    osid=$(grep -m1 '^ID='         "$osrel" 2>/dev/null | cut -d= -f2- | tr -d '"')
    osver=$(grep -m1 '^VERSION_ID=' "$osrel" 2>/dev/null | cut -d= -f2- | tr -d '"')

    line=$(printf '%s\n' "$KEYMAP" | awk -F'|' -v k="$key" '$1 == k { print; exit }')
    if [ -n "$line" ]; then
      name=$(printf '%s' "$line" | cut -d'|' -f2)
      image=$(printf '%s' "$line" | cut -d'|' -f3)
      digest=$(printf '%s' "$line" | cut -d'|' -f4)
      k8sns=$(printf '%s' "$line" | cut -d'|' -f5)
      k8spod=$(printf '%s' "$line" | cut -d'|' -f6)
      k8sctr=$(printf '%s' "$line" | cut -d'|' -f7)
      workload=$(printf '%s' "$line" | cut -d'|' -f8)
      cid="$name"
    else
      # docker 가 모르는 컨테이너(containerd/CRI = 쿠버네티스, podman …).
      # 키가 곧 컨테이너 ID 다 — `crictl inspect <id>` 로 바로 조회된다.
      name=""; image=""; digest=""; k8sns=""; k8spod=""; k8sctr=""; workload=""; cid="$key"
    fi

    pkgs=""; mgr=""
    if [ -f "$root/var/lib/dpkg/status" ]; then
      mgr="dpkg"
      # 레코드는 빈 줄로 구분. "Status: ... installed" 인 것만(제거됐고 설정만 남은 rc 는 제외).
      pkgs=$(awk -v cid="$cid" 'BEGIN{RS="";FS="\n"}{
               p="";v="";s="";ok=0
               for(i=1;i<=NF;i++){
                 if($i ~ /^Package: /)      { p=substr($i,10) }
                 else if($i ~ /^Version: /) { v=substr($i,10) }
                 else if($i ~ /^Source: /)  { s=substr($i,9); sub(/ .*/,"",s) }
                 else if($i ~ /^Status: .*installed$/) { ok=1 }
               }
               if(ok && p!="" && v!="") print cid"|dpkg|"p"|"v"|"s
             }' "$root/var/lib/dpkg/status" 2>/dev/null)
    elif [ -d "$root/var/lib/dpkg/status.d" ]; then
      # distroless(gcr.io/distroless — 쿠버네티스 etcd/kube-* 가 이걸 쓴다)는 status 하나 대신
      # status.d/<패키지> 로 쪼갠다. **Status: 필드가 없다** — 파일이 있다는 것 자체가 설치됐다는 뜻.
      # 같은 디렉터리의 <패키지>.md5sums 는 체크섬 목록이라 건너뛴다.
      # 파일 하나 = 패키지 하나. 이어붙여 한 번에 읽지 않는다 — 이 파일들은 끝에 빈 줄이 없어서
      # cat 으로 붙이면 두 스탠자가 한 레코드로 뭉친다(뒤엣것이 앞엣것을 덮어써 패키지가 사라진다).
      mgr="dpkg"
      pkgs=$(for f in "$root"/var/lib/dpkg/status.d/*; do
               case "$f" in *.md5sums) continue ;; esac
               [ -f "$f" ] || continue
               awk -v cid="$cid" '
                 /^Package: / { p=substr($0,10) }
                 /^Version: / { v=substr($0,10) }
                 /^Source: /  { s=substr($0,9); sub(/ .*/,"",s) }
                 END { if(p!="" && v!="") print cid"|dpkg|"p"|"v"|"s }
               ' "$f" 2>/dev/null
             done)
    elif [ -f "$root/lib/apk/db/installed" ]; then
      mgr="apk"
      # P:이름 / V:버전 / o:origin(소스패키지), 레코드는 빈 줄 구분
      pkgs=$(awk -v cid="$cid" 'BEGIN{RS="";FS="\n"}{
               p="";v="";o=""
               for(i=1;i<=NF;i++){
                 if($i ~ /^P:/)      { p=substr($i,3) }
                 else if($i ~ /^V:/) { v=substr($i,3) }
                 else if($i ~ /^o:/) { o=substr($i,3) }
               }
               if(p!="" && v!="") print cid"|apk|"p"|"v"|"o
             }' "$root/lib/apk/db/installed" 2>/dev/null)
    elif [ -d "$root/var/lib/rpm" ]; then
      # rpm DB 는 바이너리라 읽으려면 rpm 이 필요하다. 두 가지를 순서대로 시도한다.
      # 1) 호스트 rpm 으로 --root 읽기.
      if have rpm; then
        pkgs=$(timeout "$CMD_TIMEOUT" rpm --root="$root" -qa \
                 --qf "${cid}|rpm|%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}|%{SOURCERPM}\n" 2>/dev/null)
      fi
      # 2) 안 되면 **컨테이너 자기 rpm** 을 chroot 로 돌린다. 두 경우를 한꺼번에 푼다:
      #    - 호스트에 rpm 이 아예 없다(데비안/우분투 호스트 + rhel 컨테이너 — 운영 실측 10개가 여기).
      #    - 호스트 rpm 이 옛 BDB 만 알아서 컨테이너의 sqlite DB(rpm 4.16+, rhel9/ol9)를 못 읽는다.
      #    컨테이너 rootfs 안의 rpm 은 그 DB 형식을 정확히 안다.
      if [ -z "$pkgs" ] && { [ -x "$root/usr/bin/rpm" ] || [ -x "$root/bin/rpm" ]; }; then
        pkgs=$(timeout "$CMD_TIMEOUT" chroot "$root" rpm -qa \
                 --qf "${cid}|rpm|%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}|%{SOURCERPM}\n" 2>/dev/null)
      fi
      # 3) 그래도 안 되면 **DB 파일 자체를 중앙으로 올린다**(중앙이 파싱한다).
      #    실측: calico UBI8 이미지엔 rpm 바이너리가 없고 호스트(데비안)에도 rpm 이 없다
      #    → 그 컨테이너의 패키지가 통째로 안 보였다(미탐). 에이전트에 rpm 을 깔 수는 없고
      #    (무설치 원칙), 셸로 바이너리 DB 를 파싱할 수도 없다. Trivy·Grype 처럼 **DB 를 그대로
      #    넘기고 중앙이 해석**한다 — "에이전트는 사실만 나르고 판정은 중앙" 원칙 그대로다.
      #    형식은 중앙이 시그니처로 판별한다(sqlite: rpm 4.16+ / BDB: rpm 4.14).
      if [ -z "$pkgs" ]; then
        for _db in "$root/var/lib/rpm/rpmdb.sqlite" "$root/var/lib/rpm/Packages"; do
          [ -f "$_db" ] || continue
          _sz=$(stat -c%s "$_db" 2>/dev/null || echo 0)
          # 너무 크면 보내지 않는다(전송 본문 한계 32MB). 실측은 11~15MB → gzip 2~4MB.
          [ "$_sz" -gt 0 ] && [ "$_sz" -le 67108864 ] || continue
          if have gzip && have base64; then
            printf '%s|gz|%s\n' "$cid" "$(gzip -c "$_db" 2>/dev/null | base64 -w0 2>/dev/null)" \
              >> "$TMP/containers__rpmdb.txt"
            mgr="rpm"   # 매니저는 rpm 이다 — 패키지 0개를 "깨끗함"으로 오독하면 미탐이다
          fi
          break
        done
      fi
      # 전부 실패하면 manager 를 비워 남긴다 — 패키지 0개를 "깨끗함"으로 오독하면 그게 미탐이다.
      [ -n "$pkgs" ] && mgr="rpm"
    fi

    # Go 바이너리는 **의존 모듈 목록을 자기 안에 박아 둔다**(buildinfo). 그걸 그대로 인벤토리로 쓴다.
    #   왜 필요한가 — 두 종류의 구멍을 한꺼번에 메운다:
    #   1) 패키지 DB 가 아예 없는 이미지(Calico 등 rpm DB 를 지우고 빌드) → 유일한 인벤토리다.
    #      여태 "판정 불가"로 남겨둘 수밖에 없었다(운영 실측 9개).
    #   2) DB 는 있지만 알맹이가 Go 인 이미지 → kube-apiserver 는 dpkg 로는 4개뿐인데 Go 의존은
    #      248개다. **진짜 공격면을 통째로 놓치고 있었다.**
    #   OSV 에 Go 생태계가 있어 모듈명+버전 그대로 매칭된다(v 접두 유무 모두 받는다 — 실측).
    gopkgs=$(ctr_go_deps "$pid" "$cid")
    if [ -n "$gopkgs" ]; then
      pkgs="${pkgs:+$pkgs
}$gopkgs"
      [ -z "$mgr" ] && mgr="go"     # 배포판 DB 가 없던 컨테이너는 이제 go 로 판정된다
    fi

    # 패키지 DB 도 Go 도 없는 마지막 부류 — **업스트림 데몬을 그냥 얹은 이미지**.
    #   실측: calico 의 whisker 는 nginx 1.28.2(C 바이너리)를 담고 있는데, rpm/dpkg DB 가 없고
    #   Go 도 아니라 여태 "판정 불가"였다. 바이너리에 버전 문자열이 박혀 있으니 그걸 뽑는다.
    #   OSV 의 **Bitnami 생태계**가 업스트림 앱(nginx 등)을 커버한다 — 1.28.2 로 물으면
    #   BIT-nginx-2025-53859 가 나온다(API 로 확인).
    #   DB 가 있는 컨테이너에는 하지 않는다 — 거기선 패키지 매니저가 이미 정확한 답을 준다.
    if [ -z "$mgr" ]; then
      binpkgs=$(ctr_upstream_bins "$pid" "$cid")
      if [ -n "$binpkgs" ]; then
        pkgs="${pkgs:+$pkgs
}$binpkgs"
        mgr="upstream"
      fi
    fi

    cnt=0
    [ -n "$pkgs" ] && { printf '%s\n' "$pkgs"; cnt=$(printf '%s\n' "$pkgs" | grep -c '^'); }
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s||\n' "$cid" "$name" "$image" "$osid" "$osver" "$mgr" "$cnt" "$digest" "$k8sns" "$k8spod" "$k8sctr" "$workload" "running" \
      >> "$TMP/containers__list.txt"

    # 런타임 증거 수집(collect_container_runtime)이 컨테이너를 다시 찾아 헤매지 않도록
    # 여기서 알아낸 것을 남긴다. `__` 가 없는 이름이라 전송 섹션으로 잡히지 않는다.
    [ -n "$mgr" ] && printf '%s|%s|%s|%s\n' "$cid" "$pid" "$root" "$mgr" >> "$TMP/.ctrmap"
  done
}

# ctr_pkgmap : 컨테이너 안의 "파일 → 패키지" 맵 (컨테이너당 한 번만 만든다)
#   호스트처럼 파일마다 `dpkg -S` 를 부르면 안 된다 — 컨테이너 파일은 오버레이 경로라
#   호출마다 DB 전체스캔이 되어 수백 번이면 에이전트가 멈춘다. (호스트 프로세스 수집이
#   컨테이너를 통째로 건너뛰는 이유가 바로 이것이다 — collect_processes 주석 참고.)
ctr_pkgmap() {   # $1=root $2=manager  → "경로|패키지"
  local root="$1" f pkg
  case "$2" in
    dpkg)
      if ls "$root"/var/lib/dpkg/info/*.list >/dev/null 2>&1; then
        for f in "$root"/var/lib/dpkg/info/*.list; do
          pkg=$(basename "$f" .list); pkg=${pkg%%:*}          # libc6:amd64 → libc6
          awk -v p="$pkg" 'NF{print $0"|"p}' "$f" 2>/dev/null
        done
      else
        # distroless 는 info/ 가 없다. 파일 목록은 status.d/<패키지>.md5sums 가 들고 있다
        # (해시 + 공백 + 경로, 선행 "/" 없음).
        for f in "$root"/var/lib/dpkg/status.d/*.md5sums; do
          [ -f "$f" ] || continue
          pkg=$(basename "$f" .md5sums)
          awk -v p="$pkg" 'NF>=2{ $1=""; sub(/^[ \t]+/,""); print "/"$0"|"p }' "$f" 2>/dev/null
        done
      fi ;;
    apk)
      # P:패키지 / F:디렉터리 / R:파일 (R 은 직전 F 에 대한 상대경로)
      awk 'BEGIN{RS="";FS="\n"}{ p=""; d=""
             for(i=1;i<=NF;i++){
               if($i ~ /^P:/)      { p=substr($i,3) }
               else if($i ~ /^F:/) { d=substr($i,3) }
               else if($i ~ /^R:/ && p!="") { print "/"d"/"substr($i,3)"|"p }
             }}' "$root/lib/apk/db/installed" 2>/dev/null ;;
    rpm)
      # 파일 목록은 rpm DB 안에만 있다 → 한 번에 덤프. 컨테이너 자기 rpm 을 먼저 쓴다
      # (호스트 rpm 이 없거나 컨테이너의 sqlite DB 를 못 읽는 경우가 있다).
      #   `%{=NAME}` 의 `=` 는 **스칼라 강제**다. 이게 없으면 rpm 이 NAME 도 배열로 보고
      #   "array iterator used with different sized arrays" 로 죽는다(실측).
      #   출력이 "패키지|경로" 순이라 뒤집어서 "경로|패키지" 로 맞춘다.
      if [ -x "$root/usr/bin/rpm" ] || [ -x "$root/bin/rpm" ]; then
        timeout "$CMD_TIMEOUT" chroot "$root" rpm -qa --qf '[%{=NAME}|%{FILENAMES}\n]' 2>/dev/null
      elif have rpm; then
        timeout "$CMD_TIMEOUT" rpm --root="$root" -qa --qf '[%{=NAME}|%{FILENAMES}\n]' 2>/dev/null
      fi | awk -F'|' 'NF>=2 && $2 ~ /^\//{print $2"|"$1}' ;;
  esac
}

# collect_container_runtime : 컨테이너 **안**의 프로세스·리스닝 포트
#   왜 필요한가 — 매처는 "설치만 됨" 이면 LOW 로 깐다. 컨테이너는 런타임 증거가 없어서
#   **아무리 위험해도 전부 LOW** 였다(KEV 라도 MEDIUM). 인터넷에 노출된 컨테이너의 취약한
#   openssl 이 LOW 로 묻힌다는 뜻이라, 오탐이 아니라 과소평가 = 사실상 미탐이다.
#   호스트 신호를 그대로 물려주면 반대로 오탐이 되므로(호스트 nginx 의 노출이 컨테이너
#   openssl 로 샌다), 컨테이너 것은 컨테이너 안에서 따로 모은다.
#
#   출력 두 종류를 한 번에 쓴다(프로세스는 stdout, 노출은 파일):
#     stdout : cid|pid|comm|user|exe_pkg|loaded_pkgs
#     파일   : $TMP/containers__exposure.txt  (cid|pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs)
collect_container_runtime() {
  is_root || return 0
  [ -f "$TMP/.ctrmap" ] || return 0
  local cid cpid root mgr pidns pid map paths pkgs slug ports comm user uid exe start
  start=$SECONDS

  while IFS='|' read -r cid cpid root mgr; do
    [ $((SECONDS - start)) -gt 120 ] && break        # 안전장치 — 컨테이너가 많아도 스캔을 끝낸다
    [ -d "$root" ] || continue
    pidns=$(readlink "/proc/$cpid/ns/pid" 2>/dev/null) || continue
    [ -z "$pidns" ] && continue

    # **cid 를 파일명으로 쓰지 않는다.** k8s 컨테이너의 cid 는 "파드/컨테이너" 라 슬래시가 들어간다
    #   → "$TMP/.pkgmap.etcd-x/etcd" 는 없는 디렉터리를 가리켜 리다이렉트가 실패하고, 그 컨테이너의
    #   런타임 증거가 통째로 사라진다(운영 실측: 40건 → 13건, k8s 19개가 전부 빠졌다).
    slug=$(printf '%s' "$cid" | tr -c 'A-Za-z0-9._-' '_')
    map="$TMP/.pkgmap.$slug"
    ctr_pkgmap "$root" "$mgr" > "$map" 2>/dev/null
    [ -s "$map" ] || { rm -f "$map"; continue; }     # 파일맵을 못 만들면 이 컨테이너는 건너뛴다

    # 이 컨테이너의 프로세스들(같은 PID namespace) → "pid|E|exe" + "pid|L|라이브러리"
    paths="$TMP/.paths.$slug"; : > "$paths"
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
      [ "$(readlink "/proc/$pid/ns/pid" 2>/dev/null)" = "$pidns" ] || continue
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null); exe=${exe% (deleted)}
      [ -z "$exe" ] && continue                      # 커널 스레드
      printf '%s|E|%s\n' "$pid" "$exe" >> "$paths"
      awk -v p="$pid" 'NF>=6 && $6 ~ /\.so/ { print p"|L|"$6 }' "/proc/$pid/maps" 2>/dev/null \
        | sort -u >> "$paths"
    done
    [ -s "$paths" ] || { rm -f "$map" "$paths"; continue; }

    # 경로 → 패키지 (맵 한 번 읽고 전부 해결. 파일마다 조회하면 느려서 못 쓴다)
    #   usr-merge: /usr/lib 와 /lib 는 같은 곳인데 DB 표기가 갈린다 → 양쪽을 같은 키로 정규화.
    awk -F'|' -v cid="$cid" '
      function norm(p) { sub(/^\/usr\//, "/", p); return p }
      NR==FNR { k=norm($1); if (!(k in M)) M[k]=$2; next }
      {
        pid=$1; kind=$2; pk=M[norm($3)]
        if (kind == "E") { ORDER[++n]=pid; EXE[pid]=(pk != "" ? pk : "UNPACKAGED") }
        else if (pk != "" && !((pid SUBSEP pk) in SEEN)) {
          SEEN[pid SUBSEP pk]=1; L[pid]=L[pid] (L[pid]=="" ? "" : ",") pk
        }
      }
      END { for (i=1; i<=n; i++) { p=ORDER[i]; print cid"|"p"|"EXE[p]"|"L[p] } }
    ' "$map" "$paths" > "$TMP/.pkgs.$slug"
    pkgs="$TMP/.pkgs.$slug"

    # 프로세스 인벤토리 — 사용자 이름은 **컨테이너의 /etc/passwd** 로 푼다
    # (호스트 이름으로 풀면 uid 가 같아도 다른 사람이 된다).
    while IFS='|' read -r _ pid exe_pkg loaded; do
      comm=$(cat "/proc/$pid/comm" 2>/dev/null)
      uid=$(awk '/^Uid:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null)
      user=$(awk -F: -v u="$uid" '$3==u{print $1; exit}' "$root/etc/passwd" 2>/dev/null)
      [ -z "$user" ] && user="uid:$uid"
      printf '%s|%s|%s|%s|%s|%s\n' "$cid" "$pid" "$comm" "$user" "$exe_pkg" "$loaded"
    done < "$pkgs"

    ctr_exposure "$cid" "$cpid" "$pidns" "$pkgs" >> "$TMP/containers__exposure.txt"
    rm -f "$map" "$paths" "$pkgs"
  done < "$TMP/.ctrmap"
}

# ctr_exposure : 컨테이너가 **실제로 듣고 있는** 포트 + 그 포트를 연 프로세스의 패키지
#   컨테이너의 network namespace 소켓은 /proc/<그 컨테이너의 pid>/net/tcp 에 보인다.
#   scope 판정(과대평가 금지):
#     호스트로 게시(-p)됐고 방화벽이 그 포트를 열어둠 → EXTERNAL
#     게시됐지만 방화벽이 막음                        → FILTERED
#     게시 안 됨(도커 내부망에서만 닿음)              → LOCAL
#   게시 정보가 없는 런타임(k8s 등)은 LOCAL 로 둔다 — 모르면서 EXTERNAL 이라 하지 않는다.
ctr_exposure() {   # $1=cid $2=대표pid $3=pidns $4=pkgs파일
  local cid="$1" cpid="$2" pidns="$3" pkgfile="$4"
  local pub socks pid inode line bind port proto scope hostport comm exe_pkg loaded

  pub=""
  if have docker; then
    pub=$(timeout "$CMD_TIMEOUT" docker port "$cid" 2>/dev/null)   # "80/tcp -> 0.0.0.0:8080"
  fi

  # 리스닝 소켓(st=0A) → "inode|bind|port|proto"
  #   strtonum() 은 gawk 전용이라 쓸 수 없다(대상 서버는 mawk/busybox awk 일 수 있다) → 직접 변환.
  #   IPv4 주소는 리틀엔디언 hex 다: "0100007F" = 127.0.0.1.
  socks=$(for f in tcp tcp6; do
            awk -v pr="$f" '
              function hx(s,  i,c,n) { n=0; s=toupper(s)
                for (i=1; i<=length(s); i++) { c=index("0123456789ABCDEF", substr(s,i,1))-1; n=n*16+c }
                return n }
              function ip4(h) { return hx(substr(h,7,2)) "." hx(substr(h,5,2)) "." \
                                       hx(substr(h,3,2)) "." hx(substr(h,1,2)) }
              NR>1 && $4=="0A" {
                split($2, a, ":")
                bind = (length(a[1]) == 8) ? ip4(a[1]) : (a[1] ~ /^0+$/ ? "::" : "::" )
                print $10"|"bind"|"hx(a[2])"|"pr
              }' "/proc/$cpid/net/$f" 2>/dev/null
          done)
  [ -z "$socks" ] && return 0

  # 소켓 inode → pid (그 컨테이너의 프로세스들만 뒤진다)
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(readlink "/proc/$pid/ns/pid" 2>/dev/null)" = "$pidns" ] || continue
    for inode in $(ls -l "/proc/$pid/fd" 2>/dev/null | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p'); do
      line=$(printf '%s\n' "$socks" | awk -F'|' -v i="$inode" '$1==i{print; exit}')
      [ -z "$line" ] && continue
      bind=$(printf '%s' "$line" | cut -d'|' -f2)
      port=$(printf '%s' "$line" | cut -d'|' -f3)
      proto=$(printf '%s' "$line" | cut -d'|' -f4)

      # 호스트로 게시된 포트인가 → 게시됐으면 호스트 방화벽까지 본다.
      #   fw_port_allowed 는 **<포트> <proto> 두 인자**를 받는다. 하나만 넘기면 set -u 가
      #   "$2: unbound variable" 로 **에이전트를 통째로 죽인다**(운영에서 실제로 죽었다).
      #   /proc/net 의 proto 는 tcp/tcp6 인데 방화벽 규칙은 tcp 로 적히므로 6 을 떼고 넘긴다.
      scope="LOCAL"
      hostport=$(printf '%s\n' "$pub" | awk -v p="$port" -F' -> ' \
                   '$1 ~ "^"p"/" { n=split($2, a, ":"); print a[n]; exit }')
      if [ -n "$hostport" ]; then
        if fw_port_allowed "$hostport" "${proto%6}"; then scope="EXTERNAL"; else scope="FILTERED"; fi
      fi

      comm=$(cat "/proc/$pid/comm" 2>/dev/null)
      exe_pkg=$(awk -F'|' -v p="$pid" '$2==p{print $3; exit}' "$pkgfile" 2>/dev/null)
      loaded=$(awk -F'|' -v p="$pid" '$2==p{print $4; exit}' "$pkgfile" 2>/dev/null)
      printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$cid" "$pid" "$comm" "$proto" "$bind" "$port" "$scope" "$exe_pkg" "$loaded"
    done
  done
}

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
    progress_heartbeat
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
progress_report system 12 '시스템 정보와 운영체제를 확인하고 있습니다.'
cap meta hostname_fqdn 'hostname -f 2>/dev/null || hostname'
cap meta collected_at  'date -Is'
cap meta agent_version "echo $SCRIPT_VERSION"
cap meta primary_ip "ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i==\"src\"){print \$(i+1); exit}}'"
cap meta running_as    'id -un'
# 수집 주기 — install-agent.sh 가 agent.env 에 SCHEDULE 을 써 두고 run.sh 가 export 한다.
#   중앙(assets.php)이 노드별 타이머 주기를 읽기전용으로 보여주는 근거. 값을 못 받으면 빈칸.
cap meta schedule      'echo "${SCHEDULE:-}"'
cap meta loadavg       'cat /proc/loadavg'
cap meta nproc         'nproc'
cap meta mem_total_mb  'awk "/^MemTotal:/{printf \"%.0f\", \$2/1024}" /proc/meminfo'

cap system os_release     'cat /etc/os-release'
cap system redhat_release 'cat /etc/redhat-release'
cap system debian_version 'cat /etc/debian_version'
cap system kernel         'uname -a'
cap system kernel_release 'uname -r'
cap system arch           'uname -m'
cap system uptime         'uptime'
cap system boot_time      'uptime -s 2>/dev/null || who -b'
cap system timezone       'timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null'

# jar 파일 하나(내부 임시추출 jar 포함)에서 maven|group:artifact|version 을 뽑는다.
#   1순위: META-INF/maven/*/pom.properties (정확)
#   2순위: META-INF/MANIFEST.MF 의 Implementation-*/Bundle-* 헤더
#   3순위: 파일명 "이름-버전.jar" 패턴 → unknown:이름|버전
# 확신 없으면(패턴이 안 맞으면) 아무 것도 출력하지 않는다 — 잘못된 매핑이 OSV 오매칭을 유발.
emit_jar_meta() {
  local jar="$1" fname="$2" key group name ver found=0
  if have unzip; then
    while IFS= read -r key; do
      group=$(unzip -p "$jar" "$key" 2>/dev/null|sed -n 's/^groupId=//p'|head -1)
      name=$(unzip -p "$jar" "$key" 2>/dev/null|sed -n 's/^artifactId=//p'|head -1)
      ver=$(unzip -p "$jar" "$key" 2>/dev/null|sed -n 's/^version=//p'|head -1)
      if [ -n "$group" ] && [ -n "$name" ] && [ -n "$ver" ]; then
        printf 'maven|%s:%s|%s\n' "$group" "$name" "$ver"
        found=1
      fi
    done < <(unzip -Z1 "$jar" 2>/dev/null|grep '^META-INF/maven/.*/pom.properties$'|head -20)
  fi
  [ "$found" -eq 1 ] && return 0
  if have unzip; then
    local manifest title vendor version bname bver
    manifest=$(unzip -p "$jar" META-INF/MANIFEST.MF 2>/dev/null|tr -d '\r')
    if [ -n "$manifest" ]; then
      title=$(printf '%s\n' "$manifest"|sed -n 's/^Implementation-Title: *//p'|head -1)
      vendor=$(printf '%s\n' "$manifest"|sed -n 's/^Implementation-Vendor-Id: *//p'|head -1)
      version=$(printf '%s\n' "$manifest"|sed -n 's/^Implementation-Version: *//p'|head -1)
      bname=$(printf '%s\n' "$manifest"|sed -n 's/^Bundle-SymbolicName: *//p'|head -1)
      bver=$(printf '%s\n' "$manifest"|sed -n 's/^Bundle-Version: *//p'|head -1)
      [ -z "$title" ] && title="$bname"
      [ -z "$version" ] && version="$bver"
      if [ -n "$title" ] && [ -n "$version" ]; then
        if [ -n "$vendor" ]; then
          printf 'maven|%s:%s|%s\n' "$vendor" "$title" "$version"
        else
          printf 'maven|unknown:%s|%s\n' "$title" "$version"
        fi
        return 0
      fi
    fi
  fi
  local base="${fname%.jar}"
  if [[ "$base" =~ ^(.+)-([0-9][0-9A-Za-z.+_]*)$ ]]; then
    printf 'maven|unknown:%s|%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  fi
}

# war/ear/fat-jar 내부의 중첩 jar(BOOT-INF/lib, WEB-INF/lib, lib/*)를 재귀 깊이 1단계까지만
# 뽑아 emit_jar_meta 를 재적용한다. 아카이브당 최대 200개, 임시파일은 처리 즉시 삭제한다.
emit_nested_jars() {
  local archive="$1" inner tmp icount=0
  have unzip || return 0
  while IFS= read -r inner; do
    icount=$((icount+1)); [ "$icount" -le 200 ] || break
    tmp=$(mktemp 2>/dev/null) || continue
    if unzip -p "$archive" "$inner" > "$tmp" 2>/dev/null; then
      emit_jar_meta "$tmp" "$(basename "$inner")"
    fi
    rm -f "$tmp"
  done < <(unzip -Z1 "$archive" 2>/dev/null|grep -E '(^|/)(BOOT-INF/lib|WEB-INF/lib|lib)/[^/]*\.jar$'|head -200)
}

# Project-local dependencies missed by global package-manager commands.
# Output: manager|name|version. File count/depth is bounded for predictable load.
collect_project_dependencies() {
  local root f name ver group count=0
  for root in $PROJECT_SCAN_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r f; do
      count=$((count+1)); [ "$count" -le 3000 ] || return 0
      case "$f" in
        */METADATA) name=$(sed -n 's/^Name: //p' "$f"|head -1);ver=$(sed -n 's/^Version: //p' "$f"|head -1);[ -n "$name" ]&&[ -n "$ver" ]&&printf 'pip|%s|%s\n' "$name" "$ver";;
        */Cargo.lock) awk 'BEGIN{n=""}/^name = /{gsub(/^name = "|"$/,"",$0);n=$0}/^version = /{gsub(/^version = "|"$/,"",$0);if(n!="")print "cargo|"n"|"$0}' "$f";;
        */package-lock.json) have jq&&jq -r '.packages//{}|to_entries[]|select(.value.name and .value.version)|"npm|\(.value.name)|\(.value.version)"' "$f" 2>/dev/null;;
        */composer/installed.json) have jq&&jq -r '(.packages//.)[]?|select(.name and .version)|"composer|\(.name)|\(.version|sub("^v";""))"' "$f" 2>/dev/null;;
        *.deps.json) have jq&&jq -r '.targets[]?|keys[]|select(test("/"))|split("/")|"nuget|\(.[0])|\(.[1])"' "$f" 2>/dev/null;;
        *.jar) emit_jar_meta "$f" "$(basename "$f")"; emit_nested_jars "$f";;
        *.war|*.ear) emit_nested_jars "$f";;
      esac
    done < <(find "$root" -xdev -maxdepth 8 -type f \( -path '*/site-packages/*.dist-info/METADATA' -o -name Cargo.lock -o -name package-lock.json -o -path '*/composer/installed.json' -o -name '*.deps.json' -o -name '*.jar' -o -name '*.war' -o -name '*.ear' \) 2>/dev/null|head -3000)
  done | sort -u
}
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
progress_report packages 28 '설치 패키지를 수집하고 있습니다.'
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
progress_report patches 40 '패치와 보안 권고 적용 상태를 확인하고 있습니다.'
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
progress_report runtimes 55 '언어 런타임 패키지를 확인하고 있습니다.'
have pip3 && cap langpkg pip 'pip3 list --format=freeze --disable-pip-version-check 2>/dev/null'
have npm  && cap langpkg npm_global 'npm ls -g --depth=0 2>/dev/null'
have gem  && cap langpkg gem 'gem list 2>/dev/null'
have composer && cap langpkg composer 'composer global show 2>/dev/null'
have cargo && cap langpkg cargo 'cargo install --list 2>/dev/null'
have dotnet && cap langpkg nuget 'dotnet tool list -g 2>/dev/null | awk "NR>2 && NF>=2 {print \$1,\$2}"'
collect_project_dependencies | head -c "$MAX_BYTES" > "$TMP/langpkg__inventory.txt" 2>/dev/null || true
[ -s "$TMP/langpkg__inventory.txt" ] || rm -f "$TMP/langpkg__inventory.txt"

# ==================================================================
# 7) 컨테이너 이미지 (이미지별 CVE 매핑)
# ==================================================================
progress_report containers 63 '컨테이너 이미지와 내부 패키지를 확인하고 있습니다.'
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
progress_report exposure 74 '프로세스와 네트워크 노출을 분석하고 있습니다.'
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

# 패키지 출처(Origin 라벨) — 서드파티 저장소 패키지 식별(cap 은 서브셸이라 함수를 못 본다)
collect_pkg_origins > "$TMP/pkg__origins.txt" 2>/dev/null || true
[ -s "$TMP/pkg__origins.txt" ] || rm -f "$TMP/pkg__origins.txt"

# 컨테이너 내부 패키지 — 호스트 스캔에서 빠져 통째로 미탐이던 영역.
#   목록(list)은 함수가 직접 append 하므로 헤더를 먼저 써 둔다. 패키지는 함수의 stdout.
echo "cid|name|image|os_id|os_version|manager|pkg_count|image_digest|k8s_namespace|k8s_pod|k8s_container|workload_ref|runtime_state|sbom_format|sbom_hash" > "$TMP/containers__list.txt"
{
  echo "cid|manager|name|version|source"
  collect_containers
} > "$TMP/containers__packages.txt" 2>/dev/null || true
# 컨테이너가 없으면(헤더뿐) 두 섹션 모두 지운다
[ "$(wc -l < "$TMP/containers__list.txt" 2>/dev/null || echo 0)" -ge 2 ] \
  || rm -f "$TMP/containers__list.txt" "$TMP/containers__packages.txt"

# 컨테이너 런타임 증거(프로세스·리스닝 포트) — 이게 없으면 컨테이너 취약점은 전부 LOW 로 깔린다.
#   ctr_exposure 가 노출 파일에 직접 append 하므로 헤더를 먼저 써 둔다.
collect_sbom | head -c "$MAX_BYTES" > "$TMP/containers__sbom.txt" 2>/dev/null || true
[ -s "$TMP/containers__sbom.txt" ] || rm -f "$TMP/containers__sbom.txt"
echo "cid|pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs" > "$TMP/containers__exposure.txt"
{
  echo "cid|pid|comm|user|exe_pkg|loaded_pkgs"
  collect_container_runtime
#   stderr 를 /dev/null 로 보내지 않는다 — 여기서 죽었을 때 에러가 통째로 묻힌다.
#   실제로 fw_port_allowed 인자 하나를 빠뜨려 set -u 가 에이전트를 죽였는데, 화면엔 아무것도
#   안 나와 "수집 시작" 만 찍히고 조용히 끝났다. 원인을 찾는 데 추적(bash -x)까지 동원해야 했다.
} > "$TMP/containers__processes.txt" || true
for f in containers__processes containers__exposure; do
  [ "$(wc -l < "$TMP/$f.txt" 2>/dev/null || echo 0)" -ge 2 ] || rm -f "$TMP/$f.txt"
done
rm -f "$TMP/.ctrmap"

# ==================================================================
# 11) 리포지토리 설정
# ==================================================================
progress_report security 86 '보안 설정과 예약 작업을 확인하고 있습니다.'
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
# sshd -T 는 "실제 적용값"이라 권위 있지만, 호스트키가 없거나 설정 오류가 있으면 실패한다.
#   그때 config 폴백이 없으면 SSH 점검이 통째로 "판정 불가"가 된다 → **둘 다 수집**한다.
#   (서버는 effective 를 먼저 보고, 없으면 config 로 판정한다.)
if is_root; then
  cap users sshd_effective 'sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|x11forwarding|logingracetime|clientaliveinterval|clientalivecountmax|ciphers|macs"'
fi
cap users sshd_config 'grep -iE "^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|MaxAuthTries|X11Forwarding|LoginGraceTime|ClientAlive)" /etc/ssh/sshd_config 2>/dev/null'

# ── KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 가이드」 점검용 수집 ──
#   CCE 는 CVE 처럼 받아올 피드가 없다(MITRE/NIST CCE 사전은 2013년경 갱신 중단, KISA·금보원
#   가이드는 PDF/HWP 문서 배포). 그래서 가이드 항목을 코드로 옮기고, 판정에 필요한 원자료를
#   여기서 모은다. 전부 읽기 전용이고 stat/grep 수준이라 가볍다.
#   find 기반 항목(U-06 소유자 없는 파일, U-13 SUID 전수, U-15 world-writable)은 전체 파일시스템을
#   훑어야 해서 넣지 않았다 — 이 에이전트의 "서버에 무리 주지 않는다" 원칙과 충돌한다.
cap security file_perms '
  stat -c "%a %U %G %n" /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/hosts \
    /etc/services /etc/crontab /etc/inetd.conf /etc/xinetd.conf /etc/rsyslog.conf /etc/syslog.conf \
    2>/dev/null'
cap security login_defs 'grep -E "^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|UMASK)" /etc/login.defs 2>/dev/null'
cap security pam_rules  'cat /etc/security/pwquality.conf 2>/dev/null | grep -vE "^\s*#|^\s*$";
                         grep -hE "pam_(pwquality|cracklib|faillock|tally2|wheel)" /etc/pam.d/* 2>/dev/null'
cap security tmout      'grep -hE "^\s*(export\s+)?TMOUT" /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/*.sh 2>/dev/null'
cap security root_path  'grep -hE "^\s*(export\s+)?PATH=" /root/.bash_profile /root/.bashrc /root/.profile /etc/profile 2>/dev/null'
# "위반 없음"과 "수집 실패"는 다르다. cap 은 출력이 비면 섹션 파일을 지우므로, 없을 때
# NONE 을 찍지 않으면 정상인 호스트가 중앙에서 "판정 불가(NA)"로 보인다.
cap security rhosts     'ls -l /etc/hosts.equiv /root/.rhosts /home/*/.rhosts 2>/dev/null | grep . || echo NONE'
cap security tcp_wrapper 'cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -vE "^\s*#|^\s*$"'
cap security legacy_services '
  systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | awk "{print \$1}";
  ls /etc/xinetd.d/ 2>/dev/null;
  grep -vE "^\s*#|^\s*$" /etc/inetd.conf 2>/dev/null'
# 빈 패스워드 계정 — /etc/shadow 는 root 만 읽는다. **읽을 수 있을 때만** NONE 을 찍는다:
# 못 읽는데 NONE 을 찍으면 "빈 패스워드 없음(정상)"으로 오판해 진짜 위험을 숨긴다.
cap security empty_passwords '[ -r /etc/shadow ] && { awk -F: "(\$2 == \"\") { print \$1 }" /etc/shadow | grep . || echo NONE; }'
cap security passwd_shadowed 'awk -F: "(\$2 != \"x\" && \$2 != \"*\") { print \$1 }" /etc/passwd 2>/dev/null | grep . || echo NONE'
cap security duplicate_uid   'getent passwd | awk -F: "{ print \$3 }" | sort | uniq -d | grep . || echo NONE'
cap scheduled crontab_system 'cat /etc/crontab 2>/dev/null; cat /etc/cron.d/* 2>/dev/null'
cap scheduled cron_users 'for u in $(cut -d: -f1 /etc/passwd); do o=$(crontab -l -u "$u" 2>/dev/null); [ -n "$o" ] && { echo "== $u =="; echo "$o"; }; done'
have systemctl && cap scheduled timers 'systemctl list-timers --all --no-pager --no-legend 2>/dev/null'
cap filesystem mounts 'findmnt -A 2>/dev/null || mount'
cap filesystem fstab  'cat /etc/fstab'

# ==================================================================
# 결과 조립
# ==================================================================
progress_report packaging 94 '수집 결과를 조립하고 있습니다.'
build_json_output() {
  local f base
  if have jq && [ "${VG_FORCE_AWK:-0}" != 1 ]; then
    for f in "$TMP"/*.txt; do
      [ -e "$f" ] || continue
      base="$(basename "$f" .txt)"
      jq -Rs -c --arg c "${base%%__*}" --arg k "${base#*__}" \
        '{c:$c,k:$k,v:(sub("\n+$";""))}' "$f"
    done > "$TMP/_flat.jsonl"
    jq -s 'reduce .[] as $x ({}; .[$x.c][$x.k] = $x.v)' "$TMP/_flat.jsonl"
  elif have awk; then
    vg_json_build
  else
    return 127
  fi
}

# 조립은 별도 프로세스로 돌려 10초마다 heartbeat를 보낸다. 비정상 데이터나 구현 회귀가 있어도
# 120초 뒤에는 실패로 끝내 웹에 영원히 94% running 명령을 남기지 않는다.
(trap - EXIT; build_json_output) > "$OUT" & JSON_PID=$!
PACKAGING_STARTED=$SECONDS
NEXT_PACKAGING_HEARTBEAT=$(( SECONDS + 10 ))
while kill -0 "$JSON_PID" 2>/dev/null; do
  sleep 1
  kill -0 "$JSON_PID" 2>/dev/null || break
  if [ "$SECONDS" -ge "$NEXT_PACKAGING_HEARTBEAT" ]; then
    progress_report packaging 94 '수집 결과를 조립하고 있습니다.'
    NEXT_PACKAGING_HEARTBEAT=$(( SECONDS + 10 ))
  fi
  if [ $(( SECONDS - PACKAGING_STARTED )) -ge "$PACKAGING_TIMEOUT" ]; then
    kill "$JSON_PID" 2>/dev/null || true
    wait "$JSON_PID" 2>/dev/null || true
    OUTPUT_IS_JSON=0
    echo ">> [실패] JSON 조립 제한시간(${PACKAGING_TIMEOUT}초)을 초과했습니다." >&2
    progress_report failed 100 '수집 결과 조립 제한시간을 초과했습니다.' failed
    exit 1
  fi
done
if wait "$JSON_PID" && [ -s "$OUT" ]; then
  OUTPUT_IS_JSON=1
else
  OUTPUT_IS_JSON=0
  echo ">> [실패] JSON 결과를 만들 수 없습니다." >&2
  progress_report failed 100 '수집 결과를 조립하지 못했습니다.' failed
  exit 1
fi

# 조립까지 끝난 시점에 자기계측을 마감한다. 이전에는 조립 직전에 마감해 실제 100분 병목이
# 소요시간 23초·CPU 0초처럼 누락됐다. 한 번의 선형 AWK 패스로 meta와 command_id를 함께 주입한다.
ELAPSED=$(( SECONDS - START_TS ))
measure_finish
awk -v elapsed="$ELAPSED" -v rss="$PEAK_RSS_MB" -v cpu="$CPU_SECONDS" -v cid="$COMMAND_ID" '
  {
    meta="\"elapsed_seconds\":\"" elapsed "\""
    if (rss != "") meta=meta ",\"peak_rss_mb\":\"" rss "\""
    if (cpu != "") meta=meta ",\"cpu_seconds\":\"" cpu "\""
    sub(/"meta":\{/, "\"meta\":{" meta ",")
    if (cid != "") sub(/}[ \t]*$/, ",\"command_id\":" cid "}")
    print
  }
' "$OUT" > "$TMP/_out_meta.json" && mv "$TMP/_out_meta.json" "$OUT"
JSON_ENGINE="jq"
if [ "${VG_FORCE_AWK:-0}" = 1 ] || ! have jq; then JSON_ENGINE="awk — jq 없이"; fi
echo ">> JSON 저장 완료($JSON_ENGINE): $OUT" >&2

# ---------- command_id 주입(--command-id) ----------
#   run.sh(데몬)가 agent-poll.php 의 due_command_id 를 넘겨받았을 때만 채워진다.
#   최종 JSON 최상위에 "command_id" 필드를 얹어 POST 하면 ingest.php 가 그 명령을 완료
#   처리한다. jq/awk 두 경로 모두 마지막 줄이 최상위 객체를 닫는 "}" 이므로 그 줄만 고친다.
# command_id는 위의 meta 주입 패스에서 함께 넣는다.

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
#   - 전송을 요청받았는데 못 보냈으면 **종료코드 1**. 예전엔 조용히 0 으로 끝나서,
#     타이머는 매시간 초록불인데 중앙엔 자산이 영영 안 올라오는 상태를 아무도 몰랐다.
# ==================================================================
AGENT_SENT_AT=$(date +%s)
AGENT_NONCE=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%s-%s-%s' "$AGENT_SENT_AT" "$$" "${RANDOM:-0}")
SEND_FAILED=0
if [ -n "$SEND_URL" ]; then
  progress_report uploading 97 '수집 결과를 중앙 서버로 전송하고 있습니다.'
  if [ "${OUTPUT_IS_JSON:-0}" != 1 ]; then
    echo ">> 전송 생략: JSON 을 만들지 못했습니다(jq·awk 둘 다 없음)." >&2
    SEND_FAILED=1
  elif ! have curl && have wget; then
    # curl 이 없는 시스템을 위한 폴백. HTTPS 를 순수 셸로 할 수는 없으므로 둘 중 하나는 필요하다.
    #   주의: wget 은 헤더를 **파일로** 받지 못한다 → 토큰이 잠깐 ps 에 보인다(curl 경로엔 없는 위험).
    #   그래서 curl 이 있으면 언제나 curl 을 쓴다.
    echo ">> 전송 시작(wget) → $SEND_URL" >&2
    HTTP_CODE=$(wget -q -O "$TMP/_ingest_resp.json" --server-response \
      --header='Content-Type: application/json' \
      --header="X-Agent-Timestamp: $AGENT_SENT_AT" --header="X-Agent-Nonce: $AGENT_NONCE" \
      ${SEND_TOKEN:+--header="X-Agent-Token: $SEND_TOKEN"} \
      --post-file="$OUT" "$SEND_URL" 2>&1 | awk '/^  HTTP\//{code=$2} END{print (code ? code : "000")}')
    if [ "$HTTP_CODE" = "200" ]; then
      echo ">> 전송 성공(HTTP 200): $(cat "$TMP/_ingest_resp.json" 2>/dev/null)" >&2
    else
      echo ">> 전송 실패(HTTP $HTTP_CODE)" >&2
      SEND_FAILED=1
    fi
  elif ! have curl; then
    echo ">> 전송 생략: curl·wget 이 모두 없습니다." >&2
    SEND_FAILED=1
  else
    echo ">> 전송 시작 → $SEND_URL" >&2
    # 토큰을 curl 명령행 인자(-H "...")로 주면 수집 도는 동안 /proc/<pid>/cmdline 이나 ps 로
    # 로컬에서 평문 노출된다. 헤더 파일(600, $TMP 아래 — 스크립트 EXIT trap 이 통째로 지움)로 넘긴다.
    HDR_FILE="$TMP/_agent_token_header.txt"
    if [ -n "$SEND_TOKEN" ]; then
      : > "$HDR_FILE"; chmod 600 "$HDR_FILE"
      printf 'X-Agent-Token: %s\r\nX-Agent-Timestamp: %s\r\nX-Agent-Nonce: %s\r\n' "$SEND_TOKEN" "$AGENT_SENT_AT" "$AGENT_NONCE" > "$HDR_FILE"
    fi
    HTTP_CODE=$(curl -sS -m 30 \
      -o "$TMP/_ingest_resp.json" -w '%{http_code}' \
      -X POST "$SEND_URL" \
      -H 'Content-Type: application/json' \
      ${SEND_TOKEN:+-H @"$HDR_FILE"} \
      --data-binary @"$OUT" 2>"$TMP/_ingest_err.txt") || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
      echo ">> 전송 성공(HTTP 200): $(cat "$TMP/_ingest_resp.json" 2>/dev/null)" >&2
    else
      echo ">> 전송 실패(HTTP $HTTP_CODE): $(cat "$TMP/_ingest_resp.json" 2>/dev/null)$(cat "$TMP/_ingest_err.txt" 2>/dev/null)" >&2
      SEND_FAILED=1
    fi
  fi
fi

[ "$SEND_FAILED" = 0 ] || progress_report failed 100 '수집 결과 전송에 실패했습니다.' failed

exit "$SEND_FAILED"
