#!/usr/bin/env bash
# Copyright (C) 2026 JeongDoWook · AGPL-3.0-or-later
# 전문: 저장소의 LICENSE 또는 <https://www.gnu.org/licenses/agpl-3.0.html>
#
# vuln-inventory-agent.sh  (v3.9)
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
#    ./vuln-inventory-agent.sh --verify-files  # 패키지 무결성 검증(rpm -Va / dpkg --verify)
#        # 기본 꺼짐. 설치된 모든 패키지의 모든 파일을 해시하므로 수 분 + 무거운 디스크 IO 다.
#        # 상한은 --verify-timeout(기본 300초). 잘리면 "부분 결과"로 표시해 보낸다.
#    ./vuln-inventory-agent.sh --verify-files --verify-timeout 600
#    ./vuln-inventory-agent.sh \
#        --send http://SERVER:8080/ingest.php \
#        --token 호스트별토큰                   # 수집 후 중앙 서버로 전송(파일 저장은 유지)
#    ./vuln-inventory-agent.sh --send ... --token ... --command-id 42
#        # run.sh(데몬)가 agent-poll.php 의 due_command_id 를 넘길 때 사용 — POST 바디
#        # 최상위에 command_id 필드가 실려 그 명령이 완료 처리된다.
#    ./vuln-inventory-agent.sh --poll-once --state-dir /opt/vuln-agent/logs
#        # 수집하지 않는다. agent-poll.php 를 한 번 GET 해 "이번에 무엇을 할지"를 정하고,
#        # run.sh 가 읽을 지시문(키=값 줄들)을 stdout 으로 낸다. SEND_URL·SEND_TOKEN 은
#        # env(agent.env)에서 읽는다 — 토큰은 인자로도 출력으로도 나가지 않는다.
#        # run.sh(데몬 루프)가 10초마다 이걸 부른다. 응답 파싱·수집 인자 조립이 여기 있는
#        # 이유는 아래 "--poll-once" 절 참고(자동 업데이트되는 파일이라야 노드에 도달한다).
# ==================================================================

set -uo pipefail

# ---------- 기본 설정 (환경변수로 덮어쓰기 가능) ----------
SCRIPT_VERSION="3.23"
CMD_TIMEOUT="${CMD_TIMEOUT:-20}"      # 명령 하나당 최대 실행 시간(초)
PACKAGING_TIMEOUT="${PACKAGING_TIMEOUT:-120}" # JSON 조립 전체 상한(초)
PROC_SCAN_TIMEOUT="${PROC_SCAN_TIMEOUT:-180}" # collect_processes /proc 순회 상한(초). 462개 프로세스 호스트 실측 744초 — 90초는 대부분 잘림, 무제한 상향은 스캔 전체 소요에 영향
# 숫자가 아니거나 범위 밖이면 기본값으로 되돌린다(install-agent.sh 의 CPU_QUOTA/PACKAGING_TIMEOUT/
#   MEM_MAX 와 같은 패턴). 검증 없이 두면 잘못된 값(예: "abc")이 [ "$SECONDS" -gt "$PROC_SCAN_TIMEOUT" ]
#   에서 에러를 내고, 그 에러가 조용히 버려지면 컷오프가 무력화돼 탐지 회피에 악용될 수 있다.
case "$PROC_SCAN_TIMEOUT" in ''|*[!0-9]*) PROC_SCAN_TIMEOUT=180 ;; esac
if [ "$PROC_SCAN_TIMEOUT" -lt 30 ] || [ "$PROC_SCAN_TIMEOUT" -gt 3600 ]; then PROC_SCAN_TIMEOUT=180; fi
MAX_BYTES="${MAX_BYTES:-524288}"      # 섹션당 출력 상한 (512KB)
CPU_QUOTA="${CPU_QUOTA:-10%}"         # 기본 CPU 상한(4코어 호스트 전체 기준 최대 약 2.5%)
MEM_MAX="${MEM_MAX:-300M}"             # 기본 메모리 상한
SBOM_DIR="${SBOM_DIR:-/opt/vuln-agent/sbom}" # 선택적 CycloneDX/SPDX 입력 디렉터리
PROJECT_SCAN_ROOTS="${PROJECT_SCAN_ROOTS:-/opt /srv /app /usr/local /var/lib/tomcat* /usr/share/tomcat*}"
SCAN_MAX_FILES="${SCAN_MAX_FILES:-3000}"     # 프로젝트 의존성 스캔 파일 상한(패스별로 각각 적용)
SCAN_MAX_DEPTH="${SCAN_MAX_DEPTH:-8}"        # 프로젝트 의존성 스캔 디렉터리 깊이 상한
PROJECT_SCAN_TIMEOUT="${PROJECT_SCAN_TIMEOUT:-300}" # 프로젝트 의존성 스캔 전체 상한(초)
# 배포판이 깐 파이썬 패키지(deb 의 `python3-*`, rpm 의 `python3-*`)의 메타 경로.
#   PROJECT_SCAN_ROOTS 에 얹지 않고 **일부러 분리**한다 — 자세한 이유는 collect_python_system_meta 주석.
#   글롭은 `for root in $PY_SYS_META_ROOTS` 에서 경로확장되고, 안 맞으면 리터럴이 남아 `[ -d ]` 로 걸린다
#   (PROJECT_SCAN_ROOTS 의 `/var/lib/tomcat*` 과 같은 방식).
PY_SYS_META_ROOTS="${PY_SYS_META_ROOTS:-/usr/lib/python3*/dist-packages /usr/lib/python3*/site-packages /usr/lib64/python3*/site-packages}"
PY_SYS_META_MAX="${PY_SYS_META_MAX:-2000}"   # 이 패스 자체의 상한(메타 디렉터리 개수). 예산을 공유하지 않는다
# 호스트 Go 바이너리 buildinfo 스캔 — 전체 strings 는 비싸다(149MB calico-node 에 1.34초).
#   그래서 개수 상한을 따로 두고, 그 전에 값싼 선별(크기 → ELF 매직 → 앞부분 Go 표식)을 건다.
GO_BIN_SCAN_MAX="${GO_BIN_SCAN_MAX:-40}"          # buildinfo 를 실제로 뽑을 Go 바이너리 개수 상한
GO_BIN_MIN_SIZE="${GO_BIN_MIN_SIZE:-1M}"          # 이보다 작은 파일은 Go 바이너리가 아니다(hello world 도 1.5MB)
GO_BIN_PROBE_BYTES="${GO_BIN_PROBE_BYTES:-65536}" # Go 표식을 찾을 앞부분 크기(전체 스캔 회피용)
DO_CHANGELOG=1                        # 핵심 패키지 CVE changelog 수집 여부
# 패키지 무결성 검증(rpm -Va / dpkg --verify) — **기본 꺼짐**. 설치된 모든 패키지의 모든 파일을
#   해시하므로 시스템에 따라 수 분 + 무거운 디스크 IO 다. "대상 서버에 무리를 주지 않는다"는
#   이 에이전트의 대전제와 정면으로 부딪히므로 `--verify-files` 를 준 실행에서만 돈다.
DO_VERIFY=0
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-300}"      # 무결성 검증 단독 상한(초). CMD_TIMEOUT(20초)로는 무조건 잘린다.
VERIFY_MAX_LINES="${VERIFY_MAX_LINES:-500}"  # 전송할 위반 줄 수 상한(피크 메모리가 페이로드 크기에 비례)
# 무결성 결과에서 통째로 버릴 경로 접두어(공백 구분). 문서·man·번역·info 는 컨테이너·최소설치
#   이미지가 흔히 쓰는 `dpkg --path-exclude=/usr/share/doc/*` 때문에 애초에 안 깔려 있어
#   `dpkg --verify` 가 전부 "md5 불일치"로 잡는다 — 침해가 아니라 정상인데 진짜 신호를 파묻는다
#   (실측: 한 노드가 11,368건을 보고했고 전부 이 경로라 상한 500에 잘렸다).
VERIFY_EXCLUDE_PREFIXES="${VERIFY_EXCLUDE_PREFIXES:-/usr/share/doc/ /usr/share/man/ /usr/share/locale/ /usr/share/info/}"
DO_LIMIT="${AGENT_LIMIT:-1}"          # 기본 cgroup 리밋 사용(AGENT_LIMIT=0 으로만 해제)
OUT=""
SEND_URL="${SEND_URL:-}"             # --send : 중앙 수신 API(ingest.php) URL
SEND_TOKEN="${SEND_TOKEN:-}"         # --token: 중앙에서 이 호스트에 발급한 인증 토큰
COMMAND_ID=""                        # --command-id: agent-poll.php 의 due_command_id (완료 처리용)
# TOKEN_VIA_ENV: cgroup 재실행 때 "토큰을 env 로 넘겼다"는 사실만 알리는 플래그(값은 안 실린다).
# 토큰 자체를 --token 인자로 넘기면 수집이 도는 내내 ps//proc/<pid>/cmdline 로 그 호스트의
# 아무 사용자나 중앙 수집 토큰을 읽어간다(CWE-214). 그래서 값은 env 로만 넘기고, 이 플래그로
# "넘겼는데 안 도착한 경우"를 재실행된 쪽에서 잡아 조용한 무인증 전송을 막는다(아래 가드).
TOKEN_VIA_ENV=0
POLL_ONCE=0                          # --poll-once: 수집 대신 "중앙에 한 번 물어보고 할 일을 정한다"
STATE_DIR="${STATE_DIR:-}"           # --state-dir: run.sh 의 로그/상태 디렉터리(--poll-once 전용)
# _RELAUNCHED: cgroup 재실행 가드. env(export) 상속에만 기대지 않는다 — 일부 호스트(Jetson 계열
# systemd-run)에서 export 로 세팅한 셸 환경변수가 D-Bus 로 시작되는 새 scope 에 전달되지 않아
# export 만으로는 가드가 씹히고 무한 재귀 재실행에 빠지는 사례가 실측됐다. 그래서 --setenv 로도
# 넘기고, 커맨드라인 플래그(--relaunched, 아래 getopts)로도 명시 전달해 인자로도 env 로도
# 반드시 살아남게 이중화한다.
_RELAUNCHED="${_RELAUNCHED:-0}"
PAGESIZE="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

# ---------- 인자 파싱 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output)     OUT="$2"; shift 2 ;;
    --limit)         DO_LIMIT=1; shift ;;
    --no-changelog)  DO_CHANGELOG=0; shift ;;
    --verify-files)  DO_VERIFY=1; shift ;;
    --verify-timeout) VERIFY_TIMEOUT="$2"; shift 2 ;;
    --timeout)       CMD_TIMEOUT="$2"; shift 2 ;;
    --send)          SEND_URL="$2"; shift 2 ;;
    --token)         SEND_TOKEN="$2"; shift 2 ;;
    --command-id)    COMMAND_ID="$2"; shift 2 ;;
    --poll-once)     POLL_ONCE=1; shift ;;
    --state-dir)     STATE_DIR="$2"; shift 2 ;;
    --relaunched)    _RELAUNCHED=1; shift ;;
    --token-via-env) TOKEN_VIA_ENV=1; shift ;;
    -h|--help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

# 토큰이 재실행 경계에서 유실됐는지 확인한다. 부모가 env 로 토큰을 넘겼다고 알렸는데
# ($TOKEN_VIA_ENV=1) 여기서 SEND_TOKEN 이 비어 있으면, 이 호스트의 systemd-run --scope 가
# 환경변수를 새 scope 로 전달하지 못한 것이다(같은 계열의 실측 사례가 _RELAUNCHED 주석에 있다).
# 이때 조용히 무인증 전송을 시도하거나 조용히 전송을 건너뛰면 안 된다 — 예전에 재실행 때
# --send/--token 이 유실돼 "타이머는 매시간 초록불인데 중앙엔 자산이 영영 안 올라오는" 사고가
# 두 번 있었다. 원인이 분명한 메시지와 함께 즉시 실패한다(토큰 값은 절대 찍지 않는다).
if [ "$TOKEN_VIA_ENV" = 1 ] && [ -z "$SEND_TOKEN" ]; then
  cat >&2 <<'EOF'
>> [치명] 인증 토큰이 cgroup 재실행 경계에서 유실됐습니다(SEND_TOKEN 이 비어 있음).
   이 호스트의 systemd-run --scope 가 환경변수를 새 scope 로 전달하지 못한 경우입니다.
   무인증으로 전송하면 중앙이 거부하고, 조용히 건너뛰면 수집이 사라진 걸 아무도 모릅니다.
   → 우회: AGENT_LIMIT=0 으로 실행(cgroup 재실행 없이 돈다) 또는 systemd 버전 확인.
EOF
  exit 1
fi

if [ -n "$COMMAND_ID" ]; then
  case "$COMMAND_ID" in
    ''|*[!0-9]*) echo "--command-id 는 숫자여야 합니다: $COMMAND_ID" >&2; exit 1 ;;
  esac
fi
case "$VERIFY_TIMEOUT" in
  ''|*[!0-9]*|0) echo "--verify-timeout 은 1 이상의 숫자여야 합니다: $VERIFY_TIMEOUT" >&2; exit 1 ;;
esac

have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

# ==================================================================
# --poll-once : 중앙(agent-poll.php)에 한 번 물어보고 "이번에 무엇을 할지"를 정한다.
# ==================================================================
#   왜 여기(본체)에 있나 — 이 로직은 **응답 필드가 늘 때마다 바뀐다.** 예전엔 run.sh 안에
#   있었는데, run.sh 는 install-agent.sh 가 heredoc 으로 만드는 파일이라 자동 업데이트
#   대상이 아니다(do_update() 는 이 본체 하나만 교체한다). 그래서 응답에 필드를 추가해도
#   기존 노드에는 영원히 도달하지 못했고, 명령은 done 으로 처리되는데 결과만 없는
#   **조용한 실패**가 났다(실제 사고: due_command_verify_files → integrity_checked=0).
#   자동 업데이트되는 이 파일로 옮기면 같은 사고가 구조적으로 안 생긴다.
#
#   run.sh 에 남는 것: env 로드 · 데몬 루프 · 로그 경로 · do_update()(자기 갱신 코드는
#   갱신 대상 밖에 있어야 한다 — 닭과 달걀).
#
#   출력(stdout): run.sh 가 읽는 지시문. `키=값` 한 줄 하나, 값에 `=` 가 들어가도 안전하게
#   **첫 `=` 에서만** 자른다. 모르는 키는 run.sh 가 무시하므로 필드를 늘려도 옛 run.sh 가
#   깨지지 않는다(이 파일만 갱신되는 상황을 전제로 한 계약이다).
#     poll_schedule=<초>                     정기수집 주기(참고용)
#     update_version/sha256/path/signature   자동 업데이트 지시(값이 다 있을 때만)
#     scan=scheduled|command                 수집을 돌려라(이유). 없으면 이번엔 안 돈다
#     env=<KEY=VALUE>                        수집 프로세스에 줄 환경변수(속도 티어)
#     arg=<인자>                             수집 인자 한 개(순서대로)
#   토큰은 절대 싣지 않는다 — 자식 프로세스가 env 로 물려받는다(argv·파이프에 안 남긴다).
#
#   종료코드: 0=poll 성공, 1=실패(run.sh 가 백오프 판단에 쓴다).
vg_poll_urlencode() {
  # 순수 bash RFC3986 퍼센트인코딩(영숫자·-_.~ 만 그대로).
  local s="$1" out="" i c
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9._~-]) out+="$c" ;;
      *) out+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  printf '%s' "$out"
}

# 폴백(jq 없음) 전용 — flat JSON 응답에서 문자열 필드 하나를 뽑아 JSON 이스케이프를 푼다.
#   ★ 이스케이프를 반드시 푼다: PHP json_encode 는 기본으로 "/" 를 "\/" 로 쓴다. 그대로 두면
#     update_signature(base64)에 역슬래시가 섞여 base64 디코드가 깨지고 서명 검증이 실패한다
#     — jq 가 없는 노드 전부에서 자동 업데이트가 죽었던 실제 사고다(3.17 → 3.18,
#     signature_invalid). 서버(agent-poll.php)에 JSON_UNESCAPED_SLASHES 를 넣어 막았지만,
#     구버전 서버가 남아 있어도 노드가 스스로 견뎌야 한다.
#   푸는 것은 \/ · \" · \\ 셋뿐이다. \n·\t·\uXXXX 는 일부러 그대로 둔다 — 이 네 필드
#   (버전·sha256·경로·서명)에 제어문자가 올 이유가 없고, 풀어 주면 서버 응답이 지시문
#   (한 줄 = 한 지시) 출력에 줄바꿈을 심어 없는 지시를 끼워 넣을 수 있다.
#   sed 대신 순수 bash 로 훑는다 — 값 안의 \" 를 건너뛰는 정규식은 폴백에 두기엔 너무 깨지기 쉽다.
vg_poll_json_str() {
  local key="$1" json="$2" rest out="" i=0 c n
  rest="${json#*\"$key\"}"
  [ "$rest" = "$json" ] && { printf ''; return; }   # 그 키가 응답에 없다
  rest="${rest#*:}"
  while :; do
    case "${rest:0:1}" in ' '|'	') rest="${rest:1}" ;; *) break ;; esac
  done
  [ "${rest:0:1}" = '"' ] || { printf ''; return; } # null·숫자 등 문자열이 아니다
  rest="${rest:1}"
  while [ "$i" -lt "${#rest}" ]; do
    c="${rest:i:1}"
    case "$c" in
      '"') break ;;                                # 닫는 따옴표
      '\')
        n="${rest:i+1:1}"
        case "$n" in
          '/'|'"'|'\') out+="$n" ;;
          '')          out+="$c"; i=$((i+1)); continue ;;
          *)           out+="$c$n" ;;              # \n·\uXXXX 등은 원문 그대로
        esac
        i=$((i+2)); continue
        ;;
    esac
    out+="$c"; i=$((i+1))
  done
  printf '%s' "$out"
}

# 숫자 + 상식적 범위 밖이면 빈 값으로 떨군다 — 수집은 스크립트 기본값으로 안전하게 계속된다.
vg_poll_num_in_range() {
  local v="$1" lo="$2" hi="$3"
  case "$v" in ''|*[!0-9]*) printf ''; return ;; esac
  if [ "$v" -lt "$lo" ] || [ "$v" -gt "$hi" ]; then printf ''; return; fi
  printf '%s' "$v"
}

vg_poll_once() {
  local poll_url resp="" qs report state_dir
  state_dir="$STATE_DIR"
  if [ -z "$state_dir" ] || [ ! -d "$state_dir" ]; then
    echo ">> --poll-once 에는 --state-dir <디렉터리> 가 필요합니다(현재: ${state_dir:-없음})" >&2
    return 1
  fi
  if [ -z "$SEND_URL" ] || [ -z "$SEND_TOKEN" ]; then
    echo ">> --poll-once 에는 SEND_URL·SEND_TOKEN 이 필요합니다(agent.env)." >&2
    return 1
  fi
  poll_url="${SEND_URL%ingest.php}agent-poll.php"

  local report_file="$state_dir/update_report"       # run.sh 의 do_update() 가 남긴 직전 결과 1줄
  local last_scan_file="$state_dir/last_scan_at"
  local poll_state_file="$state_dir/poll_interval"

  # 현재 버전을 같이 보내 서버가 최신인지 판단하게 하고, 직전 업데이트 결과(있으면)도 같은
  #   GET 에 실어 보고한다 — 새 인바운드 경로를 만들지 않고 기존 폴링을 재사용한다.
  qs="agent_version=$(vg_poll_urlencode "$SCRIPT_VERSION")"
  if [ -f "$report_file" ]; then
    report=$(cat "$report_file" 2>/dev/null)
    # 형식: "<result> <from> <to>". 필드가 깨져 있으면 그냥 흘려보낸다.
    # set -f 로 워드스플릿 결과의 글롭 확장(*·? 등)을 막는다.
    set -f; set -- $report; set +f
    if [ -n "${1:-}" ]; then
      qs="${qs}&update_result=$(vg_poll_urlencode "${1}")&update_from=$(vg_poll_urlencode "${2:-}")&update_to=$(vg_poll_urlencode "${3:-}")"
    fi
  fi

  if have curl; then
    resp=$(curl -sS -m 15 -H "X-Agent-Token: $SEND_TOKEN" "${poll_url}?${qs}" 2>/dev/null)
  elif have wget; then
    resp=$(wget -qO- --timeout=15 --header="X-Agent-Token: $SEND_TOKEN" "${poll_url}?${qs}" 2>/dev/null)
  else
    echo ">> curl·wget 이 모두 없어 poll 을 할 수 없습니다." >&2
    return 1
  fi
  [ -z "$resp" ] && return 1

  local poll_schedule due_cmd due_verify cpu_quota packaging_timeout mem_max
  local update_available update_version update_sha256 update_path update_signature
  # VG_FORCE_AWK=1 은 jq 가 있어도 폴백(grep/sed) 경로를 태운다 — 이 스크립트가 JSON 조립에서
  #   이미 쓰는 것과 같은 스위치다(아래 JSON_ENGINE). 폴백은 정규식이라 깨지기 쉬워서
  #   jq 가 깔린 개발/CI 환경에서도 반드시 한 번은 태워 봐야 한다(tests/agent_poll_once_test.sh).
  if have jq && [ "${VG_FORCE_AWK:-0}" != 1 ]; then
    printf '%s' "$resp" | jq -e . >/dev/null 2>&1 || return 1
    poll_schedule=$(printf '%s' "$resp" | jq -r '.poll_schedule_seconds // empty')
    due_cmd=$(printf '%s' "$resp" | jq -r '.due_command_id // empty')
    due_verify=$(printf '%s' "$resp" | jq -r '.due_command_verify_files // empty')
    cpu_quota=$(printf '%s' "$resp" | jq -r '.cpu_quota_percent // empty')
    packaging_timeout=$(printf '%s' "$resp" | jq -r '.packaging_timeout_seconds // empty')
    mem_max=$(printf '%s' "$resp" | jq -r '.mem_max_mb // empty')
    update_available=$(printf '%s' "$resp" | jq -r '.update_available // false')
    update_version=$(printf '%s' "$resp" | jq -r '.update_version // empty')
    update_sha256=$(printf '%s' "$resp" | jq -r '.update_sha256 // empty')
    update_path=$(printf '%s' "$resp" | jq -r '.update_download_path // empty')
    update_signature=$(printf '%s' "$resp" | jq -r '.update_signature // empty')
  else
    # 숫자 필드는 응답이 단순 flat JSON 이라 grep -o 로 충분하다(null 은 숫자 패턴에 안 걸려 빈 값).
    #   문자열 필드는 vg_poll_json_str 로 뽑는다 — 뽑기만 하면 JSON 이스케이프가 남아 값이 깨진다.
    poll_schedule=$(printf '%s' "$resp" | grep -o '"poll_schedule_seconds"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+$')
    due_cmd=$(printf '%s' "$resp" | grep -o '"due_command_id"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+$')
    due_verify=$(printf '%s' "$resp" | grep -o '"due_command_verify_files"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+$')
    cpu_quota=$(printf '%s' "$resp" | grep -o '"cpu_quota_percent"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+$')
    packaging_timeout=$(printf '%s' "$resp" | grep -o '"packaging_timeout_seconds"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+$')
    mem_max=$(printf '%s' "$resp" | grep -o '"mem_max_mb"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+$')
    update_available=false
    printf '%s' "$resp" | grep -q '"update_available"[[:space:]]*:[[:space:]]*true' && update_available=true
    update_version=$(vg_poll_json_str update_version "$resp")
    update_sha256=$(vg_poll_json_str update_sha256 "$resp")
    update_path=$(vg_poll_json_str update_download_path "$resp")
    update_signature=$(vg_poll_json_str update_signature "$resp")
  fi

  # poll_schedule 이 숫자가 아니면 응답 자체를 못 믿는다 → 이번 poll 은 실패로 끝낸다.
  case "$poll_schedule" in ''|*[!0-9]*) return 1 ;; esac
  # 무결성 검사 포함 여부(0/1). 구버전 서버는 이 필드를 안 주므로 빈 값 → 0 이다.
  #   poll 마다 반드시 다시 계산된다 — 한 번 1 이 들어온 뒤 그대로 남아 다음 정기수집까지
  #   무겁게 도는 일이 없게, "1 이 아니면 0" 으로 못 박는다.
  case "$due_verify" in 1) due_verify=1 ;; *) due_verify=0 ;; esac
  case "$due_cmd" in ''|*[!0-9]*) due_cmd="" ;; esac
  cpu_quota="$(vg_poll_num_in_range "$cpu_quota" 1 100)"
  packaging_timeout="$(vg_poll_num_in_range "$packaging_timeout" 30 3600)"
  mem_max="$(vg_poll_num_in_range "$mem_max" 64 8192)"

  # 응답 검증을 전부 통과한 뒤에만 지운다 — 서버가 오류/깨진 응답을 주면 이번 poll 은 실패로
  # 끝나고(위 return 1 들) 리포트 파일이 남아 다음 poll 에 다시 보고된다(유실 방지).
  rm -f "$report_file"
  printf '%s\n' "$poll_schedule" > "$poll_state_file"
  printf 'poll_schedule=%s\n' "$poll_schedule"

  # 자동 업데이트 지시 — 값이 다 있을 때만 넘긴다(내려받기·검증·교체는 run.sh 의 do_update()).
  if [ "$update_available" = true ] && [ -n "$update_version" ] && [ -n "$update_sha256" ] && [ -n "$update_path" ]; then
    printf 'update_version=%s\n'   "$update_version"
    printf 'update_sha256=%s\n'    "$update_sha256"
    printf 'update_path=%s\n'      "$update_path"
    printf 'update_signature=%s\n' "$update_signature"
  fi

  # 정기수집 만기 판단. 명령(due_cmd)으로 돌았다고 정기수집 타이머를 리셋하지 않는다 —
  #   그러면 "예약 실행 걸었더니 다음 정기수집이 늦어졌다"는 혼란이 생긴다.
  local now last scheduled_due=0
  now=$(date +%s)
  last=$(cat "$last_scan_file" 2>/dev/null || echo 0)
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  [ $(( now - last )) -ge "$poll_schedule" ] && scheduled_due=1

  if [ "$scheduled_due" = 1 ] || [ -n "$due_cmd" ]; then
    if [ "$scheduled_due" = 1 ]; then
      printf '%s\n' "$now" > "$last_scan_file"
      printf 'scan=scheduled\n'
    else
      printf 'scan=command\n'
    fi
    # 호스트별 속도 티어 — 이 스크립트 상단이 이미 CPU_QUOTA/PACKAGING_TIMEOUT/MEM_MAX
    #   환경변수를 지원하므로 새 플래그 없이 env 로만 넘긴다. 비어 있으면(구버전 서버 등)
    #   스크립트 자체 기본값(10%/120초/300M)이 그대로 쓰인다.
    [ -n "$cpu_quota" ]         && printf 'env=CPU_QUOTA=%s%%\n' "$cpu_quota"
    [ -n "$packaging_timeout" ] && printf 'env=PACKAGING_TIMEOUT=%s\n' "$packaging_timeout"
    [ -n "$mem_max" ]           && printf 'env=MEM_MAX=%sM\n' "$mem_max"
    printf 'arg=-o\narg=%s\n' "$state_dir/last.json"
    [ -n "$due_cmd" ] && printf 'arg=--command-id\narg=%s\n' "$due_cmd"
    # 패키지 무결성 검증 — 둘 중 하나라도 1 이면 붙인다(OR).
    #   (a) VERIFY_FILES : 설치 시 --verify-files 를 준 노드 고정값(기본 꺼짐). 구버전
    #       agent.env 에는 이 키가 없으므로 :-0 으로 안전하게 꺼진 상태를 유지한다.
    #   (b) due_verify   : 중앙이 이번 명령에 한해 켠 값(due_command_verify_files).
    #       명령 단위라 다음 정기수집에는 따라붙지 않는다 — 기본 꺼짐이라는 대전제는 그대로다.
    #   --verify-timeout 은 무결성 검증 단독 상한. CMD_TIMEOUT(20초)로는 무조건 잘린다.
    if [ "${VERIFY_FILES:-0}" = 1 ] || [ "$due_verify" = 1 ]; then
      printf 'arg=--verify-files\narg=--verify-timeout\narg=%s\n' "$VERIFY_TIMEOUT"
    fi
  fi
  return 0
}

if [ "$POLL_ONCE" = 1 ]; then
  vg_poll_once
  exit $?
fi

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
declare -A RPPATH   # 원경로($f) → realpath 결과 캐시. realpath 자체도 매번 fork 라 별도로 캐시한다.
FTP_LAST=""          # file_to_pkg 의 결과를 "echo 로만" 말고 이 전역변수로도 넘긴다.
                     # 이유: 호출부가 loop 안에서 p=$(file_to_pkg …) 로 명령치환하면 그때마다
                     # 서브셸이 새로 뜨고, 그 서브셸이 채운 LIBPKG/RPPATH 는 부모 루프로 안 돌아온다
                     # (아래 주석의 "서브셸마다 복사" 문제) → 실측: 프로세스 367개 스캔에서
                     # 캐시가 있는데도 file_to_pkg 가 매 pid·매 lib 마다 파일캐시 awk 를 다시
                     # fork 했다(호출 367*10회, 부모 셸에서 관측된 LIBPKG 갱신은 0회). 호출부를
                     # "$(... | while read; do file_to_pkg; done)" 대신 "while … done <<< …" 로
                     # 바꿔 서브셸을 없애면 이 전역변수 경유로 인메모리 캐시가 실제로 프로세스
                     # 전체에 걸쳐 유지된다(파일캐시 fallback 은 그대로 둔다 — 서브셸을 못 없애는
                     # 호출부(collect_containers 등)를 위한 안전망).
file_to_pkg() {
  local f="$1" rp p="" cache
  FTP_LAST=""
  [ -z "$f" ] && { echo ""; return; }
  if [ -n "${RPPATH[$f]+x}" ]; then
    rp="${RPPATH[$f]}"
  else
    rp=$(realpath "$f" 2>/dev/null); [ -z "$rp" ] && rp="$f"   # 삭제된 파일은 realpath 실패 → 원 경로
    RPPATH[$f]="$rp"
  fi
  if [ -n "${LIBPKG[$rp]+x}" ]; then FTP_LAST="${LIBPKG[$rp]}"; echo "$FTP_LAST"; return; fi

  # collect_exposure/collect_processes 는 명령 치환과 파이프라인 안에서 이 함수를 부를 수 있다.
  # Bash associative array는 그 서브셸마다 복사되어 결과가 부모와 다음 프로세스에 남지 않는다.
  # 실행 전용 TMP 파일에도 결과를 기록해, 같은 libc/libssl 경로를 프로세스마다 dpkg -S로
  # 수백 번 다시 조회하지 않는다. 소유 패키지가 없는 경로(빈 값)도 캐시해야 실패 조회도 반복되지 않는다.
  cache="$TMP/.file-to-pkg.cache"
  if [ -f "$cache" ]; then
    if p=$(awk -F '\t' -v k="$rp" '
        $1 == k { pos=index($0,"\t"); print substr($0,pos+1); found=1; exit }
        END { exit(found ? 0 : 1) }
      ' "$cache" 2>/dev/null); then
      LIBPKG[$rp]="$p"; FTP_LAST="$p"; echo "$p"; return
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
  FTP_LAST="$p"
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
if [ "$DO_LIMIT" = 1 ] && [ "$_RELAUNCHED" != 1 ] && is_root && have systemd-run; then
  echo ">> cgroup 리밋 적용(CPU=$CPU_QUOTA, MEM=$MEM_MAX) 후 재실행" >&2
  # 재실행 커맨드에 옵션을 그대로 실어야 한다. 예전엔 ${OUT:+…} ${DO_CHANGELOG:+} 만 붙여
  # --no-changelog·--send·--token 이 유실됐고, 특히 `--limit --send URL` 이면 전송이 통째로
  # 사라졌다(${DO_CHANGELOG:+} 는 항상 빈 문자열). 파싱된 값으로 인자를 배열로 재구성한다.
  # (--limit 은 다시 넘기지 않는다 — _RELAUNCHED 가드로 재진입이 막히고, 스코프는 이미 적용됨.)
  # _RELAUNCHED 가드는 --setenv 와 --relaunched 인자 양쪽으로 이중 전달한다: 일부 호스트
  # (Jetson 계열)에서 export 로 세팅한 환경변수가 systemd-run --scope 로 시작되는 새 scope 에
  # 상속되지 않아, env 에만 의존하면 가드가 씹히고 무한 재귀 재실행에 빠지는 사례가 실측됐다.
  relaunch_args=(--relaunched --timeout "$CMD_TIMEOUT")
  [ -n "$OUT" ]                && relaunch_args+=(-o "$OUT")
  [ "$DO_CHANGELOG" = 0 ]      && relaunch_args+=(--no-changelog)
  # 무결성 검증도 여기서 다시 붙인다 — 안 붙이면 --limit 과 함께 준 --verify-files 가
  #   재실행 때 통째로 사라져 "켰는데 아무것도 안 오는" 상태가 된다(위 사고와 같은 클래스).
  [ "$DO_VERIFY" = 1 ]         && relaunch_args+=(--verify-files --verify-timeout "$VERIFY_TIMEOUT")
  [ -n "$SEND_URL" ]           && relaunch_args+=(--send "$SEND_URL")
  [ -n "$COMMAND_ID" ]         && relaunch_args+=(--command-id "$COMMAND_ID")
  # 토큰만은 인자로 넘기지 않는다 — 재실행된 프로세스는 수집이 끝날 때까지 살아 있고, 그동안
  # `ps aux`/`/proc/<pid>/cmdline` 로 그 호스트의 아무 사용자나 중앙 수집 토큰을 읽어간다
  # (CWE-214, 실측: 운영 노드 ubuntu). agent.env 를 600 으로 막아둔 게 이 한 줄로 무력화됐다.
  # 전송 경로가 curl -H 대신 헤더 파일을 쓰는 것과 같은 이유다(아래 send 절 주석 참고).
  # env 로 넘기면 /proc/<pid>/environ 에만 남고, 그건 같은 사용자와 root 만 읽는다.
  #   - export: systemd-run 은 자기 자신을 exec 으로 대체하므로 보통은 이것으로 상속된다.
  #   - --setenv: _RELAUNCHED 와 같은 이유로 이중화한다(export 상속이 안 되던 호스트 실측).
  #     (systemd-run 자신의 argv 에 값이 실리지만 곧바로 exec 으로 덮이는 찰나뿐이고,
  #      scope 는 env 를 PID1 로 보내지 않는다 — 노출 구간이 "수집 내내"에서 사라진다.)
  #   - --token-via-env: 값이 아니라 "넘겼다"는 사실만 인자로 알린다. 재실행된 쪽에서 이게
  #     켜졌는데 SEND_TOKEN 이 비면 조용히 넘어가지 않고 즉시 실패한다(위 가드).
  relaunch_env=(--setenv=_RELAUNCHED=1)
  if [ -n "$SEND_TOKEN" ]; then
    export SEND_TOKEN
    relaunch_env+=(--setenv=SEND_TOKEN="$SEND_TOKEN")
    relaunch_args+=(--token-via-env)
  fi
  exec systemd-run --scope --quiet \
      "${relaunch_env[@]}" \
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
# ORIGINS_PID: collect_pkg_origins() 가 백그라운드 apt-cache 를 돌리는 동안만 설정한다.
# cancel_if_requested() 의 exit 130 은 함수 RETURN 을 안 거치고 프로세스를 바로 끝내므로,
# 그 자식을 정리할 곳은 결국 여기(전역 EXIT 트랩)뿐이다 — 정상 종료 시엔 이미 wait 로 끝난
# 뒤라 kill 이 조용히 실패할 뿐 무해하다.
trap 'kill "${ORIGINS_PID:-}" 2>/dev/null; rm -rf "$TMP"' EXIT
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
  local stage="${1:-exposure}" percent="${2:-74}" \
        message="${3:-프로세스와 네트워크 노출을 분석하고 있습니다.}"
  local now last=0
  now=$(date +%s); [ -f "$TMP/.progress-heartbeat" ] && read -r last < "$TMP/.progress-heartbeat"
  if [ $((now - last)) -ge 5 ]; then
    printf '%s' "$now" > "$TMP/.progress-heartbeat"
    progress_report "$stage" "$percent" "$message"
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
  # 이 함수가 **에이전트 전체를 종료시킨다**. 기본값으로 그것을 막는다.
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

# ---------- 런타임 노출 · 패키지 출처 수집 함수 ----------
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
  local pid comm exe exepkg loaded socks proto addr bind port scope lib maplibs
  local -a pkglist
  for pid in $pids; do
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    exe=$(realpath /proc/$pid/exe 2>/dev/null)
    file_to_pkg "$exe" >/dev/null; exepkg="$FTP_LAST"; [ -z "$exepkg" ] && exepkg="UNPACKAGED"
    # file_to_pkg 를 "$(... | while read; do file_to_pkg; done)" 파이프 서브셸 안에서 부르면
    #   호출마다 LIBPKG/RPPATH 캐시가 서브셸에 갇혀 부모로 안 돌아온다(위 file_to_pkg 주석 참고).
    #   여기선 "while … done <<< …" (here-string, 서브셸 없음)으로 불러 인메모리 캐시가
    #   pid 를 넘어 실제로 누적되게 한다 — 출력(정렬·중복제거된 pkg 목록)은 원본과 동일.
    maplibs=$(awk '/\.so/{print $6}' /proc/$pid/maps 2>/dev/null | sort -u)
    pkglist=()
    while IFS= read -r lib; do
      [ -z "$lib" ] && continue
      file_to_pkg "$lib" >/dev/null
      [ -n "$FTP_LAST" ] && pkglist+=("$FTP_LAST")
    done <<< "$maplibs"
    if [ "${#pkglist[@]}" -gt 0 ]; then
      loaded=$(printf '%s\n' "${pkglist[@]}" | sort -u | paste -sd, -)
    else
      loaded=""
    fi
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
  # apt-cache policy 를 패키지 수천 개에 돌리면 CMD_TIMEOUT 기본값(20초) 기준으로도 이 블록
  # 전체가 ~40초(policy 전체 20초 + policy 패키지목록 20초)까지 걸릴 수 있다 — 웹 UI 의 180초
  # "마지막 통신 지연" 임계(server/public/assets/app.js:315)엔 원래 안 닿지만, CMD_TIMEOUT 을
  # 크게 잡은 환경이나 apt-cache 가 timeout 안에서도 굼뜬 환경까지 고려해 하트비트를 둔다.
  # 백그라운드로 돌리고 그 PID 가 끝날 때까지 5초 간격으로 progress_heartbeat() 를 부르며
  # 대기한다 — awk 로 들어가는 stdin 내용·순서는 원본과 완전히 동일해야 하므로, 백그라운드
  # 출력을 임시파일에 그대로 받아 끝난 뒤 그 파일을 awk 에 넘긴다(파이프라인 구조 자체는
  # 바꾸지 않음). cap() 과 동일하게 head -c 로 바이트 상한을 걸고, timeout -k 2 로 SIGTERM
  # 을 무시하는 자식이 있어도 kill -0 대기 루프가 영원히 끝나지 않는 걸 막는다.
  local origins_raw="$TMP/.pkg-origins-raw.txt"
  {
    timeout -k 2 "$CMD_TIMEOUT" apt-cache policy 2>/dev/null
    echo "@@@SPLIT@@@"
    timeout -k 2 "$CMD_TIMEOUT" apt-cache policy $(dpkg-query -W -f='${Package}\n' 2>/dev/null) 2>/dev/null
  } | head -c "$MAX_BYTES" > "$origins_raw" &
  ORIGINS_PID=$!
  while kill -0 "$ORIGINS_PID" 2>/dev/null; do
    progress_heartbeat pkg_origins 80 '패키지 출처(서드파티 저장소)를 확인하고 있습니다.'
    sleep 5
  done
  wait "$ORIGINS_PID"
  ORIGINS_PID=""
  awk '
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
    }' "$origins_raw"
  rm -f "$origins_raw"
}

# ---------- 컨테이너(도커/containerd) 이미지 · SBOM · 런타임 노출 수집 함수 ----------
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
    timeout "$CMD_TIMEOUT" strings -a "$file" 2>/dev/null
  else
    # binutils가 없는 최소 호스트: grep -P(PCRE)는 busybox 에 없다. 비인쇄 문자(탭 제외)를
    # 줄바꿈으로 바꾸면 strings 와 사실상 같은 입력이 되어 아래 awk 를 그대로 재사용할 수 있다.
    # `[:print:]` 는 busybox tr 이 POSIX 클래스로 안 읽고 글자 그대로의 집합으로 취급해
    # 대부분의 문자를 지워버린다(실측) — 그래서 인쇄 가능 ASCII 범위를 8진 코드로 직접 준다.
    # LC_ALL=C 는 이 명령에만 준다 — 멀티바이트 로케일이면 tr 이 바이너리 바이트를 잘못 다룬다.
    LC_ALL=C timeout "$CMD_TIMEOUT" tr -c '\040-\176\011' '\n' < "$file" 2>/dev/null
  fi | awk -F'\t' -v c="$cid" '$1=="dep" && NF>=3 && $2 ~ /\// { print c"|go|"$2"|"$3"|" }'
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
        ver=$(timeout "$CMD_TIMEOUT" grep -ao 'nginx/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' "/proc/$p/root$exe" 2>/dev/null \
              | head -1 | cut -d/ -f2)
        [ -n "$ver" ] && printf '%s|upstream|nginx|%s|\n' "$cid" "$ver"
        ;;
    esac
  done | sort -u
}

# 선택적 오프라인 SBOM 반입. 파일명(.json 제외)이 곧 대상이다:
#   _host.json    -> 호스트 자신(서버가 container_id=0 으로 저장하는 예약 cid)
#   <cid>.json    -> 그 컨테이너. cid 는 collect_containers 가 **실제로 출력한 첫 필드**여야 한다
#                    (docker/podman 이 아는 컨테이너면 그 이름, 어느 런타임 CLI 도 모르면 cgroup 키 12자).
# "이름으로도 되고 ID 로도 된다"가 아니다 — 서버는 그 cid 문자열 하나로만 맞춘다:
#   server/src/ingest/store/containers.php:22 vg_ingest_ctr_ids_with_host() 가 cid => container_id
#   지도에 예약 cid `_host` 만 더할 뿐, 이름으로 되짚는 경로가 없다. cid 가 tb_container 의
#   자연키 축(UNIQUE(scan_id, cid))이고 이름은 유일하지 않아서다 — 같은 컨테이너 이름이
#   호스트마다·파드마다 또 있다. 이름 매칭을 새로 붙이지 마라(어느 행을 뜻하는지 정해지지 않는다).
# k8s(CRI) 컨테이너의 cid 는 `파드/컨테이너` 형태라 `/` 가 들어간다 → 파일명으로 못 쓴다.
#   이 경로로는 k8s 컨테이너에 SBOM 을 붙일 수 없다(호스트·도커 컨테이너만 가능).
# 그 밖의 파일명은 서버가 버리고 ingest 응답의 sbom_dropped 로 되돌려준다 — 조용히 호스트에 붙지 않는다.
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
      #   "$2: unbound variable" 로 **에이전트를 통째로 종료시킨다**.
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

# ---------- 프로세스 인벤토리 · 재시작 필요 판정 함수 ----------
# collect_processes : 실행 중인 "모든" 프로세스 + 소속 패키지 + 로드한 라이브러리 패키지
#   collect_stale(재시작 필요 판정)이 필요로 하는 "이 pid 가 물고 있는 삭제된 .so" 도
#   **같은 /proc 순회 한 번**에서 같이 뽑아 "$TMP/.stale-scan.txt" 에 적어 둔다 — 예전엔
#   collect_processes 와 collect_stale 이 365개 pid 목록을 각각 따로 훑으며(ns 판정 readlink
#   2회, maps 읽기(grep+awk) 3~4회, comm cat 2회 씩 중복 수행) 프로세스당 fork 를 두 배로
#   냈다. 두 출력 다 "이 pid 가 매핑한 .so 목록"에서 파생되므로 pid 당 maps 를 한 번만 읽어
#   전체 .so 목록(loaded)과 그중 삭제된 것(stale)을 동시에 뽑을 수 있다.
#   게이트 동일성: collect_processes 원본은 "maps 에 .so 문자열이 하나라도 있으면" 통과였다.
#   삭제된 라이브러리의 경로($6)도 여전히 ".so" 문자열을 포함하므로(삭제 표시는 별도 필드
#   "(deleted)") stale 대상 프로세스는 항상 이 게이트를 통과한다 — 게이트를 합쳐도 안전.
#   실측(컨테이너 370 pid 스냅샷): 원본 2-pass 평균 7.7초 → 병합 1-pass 평균 3.5초, 출력
#   바이트단위 동일(diff 없음). 자세한 벤치마크는 PR 설명 참고.
#   출력: pid|comm|user|exe_pkg|loaded_pkgs(,)
PROC_SCAN_TRUNCATED=0   # PROC_SCAN_TIMEOUT 컷오프로 /proc 순회가 중간에 끊겼는지 — meta__processes_truncated 로 노출

collect_processes() {
  local pid comm user exe exepkg loaded pns lib delf
  # 컨테이너(쿠버네티스/도커) 프로세스는 다른 mount namespace → 호스트 자신만 인벤토리한다.
  #   (컨테이너 라이브러리는 오버레이 경로라 dpkg -S 가 매번 DB 전체스캔 = 수백~수천회로 멈춤.
  #    컨테이너는 각자 에이전트가 스캔해야 함.) + 안전장치: 오래 걸리면 중단.
  local HOST_NS start; HOST_NS=$(readlink /proc/self/ns/mnt 2>/dev/null); start=$SECONDS
  : > "$TMP/.stale-scan.txt"
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    progress_heartbeat
    if [ $((SECONDS - start)) -gt "$PROC_SCAN_TIMEOUT" ]; then
      PROC_SCAN_TRUNCATED=1   # PROC_SCAN_TIMEOUT 컷오프로 전체 pid 를 못 돌았다 — 프로세스/재시작필요
      break                    # 판정이 불완전할 수 있음을 meta__processes_truncated 로 알린다.
    fi
    pns=$(readlink /proc/$pid/ns/mnt 2>/dev/null)
    [ -n "$pns" ] && [ "$pns" != "$HOST_NS" ] && continue      # 다른 ns(컨테이너) 제외

    # maps 를 이 pid 당 딱 한 번만 읽어 "유니크 .so 경로 목록 + 그중 삭제여부"를 동시에 뽑는다
    # (원본의 grep -ql '\.so' 게이트 + collect_processes 용 awk + collect_stale 용 awk 를 통합).
    local maplines; maplines=$(awk '
        $0 ~ /\.so/ && NF>=6 {
          key=$6; d = (/\(deleted\)$/) ? 1 : 0
          if (!(key in seen)) { order[++n]=key; seen[key]=1; delf[key]=d }
          else if (d) { delf[key]=1 }
        }
        END { for (i=1;i<=n;i++) print order[i] "\t" delf[order[i]] }
      ' /proc/$pid/maps 2>/dev/null)
    [ -z "$maplines" ] && continue   # 원본 grep -ql '\.so' 게이트와 동일 (실제 프로그램만)

    comm=$(cat /proc/$pid/comm 2>/dev/null)

    # file_to_pkg 를 "$(... | while read; do file_to_pkg; done)" 파이프 서브셸 안에서 부르면
    #   호출마다 인메모리 캐시(LIBPKG/RPPATH)가 서브셸에 갇혀 사라진다(file_to_pkg 정의부 주석
    #   참고 — 실측: 이 문제로 365개 프로세스가 같은 libc.so.6 를 매번 파일캐시(awk fork)로
    #   다시 조회했다). here-string(<<<, 서브셸 없음)으로 불러 캐시가 pid 를 넘어 누적되게 한다.
    # dellist 를 "lib|pkg" 문자열로 패킹하면 lib 경로(비특권 로컬 사용자가 임의 파일명으로
    #   통제 가능)에 포함된 '|' 가 구분자와 충돌해 필드를 위조할 수 있다 — 그래서 패킹/언패킹
    #   자체를 없애고 병렬 배열 두 개로 들고 다닌다.
    local -a pkglist=() dellist_file=() dellist_pkg=()
    while IFS=$'\t' read -r lib delf; do
      [ -z "$lib" ] && continue
      file_to_pkg "$lib" >/dev/null
      [ -n "$FTP_LAST" ] && pkglist+=("$FTP_LAST")
      if [ "$delf" = "1" ]; then
        dellist_file+=("$lib")
        dellist_pkg+=("$FTP_LAST")
      fi
    done <<< "$maplines"

    if [ "${#pkglist[@]}" -gt 0 ]; then
      loaded=$(printf '%s\n' "${pkglist[@]}" | sort -u | paste -sd, -)
    else
      loaded=""
    fi

    user=$(stat -c '%U' /proc/$pid 2>/dev/null)
    exe=$(realpath /proc/$pid/exe 2>/dev/null)
    file_to_pkg "$exe" >/dev/null; exepkg="$FTP_LAST"
    [ -z "$exepkg" ] && exepkg="UNPACKAGED"
    # "$TMP/.stale-scan.txt" 는 '|' 구분 4필드 그대로 남기지만, 값(특히 lib 경로)에 '|' 나
    #   개행이 섞여 있으면 필드가 밀린다 — 출력 직전에 제거해 필드 무결성을 서버측 explode
    #   limit 과 이중으로 보장한다.
    local safe_comm safe_dpkg safe_dfile
    safe_comm="${comm//[$'|\n']/_}"
    echo "${pid}|${safe_comm}|${user}|${exepkg}|${loaded}"

    local i dfile dpkg
    for ((i=0; i<${#dellist_file[@]}; i++)); do
      dfile="${dellist_file[$i]}"; dpkg="${dellist_pkg[$i]}"
      [ -z "$dpkg" ] && continue   # 소유 패키지를 못 찾으면(예: 미패키징 lib) 원본과 동일하게 skip
      safe_dpkg="${dpkg//[$'|\n']/_}"
      safe_dfile="${dfile//[$'|\n']/_}"
      printf '%s|%s|%s|%s\n' "$pid" "$safe_comm" "$safe_dpkg" "$safe_dfile" >> "$TMP/.stale-scan.txt"
    done
  done
}

# collect_stale : 삭제된 라이브러리를 아직 메모리에 물고 있는 프로세스 (재시작 필요)
#   패키지를 업데이트하면 옛 .so 는 unlink 되고(=maps 에 "(deleted)") 새 파일이 깔린다.
#   하지만 이미 뜬 프로세스는 **옛 코드를 계속 실행**한다. 그래서 "패치됨"으로 보이지만
#   실제로는 여전히 취약하다 — 오탐이 아니라 **미탐**이라 더 위험하다.
#   실제 /proc 순회는 collect_processes() 가 이미 했다(위 주석 참고) — 호출 순서 전제:
#   collect_processes 가 먼저 실행되어 "$TMP/.stale-scan.txt" 를 채운 뒤 이 함수가 불려야 한다
#   (실제 호출부는 그 순서를 따른다). 여기서는 그 결과를 그대로 내보내기만 한다.
#   출력: pid|comm|pkg|lib
collect_stale() {
  # cap() 을 거치지 않고 직접 append 되는 파일이라 MAX_BYTES 상한을 안 거친다 — 여기서 씌운다.
  head -c "$MAX_BYTES" "$TMP/.stale-scan.txt" 2>/dev/null
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

# Gemfile.lock 의 GEM 섹션에서 해결된 gem 버전을 뽑는다. 출력: gem|이름|버전
#   · 들여쓰기 4칸이 패키지, 6칸은 그 패키지의 "의존성 선언"이라 버린다 — 6칸을 패키지로 오인하면
#     `(= 7.0.4)` 같은 제약 표현이 버전으로 들어가 통째로 오탐이 된다.
#   · PATH(로컬 gem)·GIT(git 소스) 섹션도 specs: 를 갖지만 읽지 않는다. git 소스는 버전 문자열이
#     실제 릴리스와 달라 매칭에 오탐만 만든다(YAGNI).
#   · `nokogiri (1.13.8-x86_64-linux)` 처럼 플랫폼이 붙는 경우가 있어 하이픈 뒤는 떼어낸다
#     (Gem::Version 자체엔 하이픈이 없다 — 하이픈은 곧 플랫폼 구분자다).
#   · **라이선스는 내지 않는다(fd 3 을 쓰지 않는다) — Gemfile.lock 에는 라이선스 필드가 없다.**
#     그래서 이 경로로만 발견된 gem 은 DB 에서 license 가 NULL 이다. 결함이 아니라 설계다
#     (라이선스는 emit_gemspec_name 이 설치본 gemspec 본문에서만 읽는다).
emit_gemfile_lock() {
  awk '
    /^[A-Z]/ { ingem = ($0 == "GEM"); inspecs = 0; next }   # 최상위 섹션 경계
    ingem && /^  specs:[ \t]*$/ { inspecs = 1; next }
    inspecs {
      if ($0 ~ /^    [^ ]/) {
        if ($0 ~ /^    [A-Za-z0-9_.-]+ \([^()]+\)$/) {
          line = $0; sub(/^    /, "", line)
          n  = index(line, " ")
          nm = substr(line, 1, n - 1)
          vr = substr(line, n + 2); sub(/\)$/, "", vr); sub(/-.*$/, "", vr)
          if (nm != "" && vr ~ /^[0-9]/) print "gem|" nm "|" vr
        }
      } else if ($0 !~ /^      /) { inspecs = 0 }           # specs 블록 종료
    }
  ' "$1"
}

# 설치된 gem 의 gemspec 본문에서 라이선스를 뽑는다. 출력: 한 줄(없으면 아무것도 내지 않는다).
#   ruby:3.2-slim 의 specifications/*.gemspec 실측 형식:
#     s.licenses = ["MIT".freeze]                          (복수 — 배열)
#     s.licenses = ["Ruby".freeze, "BSD-2-Clause".freeze]  (복수 — 값 여럿)
#     s.license  = "MIT".freeze                            (단수 — 문자열)
#   · 변수명이 `s.` 라는 보장이 없다(`spec.`·`gem.`) → 앞부분에 기대지 않고 `licenses? =` 만 기준으로 잡는다.
#   · `.freeze` 와 따옴표를 뗀다. 값이 여럿이면 " OR " 로 잇는다 — composer 분기가 같은 상황을
#     `join(" OR ")` 로 처리하는 것과 같은 관례다(DRY). `MIT OR Apache-2.0` 같은 복합 표현식은
#     중앙 vg_license_classify()(server/src/license_risk.php)가 괄호 벗기기·OR/AND/WITH 토큰화로
#     이미 읽는다 → **에이전트에는 매핑표를 두지 않는다**(pip 라이선스와 같은 원칙).
#   · 따옴표가 없는 값(변수·메서드 호출)은 값을 알 수 없으니 버린다. SPDX 식별자 모양을 벗어난
#     값도 버린다 — 확신이 안 서면 내지 않는다(이름·버전 파싱과 같은 태도).
#   · 남는 값이 하나도 없으면 아무것도 내지 않는다. 빈 문자열을 내면 fd 3 에 빈 라이선스가 쌓인다.
#   · 옛날 gem 의 gemspec 에는 라이선스 선언 자체가 없다(rubygems 가 `licenses=` 를 권장하기 전).
#     `log4r 1.1.10`(2012) · `little-plugger 1.1.4`(2015) 는 본문 어디에도 `license` 가 없어
#     NULL 이 되는 게 맞다 — 이런 건 파서를 넓혀도 못 채운다. 2026-08-21 ruby:3.2-slim 실측.
gemspec_license() {
  awk '
    /(^|[^A-Za-z0-9_])licenses?[ \t]*=/ {
      v = $0
      sub(/^.*licenses?[ \t]*=[ \t]*/, "", v)      # `= ` 오른쪽만 남긴다
      if (v !~ /^[["]/) next                       # 값이 배열·문자열로 시작하지 않으면 라이선스 선언이 아니다
      gsub(/\.freeze/, "", v)
      sub(/^\[/, "", v); sub(/\][ \t]*$/, "", v)   # 배열이면 대괄호를 벗긴다
      n = split(v, a, ","); out = ""
      for (i = 1; i <= n; i++) {
        s = a[i]; gsub(/^[ \t]+|[ \t]+$/, "", s)
        if (s !~ /"/) continue                     # 따옴표 없는 값은 리터럴이 아니다
        gsub(/"/, "", s); gsub(/^[ \t]+|[ \t]+$/, "", s)
        if (s ~ /^[A-Za-z0-9][A-Za-z0-9.+_ -]*$/) out = (out == "" ? s : out " OR " s)
      }
      if (out != "") { print out; exit }
    }
  ' "$1"
}

# vendored gem 의 `specifications/이름-버전[-플랫폼].gemspec` 을 읽는다.
#   출력: stdout 으로 `gem|이름|버전`, 라이선스를 찾으면 fd 3 으로 `gem|이름|버전|라이선스`
#   (pip·composer 라이선스와 같은 채널·같은 4필드 포맷이다).
#   $1=파일명(basename) · $2=파일 경로(선택 — 없으면 라이선스는 보지 않는다).
#   이름·버전은 여전히 **파일명만** 본다 — 본문은 루비 코드라 제대로 읽으려면 루비가 필요하다(KISS).
#   왼쪽부터 조각을 훑다가 "버전처럼 생긴 첫 조각"(숫자로 시작, 점으로만 이어짐)을 버전으로 보고
#   그 뒤는 플랫폼 접미사로 버린다. 확신이 안 서면 아무것도 내지 않는다 — 틀린 값은 없는 값보다 나쁘다.
#   라이선스만은 본문에 한 줄로 박혀 있어 루비 없이도 읽힌다 → gemspec_license 로 뽑는다.
emit_gemspec_name() {
  local rest="${1%.gemspec}" path="${2:-}" name="" seg ver plat lic
  while [ -n "$rest" ]; do
    case "$rest" in *-*) seg="${rest%%-*}" ;; *) seg="$rest" ;; esac
    if [ -n "$name" ] && [[ "$seg" =~ ^[0-9]+(\.[0-9A-Za-z]+)*$ ]]; then
      ver="$seg"; plat="${rest#"$seg"}"; plat="${plat#-}"
      if [ -z "$plat" ] || [[ "$plat" =~ ^[0-9A-Za-z_.-]+$ ]]; then
        printf 'gem|%s|%s\n' "${name%-}" "$ver"
        if [ -n "$path" ] && [ -r "$path" ]; then
          lic=$(gemspec_license "$path")
          [ -n "$lic" ] && printf 'gem|%s|%s|%s\n' "${name%-}" "$ver" "$lic" >&3
        fi
      fi
      return 0
    fi
    name="$name$seg-"
    case "$rest" in *-*) rest="${rest#*-}" ;; *) rest="" ;; esac
  done
}

# yarn.lock 에서 해결된 버전을 뽑는다. 출력: npm|이름|버전
#   v1(Classic)  : `lodash@^4.17.20:` 헤더 + 들여쓴 `version "4.17.21"`
#   v2+(Berry)   : `"lodash@npm:^4.17.20":` 헤더 + 들여쓴 `version: 4.17.21`
#   두 형식의 차이는 "헤더 따옴표 / 값 따옴표 / npm: 프로토콜 접두" 뿐이라 한 awk 로 처리한다(KISS).
#   · 헤더에 `"@babel/core@^7.0.0, @babel/core@^7.1.0":` 처럼 범위가 여러 개 붙는다 → 첫 조각만 본다
#     (어느 조각이든 이름은 같다).
#   · 스코프 패키지 `@scope/name` 의 선두 `@` 와 범위 구분자 `@` 를 혼동하면 이름이 통째로 깨진다
#     → **마지막 `@`** 기준으로 가른다.
#   · 범위가 workspace:/link:/file:/patch:/git 등이면 레지스트리 패키지가 아니다(자기 자신·로컬 경로).
#     버전이 `0.0.0-use.local` 같은 가짜값이라 인벤토리에 넣으면 오탐만 만든다 → 버린다.
#   · 이름이 npm 명명규칙에서 벗어나면(확신 불가) 아무것도 내지 않는다.
emit_yarn_lock() {
  awk '
    /^[^ \t#].*:[ \t]*$/ {                          # 들여쓴 줄·주석은 헤더가 아니다
      hdr = $0; sub(/:[ \t]*$/, "", hdr)
      gsub(/"/, "", hdr)
      sub(/,.*$/, "", hdr)                          # 첫 범위 조각만
      gsub(/^[ \t]+|[ \t]+$/, "", hdr)
      at = 0
      for (i = length(hdr); i > 1; i--) if (substr(hdr, i, 1) == "@") { at = i; break }
      name = ""; want = 0
      if (at > 1) {
        name = substr(hdr, 1, at - 1)
        spec = substr(hdr, at + 1)
        if (name ~ /^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/ &&
            spec !~ /^(workspace|link|portal|file|patch|exec|git|https?|ssh):/ && spec !~ /git\+/) want = 1
      }
      next
    }
    want && /^[ \t]+version[ \t:]/ {
      v = $0
      sub(/^[ \t]+version[ \t]*:?[ \t]*/, "", v)
      gsub(/"/, "", v); gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (v ~ /^[0-9]/) print "npm|" name "|" v
      want = 0
    }
  ' "$1"
}

# pnpm-lock.yaml 의 `packages:` 블록 키에서 이름·버전을 뽑는다. 출력: npm|이름|버전
#   YAML 파서(yq)를 필수 의존으로 만들지 않는다 — 최소 호스트엔 없다. 키 한 줄만 읽으면 충분하다.
#   lockfileVersion 별 표기: v5 `/lodash/4.17.21:` · v6 `/lodash@4.17.21:` · v9 `lodash@4.17.21:`
#   피어 접미사(`(react@18.0.0)`)와 v5 의 `_peer` 접미사는 잘라낸다.
#   `snapshots:`(v9) 는 packages 와 같은 키를 중복해 갖고 있어 읽지 않는다 — packages 만으로 충분.
#   확신할 수 없는 줄(버전이 숫자로 시작하지 않거나 이름이 규칙 밖)은 버린다.
emit_pnpm_lock() {
  awk '
    /^[^ \t#]/ { inpkgs = ($0 ~ /^packages:[ \t]*$/); next }   # 최상위 키 경계
    !inpkgs { next }
    /^  [^ \t]/ {
      k = $0; sub(/:[ \t]*$/, "", k)
      gsub(/"|'"'"'/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", k)
      sub(/\(.*$/, "", k)                          # 피어 접미사 (react@18.0.0)
      sub(/^\//, "", k)
      if (k ~ /(^|\/)(file|link):/) next
      # ① v6+ 의 `이름@버전` 으로 먼저 가른다(마지막 @ 기준 — 스코프 선두 @ 와 헷갈리면 안 된다).
      at = 0
      for (i = length(k); i > 1; i--) if (substr(k, i, 1) == "@") { at = i; break }
      if (at > 1 && emit(substr(k, 1, at - 1), substr(k, at + 1))) next
      # ② 아니면 v5 의 `/이름/버전` 이다. 이 표기에서만 `_react@17.0.2` 피어 접미사가 붙는데,
      #    버전 쪽에만 잘라낸다 — 이름엔 `_` 가 정상으로 쓰인다(@types/babel__core).
      sl = 0
      for (i = length(k); i > 1; i--) if (substr(k, i, 1) == "/") { sl = i; break }
      if (sl < 2) next
      ver = substr(k, sl + 1); sub(/_.*$/, "", ver)
      emit(substr(k, 1, sl - 1), ver)
    }
    function emit(name, ver) {
      # 스코프는 반드시 `@` 로 시작한다 — 이 조건이 없으면 v5 의 `react-dom/17.0.2_react` 가
      #   이름으로 통과해 `react-dom/17.0.2_react` 라는 없는 패키지가 잡힌다.
      if (name !~ /^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/ || ver !~ /^[0-9]/) return 0
      print "npm|" name "|" ver
      return 1
    }
  ' "$1"
}

# poetry.lock 의 `[[package]]` 블록에서 name/version 을 뽑는다. 출력: pip|이름|버전
#   Cargo.lock 분기와 구조는 같지만 그쪽은 헤더를 안 본다 — poetry 는 `[package.dependencies]`·
#   `[package.extras]` 같은 하위 테이블이 뒤따라서, 헤더를 보지 않으면 거기 값을 패키지로 오인한다.
emit_poetry_lock() {
  awk '
    /^\[/ { inpkg = ($0 ~ /^\[\[package\]\]/); n = ""; next }
    !inpkg { next }
    /^name = / { n = $0; gsub(/^name = "|"$/, "", n); next }
    /^version = / { v = $0; gsub(/^version = "|"$/, "", v); if (n != "" && v ~ /^[0-9]/) print "pip|" n "|" v }
  ' "$1"
}

# pip 메타(dist-info/METADATA·egg-info/PKG-INFO)에서 라이선스 한 줄을 뽑는다. PEP 639 우선순위:
#   1) License-Expression — PEP 639 가 정한 정식 필드. 이미 검증된 SPDX 표현식이라 그대로 쓴다.
#   2) License — 없을 때만. 자유서술이라 값이 지저분하지만 구식 패키지엔 이것뿐이다.
#   3) Classifier: License :: OSI Approved :: X — 앞의 둘이 다 없을 때만. `OSI Approved :: ` 를
#      떼면 "MIT License"·"Apache Software License" 가 되는데, 이건 중앙의 VG_LICENSE_ALIASES
#      (server/src/license_risk.php)가 pip 의 `License:` 자유서술을 받으려고 이미 갖고 있는 표기다
#      → 에이전트에 매핑표를 새로 두지 않는다. 실측 4종(MIT/BSD/Apache/MPL) 전부 별칭에 걸린다.
#      `OSI Approved` 가 안 붙는 trove 값(Public Domain 등)은 안 받는다 — 표본에 없었고(YAGNI),
#      받으면 `Classifier: License :: OSI Approved` 한 줄짜리 무의미한 값까지 같이 들어온다.
#   조건이 셋이라 한 줄에 밀어 넣으면 읽을 수 없어 헬퍼로 뺀다(emit_poetry_lock 등과 같은 패턴).
pip_meta_license() {
  local lic
  lic=$(sed -n 's/^License-Expression: //p' "$1"|head -1)
  # UNKNOWN 은 setuptools 가 값이 없을 때 `License:` 에 채우는 자리표시자다 — 라이선스가 아니므로
  #   "없음"으로 보고 다음 후보로 내려간다. 여기서 안 걸러내면 그 한 줄이 Classifier 폴백을 막는다.
  [ -n "$lic" ] || lic=$(sed -n 's/^License: //p' "$1"|grep -vx UNKNOWN|head -1)
  [ -n "$lic" ] || lic=$(sed -n 's/^Classifier: License :: OSI Approved :: //p' "$1"|head -1)
  printf '%s\n' "$lic"
}

# 배포판이 깐 파이썬 패키지의 메타(`*.dist-info/METADATA` · `*.egg-info/PKG-INFO`)만 골라 읽는 좁은 패스.
#   출력 계약은 collect_project_deps_installed 의 METADATA 분기와 **동일**하다
#   (stdout `pip|name|version`, fd 3 `pip|name|version|라이선스`).
#
# 왜 필요한가 — `pip3 list`(cap langpkg pip)는 이 패키지들의 **이름·버전만** 낸다. 라이선스를 읽는
#   쪽은 collect_project_deps_installed 인데 그건 PROJECT_SCAN_ROOTS(/opt /srv /app /usr/local …)
#   안만 훑고, 데비안·우분투의 배포판 파이썬은 `/usr/lib/python3/dist-packages` 라 범위 밖이었다.
#   운영 실측: `ubuntu` 호스트의 pip 패키지 130개 전부가 라이선스 0건이었다.
#
# 왜 PROJECT_SCAN_ROOTS 에 경로만 더하지 않았나 — 세 가지다.
#   (a) 그 변수는 운영자가 환경변수로 덮어쓸 수 있다. 좁히는 순간 배포판 라이선스가 함께 사라진다.
#   (b) SCAN_MAX_FILES(3000)는 **한 패스에 누적**되고 상한에 닿으면 `break 2` 로 패스가 통째로 끊긴다
#       → 앱 의존성(/opt 등)의 예산을 나눠 쓰게 된다. 여기서 자체 상한(PY_SYS_META_MAX)을 따로 든다.
#   (c) 애초에 기존 find 패턴은 `*/site-packages/*.dist-info/METADATA` 라 `dist-packages` 를 못 잡는다
#       — 경로만 더해도 데비안 계열에선 한 건도 안 늘었다.
#
# 왜 글롭인가(`python3 -c 'import site'` 가 아니라) — 인터프리터 실행은 `have python3` 가드가
#   필요하고, 성공해도 **그 인터프리터 하나**의 경로만 알려준다(호스트에 python 이 여럿이면 반쪽).
#   반면 배포판별 관례는 고정돼 있어 글롭 셋으로 덮인다: 데비안·우분투 `dist-packages`,
#   RHEL·Alpine·SUSE `site-packages`, 64비트 RPM 계열은 `/usr/lib64`. 실패 경로도 없다.
#
# 비용 — `-maxdepth 1 -type d` 라 루트 디렉터리 목록만 읽고 패키지 안으로는 안 들어간다.
#   ubuntu:24.04 실측: 전체 재귀는 파일 1,741개, 이 방식은 항목 9개.
collect_python_system_meta() {
  local root d m name ver lic count=0
  for root in $PY_SYS_META_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r d; do
      count=$((count+1)); [ "$count" -le "$PY_SYS_META_MAX" ] || break 2
      # dist-info 는 METADATA, egg-info 는 PKG-INFO — 필드 구조가 같아 먼저 있는 쪽 하나만 읽는다.
      for m in "$d/METADATA" "$d/PKG-INFO"; do
        [ -f "$m" ] || continue
        name=$(sed -n 's/^Name: //p' "$m"|head -1);ver=$(sed -n 's/^Version: //p' "$m"|head -1);lic=$(pip_meta_license "$m")
        [ -n "$name" ]&&[ -n "$ver" ]&&{ printf 'pip|%s|%s\n' "$name" "$ver"; [ -n "$lic" ]&&printf 'pip|%s|%s|%s\n' "$name" "$ver" "$lic" >&3; }
        break
      done
    done < <(find "$root" -xdev -maxdepth 1 -type d \( -name '*.dist-info' -o -name '*.egg-info' \) 2>/dev/null|head -"$PY_SYS_META_MAX")
  done
}

# 설치본에서 직접 읽는 고신뢰 소스 — METADATA/lock/jar. 출력: manager|name|version
# 파일 수·깊이는 SCAN_MAX_FILES/SCAN_MAX_DEPTH 로 제한한다. sort 로 출력 순서를 고정해
# 파일시스템 탐색 순서가 달라져도 같은 결과가 나오게 한다(content_hash 처닝 방지).
collect_project_deps_installed() {
  local root f name ver lic count=0
  # 배포판 파이썬 패스는 예산(count)을 공유하지 않으려고 함수를 나눠 뒀지만, 출력은 여기서 합쳐
  #   fd 3(라이선스)·`sort -u`(순서 고정) 계약을 그대로 태운다 — 호출부를 늘리지 않는다(DRY).
  #   `break 2` 는 위쪽 for/while 만 끊으므로 프로젝트 패스가 상한에 걸려도 이 패스는 그대로 돈다.
  { for root in $PROJECT_SCAN_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r f; do
      count=$((count+1)); [ "$count" -le "$SCAN_MAX_FILES" ] || break 2
      case "$f" in
        # egg-info/PKG-INFO 는 구식(setuptools) 파이썬 패키지가 남기는 메타로, dist-info/METADATA 와
        #   `Name:`/`Version:`/라이선스 필드 구조가 같다 → 같은 분기에 태운다(DRY). 라이선스 fd 3
        #   경로도 그대로 탄다 — 여기만 빼면 같은 파이썬 패키지인데 소스에 따라 라이선스가 비게 된다.
        */METADATA|*.egg-info/PKG-INFO) name=$(sed -n 's/^Name: //p' "$f"|head -1);ver=$(sed -n 's/^Version: //p' "$f"|head -1);lic=$(pip_meta_license "$f");[ -n "$name" ]&&[ -n "$ver" ]&&{ printf 'pip|%s|%s\n' "$name" "$ver"; [ -n "$lic" ]&&printf 'pip|%s|%s|%s\n' "$name" "$ver" "$lic" >&3; };;
        */Cargo.lock) awk 'BEGIN{n=""}/^name = /{gsub(/^name = "|"$/,"",$0);n=$0}/^version = /{gsub(/^version = "|"$/,"",$0);if(n!="")print "cargo|"n"|"$0}' "$f";;
        */Gemfile.lock) emit_gemfile_lock "$f";;
        # 이름·버전은 파일명에서, 라이선스는 본문에서 읽는다 → 파일 경로도 함께 넘긴다.
        */specifications/*.gemspec) emit_gemspec_name "$(basename "$f")" "$f";;
        */package-lock.json) have jq&&jq -r '.packages//{}|to_entries[]|select(.value.name and .value.version)|"npm|\(.value.name)|\(.value.version)"' "$f" 2>/dev/null;;
        # yarn/pnpm 을 쓰는 프로젝트엔 package-lock.json 이 아예 없다 — 이 둘이 없으면 앱 의존성이
        #   통째로 0건이 된다(npm ls -g 는 전역 설치만 보므로 대신하지 못한다).
        */yarn.lock) emit_yarn_lock "$f";;
        */pnpm-lock.yaml) emit_pnpm_lock "$f";;
        */poetry.lock) emit_poetry_lock "$f";;
        # Pipfile.lock 은 JSON 이라 jq 가 가장 단순하다(기존 package-lock.json 과 같은 have jq 가드).
        #   `develop`(개발 의존성)은 담지 않는다 — 운영 자산에 실제로 깔려 도는 건 `default` 쪽이고,
        #   develop 까지 넣으면 배포본에 없는 패키지의 취약점이 그 호스트 몫으로 잡힌다(오탐).
        #   version 값은 `"==1.2.3"` 형태라 `==` 를 뗀다.
        */Pipfile.lock) have jq&&jq -r '.default//{}|to_entries[]|select(.value.version)|"pip|\(.key)|\(.value.version|sub("^==";""))"' "$f" 2>/dev/null;;
        # composer 는 설치본 메타(installed.json)에 license 필드를 그대로 담고 있다 — 배열이면
        #   "OR" 로 이어붙인다(SPDX 복수라이선스 표기 관례). 라이선스 없는 패키지는 조용히 건너뛴다.
        */composer/installed.json) have jq&&{ jq -r '(.packages//.)[]?|select(.name and .version)|"composer|\(.name)|\(.version|sub("^v";""))"' "$f" 2>/dev/null; jq -r '(.packages//.)[]?|select(.name and .version and .license)|"composer|\(.name)|\(.version|sub("^v";""))|\(if (.license|type)=="array" then (.license|join(" OR ")) else .license end)"' "$f" 2>/dev/null >&3; };;
        *.deps.json) have jq&&jq -r '.targets[]?|keys[]|select(test("/"))|split("/")|"nuget|\(.[0])|\(.[1])"' "$f" 2>/dev/null;;
        *.jar) emit_jar_meta "$f" "$(basename "$f")"; emit_nested_jars "$f";;
        *.war|*.ear) emit_nested_jars "$f";;
      esac
    done < <(find "$root" -xdev -maxdepth "$SCAN_MAX_DEPTH" -type f \( -path '*/site-packages/*.dist-info/METADATA' -o -path '*.egg-info/PKG-INFO' -o -name Cargo.lock -o -name Gemfile.lock -o -path '*/specifications/*.gemspec' -o -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name poetry.lock -o -name Pipfile.lock -o -path '*/composer/installed.json' -o -name '*.deps.json' -o -name '*.jar' -o -name '*.war' -o -name '*.ear' \) 2>/dev/null|head -"$SCAN_MAX_FILES")
  done
  collect_python_system_meta
  } | sort -u
}

# 선언 파일에서 읽는 보충 소스 — go.mod/requirements.txt/pom.xml.
# 출력: manager|name|version|weak. 실제 설치본이 아니라 "선언"이라 중앙(vg_ingest_parse_langpkgs)이
# 이 표식을 보고 다른 소스가 이미 잡은 값을 덮어쓰지 않게 한다.
# 파일 예산은 위 패스와 별도로 센다 — jar 많은 호스트에서 이 패스가 통째로 굶지 않도록.
collect_project_deps_declared() {
  local root f count=0
  for root in $PROJECT_SCAN_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r f; do
      count=$((count+1)); [ "$count" -le "$SCAN_MAX_FILES" ] || break 2
      case "$f" in
        */go.mod) awk '
          /^(replace|exclude)[[:space:]]*\(/{skipblock=1;next}
          skipblock&&/^\)/{skipblock=0;next}
          skipblock{next}
          /^require[[:space:]]*\(/{inblock=1;next}
          inblock&&/^\)/{inblock=0;next}
          inblock{
            if($0 ~ /\/\/[ \t]*indirect/) next
            line=$0; sub(/\/\/.*/,"",line); gsub(/^[ \t]+|[ \t]+$/,"",line)
            if(line!=""){n=split(line,a,/[ \t]+/); if(n>=2&&a[1]!=""&&a[2]!="") print "go|"a[1]"|"a[2]"|weak"}
            next
          }
          /^require[[:space:]]+[^(]/{
            if($0 ~ /\/\/[ \t]*indirect/) next
            line=$0; sub(/^require[ \t]+/,"",line); sub(/\/\/.*/,"",line); gsub(/^[ \t]+|[ \t]+$/,"",line)
            n=split(line,a,/[ \t]+/); if(n>=2&&a[1]!=""&&a[2]!="") print "go|"a[1]"|"a[2]"|weak"
          }
        ' "$f";;
        */requirements.txt) awk '
          {
            line=$0
            sub(/#.*/,"",line)                 # 주석
            sub(/;.*/,"",line)                 # 환경 마커
            sub(/[ \t]*\\[ \t]*$/,"",line)     # 줄이음 백슬래시
            sub(/[ \t]--.*$/,"",line)          # --hash=sha256:... 등 옵션
            gsub(/^[ \t]+|[ \t]+$/,"",line)
            if(line=="") next
            if(line ~ /^-/) next               # -e / -r / 옵션만 있는 줄
            if(line ~ /git\+/) next
            if(line !~ /==/) next
            if(line ~ /[<>~!]/) next
            n=split(line,parts,"==")
            if(n!=2) next
            name=parts[1]; ver=parts[2]
            sub(/^=+/,"",ver)                  # === (arbitrary equality)
            sub(/[ \t].*$/,"",ver)             # 첫 공백 뒤는 버림
            sub(/\[.*\]/,"",name); gsub(/^[ \t]+|[ \t]+$/,"",name)
            if(name!=""&&ver!="") print "pip|"name"|"ver"|weak"
          }
        ' "$f";;
        */pom.xml) awk '
          # <exclusions>(제외 목록)·<dependencyManagement>(버전만 선언, 실제 의존 아님) 안의
          # 좌표가 부모 <dependency> 의 g/a/v 를 덮어쓰면 엉뚱한 패키지가 잡힌다 → 그 구간은 건너뛴다.
          {
            line=$0
            if(line ~ /<dependencyManagement>/) indm=1
            if(line ~ /<exclusions>/) inex=1
            if(line ~ /<dependency>/ && !indm && !inex){ inb=1; g="";a="";v="";sc="" }
            if(inb && !inex && !indm){
              if(match(line,/<groupId>[^<]*<\/groupId>/)){t=substr(line,RSTART,RLENGTH);gsub(/<\/?groupId>/,"",t);gsub(/^[ \t]+|[ \t]+$/,"",t);g=t}
              if(match(line,/<artifactId>[^<]*<\/artifactId>/)){t=substr(line,RSTART,RLENGTH);gsub(/<\/?artifactId>/,"",t);gsub(/^[ \t]+|[ \t]+$/,"",t);a=t}
              if(match(line,/<version>[^<]*<\/version>/)){t=substr(line,RSTART,RLENGTH);gsub(/<\/?version>/,"",t);gsub(/^[ \t]+|[ \t]+$/,"",t);v=t}
              if(match(line,/<scope>[^<]*<\/scope>/)){t=substr(line,RSTART,RLENGTH);gsub(/<\/?scope>/,"",t);gsub(/^[ \t]+|[ \t]+$/,"",t);sc=t}
            }
            if(line ~ /<\/dependency>/){
              if(inb&&g!=""&&a!=""&&v!=""&&g!~/\$\{/&&a!~/\$\{/&&v!~/\$\{/&&g!~/\|/&&a!~/\|/&&v!~/\|/&&sc!="test"&&sc!="provided") print "maven|"g":"a"|"v"|weak"
              inb=0
            }
            if(line ~ /<\/exclusions>/) inex=0
            if(line ~ /<\/dependencyManagement>/) indm=0
          }
        ' "$f";;
      esac
    done < <(find "$root" -xdev -maxdepth "$SCAN_MAX_DEPTH" -type f \( -name 'go.mod' -o -name 'requirements.txt' -o -name 'pom.xml' \) 2>/dev/null|head -"$SCAN_MAX_FILES")
  done | sort -u
}

# 호스트 파일시스템의 Go 바이너리에서 buildinfo 의존성을 뽑는다. 출력: go|모듈|버전 (3필드)
# go.mod 는 "선언"이라 weak 지만 바이너리 buildinfo 는 실제로 빌드에 들어간 결과물이라 weak 이 아니다
# — collect_project_deps_installed 와 같은 급의 고신뢰 소스로 취급한다.
# 추출 자체는 컨테이너 경로와 같은 헬퍼(go_deps_from_binary)를 쓴다. 그 헬퍼는 "cid|go|모듈|버전|"
#   5필드로 내므로 cid 를 빈 값으로 주고 앞뒤 구분자만 벗겨 3필드로 맞춘다 — 헬퍼를 고치면
#   컨테이너 경로(ctr_go_deps)의 출력이 바뀔 위험이 있어 손대지 않는다.
# 비용이 이 패스의 전부다. `-type f -perm -u+x` 를 전부 strings 로 훑으면 터지므로 3단 선별을 건다:
#   ① 크기(GO_BIN_MIN_SIZE) → ② ELF 매직 4바이트 → ③ 앞부분에 Go 표식이 있는지.
#   ①②는 프로세스를 하나도 안 띄운다(bash 내장 read). ③만 head+grep 한 번이다.
#   그러고도 실제 strings 대상은 GO_BIN_SCAN_MAX 개로 끊는다.
collect_go_binary_deps() {
  local root f magic probe count=0 scanned=0
  for root in $PROJECT_SCAN_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r f; do
      count=$((count+1)); [ "$count" -le "$SCAN_MAX_FILES" ] || break 2
      [ -r "$f" ] || continue
      # ELF 매직. `file` 에 의존하지 않는다 — 최소 호스트엔 없다. 내장 read 라 fork 가 없다.
      magic=''; LC_ALL=C IFS= read -r -n 4 magic < "$f" 2>/dev/null
      [ "$magic" = $'\177ELF' ] || continue
      # Go 표식: `.note.go.buildid` 노트는 ELF 헤더 바로 뒤(실측 오프셋 0xf80)에 있고, 노트 이름
      #   "Go" 뒤에 긴 빌드 ID 문자열이 곧바로 붙는다 → 앞 64KB 만 봐도 걸린다. NUL 을 지우고 봐야
      #   이름과 ID 가 이어진다. 정본 표식인 `Go buildinf:` 는 파일 중간(2MB 바이너리에서 1.38MB,
      #   13MB 에서 11.4MB)이라 앞부분 탐침으로 못 쓴다.
      #   실측(golang:1.22 이미지의 1MB 초과 ELF 51개): Go 19개 전부 적중, 비Go 오탐 0, 탐침 2ms.
      #   `grep -q ... || continue` 로 쓰면 안 된다 — 이 스크립트는 `set -o pipefail` 이라
      #   grep 이 첫 매칭에서 먼저 끝나며 앞단(head/tr)이 SIGPIPE(141)로 죽고, 그 상태가
      #   파이프라인 결과가 되어 **Go 바이너리를 전부 건너뛴다.** 결과 문자열로 판정한다.
      probe=$(head -c "$GO_BIN_PROBE_BYTES" "$f" 2>/dev/null | LC_ALL=C tr -d '\000' \
        | LC_ALL=C grep -aoEm1 'Go[A-Za-z0-9_/+=.-]{20,}')
      [ -n "$probe" ] || continue
      scanned=$((scanned+1)); [ "$scanned" -le "$GO_BIN_SCAN_MAX" ] || break 2
      go_deps_from_binary "$f" '' | sed -e 's/^|//' -e 's/|$//'
    done < <(find "$root" -xdev -maxdepth "$SCAN_MAX_DEPTH" -type f -perm -u+x -size +"$GO_BIN_MIN_SIZE" 2>/dev/null|head -"$SCAN_MAX_FILES")
  done | sort -u
}

# 패키지 의존성 그래프용 — pom.xml 원문을 그대로(경로|base64) 올린다. 옛 awk 한 줄 파싱은
# <exclusions>/<parent> 를 구조적으로 구분 못 해 오탐/0건이 났다(PR#399 리뷰) — 중앙이
# DOMDocument 로 실제 XML 트리를 따라가 최상위 <dependencies> 만 정확히 골라낸다
# (server/src/ingest_parse.php:vg_ingest_parse_pom_deps). 파일당 크기를 캡핑해 한 개의
# 거대한 pom.xml 이 예산을 통째로 먹지 못하게 한다.
POM_DEP_FILE_MAX_BYTES="${POM_DEP_FILE_MAX_BYTES:-131072}"   # 파일당 128KB
collect_pom_direct_deps() {
  local root f count=0 sz
  for root in $PROJECT_SCAN_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r f; do
      count=$((count+1)); [ "$count" -le "$SCAN_MAX_FILES" ] || break 2
      sz=$(wc -c < "$f" 2>/dev/null || echo 0)
      [ "$sz" -gt 0 ] && [ "$sz" -le "$POM_DEP_FILE_MAX_BYTES" ] || continue
      printf '%s|%s\n' "$f" "$(base64 -w0 "$f" 2>/dev/null || base64 "$f" 2>/dev/null | tr -d '\n')"
    done < <(find "$root" -xdev -maxdepth "$SCAN_MAX_DEPTH" -type f -name 'pom.xml' 2>/dev/null|head -"$SCAN_MAX_FILES")
  done
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
# 3-b) 패키지 무결성 검증 (기본 꺼짐 — `--verify-files` 일 때만)
#   패키지 관리자는 설치 시 파일마다 digest·권한·소유자를 기록해 둔다. 그걸 현재 디스크와
#   대조하면 "설치 이후 파일이 바뀌었다"를 잡는다(N2SF IN 구성요소 무결성).
#     rpm  : rpm -Va --nomtime --nouser --nogroup  → "SM5....T c /etc/…"
#     dpkg : dpkg --verify                         → "??5?????? /usr/…"(md5sums 기반)
#   ★ 비용: 설치된 **모든 패키지의 모든 파일**을 해시한다 → 수 분 + 무거운 디스크 IO.
#     그래서 기본 꺼짐 + 전용 상한(VERIFY_TIMEOUT). nice 19/ionice idle 은 위에서 이 프로세스에
#     이미 걸려 있어 자식인 rpm/dpkg 도 그대로 상속한다.
#   ★ 잘렸으면 반드시 partial 로 알린다 — 중앙이 "위반 0건 = 깨끗함"으로 오독하면 안 된다.
#   ★ `c`(설정파일) 줄은 버린다 — 관리자가 고치는 게 정상이라 전부 노이즈다.
#   ★ 같은 이유로 `VERIFY_EXCLUDE_PREFIXES`(문서·man·번역·info) 경로도 버린다 — 설치 시
#     문서를 안 깐 이미지(`dpkg --path-exclude`)가 흔해 전부 오탐이다.
#   ※ GPG 서명 검증은 여기 범위가 아니다(파일 무결성만).
collect_integrity() {
  local raw="$TMP/.integrity-raw" parsed="$TMP/.integrity-parsed" totf="$TMP/.integrity-total"
  local cmd="" rc=0 total=0 fl pa pkg
  if have rpm; then
    cmd='rpm -Va --nomtime --nouser --nogroup'
  elif have dpkg; then
    cmd='dpkg --verify'
  else
    return 0            # 지원하는 패키지 관리자가 없으면 "검사함"조차 기록하지 않는다
  fi
  timeout -k 5 "$VERIFY_TIMEOUT" bash -c "$cmd" > "$raw" 2>/dev/null || rc=$?
  put integrity checked "1"
  # rpm -Va·dpkg --verify 는 **위반이 있으면 정상 동작이어도 종료코드가 0 이 아니다.**
  #   그래서 실패로 볼 수 있는 건 timeout 이 끊은 경우(124, KILL 은 137)뿐이다.
  case "$rc" in 124|137) put integrity partial "1" ;; esac

  # 플래그/파일종류/경로 분해. 경로에 공백이 있을 수 있어 필드 분할 대신 앞에서부터 깎는다.
  awk -v max="$VERIFY_MAX_LINES" -v totf="$totf" -v excl="$VERIFY_EXCLUDE_PREFIXES" '
    BEGIN { nexcl = split(excl, exps) }   # 공백 구분 문자열 → 배열(정규식 이스케이프 문제를 피한다)
    {
      line = $0
      n = index(line, " ")
      if (n == 0) next
      flags = substr(line, 1, n - 1)
      rest  = substr(line, n + 1)
      sub(/^[ \t]+/, "", rest)
      # 파일종류 한 글자(c/d/g/l/r) 필드는 있을 수도 없을 수도 있다. 경로는 항상 "/" 로
      #   시작하므로 "한 글자 + 공백" 이면 종류 필드로 본다(오인 위험 없음).
      if (rest ~ /^[a-zA-Z][ \t]/) { ftype = substr(rest, 1, 1); rest = substr(rest, 2); sub(/^[ \t]+/, "", rest) }
      else                         { ftype = "" }
      if (ftype == "c") next                      # 설정파일 = 정상적인 변경, 버린다
      # 문서·man·번역·info = 설치 시 안 깐 이미지가 흔해 전부 오탐. total 에도 남기지 않는다
      #   (남기면 truncated 판정이 계속 틀린다).
      for (i = 1; i <= nexcl; i++) if (index(rest, exps[i]) == 1) next
      if (substr(rest, 1, 1) != "/") next         # 경로가 아닌 잡음 줄
      gsub(/\|/, "_", flags); gsub(/\|/, "_", rest)   # 구분자 오염 방지
      total++
      if (total <= max) { printf "%s|%s\n", flags, rest }
    }
    END { printf "%d", total + 0 > totf }
  ' "$raw" > "$parsed"

  total="$(cat "$totf" 2>/dev/null || echo 0)"
  put integrity total "$total"
  # 상한을 넘겼으면 "잘렸다"는 사실을 total 과 함께 보낸다(목록만 보고 전수로 읽지 않게).
  [ "$total" -gt "$VERIFY_MAX_LINES" ] && put integrity truncated "1"

  # 위반 파일이 속한 패키지는 rpm -Va/dpkg --verify 가 알려주지 않는다 → 조회한다.
  #   상한(VERIFY_MAX_LINES)만큼만 도므로 조회 비용도 그 상한에 묶인다.
  {
    echo "package|flags|path"
    while IFS='|' read -r fl pa; do
      [ -n "$pa" ] || continue
      pkg="$(file_to_pkg "$pa")"
      printf '%s|%s|%s\n' "${pkg:-미상}" "$fl" "$pa"
    done < "$parsed"
  } > "$TMP/integrity__files.txt"
  # 헤더만 남아도 지우지 않는다 — 섹션 존재 자체가 "검사했고 0건"의 증거다(노출 섹션과 같은 규약).
  rm -f "$raw" "$parsed" "$totf"
}
if [ "$DO_VERIFY" = 1 ]; then
  progress_report integrity 33 '패키지 무결성을 검증하고 있습니다.'
  collect_integrity
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
# 두 패스를 각각 자기 예산 안에서 자른다 — 한 스트림으로 이어 붙여 통째로 head -c 하면
# jar 가 많은 호스트에서 고신뢰(설치본) 데이터가 뒤로 밀려 함께 잘린다.
VG_INV="$TMP/langpkg__inventory.txt"
VG_LIC="$TMP/langpkg__pkg_license.txt"
export PROJECT_SCAN_ROOTS SCAN_MAX_FILES SCAN_MAX_DEPTH
export PY_SYS_META_ROOTS PY_SYS_META_MAX
export CMD_TIMEOUT GO_BIN_SCAN_MAX GO_BIN_MIN_SIZE GO_BIN_PROBE_BYTES
export -f have emit_jar_meta emit_nested_jars collect_project_deps_installed collect_project_deps_declared
export -f go_deps_from_binary collect_go_binary_deps
# 아래 수집 함수들은 전부 `timeout ... bash -c` 서브셸에서 돈다(바로 아래 2곳 + vg_inv_append_pass).
#   서브셸이 볼 수 있는 함수는 `export -f` 로 내보낸 것뿐이라, 수집 함수 본문에서 부르는 헬퍼는
#   **하나도 빠짐없이** 여기 있어야 한다. 빠지면 서브셸에서 `command not found` 가 되는데
#   stderr 를 2>/dev/null 로 버리는 호출부라 조용히 "그 소스만 0건"이 된다 — 테스트는
#   같은 셸에서 함수를 부르므로 못 잡는다(#735 가 그렇게 통과하고 운영에서 pip 라이선스가 비었다).
#   collect_project_deps_installed 가 부르는 헬퍼: pip_meta_license(라이선스) ·
#   emit_gemfile_lock/emit_gemspec_name/gemspec_license(gem) · emit_yarn_lock/emit_pnpm_lock(node) ·
#   emit_poetry_lock(pip). emit_gemspec_name 이 다시 gemspec_license 를 부르므로 그것도 함께 내보낸다.
#   collect_python_system_meta(배포판 파이썬 라이선스)도 같은 서브셸에서 불린다 — 빠지면
#   dist-packages 라이선스만 조용히 0건이 된다(#735 와 같은 클래스).
export -f pip_meta_license collect_python_system_meta emit_gemfile_lock emit_gemspec_name gemspec_license emit_yarn_lock emit_pnpm_lock emit_poetry_lock
# 패스 하나를 "남은 예산 안에서만" VG_INV 에 덧붙인다. 한 스트림으로 이어 붙여 통째로 head -c 하면
#   앞 패스가 큰 호스트에서 뒤 패스가 통째로 잘리므로 패스별로 자른다. head -c 가 줄 가운데를
#   자를 수 있어(다음 패스 첫 줄과 붙어 엉뚱한 좌표가 된다) 개행도 채운다.
vg_inv_append_pass() {   # $1=수집 함수 이름
  local rest
  rest=$(( MAX_BYTES - $(wc -c < "$VG_INV" 2>/dev/null || echo 0) ))
  [ "$rest" -gt 0 ] || return 0
  timeout -k 2 "$PROJECT_SCAN_TIMEOUT" bash -c "$1" 2>/dev/null | head -c "$rest" >> "$VG_INV" || true
  if [ -s "$VG_INV" ] && [ -n "$(tail -c 1 "$VG_INV")" ]; then printf '\n' >> "$VG_INV"; fi
}
# METADATA/composer installed.json 안의 license 필드는 collect_project_deps_installed 가 같은
#   find 패스 안에서 fd 3(=VG_LIC) 로 함께 뽑는다 — 파일 예산을 두 번 쓰지 않기 위함.
#   "mgr|name|version|spdx" 4필드라 기존 3필드 inventory 스트림과 겹치지 않는다.
timeout -k 2 "$PROJECT_SCAN_TIMEOUT" bash -c 'exec 3>>"$1"; collect_project_deps_installed' _ "$VG_LIC" 2>/dev/null \
  | head -c "$MAX_BYTES" > "$VG_INV" || true
# head -c 가 줄 가운데를 자를 수 있다 → 다음 패스 첫 줄과 붙어 엉뚱한 좌표가 되지 않게 개행을 채운다.
if [ -s "$VG_INV" ] && [ -n "$(tail -c 1 "$VG_INV")" ]; then printf '\n' >> "$VG_INV"; fi
# Go 바이너리 buildinfo 는 실제 빌드 결과물이라 설치본과 같은 급이다 → 선언 파일(weak)보다 먼저 넣어
#   예산이 모자랄 때 고신뢰 쪽이 남게 한다.
vg_inv_append_pass collect_go_binary_deps
vg_inv_append_pass collect_project_deps_declared
[ -s "$VG_INV" ] || rm -f "$VG_INV"
if [ -s "$VG_LIC" ]; then
  # fd3(VG_LIC) 는 collect_project_deps_installed 함수 마지막의 `| sort -u`(stdout 전용)를
  #   우회해 나가므로 여기서 별도로 정렬·중복제거해야 한다 — 안 하면 content_hash 가 라이선스
  #   반영은 맞는데(설계대로) 순서·중복이 스캔마다 흔들려 "변경 없음" 최적화가 무력화되고
  #   매 스캔 전량 재저장+재매칭이 발생한다.
  vg_lic_sorted=$(mktemp 2>/dev/null) && sort -u "$VG_LIC" > "$vg_lic_sorted" && mv "$vg_lic_sorted" "$VG_LIC"
  vg_lic_cut=$(mktemp 2>/dev/null) && head -c "$MAX_BYTES" "$VG_LIC" > "$vg_lic_cut" && mv "$vg_lic_cut" "$VG_LIC"
  # head -c 가 줄 가운데를 자를 수 있다(VG_INV 와 동일 이유) → 다음 파서가 잘린 마지막 줄을
  #   그대로 저장하지 않도록 개행을 채운다.
  if [ -s "$VG_LIC" ] && [ -n "$(tail -c 1 "$VG_LIC")" ]; then printf '\n' >> "$VG_LIC"; fi
fi
[ -s "$VG_LIC" ] || rm -f "$VG_LIC"

# 패키지 의존성 그래프(직접 선언) — pom.xml 원문(경로|base64). 언어패키지 인벤토리와 별도
# 예산으로 캡핑한다(원문 전송이라 요약 스트림보다 무겁다 — 서로의 예산을 갉아먹지 않게).
export -f collect_pom_direct_deps
timeout -k 2 "$PROJECT_SCAN_TIMEOUT" bash -c collect_pom_direct_deps 2>/dev/null \
  | head -c "$MAX_BYTES" > "$TMP/langpkg__pom_deps.txt" || true
[ -s "$TMP/langpkg__pom_deps.txt" ] || rm -f "$TMP/langpkg__pom_deps.txt"

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
# 헤더만인 파일도 보낸다. 중앙은 섹션 존재를 "수집 완료·0건(EMPTY)" 증거로 쓰며,
# 파일 자체가 없는 구버전/누락 payload만 MISSING으로 구분한다.

# 10-c) 실행 프로세스 인벤토리 (실행중/사용중 구분용) — 포트 없어도 잡음
{
  echo "pid|comm|user|exe_pkg|loaded_pkgs"
  collect_processes
} > "$TMP/runtime__processes.txt" 2>/dev/null || true
[ "$(wc -l < "$TMP/runtime__processes.txt" 2>/dev/null || echo 0)" -ge 2 ] \
  || rm -f "$TMP/runtime__processes.txt"
# PROC_SCAN_TIMEOUT 컷오프(기본 180초)로 순회가 중간에 끊겼으면 중앙이 이 스캔의 프로세스/재시작필요 판정이
#   불완전할 수 있음을 알 수 있게 meta 로 남긴다(조용한 커버리지 축소 금지).
[ "$PROC_SCAN_TRUNCATED" = "1" ] && put meta processes_truncated "1"

# 재시작 필요 — 업데이트로 교체된 옛 라이브러리를 아직 물고 있는 프로세스
{
  echo "pid|comm|pkg|lib"
  collect_stale
} > "$TMP/runtime__stale.txt" 2>/dev/null || true
[ "$(wc -l < "$TMP/runtime__stale.txt" 2>/dev/null || echo 0)" -ge 2 ] \
  || rm -f "$TMP/runtime__stale.txt"

# 패키지 출처(Origin 라벨) — 서드파티 저장소 패키지 식별(cap 은 서브셸이라 함수를 못 본다)
progress_report pkg_origins 80 '패키지 출처(서드파티 저장소)를 확인하고 있습니다.'
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

# ── 시간 동기화 (ISMS-P 2.9.6) ──
#   "모든 로그 증적의 전제". 타임스탬프가 틀어지면 감사로그 전체의 증거력이 무너진다.
#   system.timezone 이 이미 `timedatectl`(사람용 status)을 담지만, 판정은 키=값이 필요해
#   `timedatectl show`(기계용)를 따로 모은다 — 파싱을 화면용 출력에 의존하지 않는다.
cap security time_sync     'timedatectl show 2>/dev/null || timedatectl status 2>/dev/null'
cap security time_tracking 'chronyc tracking 2>/dev/null || ntpq -pn 2>/dev/null'
# is-active 는 유닛마다 한 줄이라 어느 유닛이 떴는지 알 수 없다 → "유닛=상태" 로 찍는다.
#   systemctl 이 없으면 아무것도 안 나오고, 그러면 서버는 이 항목을 NA 로 남긴다.
cap security time_services '
  for u in chrony chronyd systemd-timesyncd ntp ntpd ntpsec; do
    s="$(systemctl is-active "$u" 2>/dev/null)"
    [ -n "$s" ] && printf "%s=%s\n" "$u" "$s"
  done'

# ── 로그 설정 (ISMS-P 2.9.4) ──
#   기존 CCE-FILE-SYSLOG 는 파일 "권한"만 본다. 보존기간·원격전송 "설정"은 여기서 모은다.
cap security journald_conf '
  grep -hE "^[[:space:]]*(Storage|SystemMaxUse|MaxRetentionSec|MaxFileSec)=" \
    /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null'
# logrotate 는 전역 지시자만 본다. /etc/logrotate.d/* 의 지시자는 파일마다 블록 안에 있어
#   grep 으로 합치면 어느 rotate 가 어느 주기와 짝인지 알 수 없다(잘못 곱하면 보존기간 오판).
#   전역 지시자는 /etc/logrotate.conf 에서 들여쓰기 없이 나오므로 행머리로 구분한다.
cap security logrotate_conf '
  [ -r /etc/logrotate.conf ] && {
    grep -hE "^(daily|weekly|monthly|yearly|rotate|maxage)([[:space:]]|$)" \
      /etc/logrotate.conf 2>/dev/null | grep . || echo NONE; }'
# 원격 전송(@=UDP, @@=TCP, omfwd) — 위·변조 방지의 실질 수단. "미설정"과 "못 읽음"을 구분한다.
cap security rsyslog_remote '
  [ -r /etc/rsyslog.conf ] && {
    grep -hE "^[^#]*(@@?[A-Za-z0-9\[]|omfwd)" \
      /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep . || echo NONE; }'

# ── 암호화 (ISMS-P 2.7.1 / N2SF 제5장 DT) ──
#   디스크 암호화(LUKS) 존재 여부. lsblk 는 비-root 로도 돌고, 없으면 blkid 로 폴백한다.
#   둘 다 못 쓰면 아무것도 안 남겨 서버가 NA 로 판정한다(없음을 "정상"으로 위장하지 않는다).
cap security disk_encryption '
  out="$(lsblk -o NAME,FSTYPE 2>/dev/null || blkid 2>/dev/null)"
  [ -n "$out" ] && { printf "%s\n" "$out" | grep -i "crypto_LUKS" || echo NONE; }'

# ==================================================================
# 13) 사용자 / 인증 / 예약작업 / 파일시스템
# ==================================================================
cap users accounts     'getent passwd | awk -F: "{print \$1\"\t\"\$3\"\t\"\$7}"'
cap users interactive  'getent passwd | awk -F: "\$3>=1000 && \$7!~/nologin|false/ {print \$1}"'
#   admin 은 옛 우분투의 sudo 그룹이다 — 아직 남아 있는 서버가 있어 함께 본다(없으면 안 나온다).
cap users sudo_group   'getent group sudo wheel admin 2>/dev/null'
cap users logged_in    'who'
cap users last_logins  'last -n 20 2>/dev/null'

# ── 계정 인벤토리 (ISMS-P 2.5.1·2.5.2·2.5.5·2.5.6 / N2SF AC 계정관리) ──
#   위 accounts 는 CCE 판정용 3필드 요약이라 계정 대장을 만들 수 없다(GID·홈·정책·마지막 로그인 없음).
#   아래 네 키가 중앙에서 계정 1행을 조립하는 원자료다. 전부 읽기 전용이고 getent/awk 수준이라 가볍다
#   (전체 파일시스템 find 는 쓰지 않는다 — 이 에이전트의 "서버에 무리 주지 않는다" 원칙).
#
#   **패스워드 해시는 어떤 형태로도 수집·전송하지 않는다.** shadow 에서는 정책 필드와
#   잠금 여부(해시가 !/* 로 시작하는지)만 1/0 으로 환산해 보낸다.
# passwd: 사용자명 uid gid 셸 홈
cap users account_passwd 'getent passwd | awk -F: "{print \$1\"\t\"\$3\"\t\"\$4\"\t\"\$7\"\t\"\$6}"'
# shadow 정책: 사용자명 마지막변경일(epoch일) min max warn inactive 만료일(epoch일) 잠금(1/0)
#   /etc/shadow 는 root 만 읽는다 → 못 읽으면 파일 자체를 안 만든다(중앙에서 NA).
#   읽을 수 있는데 내용이 비었을 때만 NONE(= 정상적으로 비어 있음)을 찍는다.
cap users account_shadow '[ -r /etc/shadow ] && { awk -F: "\$1 != \"\" { lock = (\$2 ~ /^[!*]/) ? 1 : 0; print \$1\"\t\"\$3\"\t\"\$4\"\t\"\$5\"\t\"\$6\"\t\"\$7\"\t\"\$8\"\t\"lock }" /etc/shadow | grep . || echo NONE; }'
# 마지막 로그인: 사용자명 <날짜문자열|NEVER>. LC_ALL=C 로 영문 고정(중앙이 파싱한다).
#   날짜는 요일 약어부터 줄 끝까지를 통째로 넘긴다 — "From" 칸이 비면 열 위치가 밀려서
#   필드 번호로 자르면 호스트마다 다른 값이 잡힌다.
cap users account_lastlog 'LC_ALL=C lastlog 2>/dev/null | awk "NR > 1 { if (\$0 ~ /Never logged in/) { print \$1\"\tNEVER\" } else if (match(\$0, /(Mon|Tue|Wed|Thu|Fri|Sat|Sun) [A-Z][a-z][a-z]/)) { print \$1\"\t\"substr(\$0, RSTART) } }"'
# sudoers 유효 라인(주석·빈 줄 제외). 0440 이라 root 만 읽는다 → 못 읽으면 파일 없음(NA).
cap users account_sudoers '[ -r /etc/sudoers ] && { cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE "^\s*#|^\s*$" | grep . || echo NONE; }'
# sshd -T 는 "실제 적용값"이라 권위 있지만, 호스트키가 없거나 설정 오류가 있으면 실패한다.
#   그때 config 폴백이 없으면 SSH 점검이 통째로 "판정 불가"가 된다 → **둘 다 수집**한다.
#   (서버는 effective 를 먼저 보고, 없으면 config 로 판정한다.)
if is_root; then
  cap users sshd_effective 'sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|x11forwarding|logingracetime|clientaliveinterval|clientalivecountmax|ciphers|macs|kexalgorithms"'
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
    jq -sc 'reduce .[] as $x ({}; .[$x.c][$x.k] = $x.v)' "$TMP/_flat.jsonl"
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
    sub(/"meta":[ \t]*\{/, "\"meta\":{" meta ",")
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
