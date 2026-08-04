#!/usr/bin/env bash
# =============================================================================
# vuln-agent · 에이전트 리소스 벤치마크
# =============================================================================
# vuln-inventory-agent.sh 가 이 서버에서 CPU·메모리를 얼마나 쓰는지 실측한다.
# "다른 서버에서도 안심하고 깔 수 있나"를 숫자로 답하기 위한 도구다.
#
#  무엇을 재나 (한 번 실행당):
#    - 피크 메모리(RSS) : 에이전트 프로세스 트리 전체 RSS 를 0.2초마다 샘플링한 최댓값
#    - CPU 시간         : /proc/PID/stat 의 utime+stime+cutime+cstime (자식 포함)
#    - 벽시계 시간      : /proc/uptime 기준 (nice 19 라 실제 점유보다 길게 나올 수 있음)
#    - 산출물 크기·패키지 수·컨테이너 수 (규모 대비 비용을 보려고)
#  → GNU time·bc 같은 추가 패키지에 의존하지 않는다. /proc 와 awk 만 있으면 된다.
#
#  왜 /proc 샘플링인가: 에이전트는 timeout·jq·dpkg·awk 등 자식을 순차로 띄운다.
#    GNU time 의 Max RSS 는 직속 자식(bash)만 재서 jq·dpkg 피크를 놓친다. 트리 전체를
#    샘플링하면 "그 순간 가장 컸던 자식"까지 잡힌다. 에이전트가 대부분 순차 실행이라
#    피크 = 동시에 떠 있던 프로세스들의 합이 가장 컸던 순간이다.
#
#  사용법:
#    sudo ./tests/agent-bench.sh                 # 기본: full·no-changelog 각 3회 (root 권장)
#    sudo ./tests/agent-bench.sh -n 5            # 시나리오당 5회
#    sudo ./tests/agent-bench.sh --with-limit    # cgroup --limit 시나리오도 (systemd-run 필요)
#    ./tests/agent-bench.sh --agent /opt/vuln-agent/bin/vuln-inventory-agent.sh
#    ./tests/agent-bench.sh --csv /tmp/fleet.csv # 여러 서버 결과를 한 CSV 에 누적
#
#  여러 서버 조사: 각 운영 서버에서 같은 --csv 경로로 돌린 뒤 CSV 를 한곳에 모으면
#    서버 규모(패키지 수·코어 수)별 비용 분포가 그대로 나온다. 서버 1대여도 시나리오를
#    바꿔가며(full/no-changelog/limit) 여러 데이터포인트를 뽑을 수 있다.
# =============================================================================
set -uo pipefail

AGENT=""
ITERS=3
CSV=""
WITH_LIMIT=0
KEEP_OUT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --agent)       AGENT="$2"; shift 2 ;;
    -n|--iters)    ITERS="$2"; shift 2 ;;
    --csv)         CSV="$2"; shift 2 ;;
    --with-limit)  WITH_LIMIT=1; shift ;;
    --keep-output) KEEP_OUT=1; shift ;;
    -h|--help)     grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
have() { command -v "$1" >/dev/null 2>&1; }

# ---------- 에이전트 스크립트 찾기 ----------
if [ -z "$AGENT" ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  for c in "$ROOT/agent/vuln-inventory-agent.sh" \
           /opt/vuln-agent/bin/vuln-inventory-agent.sh \
           /opt/vuln-agent/vuln-inventory-agent.sh \
           /apps/vulnagent/bin/vuln-inventory-agent.sh; do
    [ -f "$c" ] && { AGENT="$c"; break; }
  done
fi
[ -n "$AGENT" ] && [ -f "$AGENT" ] || {
  echo "에이전트 스크립트를 못 찾음. --agent <경로> 로 지정하세요." >&2; exit 1; }
AGENT="$(cd "$(dirname "$AGENT")" && pwd)/$(basename "$AGENT")"

PAGESIZE="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

# ---------- 서버 컨텍스트 (규모 대비 비용 해석용) ----------
HOST="$(hostname -s 2>/dev/null || echo unknown)"
NPROC="$(nproc 2>/dev/null || echo 1)"
RAM_MB="$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)"
OS_PRETTY="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}" )"
RUN_AS="$(id -un 2>/dev/null || echo unknown)"
[ "$(id -u)" -eq 0 ] || echo -e "${YELLOW}[경고] root 가 아닙니다 — 실제 설치는 root 타이머라, 비root 측정은 부분 수집이라 비용이 과소 추정됩니다.${NC}" >&2

echo -e "${CYAN}== vuln-agent 리소스 벤치 ==${NC}"
echo "  호스트: $HOST ($OS_PRETTY)"
echo "  코어: $NPROC · RAM: ${RAM_MB}MB · 실행자: $RUN_AS"
echo "  에이전트: $AGENT"
echo "  반복: 시나리오당 ${ITERS}회"
echo ""

# ---------- 한 pid 의 자손 전체 RSS 합(KB) : /proc 만 사용 ----------
tree_rss_kb() {
  local root="$1"
  awk -v root="$root" -v pgsz="$PAGESIZE" '
    BEGIN { FS=" " }
    # /proc/*/stat 를 통째로 넘겨 ppid·rss 를 모은다 (한 번 스캔)
    { pid=$1
      # comm 에 공백·괄호가 있어 ")" 뒤부터 필드를 다시 센다
      rest=$0; sub(/^[0-9]+ \(.*\) /,"",rest); n=split(rest,f," ")
      ppid[pid]=f[2]; rssp[pid]=f[22]     # f[22]=rss(pages) : state=1..rss=22
    }
    END {
      desc[root]=1; changed=1
      while (changed) { changed=0
        for (p in ppid) if (!(p in desc) && (ppid[p] in desc)) { desc[p]=1; changed=1 } }
      total=0
      for (p in desc) total += rssp[p]*pgsz
      printf "%d", total/1024
    }
  ' /proc/[0-9]*/stat 2>/dev/null
}

# ---------- 한 pid 의 누적 CPU(jiffies) : 자신+이미 회수한 자식 ----------
top_cpu_jiffies() {
  local pid="$1" line rest
  line="$(cat /proc/$pid/stat 2>/dev/null)" || { echo 0; return; }
  rest="${line#*) }"
  # shellcheck disable=SC2086
  set -- $rest
  # $12 utime $13 stime $14 cutime $15 cstime
  echo $(( ${12:-0} + ${13:-0} + ${14:-0} + ${15:-0} ))
}

now_uptime() { awk '{print $1; exit}' /proc/uptime; }

# ---------- CSV 헤더 ----------
if [ -n "$CSV" ] && [ ! -f "$CSV" ]; then
  echo "ts,host,os,nproc,ram_mb,run_as,scenario,iter,wall_s,cpu_s,cpu_pct_of_1core,peak_rss_mb,peak_rss_pct_ram,pkg_count,container_count,agent_elapsed_s,exit,out_bytes" > "$CSV"
fi

# ---------- 산출물에서 규모 뽑기 (jq 있으면 정확, 없으면 근사) ----------
parse_out() {  # $1=outfile  →  "pkg|containers|elapsed"
  local f="$1" pk="" ct="" el=""
  if have jq && [ -s "$f" ]; then
    pk="$(jq -r '.pkg.count // (.pkg.list|split("\n")|length) // empty' "$f" 2>/dev/null)"
    ct="$(jq -r '(.containers.list|split("\n")|length-1) // 0' "$f" 2>/dev/null)"
    el="$(jq -r '.meta.elapsed_seconds // empty' "$f" 2>/dev/null)"
  fi
  echo "${pk:-}|${ct:-}|${el:-}"
}

# ---------- 시나리오 한 번 측정 ----------
# run_one <scenario-label> <extra-agent-args...>
run_one() {
  local label="$1"; shift
  local out; out="$(mktemp /tmp/agentbench.XXXXXX.json)"
  local peak=0 cpu0=0 cpu1=0 wall0 wall1 pid rss

  wall0="$(now_uptime)"
  # 백그라운드로 띄워 $! 로 에이전트 pid 를 직접 잡는다(자손은 ppid 로 따라간다).
  #   setsid 는 쓰지 않는다 — fork 후 부모가 즉시 exit 해 $! 가 엉뚱한 pid 가 된다.
  #   --send 는 붙이지 않는다(순수 수집 비용만 잰다).
  bash "$AGENT" "$@" -o "$out" >/dev/null 2>&1 &
  pid=$!

  # 첫 CPU 스냅샷은 프로세스가 뜬 직후
  cpu0="$(top_cpu_jiffies "$pid")"
  while kill -0 "$pid" 2>/dev/null; do
    rss="$(tree_rss_kb "$pid")"; [ -n "$rss" ] && [ "$rss" -gt "$peak" ] 2>/dev/null && peak="$rss"
    cpu1="$(top_cpu_jiffies "$pid")"    # 종료 직전 마지막 값이 남는다(자식 회수분 포함)
    sleep 0.2
  done
  wait "$pid"; local rc=$?
  wall1="$(now_uptime)"

  local cpu_j=$(( cpu1 - cpu0 )); [ "$cpu_j" -lt 0 ] && cpu_j=0
  local wall_s cpu_s cpu_pct peak_mb peak_pct
  wall_s="$(awk -v a="$wall0" -v b="$wall1" 'BEGIN{printf "%.2f", b-a}')"
  cpu_s="$(awk -v j="$cpu_j" -v t="$CLK_TCK" 'BEGIN{printf "%.2f", j/t}')"
  cpu_pct="$(awk -v c="$cpu_s" -v w="$wall_s" 'BEGIN{printf "%.0f", (w>0)?(c/w*100):0}')"
  peak_mb="$(awk -v k="$peak" 'BEGIN{printf "%.1f", k/1024}')"
  peak_pct="$(awk -v k="$peak" -v r="$RAM_MB" 'BEGIN{printf "%.1f", (r>0)?(k/1024/r*100):0}')"
  local out_bytes; out_bytes="$(wc -c < "$out" 2>/dev/null || echo 0)"

  local parsed pk ct el; parsed="$(parse_out "$out")"
  pk="${parsed%%|*}"; ct="$(echo "$parsed" | cut -d'|' -f2)"; el="${parsed##*|}"

  printf "  ${GREEN}%-14s${NC} 벽시계 %5ss · CPU %5ss(%s%% of 1core) · 피크 RSS %6sMB(%s%%) · %s패키지 · rc=%s\n" \
    "$label" "$wall_s" "$cpu_s" "$cpu_pct" "$peak_mb" "$peak_pct" "${pk:-?}" "$rc"

  if [ -n "$CSV" ]; then
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(date -Is 2>/dev/null || date)" "$HOST" "$OS_PRETTY" "$NPROC" "$RAM_MB" "$RUN_AS" \
      "$label" "$ITER" "$wall_s" "$cpu_s" "$cpu_pct" "$peak_mb" "$peak_pct" \
      "${pk:-}" "${ct:-}" "${el:-}" "$rc" "$out_bytes" >> "$CSV"
  fi

  # 집계용 전역 누적
  AGG_WALL="$(awk -v s="$AGG_WALL" -v x="$wall_s" 'BEGIN{print s+x}')"
  AGG_CPU="$(awk -v s="$AGG_CPU" -v x="$cpu_s" 'BEGIN{print s+x}')"
  [ "$(awk -v a="$peak_mb" -v b="$AGG_PEAK" 'BEGIN{print (a>b)?1:0}')" = 1 ] && AGG_PEAK="$peak_mb"

  [ "$KEEP_OUT" = 1 ] || rm -f "$out"
}

# ---------- 시나리오 실행 ----------
run_scenario() {
  local label="$1"; shift
  AGG_WALL=0; AGG_CPU=0; AGG_PEAK=0
  echo -e "${CYAN}[$label]${NC}"
  for ITER in $(seq 1 "$ITERS"); do
    run_one "$label#$ITER" "$@"
  done
  echo -e "  ${YELLOW}평균${NC} 벽시계 $(awk -v s="$AGG_WALL" -v n="$ITERS" 'BEGIN{printf "%.1f", s/n}')s · CPU $(awk -v s="$AGG_CPU" -v n="$ITERS" 'BEGIN{printf "%.1f", s/n}')s · 피크 RSS 최대 ${AGG_PEAK}MB"
  echo ""
}

# 1) 실제 운영에서 도는 그대로 (changelog 포함, 리밋 없음, nice 19)
run_scenario "full"

# 2) 가장 무거운 단계(changelog) 제거 — 비교 기준
run_scenario "no-changelog" --no-changelog

# 3) (옵션) cgroup 하드리밋 — systemd-run 필요. 리밋 하에선 트리가 재부모화되어
#    /proc 추적이 부정확하므로 벽시계만 신뢰하고, 메모리·CPU 는 cgroup 이 상한을 보장한다.
if [ "$WITH_LIMIT" = 1 ]; then
  if [ "$(id -u)" -eq 0 ] && have systemd-run; then
    echo -e "${CYAN}[limit]${NC} (cgroup CPU≤한 코어의 10% · MEM≤300M 을 커널이 강제 — 아래 피크 RSS 값은 재부모화로 과소 측정될 수 있음)"
    AGG_WALL=0; AGG_CPU=0; AGG_PEAK=0
    for ITER in $(seq 1 "$ITERS"); do run_one "limit#$ITER" --limit; done
    echo ""
  else
    echo -e "${YELLOW}[limit] 생략 — root + systemd-run 이 필요합니다.${NC}\n"
  fi
fi

echo -e "${GREEN}완료.${NC}"
[ -n "$CSV" ] && echo "  CSV 누적: $CSV  (다른 서버에서도 같은 경로로 돌려 모으세요)"
echo -e "  해석 가이드: ${CYAN}docs/dev/에이전트-리소스-프로파일.md${NC}"
