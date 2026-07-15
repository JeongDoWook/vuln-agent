#!/usr/bin/env bash
# =============================================================================
# agent_schedule.sh — 이미 설치된 노드들의 **수집 주기(타이머)만** 중앙에서 일괄 변경한다.
# =============================================================================
# 왜 필요한가:
#   수집 주기(OnCalendar)는 설치 때 각 노드의 로컬 systemd 타이머에 박힌다. 중앙은 노드에
#   아무것도 내려보내지 않으므로(노드가 밀어 올리기만 한다), 주기를 바꾸려면 노드마다 손대야 했다.
#   이 스크립트가 master 처럼 노드들에 SSH 로 닿는 곳에서 그걸 일괄로 한다 — agent_push.sh 와 같은
#   보안 모델(사람의 SSH 키로 CLI). 웹 버튼으로 만들지 않는 이유도 같다: 웹앱이 뚫리면 전 노드
#   root 장악으로 번진다. 보는 건 웹(assets.php 의 주기 열), 바꾸는 건 CLI.
#
# 무엇을 하나 (노드에서, 토큰은 건드리지 않는다):
#   1) systemd 타이머의 OnCalendar 를 새 값으로 바꾸고 daemon-reload → restart 로 재무장.
#   2) agent.env 의 SCHEDULE 을 같은 값으로 갱신 → 다음 수집이 meta.schedule 로 실어 보내
#      중앙 화면(assets.php)이 바뀐 주기를 그대로 보여준다.
#   토큰·URL 은 안 건드린다 — 주기 변경엔 필요 없고, 토큰이 이 스크립트를 거쳐 가지도 않는다.
#
# 무엇을 안 하나:
#   - 신규 설치를 하지 않는다. 안 깔린 노드(agent.env 없음)는 건너뛰고 알려준다.
#   - cron 폴백 노드는 hourly/daily 만 매핑한다(커스텀 OnCalendar 는 cron 표현 불가 → 건너뜀).
#
# 사용:
#   bash deploy/agent_schedule.sh daily 10.3.142.100 10.3.142.101      # 셋 다 daily
#   bash deploy/agent_schedule.sh hourly 10.3.142.100 10.3.142.101='*:0/30'  # 노드별 주기
#   AGENT_SSH_USER=pi bash deploy/agent_schedule.sh daily 10.3.142.103
#   AGENT_PREFIX=/apps/vulnagent bash deploy/agent_schedule.sh hourly 10.3.142.200
#
#   주기 값: 'hourly' · 'daily' · systemd OnCalendar('*:0/30'=30분마다 등).
#   노드별로 다르게 하려면 <노드>=<주기> 로 준다. 그냥 <노드> 만 주면 첫 인자(기본 주기)를 쓴다.
# =============================================================================
set -euo pipefail

SSH_USER="${AGENT_SSH_USER:-worker}"
PREFIX="${AGENT_PREFIX:-/opt/vuln-agent}"

if [ $# -lt 2 ]; then
  grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi

DEFAULT_SCHED="$1"; shift
case "$DEFAULT_SCHED" in *=*) echo "첫 인자는 기본 주기여야 합니다(노드가 아니라): $DEFAULT_SCHED" >&2; exit 1 ;; esac

echo "== 에이전트 주기 변경 : 기본 '$DEFAULT_SCHED' · prefix $PREFIX =="
echo

OK=(); FAIL=(); SKIP=()

for target in "$@"; do
  # <노드>=<주기> 면 개별 주기, 아니면 기본 주기. 노드는 user@host 도 허용(= 는 안 들어간다).
  case "$target" in
    *=*) node="${target%%=*}"; sched="${target#*=}" ;;
    *)   node="$target";        sched="$DEFAULT_SCHED" ;;
  esac
  case "$node" in *@*) ;; *) node="$SSH_USER@$node" ;; esac
  printf '%-28s → %-10s ' "$node" "$sched"

  # 노드에서 돌 원격 스크립트. 주기·prefix 는 위치인자로 넘긴다(sudo 를 넘어 살아남는다 — env 는 안 됨).
  out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$node" \
        "sudo bash -s -- '$sched' '$PREFIX'" 2>&1 <<'REMOTE'
set -euo pipefail
SCHED="$1"; PREFIX="$2"
ENV="$PREFIX/etc/agent.env"
TIMER=/etc/systemd/system/vuln-agent.timer

[ -f "$ENV" ] || { echo "MISSING_ENV"; exit 3; }

# agent.env 의 SCHEDULE 갱신(있으면 치환, 없으면 추가) — 다음 수집이 이 값을 실어 보낸다.
if grep -q '^SCHEDULE=' "$ENV"; then
  sed -i "s|^SCHEDULE=.*|SCHEDULE=$SCHED|" "$ENV"
else
  printf 'SCHEDULE=%s\n' "$SCHED" >> "$ENV"
fi

if command -v systemctl >/dev/null 2>&1 && [ -f "$TIMER" ]; then
  sed -i "s|^OnCalendar=.*|OnCalendar=$SCHED|" "$TIMER"
  systemctl daemon-reload
  systemctl restart vuln-agent.timer
  nextline="$(systemctl list-timers vuln-agent.timer --no-pager --no-legend 2>/dev/null | head -1)"
  echo "OK_SYSTEMD ${nextline:-재무장됨}"
elif command -v crontab >/dev/null 2>&1; then
  case "$SCHED" in
    hourly) CRON="0 * * * *" ;;
    daily)  CRON="0 3 * * *" ;;
    *) echo "CRON_UNSUPPORTED"; exit 4 ;;   # 커스텀 OnCalendar 는 cron 으로 표현 불가
  esac
  RUN="$PREFIX/bin/run.sh"
  ( crontab -l 2>/dev/null | grep -vF "$RUN"; echo "$CRON $RUN >/dev/null 2>&1" ) | crontab -
  echo "OK_CRON $CRON"
else
  echo "NO_SCHEDULER"; exit 5
fi
REMOTE
)" && rc=0 || rc=$?

  # 상태 마커는 원격 스크립트의 마지막 echo 다 — sudo 안내문 등 앞줄 노이즈에 견디게 '포함' 매칭.
  case "${out}" in
    *OK_SYSTEMD*|*OK_CRON*) echo "OK  $(printf '%s' "$out" | grep -m1 -E 'OK_SYSTEMD|OK_CRON')"; OK+=("$node") ;;
    *MISSING_ENV*)          echo "건너뜀 (미설치 — install-agent.sh 를 먼저 돌리세요)"; SKIP+=("$node") ;;
    *CRON_UNSUPPORTED*)     echo "건너뜀 (cron 노드 — '$sched' 는 cron 으로 표현 불가. hourly/daily 만 가능)"; SKIP+=("$node") ;;
    *)                      echo "실패 (rc=$rc) ${out}"; FAIL+=("$node") ;;
  esac
done

echo
echo "== 결과: 성공 ${#OK[@]} · 실패 ${#FAIL[@]} · 건너뜀 ${#SKIP[@]} =="
[ ${#FAIL[@]} -eq 0 ] || { printf '   실패: %s\n' "${FAIL[*]}"; exit 1; }
