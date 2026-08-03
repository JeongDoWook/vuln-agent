#!/usr/bin/env bash
# =============================================================================
# agent_schedule.sh — **구버전(레거시 systemd-timer / cron 폴백) 노드**의 수집 주기를
# 중앙에서 SSH 로 일괄 변경하는 보조 스크립트.
# =============================================================================
# 지금은 이게 주된 방법이 아니다 (PR #393/#394/#395 이후):
#   에이전트가 systemd 상시 데몬(`vuln-agent.service`, 10초마다 `agent-poll.php` poll)으로
#   바뀌면서, 그런 노드는 **중앙 웹(호스트 상세 → 수집 제어 카드)에서 주기를 바꾸면 다음 poll 에
#   바로 반영된다** — SSH·재설치가 필요 없다(`tb_host.poll_schedule_seconds`). 이 스크립트는
#   더 이상 그 경로에는 손대지 않는다(아래 "무엇을 안 하나" 참고) — 대신 아직 데몬 전환 전인
#   **구버전 노드(레거시 systemd-timer)** 와, systemd 자체가 없어 애초에 데몬화가 안 되는
#   **cron 폴백 노드**(정기수집만 가능, 즉시/예약 명령 미지원)에 여전히 필요하다. 그런 노드는
#   웹에서 주기를 바꿔도 반영할 방법이 없으므로(poll 루프가 없다) 이 스크립트가 유일한 수단이다.
#   agent_push.sh 와 같은 보안 모델(사람의 SSH 키로 CLI, 웹 버튼 아님) — 이유도 같다.
#
# 무엇을 하나 (노드에서, 토큰은 건드리지 않는다):
#   0) 이미 상시 데몬(vuln-agent.service, 레거시 타이머 없음)인 노드는 **건드리지 않고 건너뛴다**
#      — 웹에서 바꾸라고 안내만 한다.
#   1) 레거시 systemd-timer 노드: OnCalendar 를 새 값으로 바꾸고 daemon-reload → restart 로 재무장.
#      cron 폴백 노드: crontab 의 `run.sh --once` 항목을 새 주기로 재등록.
#   2) agent.env 의 SCHEDULE 을 같은 값으로 갱신 → 다음 수집이 meta.schedule 로 실어 보내
#      중앙 화면(assets.php)이 바뀐 주기를 그대로 보여준다.
#   토큰·URL 은 안 건드린다 — 주기 변경엔 필요 없고, 토큰이 이 스크립트를 거쳐 가지도 않는다.
#
# 무엇을 안 하나:
#   - 신규 설치를 하지 않는다. 안 깔린 노드(agent.env 없음)는 건너뛰고 알려준다.
#   - 상시 데몬 노드의 주기는 안 바꾼다 — 웹의 poll_schedule_seconds 가 그 노드의 SSOT 다.
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
SERVICE=/etc/systemd/system/vuln-agent.service
TIMER=/etc/systemd/system/vuln-agent.timer

[ -f "$ENV" ] || { echo "MISSING_ENV"; exit 3; }

# 상시 데몬 노드(레거시 타이머가 install-agent.sh 에 의해 이미 제거됨)는 건드리지 않는다 —
# 주기는 중앙 웹(호스트 상세)에서 바꾸면 다음 poll(10초 이내)에 반영된다.
if command -v systemctl >/dev/null 2>&1 && [ -f "$SERVICE" ] && [ ! -f "$TIMER" ]; then
  echo "ALREADY_DAEMON"; exit 6
fi

# agent.env 의 SCHEDULE 갱신(있으면 치환, 없으면 추가) — 다음 수집이 이 값을 실어 보낸다.
if grep -q '^SCHEDULE=' "$ENV"; then
  sed -i "s|^SCHEDULE=.*|SCHEDULE=$SCHED|" "$ENV"
else
  printf 'SCHEDULE=%s\n' "$SCHED" >> "$ENV"
fi

if command -v systemctl >/dev/null 2>&1 && [ -f "$TIMER" ]; then
  # 레거시 systemd-timer 노드(아직 상시 데몬으로 전환 전).
  sed -i "s|^OnCalendar=.*|OnCalendar=$SCHED|" "$TIMER"
  systemctl daemon-reload
  systemctl restart vuln-agent.timer
  nextline="$(systemctl list-timers vuln-agent.timer --no-pager --no-legend 2>/dev/null | head -1)"
  echo "OK_SYSTEMD ${nextline:-재무장됨}"
elif command -v crontab >/dev/null 2>&1; then
  # cron 폴백 노드 — install-agent.sh 와 동일하게 run.sh 는 항상 --once 로 돌린다(1회 poll·종료).
  case "$SCHED" in
    hourly) CRON="0 * * * *" ;;
    daily)  CRON="0 3 * * *" ;;
    *) echo "CRON_UNSUPPORTED"; exit 4 ;;   # 커스텀 OnCalendar 는 cron 으로 표현 불가
  esac
  RUN="$PREFIX/bin/run.sh"
  ( crontab -l 2>/dev/null | grep -vF "$RUN"; echo "$CRON $RUN --once >/dev/null 2>&1" ) | crontab -
  echo "OK_CRON $CRON"
else
  echo "NO_SCHEDULER"; exit 5
fi
REMOTE
)" && rc=0 || rc=$?

  # 상태 마커는 원격 스크립트의 마지막 echo 다 — sudo 안내문 등 앞줄 노이즈에 견디게 '포함' 매칭.
  case "${out}" in
    *OK_SYSTEMD*|*OK_CRON*) echo "OK  $(printf '%s' "$out" | grep -m1 -E 'OK_SYSTEMD|OK_CRON')"; OK+=("$node") ;;
    *ALREADY_DAEMON*)       echo "건너뜀 (상시 데몬 노드 — 웹의 호스트 상세에서 주기 변경, SSH 불필요)"; SKIP+=("$node") ;;
    *MISSING_ENV*)          echo "건너뜀 (미설치 — install-agent.sh 를 먼저 돌리세요)"; SKIP+=("$node") ;;
    *CRON_UNSUPPORTED*)     echo "건너뜀 (cron 노드 — '$sched' 는 cron 으로 표현 불가. hourly/daily 만 가능)"; SKIP+=("$node") ;;
    *)                      echo "실패 (rc=$rc) ${out}"; FAIL+=("$node") ;;
  esac
done

echo
echo "== 결과: 성공 ${#OK[@]} · 실패 ${#FAIL[@]} · 건너뜀 ${#SKIP[@]} =="
[ ${#FAIL[@]} -eq 0 ] || { printf '   실패: %s\n' "${FAIL[*]}"; exit 1; }
