#!/usr/bin/env bash
# =============================================================================
# vuln-agent 설치기 — 대상 리눅스 서버에서 실행(sudo)
# =============================================================================
# 에이전트를 설치하고 "주기가 되면 수집 → 중앙 전송"을 스케줄한다(agent-side push).
#   systemd 있으면 상시 데몬(vuln-agent.service, 10초마다 중앙을 poll — 주기·즉시/예약 명령은
#   poll 응답으로 받는다), 없으면 cron 폴백(run.sh --once 을 주기 실행, 정기수집만).
#   토큰은 <prefix>/etc/agent.env(600) 에 두고 env 로 전달 → ps 에 노출 안 됨.
#
# 토큰:
#   중앙 서버의 "에이전트 토큰" 화면에서 이 호스트(fqdn)용 개별 토큰을 발급받아 넣는다.
#   개별 토큰은 발급 시 정한 호스트만 갱신할 수 있어, 대상 1대가 침해돼도 다른 호스트를
#   위조하지 못한다. 공유 수집 토큰은 허용되지 않는다.
#
# 사용:
#   sudo bash install-agent.sh                    # 서버 주소·토큰·주기를 물어본다(대화형)
#   sudo bash install-agent.sh --server http://중앙서버:8080/ingest.php --token 토큰
#   sudo bash install-agent.sh --server ... --token ... --schedule daily
#   sudo bash install-agent.sh --server ... --token ... --schedule '*:0/30'   # 30분마다
#   sudo bash install-agent.sh --server ... --token ... --prefix /apps/vulnagent
#   sudo bash install-agent.sh --server ... --token ... --host-ip 10.3.142.200  # 이름을 이 IP 로
#   sudo bash install-agent.sh --server ... --token ... --ca-file ./caddy-root.crt
#   sudo bash install-agent.sh --uninstall [--prefix 설치경로]
#
#   sudo 만 있으면 된다 — chmod/chown 불필요(`bash <파일>` 로 실행하므로 실행권한이 필요없고,
#   설치물은 root 가 만드니 자동으로 root 소유가 된다).
#
# 선행 검사(preflight):
#   설치물을 깔기 **전에** 전송이 실제로 되는지 확인한다. 안 되면 고칠 수 있는 건 고치고,
#   못 고치면 아무것도 설치하지 않고 중단한다 — "설치는 됐는데 전송만 조용히 안 되는" 상태를
#   만들지 않기 위해서다(실제로 그렇게 당했다).
#     1) 필수 도구 확인. **아무것도 설치하지 않는다** — 에이전트는 대상 서버에 요구사항을 두지
#        않는다(awk 로 JSON 을 만든다. jq 는 있으면 쓰는 빠른 경로일 뿐).
#        HTTPS 전송 수단(curl 또는 wget)만 있으면 된다.
#     2) 스크립트 옆의 caddy-root.crt(또는 --ca-file)를 신뢰 저장소에 등록.
#        중앙 Caddy 가 자체서명(tls internal)이라 없으면 TLS 검증이 실패한다.
#     3) 중앙에 GET 을 한 번 던져 본다. 못 붙으면 중앙의 내부 IP 를 묻고(--host-ip)
#        /etc/hosts 에 이름을 묶는다 — 도메인이 공인 IP 로 풀려 내부망에서 되돌아오지
#        못하는 망(헤어핀 NAT)이 있다.
#
# 설치물은 --prefix(기본 /opt/vuln-agent) 한 곳에 모인다:
#   <prefix>/bin/{vuln-inventory-agent.sh,run.sh}   실행 파일
#   <prefix>/etc/agent.env                          설정(600)
#   <prefix>/logs/last.json                         수집 결과
# =============================================================================
set -euo pipefail

SERVER=""; TOKEN=""; SCHEDULE=""; UNINSTALL=0; PREFIX=/opt/vuln-agent
CA_FILE=""; HOST_IP=""
ORIG_ARGS="$*"   # root 안내 메시지에 원래 인자를 그대로 되돌려주기 위해 보관
while [ $# -gt 0 ]; do
  case "$1" in
    --server)    SERVER="$2"; shift 2 ;;
    --token)     TOKEN="$2"; shift 2 ;;
    --schedule)  SCHEDULE="$2"; shift 2 ;;
    --prefix)    PREFIX="$2"; shift 2 ;;
    --ca-file)   CA_FILE="$2"; shift 2 ;;
    --host-ip)   HOST_IP="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

# root 강제 — /opt 설치, systemd 유닛 작성, cron 등록은 root 아니면 애초에 불가능.
# 실행권한(chmod +x)이 없어도 되도록 `bash <파일>` 형태를 안내한다.
if [ "$(id -u)" -ne 0 ]; then
  echo "root 권한이 필요합니다. 이렇게 실행하세요:" >&2
  echo "    sudo bash $0${ORIG_ARGS:+ $ORIG_ARGS}" >&2
  exit 1
fi

case "$PREFIX" in /*) ;; *) echo "--prefix 는 절대경로여야 합니다: $PREFIX" >&2; exit 1 ;; esac
BIN="$PREFIX/bin"
ETC="$PREFIX/etc"
LOG="$PREFIX/logs"
RUN="$BIN/run.sh"
UNIT=/etc/systemd/system/vuln-agent.service
TIMER=/etc/systemd/system/vuln-agent.timer

if [ "$UNINSTALL" = 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now vuln-agent.service 2>/dev/null || true
    systemctl disable --now vuln-agent.timer 2>/dev/null || true   # 구버전(oneshot+timer) 잔재 정리
    rm -f "$UNIT" "$TIMER"; systemctl daemon-reload 2>/dev/null || true
  fi
  ( crontab -l 2>/dev/null | grep -vF "$RUN" ) | crontab - 2>/dev/null || true
  rm -rf "$BIN" "$ETC" "$LOG"
  rmdir "$PREFIX" 2>/dev/null || true
  echo "제거 완료."
  exit 0
fi

# 인자를 안 줬으면 물어본다. 터미널이 아니면(파이프·자동화) 예전처럼 인자 필수.
if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then
  [ -t 0 ] || { echo "필수: --server, --token (터미널이 아니라 물어볼 수 없습니다)" >&2; exit 1; }
  echo "== vuln-agent 설치 =="
  while [ -z "$SERVER" ]; do
    printf '중앙 서버 주소 (예: vulnagent.example.com:8080): '
    read -r SERVER
  done
  while [ -z "$TOKEN" ]; do
    printf '전송 토큰 (입력은 화면에 보이지 않습니다): '
    read -rs TOKEN; echo
  done
  printf '수집 주기 [%s] (daily / '"'"'*:0/30'"'"'=30분마다): ' "${SCHEDULE:-hourly}"
  read -r _ans; [ -n "$_ans" ] && SCHEDULE="$_ans"
fi
SCHEDULE="${SCHEDULE:-hourly}"

# 주소 보정 — 도메인만 넣어도 되게 스킴과 /ingest.php 를 채운다(이미 있으면 그대로).
case "$SERVER" in http://*|https://*) ;; *) SERVER="https://$SERVER" ;; esac
case "$SERVER" in
  */ingest.php) ;;
  */)  SERVER="${SERVER}ingest.php" ;;
  *)   SERVER="$SERVER/ingest.php" ;;
esac
echo ">> 전송 대상: $SERVER"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 선행 검사(preflight) ─────────────────────────────────────
# 여기서 막히면 아무것도 설치하지 않고 중단한다. 설치를 마친 뒤에 전송만 실패하면
# "타이머는 도는데 자산은 안 올라오는" 조용한 실패가 되고, 원인은 사람이 찾아야 한다.

# 1) 의존 명령 — **대상 서버에 아무것도 설치하지 않는다.**
#    예전엔 jq 가 없으면 apt 로 깔았다. 틀렸다 — 현장 폐쇄망 서버엔 apt 자체가 없고,
#    남의 서버에 패키지를 심는 건 승인 사안이다. 이제 에이전트가 JSON 을 awk 로 조립하므로
#    jq 는 "있으면 빠른 경로" 일 뿐이다(awk 는 POSIX 필수 — busybox 에도 있다).
#    남은 필수는 전송 수단 하나뿐: HTTPS 를 순수 셸로는 못 하니 curl 또는 wget 이 있어야 한다.
if ! command -v awk >/dev/null 2>&1; then
  echo ">> [중단] awk 가 없습니다(POSIX 필수 명령인데도). JSON 을 만들 수 없습니다." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  echo ">> [중단] curl·wget 이 모두 없습니다. HTTPS 전송 수단이 필요합니다." >&2
  echo "   설치기는 대상 서버에 아무것도 설치하지 않습니다 — 둘 중 하나를 준비한 뒤 다시 실행하세요." >&2
  exit 1
fi
command -v jq >/dev/null 2>&1 || echo ">> jq 없음 → awk 로 JSON 을 만듭니다(정상 동작, 설치 불필요)."

# 2) 루트 CA — 중앙 Caddy 는 자체서명(tls internal)이라 대상이 발급자를 모른다.
#    스크립트 옆에 caddy-root.crt 를 같이 복사해 두면(scp 한 번에) 여기서 알아서 등록한다.
if [ -z "$CA_FILE" ] && [ -f "$SRC_DIR/caddy-root.crt" ]; then CA_FILE="$SRC_DIR/caddy-root.crt"; fi
if [ -n "$CA_FILE" ]; then
  if [ ! -f "$CA_FILE" ]; then echo ">> [중단] CA 파일이 없습니다: $CA_FILE" >&2; exit 1; fi
  if   command -v update-ca-certificates >/dev/null 2>&1 && [ -d /usr/local/share/ca-certificates ]; then
    install -m 0644 "$CA_FILE" /usr/local/share/ca-certificates/vulnagent-root.crt
    update-ca-certificates >/dev/null 2>&1 || true
    echo ">> 루트 CA 등록: $CA_FILE"
  elif command -v update-ca-trust >/dev/null 2>&1 && [ -d /etc/pki/ca-trust/source/anchors ]; then
    install -m 0644 "$CA_FILE" /etc/pki/ca-trust/source/anchors/vulnagent-root.crt
    update-ca-trust extract >/dev/null 2>&1 || true
    echo ">> 루트 CA 등록: $CA_FILE"
  else
    echo ">> [경고] CA 신뢰 저장소를 찾지 못했습니다 — TLS 검증이 실패할 수 있습니다"
  fi
fi

# 3) 연결 확인 — GET 은 405(POST 전용)가 정상. 코드가 뭐로 오든 "붙었다"는 뜻이다.
SRV_HOST="${SERVER#*://}"; SRV_HOST="${SRV_HOST%%/*}"; SRV_HOST="${SRV_HOST%%:*}"
vg_probe() {
  if command -v curl >/dev/null 2>&1; then
    curl -s -o /dev/null -m 8 -w '%{http_code}' "$SERVER" 2>/dev/null | grep -v '^000$' || true
  else
    # wget 만 있는 시스템 — 응답 헤더에서 상태코드를 뽑는다.
    wget -q -O /dev/null --timeout=8 --server-response "$SERVER" 2>&1 \
      | awk '/^  HTTP\//{code=$2} END{if (code) print code}' || true
  fi
}

CODE="$(vg_probe)"
if [ -z "$CODE" ]; then
  RC=0
  if command -v curl >/dev/null 2>&1; then
    curl -s -o /dev/null -m 8 "$SERVER" >/dev/null 2>&1 || RC=$?
  else
    wget -q -O /dev/null --timeout=8 "$SERVER" >/dev/null 2>&1 || RC=$?
  fi
  if [ "$RC" = 60 ] || [ "$RC" = 35 ] || [ "$RC" = 77 ]; then
    echo ">> [중단] TLS 인증서를 검증하지 못했습니다 — 중앙 Caddy 는 자체서명입니다." >&2
    echo "   중앙에서 루트 CA 를 꺼내 이 스크립트 옆(caddy-root.crt)에 두고 다시 실행하세요:" >&2
    echo "     sudo docker cp vulnagent-caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt" >&2
    exit 1
  fi
  # 이름이 공인 IP 로 풀려 내부망에서 자기 라우터로 되돌아오지 못하는 망(헤어핀 NAT)이 흔하다.
  # 이름은 유지해야 한다 — Caddy 가 SNI 로 사이트를 고르므로 IP 직접 접속은 실패한다.
  case "$SRV_HOST" in
    *[a-zA-Z]*)
      if [ -z "$HOST_IP" ] && [ -t 0 ]; then
        echo ">> $SRV_HOST 에 붙지 못했습니다(curl rc=$RC). 내부망이면 중앙의 내부 IP 로 풀어야 합니다."
        printf '중앙 서버의 내부 IP (모르면 엔터 → 중단): '
        read -r HOST_IP
      fi
      if [ -n "$HOST_IP" ]; then
        if ! grep -qE "^[^#]*[[:space:]]${SRV_HOST}([[:space:]]|$)" /etc/hosts; then
          printf '%s\t%s\n' "$HOST_IP" "$SRV_HOST" >> /etc/hosts
          echo ">> /etc/hosts 등록: $HOST_IP  $SRV_HOST"
        fi
        CODE="$(vg_probe)"
      fi
      ;;
  esac
fi
if [ -z "$CODE" ]; then
  echo ">> [중단] 중앙($SERVER)에 붙지 못했습니다. 주소·방화벽을 확인하세요." >&2
  echo "   아무것도 설치하지 않았습니다." >&2
  exit 1
fi
echo ">> 중앙 연결 확인: HTTP $CODE"

# 1) 파일 배치
install -d "$BIN" "$ETC" "$LOG"
install -m 0755 "$SRC_DIR/vuln-inventory-agent.sh" "$BIN/vuln-inventory-agent.sh"

# 2) 설정(토큰) — 600 권한, env 로만 전달
umask 077
cat > "$ETC/agent.env" <<EOF
SEND_URL=$SERVER
SEND_TOKEN=$TOKEN
SCHEDULE=$SCHEDULE
EOF
chmod 600 "$ETC/agent.env"

# 3) 실행 래퍼 — env 로드 후 poll_and_maybe_scan 을 10초마다 반복하는 데몬(systemd Type=simple).
#   agent-poll.php 를 10초마다 GET 해 (a) 정기수집 주기(poll_schedule_seconds)가 지났거나
#   (b) 즉시/예약 명령(due_command_id)이 와 있으면 vuln-inventory-agent.sh 를 돌린다.
#   changelog 수집은 백포트 오탐 제거(서버가 "이미 패치됨"을 증명)의 근거라 켜둔다.
#   과거엔 --no-changelog 로 껐지만, 에이전트에 명령별 timeout·바이트 상한이 있어
#   느린 changelog 로부터 보호되고 실측 비용도 수 초라 부담이 없다.
#   cron 폴백 노드는 상시 프로세스를 못 돌리므로 `run.sh --once` 로 1회만 poll·판단하고 종료한다
#   (systemd 데몬 경로는 --once 없이 무한루프로 상시 기동).
cat > "$RUN" <<EOF
#!/usr/bin/env bash
# vuln-agent 데몬 루프 — install-agent.sh 가 생성한다. 재설치 시 덮어써지므로 직접 고치지 말 것.
set -a; . $ETC/agent.env; set +a
set -uo pipefail

BIN_DIR="$BIN"
LOG_DIR="$LOG"
POLL_URL="\${SEND_URL%ingest.php}agent-poll.php"
LAST_SCAN_FILE="\$LOG_DIR/last_scan_at"
POLL_STATE_FILE="\$LOG_DIR/poll_interval"
ONCE=0
[ "\${1:-}" = "--once" ] && ONCE=1

# --schedule 은 초기값일 뿐이다 — 이후 주기는 agent-poll.php 응답의 poll_schedule_seconds 가
# 우선하며 POLL_STATE_FILE 에 저장돼 재시작해도 유지된다(중앙 웹에서 바꾸면 다음 poll 에 반영,
# SSH 재설치 불필요).
case "\$SCHEDULE" in
  hourly) INIT_INTERVAL=3600 ;;
  daily)  INIT_INTERVAL=86400 ;;
  *)      INIT_INTERVAL=3600 ;;   # 커스텀 OnCalendar 는 초로 못 바꾸므로 서버 응답을 받을 때까지만 사용
esac

have() { command -v "\$1" >/dev/null 2>&1; }
log()  { echo "[\$(date -Is 2>/dev/null || date)] \$*" >&2; }

# do_poll : agent-poll.php GET → POLL_SCHEDULE / DUE_CMD 채움. 성공(0)/실패(1).
do_poll() {
  local resp=""
  if have curl; then
    resp=\$(curl -sS -m 15 -H "X-Agent-Token: \$SEND_TOKEN" "\$POLL_URL" 2>/dev/null)
  elif have wget; then
    resp=\$(wget -qO- --timeout=15 --header="X-Agent-Token: \$SEND_TOKEN" "\$POLL_URL" 2>/dev/null)
  else
    log "curl·wget 이 모두 없어 poll 을 할 수 없습니다."
    return 1
  fi
  [ -z "\$resp" ] && return 1
  if have jq; then
    printf '%s' "\$resp" | jq -e . >/dev/null 2>&1 || return 1
    POLL_SCHEDULE=\$(printf '%s' "\$resp" | jq -r '.poll_schedule_seconds // empty')
    DUE_CMD=\$(printf '%s' "\$resp" | jq -r '.due_command_id // empty')
    POLL_CPU_QUOTA=\$(printf '%s' "\$resp" | jq -r '.cpu_quota_percent // empty')
    POLL_PACKAGING_TIMEOUT=\$(printf '%s' "\$resp" | jq -r '.packaging_timeout_seconds // empty')
  else
    # 응답이 단순 flat JSON 필드뿐이라 grep -o 로 충분하다(null 은 숫자 패턴에 안 걸려 빈 값이 됨).
    POLL_SCHEDULE=\$(printf '%s' "\$resp" | grep -o '"poll_schedule_seconds"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+\$')
    DUE_CMD=\$(printf '%s' "\$resp" | grep -o '"due_command_id"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+\$')
    POLL_CPU_QUOTA=\$(printf '%s' "\$resp" | grep -o '"cpu_quota_percent"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+\$')
    POLL_PACKAGING_TIMEOUT=\$(printf '%s' "\$resp" | grep -o '"packaging_timeout_seconds"[[:space:]]*:[[:space:]]*[0-9]\+' | grep -o '[0-9]\+\$')
  fi
  case "\$POLL_SCHEDULE" in ''|*[!0-9]*) return 1 ;; esac
  # POLL_CPU_QUOTA/POLL_PACKAGING_TIMEOUT 는 숫자+상식적 범위(CPU 1~100, 타임아웃 30~3600)
  #   벗어나면 빈 값으로 떨군다 — run_scan 이 그대로 vuln-inventory-agent.sh 기본값(10%/120초)
  #   으로 폴백하므로 여기서 막아도 수집 자체는 안전하게 계속된다.
  case "\$POLL_CPU_QUOTA" in ''|*[!0-9]*) POLL_CPU_QUOTA="" ;; esac
  if [ -n "\$POLL_CPU_QUOTA" ] && { [ "\$POLL_CPU_QUOTA" -lt 1 ] || [ "\$POLL_CPU_QUOTA" -gt 100 ]; }; then
    POLL_CPU_QUOTA=""
  fi
  case "\$POLL_PACKAGING_TIMEOUT" in ''|*[!0-9]*) POLL_PACKAGING_TIMEOUT="" ;; esac
  if [ -n "\$POLL_PACKAGING_TIMEOUT" ] && { [ "\$POLL_PACKAGING_TIMEOUT" -lt 30 ] || [ "\$POLL_PACKAGING_TIMEOUT" -gt 3600 ]; }; then
    POLL_PACKAGING_TIMEOUT=""
  fi
  return 0
}

run_scan() {
  local cmd_id="\$1"
  local args=(-o "\$LOG_DIR/last.json" --send "\$SEND_URL" --token "\$SEND_TOKEN")
  [ -n "\$cmd_id" ] && args+=(--command-id "\$cmd_id")
  log "수집 시작\${cmd_id:+ (명령#\$cmd_id 처리 포함)}"
  # 호스트별 속도 티어(agent-poll.php 의 cpu_quota_percent/packaging_timeout_seconds) 를
  #   env override 로 넘긴다 — vuln-inventory-agent.sh 상단이 이미 CPU_QUOTA/PACKAGING_TIMEOUT
  #   환경변수를 지원하므로 새 CLI 플래그 없이 전달만 하면 된다. 값이 비어 있으면(구버전 서버
  #   등) 스크립트 자체 기본값(10%/120초)이 그대로 쓰인다.
  local tier_env=()
  [ -n "\${POLL_CPU_QUOTA:-}" ] && tier_env+=(CPU_QUOTA="\${POLL_CPU_QUOTA}%")
  [ -n "\${POLL_PACKAGING_TIMEOUT:-}" ] && tier_env+=(PACKAGING_TIMEOUT="\$POLL_PACKAGING_TIMEOUT")
  # "set -u" 상태에서 빈 배열 "\${tier_env[@]}" 확장은 bash 4.3 이하에서 unbound variable 로 죽는다.
  #   "\${tier_env[@]+"\${tier_env[@]}"}" 는 배열이 비어 있으면 통째로 없던 걸로 취급해 안전하다.
  env \${tier_env[@]+"\${tier_env[@]}"} "\$BIN_DIR/vuln-inventory-agent.sh" "\${args[@]}"
}

# poll_and_maybe_scan : poll 1회 + 필요하면 수집. poll 자체의 성공/실패를 돌려준다(백오프 판단용).
#   주의: due_command_id 로 실행했다고 정기수집 타이머(LAST_SCAN_FILE)를 리셋하지 않는다 —
#   그러면 "예약 실행 걸었더니 다음 정기수집이 늦어졌다"는 혼란이 생긴다. 타이머는 정기
#   조건(경과시간 >= poll_schedule_seconds)으로 실행했을 때만 갱신한다.
poll_and_maybe_scan() {
  if ! do_poll; then
    log "poll 실패 — 응답 없음/비정상"
    return 1
  fi
  echo "\$POLL_SCHEDULE" > "\$POLL_STATE_FILE"
  local now last scheduled_due=0
  now=\$(date +%s)
  last=\$(cat "\$LAST_SCAN_FILE" 2>/dev/null || echo 0)
  case "\$last" in ''|*[!0-9]*) last=0 ;; esac
  [ \$(( now - last )) -ge "\$POLL_SCHEDULE" ] && scheduled_due=1
  if [ "\$scheduled_due" = 1 ] || [ -n "\$DUE_CMD" ]; then
    run_scan "\$DUE_CMD"
    [ "\$scheduled_due" = 1 ] && echo "\$now" > "\$LAST_SCAN_FILE"
  fi
  return 0
}

FAIL_SLEEP=10
MAX_FAIL_SLEEP=300
while true; do
  if poll_and_maybe_scan; then
    FAIL_SLEEP=10
    SLEEP=10
  else
    FAIL_SLEEP=\$(( FAIL_SLEEP * 2 ))
    [ "\$FAIL_SLEEP" -gt "\$MAX_FAIL_SLEEP" ] && FAIL_SLEEP=\$MAX_FAIL_SLEEP
    SLEEP=\$FAIL_SLEEP
  fi
  [ "\$ONCE" = 1 ] && exit 0
  sleep "\$SLEEP"
done
EOF
chmod 0755 "$RUN"

# 4) 상시 기동 등록 (systemd 상시 서비스 우선, 실패 시 cron 폴백)
#   systemd 가 있으면 데몬(run.sh 의 while-loop)을 Type=simple 로 상시 기동한다 —
#   10초마다 agent-poll.php 를 poll 하므로 더 이상 OS 스케줄러(timer)가 주기를 쥐지 않는다.
#   cron 은 상시 프로세스를 못 돌리므로(주기 실행만 가능) 데몬화가 안 된다 — 이 경우 기존
#   oneshot 방식을 그대로 유지한다(`run.sh --once` 를 주기적으로 cron 이 실행 → 정기수집만
#   가능, 중앙의 즉시/예약 명령은 다음 주기까지 반영 안 됨).
SCHEDULED=""
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  cat > "$UNIT" <<EOF
[Unit]
Description=vuln-agent 상시 데몬(10초 poll) — 수집·중앙 전송
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
Nice=19
IOSchedulingClass=idle
ExecStart=$RUN
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
  rm -f "$TIMER"   # 구버전(oneshot+timer) 잔재 — 상시 서비스로 대체하므로 더 이상 만들지 않는다
  # enable --now 는 유닛이 이미 active 면 재시작하지 않는다(start 가 no-op) — 이러면 방금
  # 디스크에 새로 쓴 run.sh 를, 메모리에서 옛 while-loop 를 계속 돌던 기존 프로세스가 못 읽는다.
  # daemon-reload → enable(활성화만) → restart(무조건 재기동)로 새 코드 반영을 보장한다.
  if systemctl daemon-reload 2>/dev/null && systemctl enable vuln-agent.service 2>/dev/null && systemctl restart vuln-agent.service 2>/dev/null; then
    SCHEDULED="systemd 상시 데몬(10초 poll, 초기 정기수집 주기=$SCHEDULE)"
    echo ">> 서비스 재시작 완료"
  else
    rm -f "$UNIT"
    echo ">> systemd 사용 불가 → cron 으로 대체 시도(정기수집만, 즉시/예약 명령 미지원)"
  fi
fi
if [ -z "$SCHEDULED" ] && command -v crontab >/dev/null 2>&1; then
  case "$SCHEDULE" in
    hourly) CRON="0 * * * *" ;;
    daily)  CRON="0 3 * * *" ;;
    *)      CRON="0 * * * *" ;;  # 커스텀 OnCalendar 는 cron 표현 불가 → 매시로
  esac
  if ( crontab -l 2>/dev/null | grep -vF "$RUN"; \
       echo "$CRON $RUN --once >/dev/null 2>&1" ) | crontab - 2>/dev/null; then
    SCHEDULED="cron ($CRON, --once — 정기수집만)"
    echo ">> [안내] 이 노드는 systemd 가 없어 cron 폴백입니다 — 즉시실행/예약 기능을 지원하지 않습니다(정기수집만 가능)."
  fi
fi
if [ -n "$SCHEDULED" ]; then
  echo ">> 스케줄 등록: $SCHEDULED"
else
  echo ">> [경고] 자동 스케줄 등록 실패(systemd/cron 없음). 수동 등록: $RUN"
fi

# 즉시 1회 실행(통신 확인) — 스케줄 방식과 무관하게 항상 수행.
#   run.sh(--once 포함)를 거치지 않고 vuln-inventory-agent.sh 를 직접 부른다 — poll 성공
#   여부(agent-poll.php 가입 상태)와 무관하게 SEND_URL/SEND_TOKEN 자체가 맞는지만 확인하기
#   위해서다. preflight 로 "붙는 것"까지는 이미 확인했으므로, 여기서 실패하면 대개 토큰
#   문제다(401=토큰 틀림, 403=개별 토큰이 이 호스트에 안 묶임). 그걸 성공으로 끝내지 않는다.
echo ">> 즉시 1회 수집·전송 (통신 확인)..."
if ( set -a; . "$ETC/agent.env"; set +a; exec "$BIN/vuln-inventory-agent.sh" -o "$LOG/last.json" ); then
  date +%s > "$LOG/last_scan_at"   # 데몬의 정기수집 타이머 기준점 — 방금 한 수집을 재차 반복하지 않게
  echo ">> 완료. 수집 로그: $LOG/last.json"
else
  echo ">> [실패] 수집은 됐지만 전송이 안 됐습니다 (위 HTTP 코드 참고)." >&2
  echo "   401 = 토큰이 틀림 / 403 = 이 호스트($(hostname -f 2>/dev/null || hostname))에 안 묶인 토큰." >&2
  echo "   스케줄은 등록돼 있으니, 토큰을 고쳐 이 설치기를 다시 실행하면 덮어씁니다." >&2
  exit 1
fi
