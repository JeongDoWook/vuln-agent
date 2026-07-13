#!/usr/bin/env bash
# =============================================================================
# vuln-agent 설치기 — 대상 리눅스 서버에서 실행(sudo)
# =============================================================================
# 에이전트를 설치하고 "시간마다 수집 → 중앙 전송"을 스케줄한다(agent-side push).
#   systemd 있으면 systemd-timer, 없으면 cron 으로 등록.
#   토큰은 <prefix>/etc/agent.env(600) 에 두고 env 로 전달 → ps 에 노출 안 됨.
#
# 토큰:
#   중앙 서버의 "에이전트 토큰" 화면에서 이 호스트(fqdn)용 개별 토큰을 발급받아 넣는다.
#   개별 토큰은 발급 시 정한 호스트만 갱신할 수 있어, 대상 1대가 침해돼도 다른 호스트를
#   위조하지 못한다. (구버전 공유 토큰도 당분간 받지만 deprecated — 개별 토큰으로 이행 권장.)
#
# 사용:
#   sudo bash install-agent.sh                    # 서버 주소·토큰·주기를 물어본다(대화형)
#   sudo bash install-agent.sh --server http://중앙서버:8080/ingest.php --token 토큰
#   sudo bash install-agent.sh --server ... --token ... --schedule daily
#   sudo bash install-agent.sh --server ... --token ... --schedule '*:0/30'   # 30분마다
#   sudo bash install-agent.sh --server ... --token ... --prefix /apps/vulnagent
#   sudo bash install-agent.sh --uninstall [--prefix 설치경로]
#
#   sudo 만 있으면 된다 — chmod/chown 불필요(`bash <파일>` 로 실행하므로 실행권한이 필요없고,
#   설치물은 root 가 만드니 자동으로 root 소유가 된다).
#
# 설치물은 --prefix(기본 /opt/vuln-agent) 한 곳에 모인다:
#   <prefix>/bin/{vuln-inventory-agent.sh,run.sh}   실행 파일
#   <prefix>/etc/agent.env                          설정(600)
#   <prefix>/logs/last.json                         수집 결과
# =============================================================================
set -euo pipefail

SERVER=""; TOKEN=""; SCHEDULE=""; UNINSTALL=0; PREFIX=/opt/vuln-agent
ORIG_ARGS="$*"   # root 안내 메시지에 원래 인자를 그대로 되돌려주기 위해 보관
while [ $# -gt 0 ]; do
  case "$1" in
    --server)    SERVER="$2"; shift 2 ;;
    --token)     TOKEN="$2"; shift 2 ;;
    --schedule)  SCHEDULE="$2"; shift 2 ;;
    --prefix)    PREFIX="$2"; shift 2 ;;
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
    systemctl disable --now vuln-agent.timer 2>/dev/null || true
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
    printf '중앙 서버 주소 (예: ost-server.duckdns.org:8080): '
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

# 1) 파일 배치
install -d "$BIN" "$ETC" "$LOG"
install -m 0755 "$SRC_DIR/vuln-inventory-agent.sh" "$BIN/vuln-inventory-agent.sh"

# 2) 설정(토큰) — 600 권한, env 로만 전달
umask 077
cat > "$ETC/agent.env" <<EOF
SEND_URL=$SERVER
SEND_TOKEN=$TOKEN
EOF
chmod 600 "$ETC/agent.env"

# 3) 실행 래퍼 — env 로드 후 수집(에이전트가 SEND_URL/SEND_TOKEN 을 읽어 전송)
#   changelog 수집은 백포트 오탐 제거(서버가 "이미 패치됨"을 증명)의 근거라 켜둔다.
#   과거엔 --no-changelog 로 껐지만, 에이전트에 명령별 timeout·바이트 상한이 있어
#   느린 changelog 로부터 보호되고 실측 비용도 수 초라 부담이 없다.
cat > "$RUN" <<EOF
#!/usr/bin/env bash
set -a; . $ETC/agent.env; set +a
exec $BIN/vuln-inventory-agent.sh -o $LOG/last.json
EOF
chmod 0755 "$RUN"

# 4) 스케줄 등록 (systemd-timer 우선, 실패 시 cron 폴백)
SCHEDULED=""
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  cat > "$UNIT" <<EOF
[Unit]
Description=vuln-agent 수집 및 중앙 전송
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=$RUN
EOF
  cat > "$TIMER" <<EOF
[Unit]
Description=vuln-agent 주기 수집
[Timer]
OnCalendar=$SCHEDULE
Persistent=true
RandomizedDelaySec=120
[Install]
WantedBy=timers.target
EOF
  if systemctl daemon-reload 2>/dev/null && systemctl enable --now vuln-agent.timer 2>/dev/null; then
    SCHEDULED="systemd-timer (OnCalendar=$SCHEDULE)"
  else
    rm -f "$UNIT" "$TIMER"
    echo ">> systemd 사용 불가 → cron 으로 대체 시도"
  fi
fi
if [ -z "$SCHEDULED" ] && command -v crontab >/dev/null 2>&1; then
  case "$SCHEDULE" in
    hourly) CRON="0 * * * *" ;;
    daily)  CRON="0 3 * * *" ;;
    *)      CRON="0 * * * *" ;;  # 커스텀 OnCalendar 는 cron 표현 불가 → 매시로
  esac
  if ( crontab -l 2>/dev/null | grep -vF "$RUN"; \
       echo "$CRON $RUN >/dev/null 2>&1" ) | crontab - 2>/dev/null; then
    SCHEDULED="cron ($CRON)"
  fi
fi
if [ -n "$SCHEDULED" ]; then
  echo ">> 스케줄 등록: $SCHEDULED"
else
  echo ">> [경고] 자동 스케줄 등록 실패(systemd/cron 없음). 수동 등록: $RUN"
fi

# 즉시 1회 실행(통신 확인) — 스케줄 방식과 무관하게 항상 수행
echo ">> 즉시 1회 수집·전송 (통신 확인)..."
"$RUN" || echo ">> [경고] 즉시 실행 실패 — 서버 주소/토큰/방화벽 확인"
echo ">> 완료. 수집 로그: $LOG/last.json"
