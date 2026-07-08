#!/usr/bin/env bash
# =============================================================================
# vuln-agent 설치기 — 대상 리눅스 서버에서 실행(sudo)
# =============================================================================
# 에이전트를 설치하고 "시간마다 수집 → 중앙 전송"을 스케줄한다(agent-side push).
#   systemd 있으면 systemd-timer, 없으면 cron 으로 등록.
#   토큰은 /etc/vuln-agent/agent.env(600) 에 두고 env 로 전달 → ps 에 노출 안 됨.
#
# 사용:
#   sudo ./install-agent.sh --server http://중앙서버:8080/ingest.php --token 토큰
#   sudo ./install-agent.sh --server ... --token ... --schedule daily
#   sudo ./install-agent.sh --server ... --token ... --schedule '*:0/30'   # 30분마다
#   sudo ./install-agent.sh --uninstall
# =============================================================================
set -euo pipefail

SERVER=""; TOKEN=""; SCHEDULE="hourly"; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --server)    SERVER="$2"; shift 2 ;;
    --token)     TOKEN="$2"; shift 2 ;;
    --schedule)  SCHEDULE="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "root 로 실행하세요 (sudo)"; exit 1; }

DEST=/opt/vuln-agent
UNIT=/etc/systemd/system/vuln-agent.service
TIMER=/etc/systemd/system/vuln-agent.timer

if [ "$UNINSTALL" = 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now vuln-agent.timer 2>/dev/null || true
    rm -f "$UNIT" "$TIMER"; systemctl daemon-reload 2>/dev/null || true
  fi
  ( crontab -l 2>/dev/null | grep -v '/opt/vuln-agent/run.sh' ) | crontab - 2>/dev/null || true
  rm -rf "$DEST" /etc/vuln-agent
  echo "제거 완료."
  exit 0
fi

[ -n "$SERVER" ] && [ -n "$TOKEN" ] || { echo "필수: --server, --token"; exit 1; }
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1) 파일 배치
install -d "$DEST" /etc/vuln-agent /var/log/vuln-agent
install -m 0755 "$SRC_DIR/vuln-inventory-agent.sh" "$DEST/vuln-inventory-agent.sh"

# 2) 설정(토큰) — 600 권한, env 로만 전달
umask 077
cat > /etc/vuln-agent/agent.env <<EOF
SEND_URL=$SERVER
SEND_TOKEN=$TOKEN
EOF
chmod 600 /etc/vuln-agent/agent.env

# 3) 실행 래퍼 — env 로드 후 수집(에이전트가 SEND_URL/SEND_TOKEN 을 읽어 전송)
cat > "$DEST/run.sh" <<'EOF'
#!/usr/bin/env bash
set -a; . /etc/vuln-agent/agent.env; set +a
exec /opt/vuln-agent/vuln-inventory-agent.sh --no-changelog -o /var/log/vuln-agent/last.json
EOF
chmod 0755 "$DEST/run.sh"

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
ExecStart=$DEST/run.sh
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
  if ( crontab -l 2>/dev/null | grep -v '/opt/vuln-agent/run.sh'; \
       echo "$CRON /opt/vuln-agent/run.sh >/dev/null 2>&1" ) | crontab - 2>/dev/null; then
    SCHEDULED="cron ($CRON)"
  fi
fi
if [ -n "$SCHEDULED" ]; then
  echo ">> 스케줄 등록: $SCHEDULED"
else
  echo ">> [경고] 자동 스케줄 등록 실패(systemd/cron 없음). 수동 등록: $DEST/run.sh"
fi

# 즉시 1회 실행(통신 확인) — 스케줄 방식과 무관하게 항상 수행
echo ">> 즉시 1회 수집·전송 (통신 확인)..."
"$DEST/run.sh" || echo ">> [경고] 즉시 실행 실패 — 서버 주소/토큰/방화벽 확인"
echo ">> 완료. 수집 로그: /var/log/vuln-agent/last.json"
