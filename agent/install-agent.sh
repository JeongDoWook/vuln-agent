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
#   sudo bash install-agent.sh --server ... --token ... --host-ip 10.0.0.200  # 이름을 이 IP 로
#   sudo bash install-agent.sh --server ... --token ... --ca-file ./caddy-root.crt
#   sudo bash install-agent.sh --server ... --token ... --verify-files
#       # 패키지 무결성 검증(rpm -Va / dpkg --verify)을 매 수집마다 켠다. **기본 꺼짐** —
#       # 설치된 모든 패키지의 모든 파일을 해시해 수 분 + 무거운 디스크 IO 가 든다.
#   sudo bash install-agent.sh --runner-only [--prefix 설치경로]
#       # 이미 설치된 노드에서 **run.sh 와 서비스 유닛만** 다시 만든다(토큰·주소·CA·공개키는
#       # 건드리지 않는다). run.sh 는 에이전트 자동 업데이트 대상이 아니라 이 파일이 바뀌면
#       # 노드마다 갱신이 필요한데, 그때 전체 설치 절차(토큰 재입력)를 다시 밟지 않게 한다.
#       # deploy/agent_push.sh --with-runner 가 이 모드를 쓴다.
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
CA_FILE=""; HOST_IP=""; VERIFY_FILES=0; RUNNER_ONLY=0
ORIG_ARGS="$*"   # root 안내 메시지에 원래 인자를 그대로 되돌려주기 위해 보관
while [ $# -gt 0 ]; do
  case "$1" in
    --server)    SERVER="$2"; shift 2 ;;
    --token)     TOKEN="$2"; shift 2 ;;
    --schedule)  SCHEDULE="$2"; shift 2 ;;
    --prefix)    PREFIX="$2"; shift 2 ;;
    --ca-file)   CA_FILE="$2"; shift 2 ;;
    --host-ip)   HOST_IP="$2"; shift 2 ;;
    --verify-files) VERIFY_FILES=1; shift ;;
    --runner-only) RUNNER_ONLY=1; shift ;;
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

# ── 실행 래퍼(run.sh)와 스케줄 등록 ─────────────────────────────
#   설치 흐름 중간에 인라인으로 있던 것을 함수로 뺐다 — `--runner-only` 가 선행검사·토큰
#   입력을 전부 건너뛰고 **이 둘만** 다시 돌려야 하기 때문이다(자세한 이유는 --runner-only 참고).

# vg_write_runner : run.sh 를 생성한다.
#   ★ run.sh 는 얇게 유지한다. 에이전트 자동 업데이트(do_update)는 vuln-inventory-agent.sh
#     **하나만** 교체하므로, 여기(heredoc)에 넣은 로직은 이미 설치된 노드에 영원히 도달하지
#     못한다 — 실제로 중앙이 켠 무결성 검사(due_command_verify_files)가 옛 run.sh 에 파싱
#     코드가 없어 조용히 무시됐다(명령은 done, 결과는 미수행). 그래서 "이번에 무엇을 어떻게
#     수집할지"의 판단은 전부 `vuln-inventory-agent.sh --poll-once` 가 하고, run.sh 는 그
#     지시를 실행만 한다. 여기 남는 것은 갱신 대상 밖에 있어야 하는 것뿐이다:
#       env 로드 · 데몬 루프/백오프 · 로그 경로 · do_update()(자기 갱신 = 닭과 달걀).
vg_write_runner() {
cat > "$RUN" <<EOF
#!/usr/bin/env bash
# vuln-agent 데몬 루프 — install-agent.sh 가 생성한다. 재설치 시 덮어써지므로 직접 고치지 말 것.
#
#   이 파일은 **얇은 래퍼**다. 중앙 응답 파싱·수집 인자 조립 같은 "바뀌는 로직"은
#   vuln-inventory-agent.sh --poll-once 안에 있다(그 파일만 자동 업데이트된다).
#   여기 있는 것: env 로드 · 데몬 루프 · 로그 경로 · do_update()(자기 갱신).
set -a; . $ETC/agent.env; set +a
set -uo pipefail

BIN_DIR="$BIN"
LOG_DIR="$LOG"
PUB_KEY_FILE="$ETC/agent-update.pub"   # install-agent.sh 가 최초 설치 시 고정(pin). poll 로는 안 바뀐다.
AGENT_BIN="\$BIN_DIR/vuln-inventory-agent.sh"
LAST_SCAN_FILE="\$LOG_DIR/last_scan_at"            # 정기수집 타이머 — 평시엔 --poll-once 가 쓴다
UPDATE_REPORT_FILE="\$LOG_DIR/update_report"       # 다음 poll 때 보낼 "직전 업데이트 결과" 1줄
UPDATE_PENDING_FILE="\$LOG_DIR/update_pending_verify"  # 교체 직후 ~ 첫 실행 검증 전까지만 존재
UPDATE_FAILED_VERSION_FILE="\$LOG_DIR/update_failed_version"  # 롤백된 버전 기억 — 같은 버전 재시도 방지(스래싱 차단)
ONCE=0
[ "\${1:-}" = "--once" ] && ONCE=1

# --schedule 은 초기값일 뿐이다 — 평시 주기는 agent-poll.php 응답의 poll_schedule_seconds 를
# --poll-once 가 직접 쓴다(중앙 웹에서 바꾸면 다음 poll 에 반영, SSH 재설치 불필요).
# 아래 값은 poll 자체가 불가능한 폴백 경로(legacy_scan_if_due)에서만 쓰인다.
case "\$SCHEDULE" in
  hourly) INIT_INTERVAL=3600 ;;
  daily)  INIT_INTERVAL=86400 ;;
  *)      INIT_INTERVAL=3600 ;;   # 커스텀 OnCalendar 는 초로 못 바꾸므로 이 값만 쓴다
esac

have() { command -v "\$1" >/dev/null 2>&1; }
log()  { echo "[\$(date -Is 2>/dev/null || date)] \$*" >&2; }

# fail_update : do_update() 실패 경로 공통 처리(로그 + UPDATE_REPORT_FILE 기록 + tmp 정리).
#   do_update 안에서만 호출한다 — old_version/new_version/tmp 는 호출자(do_update)의 local
#   변수를 그대로 참조한다(bash 는 함수 호출 스택을 따라 local 을 동적 스코프로 본다).
#   호출 후에는 항상 caller 가 "return 1" 을 이어서 호출해야 한다(fail_update 자체는 caller 를
#   되돌리지 않는다).
fail_update() {
  local token="\$1" msg="\$2"; shift 2
  log "\$msg"
  echo "\$token \$old_version \$new_version" > "\$UPDATE_REPORT_FILE"
  rm -f "\$tmp" "\$@"
}

# do_update : 새 에이전트 스크립트를 받아 sha256 + Ed25519 서명 검증 후 원자적으로 교체한다.
#   \$1=버전 \$2=기대 sha256 \$3=다운로드 경로(agent-poll.php 가 준, 이 서버 자체 경로 고정)
#   \$4=서명(base64, agent-poll.php 가 준 update_signature — 없으면 빈 문자열).
#   ★ 이 함수만은 run.sh 에 남는다 — 자기를 갱신하는 코드가 갱신 대상 안에 있으면
#     교체 도중 실패했을 때 되돌릴 주체가 사라진다(닭과 달걀).
#   sha256 은 전송 중 손상만 잡는다 — 그 값 자체를 agent-poll.php(웹앱)가 즉석 계산해서
#   응답에 실으므로, 웹 티어가 침해되면 공격자가 준비한 파일의 해시를 그대로 "검증 통과"로
#   만들 수 있다. 서명은 그 두 값과 출처가 다르다(커밋 시점에 로컬 개인키로 만들어져 커밋되고,
#   PHP 는 파일을 읽기만 한다) — 그래서 sha256 통과와 별개로 서명 검증도 반드시 통과해야 적용한다.
#   실패해도(다운로드/체크섬/서명/문법) 조용히 넘기지 않고 UPDATE_REPORT_FILE 에 남겨 다음 poll 에
#   보고한다 — 다음 poll 에서 서버가 여전히 구버전으로 보면 자동으로 다시 시도된다(재시도는
#   "포기하지 않음" 자체가 목적이라 별도 백오프를 두지 않는다. YAGNI).
#   단, 같은 버전이 한 번 롤백된 적이 있으면(UPDATE_FAILED_VERSION_FILE) 재시도하지 않는다 —
#   그게 없으면 롤백 → pending 소멸 → 다음 poll 서버가 같은 버전을 또 제안 → 재적용 → 재실패
#   → 재롤백이 무한 반복된다(실제 결함).
do_update() {
  local new_version="\$1" new_sha256="\$2" dl_path="\$3" new_sig_b64="\${4:-}"
  local old_version dl_url tmp got_sha256 sigfile

  case "\$SEND_URL" in
    https://*) ;;
    *)
      log "HTTP 연결이라 자동 업데이트를 건너뜁니다(HTTPS 필요): \$SEND_URL"
      return 1
      ;;
  esac

  if [ -f "\$UPDATE_PENDING_FILE" ]; then
    log "직전 업데이트가 아직 검증 대기 중 — 새 업데이트는 이번 poll 에 적용하지 않고 다음으로 미룹니다."
    return 1
  fi

  if [ -f "\$UPDATE_FAILED_VERSION_FILE" ]; then
    local failed_version
    failed_version=\$(cat "\$UPDATE_FAILED_VERSION_FILE" 2>/dev/null)
    if [ -n "\$failed_version" ] && [ "\$failed_version" = "\$new_version" ]; then
      log "버전 \$new_version 은 이전에 롤백된 적이 있어 재시도하지 않습니다 — 서버에 실패로 보고만 합니다."
      echo "skipped_known_bad \${failed_version} \$new_version" > "\$UPDATE_REPORT_FILE"
      return 1
    fi
  fi

  old_version=\$(sed -n 's/^SCRIPT_VERSION="\(.*\)"/\1/p' "\$AGENT_BIN" 2>/dev/null | head -n1)

  # 다운그레이드 방어 — 서버가 제안한 버전이 현재 버전보다 낮거나 같으면 거부한다. 서버 쪽
  #   agent-poll.php 의 버전비교(agent_version < 배포버전)는 웹 티어가 침해되면 그 자체가
  #   무의미해질 수 있으므로(공격자가 PHP 응답을 마음대로 구성), 클라이언트도 독립적으로
  #   단조 증가만 허용한다 — 과거 정상 서명된 구버전 스크립트를 그대로 재생(replay)해도
  #   여기서 막힌다(sort -V 로 버전 비교, 관리자의 의도적 다운그레이드는 poll 경로가 아니라
  #   deploy/agent_push.sh 수동 CLI 로만 가능).
  if [ -n "\$old_version" ] && [ "\$(printf '%s\n%s\n' "\$old_version" "\$new_version" | sort -V | tail -n1)" != "\$new_version" ]; then
    log "다운그레이드 거부: \${old_version} → \${new_version} (자동 업데이트는 단조 증가만 허용합니다)"
    echo "downgrade_rejected \$old_version \$new_version" > "\$UPDATE_REPORT_FILE"
    return 1
  fi

  dl_url="\${SEND_URL%ingest.php}\${dl_path}"
  tmp="\$LOG_DIR/vuln-inventory-agent.sh.new"
  log "에이전트 업데이트 발견: \${old_version:-?} → \$new_version — 내려받는 중"
  rm -f "\$tmp"
  if have curl; then
    curl -sS -m 60 -H "X-Agent-Token: \$SEND_TOKEN" -o "\$tmp" "\$dl_url" 2>/dev/null
  elif have wget; then
    wget -qO "\$tmp" --timeout=60 --header="X-Agent-Token: \$SEND_TOKEN" "\$dl_url" 2>/dev/null
  fi
  if [ ! -s "\$tmp" ]; then
    fail_update download_failed "업데이트 다운로드 실패: \$dl_url"
    return 1
  fi
  if have sha256sum; then
    got_sha256=\$(sha256sum "\$tmp" | awk '{print \$1}')
  elif have shasum; then
    got_sha256=\$(shasum -a 256 "\$tmp" | awk '{print \$1}')
  else
    fail_update no_sha_tool "sha256sum·shasum 이 모두 없어 무결성 검증을 할 수 없습니다 — 적용하지 않음."
    return 1
  fi
  if [ "\$got_sha256" != "\$new_sha256" ]; then
    fail_update checksum_mismatch "업데이트 체크섬 불일치(기대 \$new_sha256 / 실제 \$got_sha256) — 적용하지 않음."
    return 1
  fi
  # 서명 검증 — sha256 통과와 별개로 반드시 통과해야 한다(위 함수 설명 참고). openssl 이
  #   없거나, 공개키가 안 고정돼 있거나, 서버가 서명을 안 보내면 "검증 불가"로 보고 적용하지
  #   않는다 — 침묵 스킵이 아니라 로그를 남기고 다음 poll 에 결과를 보고한다(sha256 도구가
  #   없을 때와 같은 패턴).
  if ! have openssl; then
    fail_update no_verify_tool "openssl 이 없어 서명 검증을 할 수 없습니다 — 적용하지 않음."
    return 1
  fi
  # openssl pkeyutl -rawin(Ed25519 원본 메시지 서명 검증)은 OpenSSL 3.0+ 전용이다.
  #   RHEL8/Ubuntu20.04/Debian10 등은 여전히 1.1.1 을 쓰므로, 버전을 감지 못하고 그대로
  #   돌리면 이런 노드에서는 서명 검증이 **항상** 실패해 자동 업데이트가 영구히 막힌다.
  #   1.1.1 대의 openssl CLI 로는 raw Ed25519 서명을 검증할 명령이 없으므로(3.0 전엔
  #   pkeyutl 이 Ed25519 를 지원하지 않는다), 이런 노드는 명시적으로 로그를 남기고
  #   sha256(위에서 이미 통과)만으로 진행한다 — 조용한 폴백이 아니라 보고되는 저하다.
  OPENSSL_VER="\$(openssl version 2>/dev/null | awk '{print \$2}')"
  case "\$OPENSSL_VER" in
    [3-9]*) OPENSSL_SUPPORTS_ED25519_RAWIN=1 ;;
    *)      OPENSSL_SUPPORTS_ED25519_RAWIN=0 ;;
  esac
  if [ "\$OPENSSL_SUPPORTS_ED25519_RAWIN" = 0 ]; then
    log "OpenSSL \${OPENSSL_VER:-알수없음} 은 3.0 미만이라 Ed25519 서명 검증(pkeyutl -rawin)을 지원하지 않습니다 — 서명 검증을 건너뛰고 sha256 만으로 진행합니다(명시적 저하)."
    echo "legacy_openssl_sha256_only \$old_version \$new_version" > "\$UPDATE_REPORT_FILE"
  else
    if [ ! -s "\$PUB_KEY_FILE" ]; then
      fail_update no_pinned_pubkey "서명 공개키가 고정돼 있지 않습니다(\$PUB_KEY_FILE) — 적용하지 않음. install-agent.sh 를 다시 실행하면 받습니다."
      return 1
    fi
    if [ -z "\$new_sig_b64" ]; then
      fail_update no_signature "서버 응답에 서명이 없습니다 — 적용하지 않음(아직 서명 안 된 배포이거나 구버전 서버)."
      return 1
    fi
    if ! have base64; then
      fail_update no_base64_tool "base64 명령이 없어 서명을 디코딩할 수 없습니다 — 적용하지 않음."
      return 1
    fi
    sigfile="\$LOG_DIR/vuln-inventory-agent.sh.sig.new"
    printf '%s' "\$new_sig_b64" | base64 -d > "\$sigfile" 2>/dev/null
    if [ ! -s "\$sigfile" ] || ! openssl pkeyutl -verify -pubin -inkey "\$PUB_KEY_FILE" -rawin -in "\$tmp" -sigfile "\$sigfile" >/dev/null 2>&1; then
      fail_update signature_invalid "업데이트 서명 검증 실패 — 적용하지 않음." "\$sigfile"
      return 1
    fi
    rm -f "\$sigfile"
  fi
  if ! bash -n "\$tmp" 2>/dev/null; then
    fail_update syntax_check_failed "업데이트 문법 검사 실패 — 적용하지 않음."
    return 1
  fi
  if ! cp -p "\$AGENT_BIN" "\$AGENT_BIN.bak"; then
    fail_update backup_failed "백업 실패 — 업데이트를 적용하지 않습니다(롤백할 원본을 남길 수 없음)."
    return 1
  fi
  chmod 0755 "\$tmp"
  mv -f "\$tmp" "\$AGENT_BIN"   # 같은 파일시스템 안 rename = 원자적 교체
  # 다음 실행이 실패하면 verify_pending_update 가 .bak 으로 롤백하도록 표시만 해 둔다 —
  # 지금 여기서 재실행하지 않는다(다음 정기/예약 실행부터 반영, 단순하게 — YAGNI).
  echo "\$old_version \$new_version" > "\$UPDATE_PENDING_FILE"
  log "업데이트 적용 완료: \${old_version:-?} → \$new_version (다음 실행에서 검증)"
  return 0
}

# verify_pending_update : 업데이트 후 첫 실행이면, 실제 수집을 시작하기 전에 새 스크립트
#   자체를 먼저 점검한다 — bash -n(문법) + --help(로드·인자파싱까지 실제로 실행, 부작용 없음).
#   이 자기점검 결과로만 롤백 여부를 정한다. 예전엔 뒤이은 수집(vuln-inventory-agent.sh 전체
#   실행)의 종료코드로 판단해서, 중앙 서버 오류·네트워크 타임아웃처럼 업데이트와 무관한 정상
#   운영 중 실패까지 "업데이트 실패"로 오판해 롤백했다(실제 결함).
verify_pending_update() {
  [ -f "\$UPDATE_PENDING_FILE" ] || return 0
  local ov nv
  read -r ov nv < "\$UPDATE_PENDING_FILE" 2>/dev/null || true
  if bash -n "\$AGENT_BIN" 2>/dev/null && "\$AGENT_BIN" --help >/dev/null 2>&1; then
    log "업데이트 자기점검 통과(\${ov:-?} → \${nv:-?}) — 적용 확정"
    echo "ok \${ov:-unknown} \${nv:-unknown}" > "\$UPDATE_REPORT_FILE"
    rm -f "\$UPDATE_PENDING_FILE" "\$AGENT_BIN.bak"
  else
    log "업데이트 자기점검 실패 — 이전 버전(\${ov:-?})으로 롤백하고 이 버전은 다시 시도하지 않습니다"
    if [ -f "\$AGENT_BIN.bak" ]; then
      mv -f "\$AGENT_BIN.bak" "\$AGENT_BIN"
    fi
    [ -n "\${nv:-}" ] && echo "\$nv" > "\$UPDATE_FAILED_VERSION_FILE"
    echo "rollback \${ov:-unknown} \${nv:-unknown}" > "\$UPDATE_REPORT_FILE"
    rm -f "\$UPDATE_PENDING_FILE"
  fi
}

# run_scan : --poll-once 가 정해 준 인자·환경변수로 수집을 돌린다.
#   인자 조립은 여기서 하지 않는다(그게 이 파일에 있으면 노드에 갱신이 안 간다).
#   SEND_URL·SEND_TOKEN 은 위 agent.env 로드로 이미 export 돼 자식이 물려받는다 —
#   일부러 인자로 넘기지 않는다(토큰을 argv 에 남기지 않는다).
run_scan() {
  verify_pending_update
  log "수집 시작 (\${SCAN_REASON:-?})"
  # "set -u" 상태에서 빈 배열 "\${arr[@]}" 확장은 bash 4.3 이하에서 unbound variable 로 죽는다.
  #   "\${arr[@]+"\${arr[@]}"}" 는 배열이 비어 있으면 통째로 없던 걸로 취급해 안전하다.
  env \${SCAN_ENV[@]+"\${SCAN_ENV[@]}"} "\$AGENT_BIN" \${SCAN_ARGS[@]+"\${SCAN_ARGS[@]}"}
}

# poll_and_maybe_scan : --poll-once 1회 + 그 지시 실행. poll 자체의 성공/실패를 돌려준다(백오프 판단용).
#   지시문은 "키=값" 한 줄 하나다. 값에 = 가 들어가도 되게 **첫 = 에서만** 자르고, 모르는 키는
#   조용히 무시한다 — 본체(자동 업데이트됨)가 새 키를 내보내도 옛 run.sh 가 깨지지 않는다.
poll_and_maybe_scan() {
  local out line key val
  if ! out="\$("\$AGENT_BIN" --poll-once --state-dir "\$LOG_DIR")"; then
    log "poll 실패 — 응답 없음/비정상"
    return 1
  fi
  local up_version="" up_sha256="" up_path="" up_sig=""
  SCAN_REASON=""; SCAN_ARGS=(); SCAN_ENV=()
  while IFS= read -r line; do
    [ -n "\$line" ] || continue
    key="\${line%%=*}"; val="\${line#*=}"
    case "\$key" in
      update_version)   up_version="\$val" ;;
      update_sha256)    up_sha256="\$val" ;;
      update_path)      up_path="\$val" ;;
      update_signature) up_sig="\$val" ;;
      scan)             SCAN_REASON="\$val" ;;
      env)              SCAN_ENV+=("\$val") ;;
      arg)              SCAN_ARGS+=("\$val") ;;
    esac
  done <<< "\$out"
  # 업데이트는 실행 중인 수집과 겹치지 않게 poll 직후(수집 시작 전)에 처리한다 — mv 는
  # 원자적이라 이미 fork 된 수집 프로세스에는 영향이 없지만, 순서를 단순하게 유지한다.
  if [ -n "\$up_version" ] && [ -n "\$up_sha256" ] && [ -n "\$up_path" ]; then
    do_update "\$up_version" "\$up_sha256" "\$up_path" "\$up_sig" || true
  fi
  [ -n "\$SCAN_REASON" ] && run_scan
  return 0
}

# legacy_scan_if_due : 설치된 본체가 --poll-once 를 모를 때의 폴백(정기수집만).
#   생길 수 있는 경우는 하나다 — agent_push.sh 로 **구버전 본체**를 일부러 되돌려 밀어넣은 노드.
#   poll 이 불가능하니 중앙 명령·자동 업데이트는 못 받지만, 노드를 깜깜하게 두지는 않는다
#   (수집은 계속 올라오므로 중앙이 이 노드의 에이전트 버전을 보고 사람이 알아챌 수 있다).
legacy_scan_if_due() {
  local now last
  now=\$(date +%s)
  last=\$(cat "\$LAST_SCAN_FILE" 2>/dev/null || echo 0)
  case "\$last" in ''|*[!0-9]*) last=0 ;; esac
  [ \$(( now - last )) -ge "\$INIT_INTERVAL" ] || return 0
  echo "\$now" > "\$LAST_SCAN_FILE"
  SCAN_REASON="폴백 정기수집"; SCAN_ARGS=(-o "\$LOG_DIR/last.json"); SCAN_ENV=()
  run_scan
}

# 설치된 본체가 이 run.sh 와 짝이 맞는지 시작할 때 한 번 확인한다(--help 에 --poll-once 가 있나).
POLL_ONCE_SUPPORTED=1
if ! "\$AGENT_BIN" --help 2>/dev/null | grep -q -- '--poll-once'; then
  POLL_ONCE_SUPPORTED=0
  log "[경고] \$AGENT_BIN 이 --poll-once 를 모릅니다(구버전 본체). 중앙 명령·자동 업데이트를 받을 수 없어 정기수집만 돕니다 — deploy/agent_push.sh 로 최신 본체를 밀어넣거나 install-agent.sh 를 다시 실행하세요."
fi

FAIL_SLEEP=10
MAX_FAIL_SLEEP=300
while true; do
  if [ "\$POLL_ONCE_SUPPORTED" = 0 ]; then
    legacy_scan_if_due
    SLEEP=60
  elif poll_and_maybe_scan; then
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
}

# vg_register_schedule : 상시 기동 등록 (systemd 상시 서비스 우선, 실패 시 cron 폴백)
#   systemd 가 있으면 데몬(run.sh 의 while-loop)을 Type=simple 로 상시 기동한다 —
#   10초마다 agent-poll.php 를 poll 하므로 더 이상 OS 스케줄러(timer)가 주기를 쥐지 않는다.
#   cron 은 상시 프로세스를 못 돌리므로(주기 실행만 가능) 데몬화가 안 된다 — 이 경우 기존
#   oneshot 방식을 그대로 유지한다(`run.sh --once` 를 주기적으로 cron 이 실행 → 정기수집만
#   가능, 중앙의 즉시/예약 명령은 다음 주기까지 반영 안 됨).
vg_register_schedule() {
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
}

# ── --runner-only : run.sh 만 다시 만들고 서비스를 재기동한다 ──────────────
#   왜 필요한가: run.sh 는 자동 업데이트 대상이 아니다(do_update 는 본체 하나만 교체).
#   그래서 run.sh 가 바뀌면 노드마다 사람이 들어가 설치기를 다시 돌려야 했는데, 그건 토큰·
#   주소를 다시 물어보는 전체 설치 절차다. 이 모드는 **이미 설치된 노드**에서 agent.env 를
#   그대로 두고 run.sh 와 유닛만 갱신한다 — deploy/agent_push.sh --with-runner 가 이걸 쓴다.
#   토큰·서버주소·CA·공개키는 건드리지 않는다(그 파일들을 읽지도 쓰지도 않는다).
if [ "$RUNNER_ONLY" = 1 ]; then
  if [ ! -f "$ETC/agent.env" ]; then
    echo ">> [중단] 설치된 흔적이 없습니다($ETC/agent.env). 신규 설치는 --runner-only 없이 실행하세요." >&2
    exit 1
  fi
  if [ ! -x "$BIN/vuln-inventory-agent.sh" ] && [ ! -f "$BIN/vuln-inventory-agent.sh" ]; then
    echo ">> [중단] 에이전트 본체가 없습니다($BIN/vuln-inventory-agent.sh)." >&2
    exit 1
  fi
  # 스케줄(cron 폴백 표현·유닛 설명)만 기존 설정에서 읽는다 — 토큰은 읽지 않는다.
  SCHEDULE="$(sed -n 's/^SCHEDULE=//p' "$ETC/agent.env" | head -n1)"
  SCHEDULE="${SCHEDULE:-hourly}"
  vg_write_runner
  echo ">> run.sh 갱신: $RUN"
  vg_register_schedule
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

# 2) 자동 업데이트 서명 공개키 고정(pin) — agent-dl.php 는 무인증(공개키는 비밀이 아니다)이라
#    토큰 없이 받는다. 최초 설치 시 한 번만 고정하고, 이후 poll 응답으로 이 키를 바꾸는 경로는
#    만들지 않는다(그 경로가 있으면 서명 체계 자체가 무의미해진다 — 웹 티어 침해로 공개키까지
#    바꿔치면 서명 검증이 우회된다). 못 받아도 설치를 중단하지 않는다 — 구버전 서버(아직 .pub 를
#    서빙하지 않는 배포)일 수 있고, 없으면 run.sh 의 do_update() 가 서명 검증 불가로 보고
#    자동 업데이트만 fail-safe 하게 건너뛴다(수집·poll 은 그대로 정상 동작).
PUB_URL="${SERVER%ingest.php}agent-dl.php?f=vuln-inventory-agent.pub"
PUB_TMP="$(mktemp)"
if command -v curl >/dev/null 2>&1; then
  # -f: HTTP 오류 응답(4xx/5xx 오류 페이지 본문)을 그대로 받지 않고 실패 처리한다 —
  #   없으면 오류 페이지가 PUB_TMP 에 쓰이고 아래 PUBLIC KEY 텍스트 검사만으로는 못 걸러낼
  #   수 있다(오류 페이지에 우연히 그 문자열이 섞이는 경우).
  curl -sS -f -m 15 -o "$PUB_TMP" "$PUB_URL" 2>/dev/null || true
else
  wget -qO "$PUB_TMP" --timeout=15 "$PUB_URL" 2>/dev/null || true
fi
# 텍스트 마커("PUBLIC KEY")만으로는 RSA/EC 등 다른 알고리즘의 공개키도 통과한다 —
#   openssl 로 알고리즘까지 Ed25519 인지 확인한다(openssl 없으면 텍스트 검사만으로 폴백).
PUB_IS_ED25519=1
if [ -s "$PUB_TMP" ] && grep -q 'PUBLIC KEY' "$PUB_TMP" 2>/dev/null && command -v openssl >/dev/null 2>&1; then
  openssl pkey -pubin -in "$PUB_TMP" -text -noout 2>/dev/null | grep -qi 'ed25519' || PUB_IS_ED25519=0
fi
if [ -s "$PUB_TMP" ] && grep -q 'PUBLIC KEY' "$PUB_TMP" 2>/dev/null && [ "$PUB_IS_ED25519" = 1 ]; then
  if [ -s "$ETC/agent-update.pub" ]; then
    # 이미 핀 고정된 공개키가 있다 — 재설치라고 무조건 덮어쓰지 않는다. 웹 티어가 침해되면
    #   검증이 실패하도록 만들어 관리자가 "재설치하세요" 안내를 보고 재실행하게 유도한 뒤,
    #   그 순간 공격자의 공개키로 갈아치우는 시나리오를 막기 위해서다. 지문이 같으면 그대로
    #   두고(무해한 재설치), 다르면 경고만 남기고 기존 핀을 유지한다 — 의도적으로 키를 바꾸고
    #   싶은 관리자는 $ETC/agent-update.pub 를 수동으로 지운 뒤 다시 실행해야 한다.
    if command -v openssl >/dev/null 2>&1; then
      OLD_FP="$(openssl pkey -pubin -in "$ETC/agent-update.pub" -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
      NEW_FP="$(openssl pkey -pubin -in "$PUB_TMP" -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
      if [ -n "$OLD_FP" ] && [ "$OLD_FP" = "$NEW_FP" ]; then
        echo ">> 자동 업데이트 서명 공개키: 기존 핀과 동일 — 유지합니다."
      else
        echo ">> [경고] 서버가 내려준 서명 공개키가 기존에 고정된 핀과 다릅니다 — 덮어쓰지 않습니다." >&2
        echo "   웹 티어 침해로 공개키가 바뀌었을 수 있습니다. 의도적으로 키를 교체하려면" >&2
        echo "   $ETC/agent-update.pub 를 수동으로 지운 뒤 이 설치기를 다시 실행하세요." >&2
      fi
    else
      echo ">> [안내] openssl 이 없어 기존 핀과 지문을 비교할 수 없습니다 — 기존 핀을 그대로 유지합니다."
    fi
  else
    install -m 0600 "$PUB_TMP" "$ETC/agent-update.pub"
    echo ">> 자동 업데이트 서명 공개키 고정: $ETC/agent-update.pub"
  fi
else
  echo ">> [안내] 서명 공개키를 받지 못했습니다 — 자동 업데이트 서명 검증 없이 시작합니다(자동 업데이트는 건너뜁니다)."
fi
rm -f "$PUB_TMP"

# 3) 설정(토큰) — 600 권한, env 로만 전달
umask 077
cat > "$ETC/agent.env" <<EOF
SEND_URL=$SERVER
SEND_TOKEN=$TOKEN
SCHEDULE=$SCHEDULE
VERIFY_FILES=$VERIFY_FILES
EOF
chmod 600 "$ETC/agent.env"

# 4) 실행 래퍼(run.sh) 생성 — 내용은 위 vg_write_runner() 참고.
vg_write_runner

# 5) 상시 기동 등록 — 내용은 위 vg_register_schedule() 참고.
vg_register_schedule

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
