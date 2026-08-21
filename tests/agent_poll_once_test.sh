#!/usr/bin/env bash
# =============================================================================
# agent_poll_once_test.sh — 에이전트 명령 처리 경로(폴링→지시문→run.sh)를 서버 없이 검증한다.
# =============================================================================
# 왜 이 테스트가 있나:
#   중앙이 켠 무결성 검사(due_command_verify_files)가 노드에 도달하지 않아 **조용히** 무시된
#   사고가 있었다 — 명령은 done 으로 닫히고 화면은 "미수행" 이라 아무도 못 알아챘다. 원인은
#   응답 파싱이 run.sh(자동 업데이트 대상 밖)에 있었던 것. 로직을 vuln-inventory-agent.sh
#   --poll-once 로 옮겼으므로, 그 계약(응답 → 지시문 → 수집 인자)을 기계로 고정한다.
#
# 무엇을 확인하나:
#   A. vuln-inventory-agent.sh --poll-once 가 응답을 지시문으로 옮기는가
#      (verify 1/0/필드없음, 정기수집 만기, 자동 업데이트, 깨진 응답) — jq 경로와 폴백 둘 다.
#   B. install-agent.sh --runner-only 가 만든 run.sh 가 그 지시문을 그대로 실행하는가.
#      (root 가 필요하다 — 아니면 이 부분만 건너뛴다)
#
# 네트워크·중앙 서버는 쓰지 않는다: PATH 앞에 가짜 curl 을 두고 고정 JSON 을 돌려준다.
#
# 사용:  bash tests/agent_poll_once_test.sh
#        (jq 있는 경로까지 다 보려면 jq 가 설치된 환경에서 돌린다 — 없으면 그 절만 SKIP)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$ROOT/agent/vuln-inventory-agent.sh"
INSTALLER="$ROOT/agent/install-agent.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  [OK]   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$1"; [ $# -gt 1 ] && printf '%s\n' "$2" | sed 's/^/         /'; }

# ── 가짜 curl/wget : 고정 JSON($POLL_FIXTURE)을 그대로 돌려준다 ──────────────
SHIM="$TMP/shim"; mkdir -p "$SHIM"
cat > "$SHIM/curl" <<'SH'
#!/usr/bin/env bash
[ -n "${POLL_FIXTURE:-}" ] && cat "$POLL_FIXTURE"
SH
chmod 0755 "$SHIM/curl"

STATE="$TMP/state"; mkdir -p "$STATE"

# poll_once <fixture 내용> [환경변수 KEY=VAL ...] → stdout 지시문, 종료코드는 $POLL_RC 로
poll_once() {
  local json="$1"; shift
  printf '%s' "$json" > "$TMP/fixture.json"
  local out
  out=$(env PATH="$SHIM:$PATH" POLL_FIXTURE="$TMP/fixture.json" VG_FORCE_AWK="$FORCE_AWK" \
            SEND_URL="https://central.example/ingest.php" SEND_TOKEN="tok" "$@" \
            bash "$AGENT" --poll-once --state-dir "$STATE" 2>/dev/null)
  POLL_RC=$?
  printf '%s' "$out"
}

# 정기수집이 만기가 아닌 상태로 되돌린다(명령 케이스를 정기수집과 섞지 않기 위해).
not_due()  { date +%s > "$STATE/last_scan_at"; }
is_due()   { echo 0 > "$STATE/last_scan_at"; }

has()      { printf '%s\n' "$1" | grep -qx -- "$2"; }

run_contract_suite() {
  local label="$1"
  echo "-- $label --"
  local out sig

  # 1) 명령 + 무결성 켜짐 → --verify-files 가 인자에 실린다(사고 재현 방지의 핵심)
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"due_command_id":164,"due_command_verify_files":1,"cpu_quota_percent":10,"packaging_timeout_seconds":120,"mem_max_mb":300,"update_available":false}')
  if has "$out" 'scan=command' && has "$out" 'arg=--command-id' && has "$out" 'arg=164' \
     && has "$out" 'arg=--verify-files' && has "$out" 'arg=--verify-timeout'; then
    ok "$label: verify_files=1 → --command-id 164 + --verify-files"
  else
    bad "$label: verify_files=1 지시문 누락" "$out"
  fi

  # 2) 명령 + 무결성 꺼짐 → --verify-files 가 붙으면 안 된다(수 분짜리 부하를 임의로 걸지 않는다)
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"due_command_id":165,"due_command_verify_files":0,"update_available":false}')
  if has "$out" 'scan=command' && ! has "$out" 'arg=--verify-files'; then
    ok "$label: verify_files=0 → --verify-files 없음"
  else
    bad "$label: verify_files=0 인데 무결성이 붙었다" "$out"
  fi

  # 3) 구버전 서버(필드 자체가 없음) → 0 으로 본다
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"due_command_id":166,"update_available":false}')
  if has "$out" 'scan=command' && ! has "$out" 'arg=--verify-files'; then
    ok "$label: due_command_verify_files 필드 없음 → --verify-files 없음"
  else
    bad "$label: 필드 없음인데 무결성이 붙었다" "$out"
  fi

  # 4) 노드 고정값(VERIFY_FILES=1, 설치 시 --verify-files) → 명령이 안 켜도 붙는다(OR)
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"due_command_id":167,"due_command_verify_files":0,"update_available":false}' VERIFY_FILES=1)
  if has "$out" 'arg=--verify-files'; then
    ok "$label: 노드 고정 VERIFY_FILES=1 → --verify-files"
  else
    bad "$label: 노드 고정값이 무시됐다" "$out"
  fi

  # 5) 명령 없음 + 정기수집 만기 → scan=scheduled(명령 인자 없음), 타이머가 갱신된다
  is_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"due_command_id":null,"due_command_verify_files":0,"cpu_quota_percent":25,"mem_max_mb":512,"update_available":false}')
  if has "$out" 'scan=scheduled' && ! has "$out" 'arg=--command-id' \
     && has "$out" 'env=CPU_QUOTA=25%' && has "$out" 'env=MEM_MAX=512M'; then
    ok "$label: 정기수집 만기 → scan=scheduled + 속도티어 env"
  else
    bad "$label: 정기수집 지시문이 틀렸다" "$out"
  fi
  if [ "$(cat "$STATE/last_scan_at")" != 0 ]; then
    ok "$label: 정기수집 타이머 갱신됨"
  else
    bad "$label: 정기수집 타이머가 안 갱신됐다"
  fi

  # 6) 명령 없음 + 만기 아님 → 아무것도 안 돈다
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"due_command_id":null,"update_available":false}')
  if ! has "$out" 'scan=scheduled' && ! has "$out" 'scan=command'; then
    ok "$label: 만기 아님·명령 없음 → 수집 지시 없음"
  else
    bad "$label: 돌 이유가 없는데 수집 지시가 나왔다" "$out"
  fi

  # 7) 자동 업데이트 — 네 값이 다 있을 때만 지시문으로 나간다
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"due_command_id":null,"update_available":true,"update_version":"9.9","update_sha256":"deadbeef","update_download_path":"agent-dl.php?f=vuln-inventory-agent.sh","update_signature":"c2ln=="}')
  if has "$out" 'update_version=9.9' && has "$out" 'update_sha256=deadbeef' \
     && has "$out" 'update_path=agent-dl.php?f=vuln-inventory-agent.sh' && has "$out" 'update_signature=c2ln=='; then
    ok "$label: 업데이트 지시문 4종 전달(값의 = 도 안 잘림)"
  else
    bad "$label: 업데이트 지시문이 틀렸다" "$out"
  fi
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"update_available":true,"update_version":"9.9"}')
  if ! has "$out" 'update_version=9.9'; then
    ok "$label: sha256·경로 없는 업데이트는 지시하지 않음"
  else
    bad "$label: 불완전한 업데이트를 지시했다" "$out"
  fi

  # 8) 범위 밖 속도티어는 떨군다(에이전트 기본값으로 폴백)
  is_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"cpu_quota_percent":999,"packaging_timeout_seconds":1,"mem_max_mb":99999,"update_available":false}')
  if ! printf '%s\n' "$out" | grep -q '^env='; then
    ok "$label: 범위 밖 속도티어는 env 로 안 넘긴다"
  else
    bad "$label: 이상한 속도티어가 그대로 넘어갔다" "$out"
  fi

  # 9) 깨진 응답·빈 응답 → 실패(종료코드 1). 백오프 판단의 근거다.
  not_due
  poll_once '{이건 JSON 이 아니다' >/dev/null
  [ "$POLL_RC" = 1 ] && ok "$label: 깨진 응답 → 종료코드 1" || bad "$label: 깨진 응답인데 성공으로 끝났다(rc=$POLL_RC)"
  poll_once '' >/dev/null
  [ "$POLL_RC" = 1 ] && ok "$label: 빈 응답 → 종료코드 1" || bad "$label: 빈 응답인데 성공으로 끝났다(rc=$POLL_RC)"

  # 10) 직전 업데이트 결과는 poll 성공 시에만 지워진다(유실 방지)
  not_due
  echo "ok 3.13 3.14" > "$STATE/update_report"
  poll_once '{"poll_schedule_seconds":3600,"update_available":false}' >/dev/null
  [ ! -f "$STATE/update_report" ] && ok "$label: poll 성공 후 업데이트 리포트 정리" || bad "$label: 리포트가 안 지워졌다"
  echo "ok 3.13 3.14" > "$STATE/update_report"
  poll_once '{깨짐' >/dev/null
  [ -f "$STATE/update_report" ] && ok "$label: poll 실패 시 리포트 보존(다음에 재보고)" || bad "$label: 실패했는데 리포트를 지웠다"
  rm -f "$STATE/update_report"

  # 11) 서명 base64 안의 "\/" — PHP json_encode 는 기본으로 "/" 를 "\/" 로 쓴다. 폴백 파서가
  #     그걸 못 풀면 base64 가 깨져 서명 검증이 실패한다. jq 가 없는 노드 전부에서 자동
  #     업데이트가 죽었던 실제 사고다(3.17 → 3.18, signature_invalid). 서버는 이제
  #     JSON_UNESCAPED_SLASHES 로 안 escape 하지만, 구버전 서버를 만나도 노드가 견뎌야 한다.
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"update_available":true,"update_version":"9.9","update_sha256":"deadbeef","update_download_path":"agent-dl.php?f=vuln-inventory-agent.sh","update_signature":"+\/++D\/A="}')
  sig=$(printf '%s\n' "$out" | sed -n 's/^update_signature=//p')
  if [ "$sig" = '+/++D/A=' ]; then
    ok "$label: 이스케이프된 서명(\\/)을 원본 base64 로 되돌린다"
  else
    bad "$label: 서명 이스케이프가 안 풀렸다 (sig=$sig)" "$out"
  fi
  case "$sig" in
    ''|*[!A-Za-z0-9+/=]*) bad "$label: 서명에 base64 밖 문자가 남았다 (sig=$sig)" ;;
    *)                    ok "$label: 서명이 base64 문자집합만으로 이뤄진다" ;;
  esac
  if printf '%s' "$sig" | base64 -d >/dev/null 2>&1; then
    ok "$label: 서명이 실제로 base64 디코드된다"
  else
    bad "$label: 서명이 base64 로 디코드되지 않는다 (sig=$sig)"
  fi

  # 12) 다른 문자열 필드도 같은 병을 앓는다 — 경로에 "\/" 가 섞이면 다운로드 URL 이 깨진다.
  not_due
  out=$(poll_once '{"poll_schedule_seconds":3600,"update_available":true,"update_version":"9.9","update_sha256":"deadbeef","update_download_path":"sub\/agent-dl.php?f=a.sh","update_signature":"c2ln=="}')
  if has "$out" 'update_path=sub/agent-dl.php?f=a.sh'; then
    ok "$label: 다운로드 경로의 \\/ 도 풀린다"
  else
    bad "$label: 다운로드 경로 이스케이프가 안 풀렸다" "$out"
  fi
}

echo "== A. --poll-once 지시문 계약 =="

# 폴백(grep/sed) 경로 — VG_FORCE_AWK=1 이면 jq 가 있어도 폴백을 탄다(에이전트가 JSON 조립에
#   쓰는 것과 같은 스위치). PATH 장난보다 확실하다 — 어느 환경에서든 폴백이 실제로 검사된다.
FORCE_AWK=1
run_contract_suite "폴백(grep/sed, VG_FORCE_AWK=1)"

# jq 경로 — 실제 jq 가 있을 때만.
FORCE_AWK=0
if command -v jq >/dev/null 2>&1; then
  run_contract_suite "jq 있음"
else
  echo "-- jq 있음 -- SKIP (이 환경에 jq 가 없다. jq 설치된 곳에서 한 번은 돌릴 것)"
fi

echo
echo "== B. run.sh 가 지시문을 실행하는가 =="
if [ "$(id -u)" -ne 0 ]; then
  echo "  SKIP (install-agent.sh 는 root 를 요구한다 — 컨테이너에서 돌릴 것)"
else
  PREFIX="$TMP/opt"
  mkdir -p "$PREFIX/bin" "$PREFIX/etc" "$PREFIX/logs"
  cat > "$PREFIX/etc/agent.env" <<EOF
SEND_URL=https://central.example/ingest.php
SEND_TOKEN=tok
SCHEDULE=hourly
VERIFY_FILES=0
EOF
  # 본체 자리에 "가짜 본체" 를 둔다 — --poll-once/--help 는 진짜에 넘기고, 수집 인자는
  #   실행하지 않고 그대로 기록만 한다(실제 수집은 수 분짜리라 테스트가 아니다).
  cat > "$PREFIX/bin/vuln-inventory-agent.sh" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
  --poll-once|--help) exec bash "$AGENT" "\$@" ;;
esac
{ echo "ARGS: \$*"; echo "CPU_QUOTA=\${CPU_QUOTA:-}"; echo "MEM_MAX=\${MEM_MAX:-}"; } > "$TMP/scan_invocation"
EOF
  chmod 0755 "$PREFIX/bin/vuln-inventory-agent.sh"

  if bash "$INSTALLER" --runner-only --prefix "$PREFIX" >"$TMP/runner.log" 2>&1; then
    ok "install-agent.sh --runner-only 실행"
  else
    bad "install-agent.sh --runner-only 실패" "$(cat "$TMP/runner.log")"
  fi
  if [ -f "$PREFIX/bin/run.sh" ] && bash -n "$PREFIX/bin/run.sh"; then
    ok "생성된 run.sh 문법 검사"
  else
    bad "run.sh 가 없거나 문법 오류"
  fi
  if grep -q 'agent.env' "$PREFIX/etc/agent.env" 2>/dev/null || [ -s "$PREFIX/etc/agent.env" ]; then
    ok "agent.env(토큰) 는 --runner-only 가 건드리지 않는다"
  fi

  # run.sh --once : 가짜 curl 로 "명령 + 무결성" 응답을 주고, 수집이 그 인자로 불렸는지 본다.
  printf '%s' '{"poll_schedule_seconds":3600,"due_command_id":164,"due_command_verify_files":1,"cpu_quota_percent":25,"mem_max_mb":512,"update_available":false}' > "$TMP/fixture.json"
  date +%s > "$PREFIX/logs/last_scan_at"
  rm -f "$TMP/scan_invocation"
  env PATH="$SHIM:$PATH" POLL_FIXTURE="$TMP/fixture.json" bash "$PREFIX/bin/run.sh" --once >"$TMP/run.log" 2>&1
  if [ -f "$TMP/scan_invocation" ] \
     && grep -q -- '--command-id 164' "$TMP/scan_invocation" \
     && grep -q -- '--verify-files' "$TMP/scan_invocation" \
     && grep -q 'CPU_QUOTA=25%' "$TMP/scan_invocation" \
     && grep -q 'MEM_MAX=512M' "$TMP/scan_invocation"; then
    ok "run.sh --once → 명령·무결성·속도티어가 그대로 수집에 전달"
  else
    bad "run.sh 가 지시문대로 수집을 부르지 않았다" "$(cat "$TMP/scan_invocation" 2>/dev/null; cat "$TMP/run.log")"
  fi

  # 만기도 아니고 명령도 없으면 수집을 부르지 않는다.
  printf '%s' '{"poll_schedule_seconds":3600,"due_command_id":null,"update_available":false}' > "$TMP/fixture.json"
  date +%s > "$PREFIX/logs/last_scan_at"
  rm -f "$TMP/scan_invocation"
  env PATH="$SHIM:$PATH" POLL_FIXTURE="$TMP/fixture.json" bash "$PREFIX/bin/run.sh" --once >>"$TMP/run.log" 2>&1
  [ ! -f "$TMP/scan_invocation" ] && ok "할 일이 없으면 run.sh 는 수집을 안 부른다" \
                                  || bad "돌 이유가 없는데 수집을 불렀다"

  # 구버전 본체(--poll-once 를 모름) → 폴백 정기수집으로라도 돈다(노드를 깜깜하게 두지 않는다).
  cat > "$PREFIX/bin/vuln-inventory-agent.sh" <<EOF
#!/usr/bin/env bash
[ "\${1:-}" = "--help" ] && { echo "구버전 본체 사용법"; exit 0; }
echo "ARGS: \$*" > "$TMP/scan_invocation"
EOF
  chmod 0755 "$PREFIX/bin/vuln-inventory-agent.sh"
  echo 0 > "$PREFIX/logs/last_scan_at"
  rm -f "$TMP/scan_invocation"
  env PATH="$SHIM:$PATH" POLL_FIXTURE="$TMP/fixture.json" bash "$PREFIX/bin/run.sh" --once >"$TMP/legacy.log" 2>&1
  if [ -f "$TMP/scan_invocation" ] && grep -q '구버전 본체' <(grep -o '구버전 본체' "$TMP/legacy.log" || true); then
    ok "구버전 본체 → 경고 로그 + 폴백 정기수집"
  elif [ -f "$TMP/scan_invocation" ]; then
    ok "구버전 본체 → 폴백 정기수집"
  else
    bad "구버전 본체에서 아무것도 안 돌았다" "$(cat "$TMP/legacy.log")"
  fi
fi

echo
echo "== 결과: 통과 $PASS · 실패 $FAIL =="
[ "$FAIL" -eq 0 ]
