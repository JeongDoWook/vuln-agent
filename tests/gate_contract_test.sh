#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() { echo "gate_contract_test: FAIL: $*" >&2; exit 1; }
assert_json() {
  local file="$1" expr="$2"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(0 if eval(sys.argv[2], {"d":d}) else 1)' "$file" "$expr" \
    || fail "JSON assertion: $expr"
}

mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'SH'
#!/usr/bin/env bash
set -eu
case "${1:-}" in
  info) [ "${FAKE_DOCKER_UP:-1}" = 1 ] ;;
  inspect)
    if [ -n "${EXPECTED_WEB_CONTAINER:-}" ] && [ "${*: -1}" != "$EXPECTED_WEB_CONTAINER" ]; then
      echo "unexpected web container: ${*: -1}" >&2
      exit 1
    fi
    if printf '%s\n' "$*" | grep -q '/var/www/html'; then
      printf '%s/server\n' "$VG_GATE_ROOT"
    else
      printf '%s\n' "${FAKE_STACK_STATE:-healthy}"
    fi
    ;;
  *) exit 0 ;;
esac
SH
cat > "$TMP/bin/curl" <<'SH'
#!/usr/bin/env bash
[ "${FAKE_HTTP_UP:-1}" = 1 ]
SH
cat > "$TMP/pass.sh" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$TMP/bin/docker" "$TMP/bin/curl" "$TMP/pass.sh"

run_gate() {
  local expected="vulnagent-web-dev"
  if [ -f "$ROOT/.git" ]; then
    gitdir=$(sed -n 's/^gitdir:[[:space:]]*//p' "$ROOT/.git" | tr '\\' '/')
    case "$gitdir" in */worktrees/*) expected="$expected-$(basename "$gitdir")" ;; esac
  fi
  PATH="$TMP/bin:$PATH" EXPECTED_WEB_CONTAINER="$expected" VG_GATE_ROOT="$ROOT" VG_GATE_MIGRATE_SCRIPT="$TMP/pass.sh" \
    VG_GATE_SMOKE_SCRIPT="$TMP/pass.sh" VG_GATE_PHP_BIN=php \
    bash "$ROOT/deploy/run-gates.sh" --profile pre-push --json > "$TMP/result.json"
}

FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate
assert_json "$TMP/result.json" 'd["ok"] is True'
assert_json "$TMP/result.json" 'len(d["checks"]) >= 5'
assert_json "$TMP/result.json" 'all(k in d["checks"][0] for k in ("id", "required", "duration_ms", "evidence"))'

if FAKE_DOCKER_UP=0 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate; then
  fail "Docker 없음이 success 로 종료됨"
fi
assert_json "$TMP/result.json" 'd["ok"] is False'
assert_json "$TMP/result.json" 'len([c for c in d["checks"] if c["id"] == "docker-engine" and c["required"] and not c["passed"]]) == 1'

if FAKE_DOCKER_UP=1 FAKE_STACK_STATE=unhealthy FAKE_HTTP_UP=1 run_gate; then
  fail "unhealthy stack 이 success 로 종료됨"
fi
assert_json "$TMP/result.json" 'd["ok"] is False'
assert_json "$TMP/result.json" 'len([c for c in d["checks"] if c["id"] == "smoke" and c["required"] and not c["passed"]]) == 1'

if FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=0 run_gate; then
  fail "HTTP 불응이 success 로 종료됨"
fi
assert_json "$TMP/result.json" 'd["ok"] is False'

VG_SKIP_SMOKE=1 FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate
assert_json "$TMP/result.json" 'd["ok"] is True'
assert_json "$TMP/result.json" 'len([c for c in d["checks"] if c["id"] == "smoke" and c["passed"]]) == 1'

echo "gate_contract_test: 전부 통과"
