#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/deploy/run-gates.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FIXTURE="$TMP/gate-root"

fail() { echo "gate_contract_test: FAIL: $*" >&2; exit 1; }

# 인터프리터는 파일에서 한 번만 찾는다(assert_json 이 여러 번 불려도 command -v 를 다시 돌지 않는다).
# 순서 이유: 리눅스 CI 에는 python3 만 있고 python 이 없는 경우가 흔해 python3 를 먼저 본다.
# Windows git-bash 는 반대로 python3 가 없고 python/python.exe 만 있어 그다음으로 내려간다.
# (tests/schema_docs_test.sh 는 Windows 개발 환경 전용이라 python 을 먼저 본다 — 전제가 다르다.)
if command -v python3 >/dev/null 2>&1; then
  python_cmd=python3
elif command -v python >/dev/null 2>&1; then
  python_cmd=python
elif command -v python.exe >/dev/null 2>&1; then
  python_cmd=python.exe
else
  fail 'python이 없어 게이트 계약 JSON 단언을 실행할 수 없습니다'
fi

assert_json() {
  local file="$1" expr="$2"
  "$python_cmd" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(0 if eval(sys.argv[2], {"d":d}) else 1)' "$file" "$expr" \
    || fail "JSON assertion: $expr"
}

mkdir -p "$FIXTURE/bin" "$FIXTURE/deploy" "$FIXTURE/server" "$FIXTURE/tests"
cat > "$FIXTURE/bin/docker" <<'SH'
#!/usr/bin/env bash
set -eu
case "${1:-}" in
  info) [ "${FAKE_DOCKER_UP:-1}" = 1 ] ;;
  inspect)
    if printf '%s\n' "$*" | grep -q '/var/www/html'; then
      printf '%s/server\n' "$VG_GATE_ROOT"
    else
      printf '%s\n' "${FAKE_STACK_STATE:-healthy}"
    fi
    ;;
  *) exit 0 ;;
esac
SH
cat > "$FIXTURE/bin/curl" <<'SH'
#!/usr/bin/env bash
[ "${FAKE_HTTP_UP:-1}" = 1 ]
SH
cat > "$FIXTURE/bin/php" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$FIXTURE/pass.sh" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$FIXTURE/deploy/gates.tsv" <<'TSV'
# id|profile|required|depends_on|description
source-state|pre-push|true|-|Fixture SHA and cleanliness
docker-engine|pre-push|true|source-state|Docker
web-stack|pre-push|true|docker-engine|Web mount
web-http|pre-push|true|web-stack|HTTP
migration-rehearsal|pre-push|true|docker-engine|Disposable migration
smoke|pre-push|true|web-http,migration-rehearsal|Smoke
schedule-unit|pre-push|false|-|Schedule
TSV
: > "$FIXTURE/deploy/empty.tsv"
printf 'tracked\n' > "$FIXTURE/tracked.txt"
chmod +x "$FIXTURE/bin/docker" "$FIXTURE/bin/curl" "$FIXTURE/bin/php" "$FIXTURE/pass.sh"

# pre-push 훅에서(즉 이 스크립트가 실제 push 도중 smoke.sh 를 거쳐 호출될 때) git 이 하위
# 프로세스에 GIT_DIR/GIT_WORK_TREE 를 물려줄 수 있다 — 물려받으면 아래 `git -C "$FIXTURE"`
# 호출이 fixture 가 아니라 **실제 저장소**를 대상으로 add/commit 해서 진짜 HEAD 를 fixture
# 스냅샷으로 덮어써 버린다(실제로 겪음: 2026-08-26, submission-hygiene-audit). fixture git 은
# 완전히 새 저장소여야 하므로 물려받을 수 있는 GIT_* 환경변수를 전부 지우고 시작한다.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CEILING_DIRECTORIES

git -C "$FIXTURE" init -q
git -C "$FIXTURE" config user.name gate-contract
git -C "$FIXTURE" config user.email gate-contract@example.invalid
git -C "$FIXTURE" add .
git -C "$FIXTURE" commit -qm 'test fixture'
TEST_SHA=$(git -C "$FIXTURE" rev-parse HEAD)

run_gate() {
  VG_GATE_TEST_MODE=1 VG_GATE_ROOT="$FIXTURE" \
    VG_GATE_MANIFEST="$FIXTURE/deploy/gates.tsv" \
    VG_GATE_DOCKER_BIN="$FIXTURE/bin/docker" VG_GATE_CURL_BIN="$FIXTURE/bin/curl" \
    VG_GATE_PHP_BIN="$FIXTURE/bin/php" VG_GATE_SMOKE_SCRIPT="$FIXTURE/pass.sh" \
    VG_GATE_MIGRATION_TEST="$FIXTURE/pass.sh" VG_GATE_BACKUP_TEST="$FIXTURE/pass.sh" \
    VG_GATE_SCHEMA_DOCS_TEST="$FIXTURE/pass.sh" VG_WEB_CONTAINER=vulnagent-web-dev \
    bash "$RUNNER" --test-mode --profile pre-push --expect-sha "$TEST_SHA" --json > "$TMP/result.json"
}

FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate
assert_json "$TMP/result.json" 'd["ok"] is True'
assert_json "$TMP/result.json" 'len(d["checks"]) == 7'
assert_json "$TMP/result.json" 'all(k in d["checks"][0] for k in ("id", "required", "duration_ms", "evidence"))'

if FAKE_DOCKER_UP=0 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate; then
  fail "Docker 없음이 success로 종료됨"
fi
assert_json "$TMP/result.json" 'd["ok"] is False'
assert_json "$TMP/result.json" 'len([c for c in d["checks"] if c["id"] == "docker-engine" and c["required"] and not c["passed"]]) == 1'

if FAKE_DOCKER_UP=1 FAKE_STACK_STATE=unhealthy FAKE_HTTP_UP=1 run_gate; then
  fail "unhealthy stack이 success로 종료됨"
fi
assert_json "$TMP/result.json" 'd["ok"] is False'
assert_json "$TMP/result.json" 'len([c for c in d["checks"] if c["id"] == "smoke" and c["required"] and not c["passed"]]) == 1'

if FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=0 run_gate; then
  fail "HTTP 불응이 success로 종료됨"
fi
assert_json "$TMP/result.json" 'd["ok"] is False'

# Historical skip flags are inert; the required smoke still executes and passes.
VG_SKIP_SMOKE=1 FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate
assert_json "$TMP/result.json" 'len([c for c in d["checks"] if c["id"] == "smoke" and c["passed"]]) == 1'

# A production invocation must reject manifest and pass-script substitution.
if VG_GATE_MANIFEST="$FIXTURE/deploy/empty.tsv" bash "$RUNNER" --profile central >"$TMP/override.log" 2>&1; then
  fail 'production manifest override가 success로 종료됨'
fi
grep -q 'override rejected' "$TMP/override.log" || fail 'manifest override 거부 근거가 없음'
if VG_GATE_SMOKE_SCRIPT="$FIXTURE/pass.sh" bash "$RUNNER" --profile central >"$TMP/pass-override.log" 2>&1; then
  fail 'production pass-script override가 success로 종료됨'
fi
grep -q 'override rejected' "$TMP/pass-override.log" || fail 'pass-script override 거부 근거가 없음'

# Even explicit test mode cannot turn an empty manifest into a green result.
if VG_GATE_TEST_MODE=1 VG_GATE_ROOT="$FIXTURE" VG_GATE_MANIFEST="$FIXTURE/deploy/empty.tsv" \
    VG_GATE_DOCKER_BIN="$FIXTURE/bin/docker" VG_GATE_CURL_BIN="$FIXTURE/bin/curl" \
    VG_GATE_PHP_BIN="$FIXTURE/bin/php" VG_GATE_SMOKE_SCRIPT="$FIXTURE/pass.sh" \
    VG_GATE_MIGRATION_TEST="$FIXTURE/pass.sh" VG_GATE_BACKUP_TEST="$FIXTURE/pass.sh" \
    VG_GATE_SCHEMA_DOCS_TEST="$FIXTURE/pass.sh" \
    bash "$RUNNER" --test-mode --profile pre-push >"$TMP/empty.log" 2>&1; then
  fail 'empty test manifest가 success로 종료됨'
fi
grep -q 'no checks' "$TMP/empty.log" || fail 'empty manifest 거부 근거가 없음'

# source-state fails closed for dirty content and for a pushed SHA other than HEAD.
printf 'dirty\n' >> "$FIXTURE/tracked.txt"
if FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate; then
  fail 'dirty bind-mounted tree가 success로 종료됨'
fi
assert_json "$TMP/result.json" 'len([c for c in d["checks"] if c["id"] == "source-state" and c["required"] and not c["passed"]]) == 1'
git -C "$FIXTURE" restore tracked.txt

OLD_TEST_SHA=$TEST_SHA
TEST_SHA=0000000000000000000000000000000000000000
if FAKE_DOCKER_UP=1 FAKE_STACK_STATE=healthy FAKE_HTTP_UP=1 run_gate; then
  fail 'pushed SHA/HEAD mismatch가 success로 종료됨'
fi
assert_json "$TMP/result.json" 'd["ok"] is False'
TEST_SHA=$OLD_TEST_SHA

grep -q '^migration-rehearsal|pre-push|true|' "$ROOT/deploy/gates.tsv" || fail 'pre-push disposable migration gate가 required가 아님'
grep -q '^schema-docs|central|true|' "$ROOT/deploy/gates.tsv" || fail 'central schema-docs gate가 required가 아님'
if grep -q '^migration-current|' "$ROOT/deploy/gates.tsv"; then
  fail 'shared-DB migration-current gate가 남아 있음'
fi

echo "gate_contract_test: 전부 통과"
