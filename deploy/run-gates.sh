#!/usr/bin/env bash
# Common operational gate. Results are always derived from deploy/gates.tsv.
set -uo pipefail

SOURCE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ROOT=$SOURCE_ROOT
PROFILE=central
JSON=0
BASE=
TEST_MODE=0
EXPECTED_SHA=

usage() {
  echo "usage: deploy/run-gates.sh [--profile pre-push|central] [--base URL] [--expect-sha SHA] [--json]" >&2
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) PROFILE=${2:-}; shift 2 ;;
    --base) BASE=${2:-}; shift 2 ;;
    --expect-sha) EXPECTED_SHA=${2:-}; shift 2 ;;
    --json) JSON=1; shift ;;
    --test-mode) TEST_MODE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$PROFILE" in pre-push|central) ;; *) usage; exit 2 ;; esac

# Production gates are repository contracts, not an environment-variable API. In
# particular, accepting a different manifest or a script that merely exits zero
# turns a required check into a false green. Contract tests get a deliberately
# awkward, two-part opt-in and may only inject files below a disposable root.
PROTECTED_OVERRIDES=(
  VG_GATE_ROOT VG_GATE_MANIFEST VG_GATE_DOCKER_BIN VG_GATE_CURL_BIN VG_GATE_PHP_BIN
  VG_GATE_SMOKE_SCRIPT VG_GATE_MIGRATION_TEST VG_GATE_BACKUP_TEST
  VG_GATE_SCHEMA_DOCS_TEST VG_GATE_SCHEMA_DOCS_PRECHECK_SCRIPT
  VG_GATE_AGENT_SIGNATURE_SCRIPT VG_GATE_AGENT_EXPORT_SCRIPT
  VG_GATE_APP_IMAGE VG_WEB_CONTAINER VG_DB_CONTAINER VG_SMOKE_BASE
)

canonical_dir() { (cd "$1" 2>/dev/null && pwd -P); }
require_test_path() {
  local label="$1" path="$2" parent resolved
  [ -n "$path" ] || { echo "test gate override missing: $label" >&2; exit 2; }
  [ -e "$path" ] || { echo "test gate override missing on disk: $label=$path" >&2; exit 2; }
  [ ! -L "$path" ] || { echo "test gate override cannot be a symlink: $label=$path" >&2; exit 2; }
  parent=$(canonical_dir "$(dirname "$path")") || {
    echo "test gate override parent unreadable: $label=$path" >&2
    exit 2
  }
  resolved="$parent/$(basename "$path")"
  case "$resolved" in "$ROOT"/*) ;; *)
    echo "test gate override escapes disposable root: $label=$path" >&2
    exit 2
  esac
}

if [ "$TEST_MODE" -eq 1 ]; then
  [ "${VG_GATE_TEST_MODE:-0}" = 1 ] || {
    echo "--test-mode requires VG_GATE_TEST_MODE=1" >&2
    exit 2
  }
  [ -n "${VG_GATE_ROOT:-}" ] || { echo "test gate root is required" >&2; exit 2; }
  ROOT=$(canonical_dir "$VG_GATE_ROOT") || { echo "test gate root unreadable: $VG_GATE_ROOT" >&2; exit 2; }
  tmp_root=$(canonical_dir "${TMPDIR:-/tmp}") || { echo "temporary root is unreadable" >&2; exit 2; }
  case "$ROOT" in "$tmp_root"/*) ;; *)
    echo "test gate root must be disposable and below $tmp_root: $ROOT" >&2
    exit 2
  esac
  [ "$ROOT" != "$SOURCE_ROOT" ] || { echo "test gate root cannot be the source repository" >&2; exit 2; }

  MANIFEST=${VG_GATE_MANIFEST:-}
  DOCKER_BIN=${VG_GATE_DOCKER_BIN:-}
  CURL_BIN=${VG_GATE_CURL_BIN:-}
  PHP_BIN=${VG_GATE_PHP_BIN:-}
  SMOKE_SCRIPT=${VG_GATE_SMOKE_SCRIPT:-}
  MIGRATION_TEST=${VG_GATE_MIGRATION_TEST:-}
  BACKUP_TEST=${VG_GATE_BACKUP_TEST:-}
  SCHEMA_DOCS_TEST=${VG_GATE_SCHEMA_DOCS_TEST:-}
  # precheck 스크립트는 모든 fixture 가 주입하지는 않는다(주입 안 한 fixture 는 manifest 에
  # 이 gate 행 자체가 없다). 그래서 필수 목록에 넣지 않고, 주입한 경우에만 다른 override 와
  # 같은 규칙(디스크 존재·심링크 금지·disposable root 안)으로 검증한다.
  SCHEMA_DOCS_PRECHECK=${VG_GATE_SCHEMA_DOCS_PRECHECK_SCRIPT:-}
  # 에이전트 서명 검사도 같은 이유로 선택적이다 — 주입한 fixture 만 검증한다.
  AGENT_SIGNATURE_CHECK=${VG_GATE_AGENT_SIGNATURE_SCRIPT:-}
  # 서브셸 export 계약 검사도 같다 — 주입한 fixture 만 검증한다.
  AGENT_EXPORT_CHECK=${VG_GATE_AGENT_EXPORT_SCRIPT:-}
  for item in \
    "manifest:$MANIFEST" "docker:$DOCKER_BIN" "curl:$CURL_BIN" "php:$PHP_BIN" \
    "smoke:$SMOKE_SCRIPT" "migration-test:$MIGRATION_TEST" \
    "backup-test:$BACKUP_TEST" "schema-docs-test:$SCHEMA_DOCS_TEST"; do
    require_test_path "${item%%:*}" "${item#*:}"
  done
  [ -z "$SCHEMA_DOCS_PRECHECK" ] || require_test_path schema-docs-precheck "$SCHEMA_DOCS_PRECHECK"
  [ -z "$AGENT_SIGNATURE_CHECK" ] || require_test_path agent-signature "$AGENT_SIGNATURE_CHECK"
  [ -z "$AGENT_EXPORT_CHECK" ] || require_test_path agent-export "$AGENT_EXPORT_CHECK"
else
  for name in "${PROTECTED_OVERRIDES[@]}" VG_GATE_TEST_MODE; do
    if [ "${!name+x}" = x ]; then
      echo "gate override rejected outside explicit test mode: $name" >&2
      exit 2
    fi
  done
  MANIFEST=$ROOT/deploy/gates.tsv
  DOCKER_BIN=docker
  CURL_BIN=curl
  PHP_BIN=php
  SMOKE_SCRIPT=$ROOT/tests/smoke.sh
  MIGRATION_TEST=$ROOT/tests/migration_rehearsal_test.sh
  BACKUP_TEST=$ROOT/tests/backup_restore_test.sh
  SCHEMA_DOCS_TEST=$ROOT/tests/schema_docs_test.sh
  SCHEMA_DOCS_PRECHECK=$ROOT/tests/schema_docs_precheck.sh
  AGENT_SIGNATURE_CHECK=$ROOT/tests/agent_signature_check.sh
  AGENT_EXPORT_CHECK=$ROOT/tests/agent_export_contract_test.sh
fi
[ -r "$MANIFEST" ] || { echo "gate manifest unreadable: $MANIFEST" >&2; exit 2; }

WT_NAME=""
# Docker Desktop에서 Git Bash의 pwd는 실제 Windows 경로 대신 내부 bind-mount
# 경로로 보일 수 있다. linked worktree의 .git 파일은 이 경우에도 worktree
# 이름을 안정적으로 보존하므로 그것을 우선 사용한다.
if [ -f "$ROOT/.git" ]; then
  gitdir=$(sed -n 's/^gitdir:[[:space:]]*//p' "$ROOT/.git" | tr '\\' '/')
  case "$gitdir" in */worktrees/*) WT_NAME=$(basename "$gitdir") ;; esac
elif [ "$(basename "$(dirname "$ROOT")")" = wt ]; then
  WT_NAME=$(basename "$ROOT")
fi
WEB_CONTAINER=${VG_WEB_CONTAINER:-vulnagent-web-dev${WT_NAME:+-$WT_NAME}}
if [ -z "$BASE" ]; then
  WEB_PORT=$(sed -n 's/^WEB_PORT=\([0-9][0-9]*\).*/\1/p' "$ROOT/deploy/.env.dev" 2>/dev/null | head -1)
  BASE="http://localhost:${WEB_PORT:-8000}"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
declare -a IDS REQUIRED PASSED DURATIONS EVIDENCE
declare -A STATUS

normalize_path() {
  local p="$1"
  if command -v cygpath >/dev/null 2>&1; then
    p=$(cygpath -am "$p" 2>/dev/null || printf '%s' "$p")
  elif command -v realpath >/dev/null 2>&1; then
    p=$(realpath -m "$p" 2>/dev/null || printf '%s' "$p")
  fi
  printf '%s' "$p" | tr '\\' '/' | tr '[:upper:]' '[:lower:]' | sed 's:/*$::'
}

check_docker_engine() { "$DOCKER_BIN" info >/dev/null; }
check_web_stack() {
  local state mounted mounted_norm root_norm
  state=$("$DOCKER_BIN" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Running}}{{end}}' "$WEB_CONTAINER") || return 1
  case "$state" in healthy|true) ;; *) echo "container $WEB_CONTAINER state=$state"; return 1 ;; esac
  mounted=$("$DOCKER_BIN" inspect -f '{{range .Mounts}}{{if eq .Destination "/var/www/html"}}{{.Source}}{{end}}{{end}}' "$WEB_CONTAINER") || return 1
  [ -n "$mounted" ] || { echo "container $WEB_CONTAINER has no /var/www/html mount"; return 1; }
  mounted_norm=$(normalize_path "$mounted")
  root_norm=$(normalize_path "$ROOT/server")
  if [ "$mounted_norm" != "$root_norm" ]; then
    # Docker Desktop가 같은 Windows 경로를 /mnt/c/... 와 내부 bind-mount
    # 해시 경로 두 형태로 노출한다. 컨테이너명은 .git worktree id로 이미
    # 고정했으므로 이 환경에서만 worktree/server 꼬리도 함께 대조한다.
    case "$mounted_norm" in
      */wt/"$WT_NAME"/server) [ -n "$WT_NAME" ] || return 1 ;;
      *) echo "container $WEB_CONTAINER mounts another tree: $mounted"; return 1 ;;
    esac
  fi
  echo "container=$WEB_CONTAINER state=$state mount=$mounted"
}
check_web_http() {
  "$CURL_BIN" -fsS -o /dev/null --max-time 5 "$BASE/" || return 1
  echo "base=$BASE"
}
check_source_state() {
  local actual dirty
  [ -n "$EXPECTED_SHA" ] || { echo "--expect-sha is required for source-state"; return 1; }
  case "$EXPECTED_SHA" in *[!0-9a-fA-F]*|'') echo "invalid expected SHA: $EXPECTED_SHA"; return 1 ;; esac
  [ "${#EXPECTED_SHA}" -eq 40 ] || { echo "expected SHA must be a full 40-character commit id"; return 1; }
  actual=$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null) || { echo "cannot resolve gate root HEAD"; return 1; }
  [ "$actual" = "$EXPECTED_SHA" ] || { echo "pushed SHA differs from gate root HEAD: push=$EXPECTED_SHA head=$actual"; return 1; }
  dirty=$(git -C "$ROOT" status --porcelain --untracked-files=normal 2>/dev/null) || {
    echo "cannot inspect gate root worktree"; return 1
  }
  [ -z "$dirty" ] || { echo "gate root has uncommitted or untracked files"; return 1; }
  echo "sha=$actual clean=true"
}
check_smoke() {
  [ -x "$SMOKE_SCRIPT" ] || { echo "required smoke is missing or not executable: $SMOKE_SCRIPT"; return 1; }
  "$SMOKE_SCRIPT" "$BASE"
}
check_schedule_unit() {
  if command -v "$PHP_BIN" >/dev/null 2>&1; then
    "$PHP_BIN" "$ROOT/tests/schedule_test.php"
  else
    "$DOCKER_BIN" run --rm -v "$ROOT:/work:ro" -w /work "${VG_GATE_APP_IMAGE:-vulnagent-app:dev}" php tests/schedule_test.php
  fi
}
# 이 push(브랜치)가 origin/main 대비 주어진 경로를 실제로 건드렸는지 본다. 무거운 게이트가
# 자기와 무관한 push 를 붙잡지 않게 하는 용도다. base 를 못 구하거나 diff 자체가 실패하면
# (얕은 clone, origin/main 없음 등) 판단을 모호하게 두지 않고 "바뀐 것으로" 보고 전체 실행에
# fallback 한다 — 속도보다 정확성을 기본값으로 둔다.
# 반환: 0=하나도 안 바뀜(스킵 가능) / 1=바뀌었거나 판단 불가(전체 실행). base 는 GATE_DIFF_BASE.
GATE_DIFF_BASE=""
gate_paths_unchanged() {
  local base
  base=$(git -C "$ROOT" merge-base HEAD origin/main 2>/dev/null) || return 1
  [ -n "$base" ] || return 1
  git -C "$ROOT" diff --quiet "$base" HEAD -- "$@" 2>/dev/null || return 1
  GATE_DIFF_BASE=$base
  return 0
}
check_migration_rehearsal() {
  if gate_paths_unchanged db/migrations 'db/*.sql'; then
    echo "migration-rehearsal: db/ 변경 없음 — 스킵 (base=$GATE_DIFF_BASE)"
    return 0
  fi
  [ -r "$MIGRATION_TEST" ] || { echo "migration rehearsal missing: $MIGRATION_TEST"; return 1; }
  bash "$MIGRATION_TEST"
}
check_backup_restore() {
  [ -r "$BACKUP_TEST" ] || { echo "backup restore test missing: $BACKUP_TEST"; return 1; }
  bash "$BACKUP_TEST"
}
check_schema_docs() {
  # 트리거에 db/ 뿐 아니라 산출물 4종도 넣는다. db/ 를 안 건드리고 산출물만 손으로 고쳐
  # erd.puml 의 마커가 옛 값으로 남고 xlsx 가 안 따라온 사고(7ea8b4d3)가 실제로 있었다 —
  # db/ 만 조건으로 쓰면 그 사고를 그대로 통과시킨다.
  if gate_paths_unchanged db/migrations 'db/*.sql' \
      'docs/dev/데이터베이스.md' 'docs/specs/diagrams/erd.puml' \
      'docs/specs/diagrams/erd.svg' 'docs/specs/테이블명세서.xlsx'; then
    echo "schema-docs: db/ 와 스키마 문서 산출물 변경 없음 — 스킵 (base=$GATE_DIFF_BASE)"
    return 0
  fi
  [ -r "$SCHEMA_DOCS_TEST" ] || { echo "schema docs test missing: $SCHEMA_DOCS_TEST"; return 1; }
  bash "$SCHEMA_DOCS_TEST"
}
check_schema_docs_precheck() {
  [ -r "$SCHEMA_DOCS_PRECHECK" ] || { echo "schema docs precheck missing: $SCHEMA_DOCS_PRECHECK"; return 1; }
  bash "$SCHEMA_DOCS_PRECHECK"
}
# agent/vuln-inventory-agent.sh 와 .sig 가 어긋난 채 push 되는 것을 막는다. 조건 없이 항상
# 돈다 — openssl 만 쓰는 130ms 검사라 조건 분기가 이득이 없고, 이전 커밋이 깨뜨린 서명도
# 다음 push 에서 그대로 잡혀야 한다(#735 는 그렇게 잠들어 있다가 #738 에서 장애가 됐다).
check_agent_signature() {
  [ -r "$AGENT_SIGNATURE_CHECK" ] || { echo "agent signature check missing: $AGENT_SIGNATURE_CHECK"; return 1; }
  bash "$AGENT_SIGNATURE_CHECK"
}
# 수집 함수는 `timeout ... bash -c` 서브셸에서 돈다. 서브셸이 보는 함수는 `export -f` 로 내보낸
# 것뿐이라 헬퍼 export 를 빠뜨리면 그 소스만 조용히 0건이 된다(#735 pip 라이선스 34.8%→6.1%,
# #559 gem 0건). 호출부가 stderr 를 버려 눈에 안 보이고, 단위 테스트는 같은 셸에서 함수를
# 부르므로 구조적으로 못 잡는다 — 그래서 push 단계의 정적 검사로 막는다. 서명 검사와 같은
# 이유로 조건 없이 항상 돈다(스크립트를 읽기만 하는 0.3초 검사라 조건 분기가 이득이 없다).
check_agent_export() {
  [ -r "$AGENT_EXPORT_CHECK" ] || { echo "agent export contract test missing: $AGENT_EXPORT_CHECK"; return 1; }
  bash "$AGENT_EXPORT_CHECK"
}

run_check() {
  case "$1" in
    source-state) check_source_state ;;
    docker-engine) check_docker_engine ;;
    web-stack) check_web_stack ;;
    web-http) check_web_http ;;
    smoke) check_smoke ;;
    schedule-unit) check_schedule_unit ;;
    migration-rehearsal) check_migration_rehearsal ;;
    backup-restore) check_backup_restore ;;
    schema-docs) check_schema_docs ;;
    schema-docs-precheck) check_schema_docs_precheck ;;
    agent-signature) check_agent_signature ;;
    agent-export) check_agent_export ;;
    *) echo "unknown gate id: $1"; return 1 ;;
  esac
}

now_ms() {
  local n
  n=$(date +%s%3N 2>/dev/null || true)
  case "$n" in *N*|'') echo $(( $(date +%s) * 1000 )) ;; *) echo "$n" ;; esac
}

validate_manifest() {
  local id profile required deps description extra line=0 selected=0 required_selected=0 source_selected=0 key
  declare -A seen=()
  while IFS='|' read -r id profile required deps description extra; do
    line=$((line + 1))
    case "$id" in ''|'#'*) continue ;; esac
    description=${description%$'\r'}
    [ -z "${extra:-}" ] || { echo "invalid gate manifest line $line: too many fields" >&2; return 1; }
    case "$profile" in pre-push|central) ;; *) echo "invalid gate profile at line $line: $profile" >&2; return 1 ;; esac
    case "$required" in true|false) ;; *) echo "invalid required flag at line $line: $required" >&2; return 1 ;; esac
    case "$id" in
      source-state|docker-engine|web-stack|web-http|smoke|schedule-unit|migration-rehearsal|backup-restore|schema-docs|schema-docs-precheck|agent-signature|agent-export) ;;
      *) echo "unknown gate id at line $line: $id" >&2; return 1 ;;
    esac
    case "$deps" in
      -) ;;
      ''|,*|*,|*,,*|*[!A-Za-z0-9,-]*) echo "invalid dependencies at line $line: $deps" >&2; return 1 ;;
    esac
    [ -n "$description" ] || { echo "missing gate description at line $line" >&2; return 1; }
    key="$profile:$id"
    [ -z "${seen[$key]:-}" ] || { echo "duplicate gate at line $line: $key" >&2; return 1; }
    seen[$key]=1
    if [ "$profile" = "$PROFILE" ]; then
      selected=$((selected + 1))
      [ "$required" = true ] && required_selected=$((required_selected + 1))
      [ "$id" = source-state ] && source_selected=$((source_selected + 1))
    fi
  done < "$MANIFEST"
  [ "$selected" -gt 0 ] || { echo "gate manifest has no checks for profile=$PROFILE" >&2; return 1; }
  [ "$required_selected" -gt 0 ] || { echo "gate manifest has no required checks for profile=$PROFILE" >&2; return 1; }
  if [ -n "$EXPECTED_SHA" ] && [ "$source_selected" -ne 1 ]; then
    echo "gate manifest must contain exactly one source-state check when --expect-sha is used" >&2
    return 1
  fi
}
validate_manifest || exit 2

index=0
source_state_index=-1
while IFS='|' read -r id profile required deps _description; do
  case "$id" in ''|'#'*) continue ;; esac
  [ "$profile" = "$PROFILE" ] || continue
  IDS[index]=$id
  REQUIRED[index]=$required
  start=$(now_ms)
  dependency_failure=""
  if [ "$deps" != - ]; then
    IFS=',' read -ra dep_list <<< "$deps"
    for dep in "${dep_list[@]}"; do
      if [ "${STATUS[$dep]:-missing}" != passed ]; then dependency_failure=$dep; break; fi
    done
  fi
  out="$TMP/$index.out"
  if [ -n "$dependency_failure" ]; then
    printf 'dependency failed: %s\n' "$dependency_failure" > "$out"
    rc=1
  # The manifest itself is this loop's stdin. A nested shell/test must never be
  # allowed to consume the remaining gate rows and silently shorten the run.
  elif run_check "$id" </dev/null >"$out" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  end=$(now_ms)
  DURATIONS[index]=$((end - start))
  evidence=$(tr '\r\n\t' '   ' < "$out" | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//' | cut -c1-1000)
  EVIDENCE[index]=${evidence:-"exit=$rc"}
  if [ "$rc" -eq 0 ]; then PASSED[index]=true; STATUS[$id]=passed; else PASSED[index]=false; STATUS[$id]=failed; fi
  [ "$id" = source-state ] && source_state_index=$index
  index=$((index + 1))
done < "$MANIFEST"

# Re-check immediately before emitting the result. This catches a concurrent
# commit or edit that happened after the initial source-state gate while the
# runtime checks were using the bind-mounted worktree.
if [ "$source_state_index" -ge 0 ] && ! final_source=$(check_source_state 2>&1); then
  PASSED[source_state_index]=false
  STATUS[source-state]=failed
  EVIDENCE[source_state_index]=$(printf '%s' "$final_source" | tr '\r\n\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//' | cut -c1-1000)
fi

required_failed=0
for ((i=0; i<index; i++)); do
  if [ "${REQUIRED[i]}" = true ] && [ "${PASSED[i]}" != true ]; then required_failed=1; fi
done

json_quote() {
  local s="$1"
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '"%s"' "$s"
}
emit_json() {
  printf '{"schema_version":1,"profile":'; json_quote "$PROFILE"
  printf ',"ok":%s,"checks":[' "$([ "$required_failed" -eq 0 ] && echo true || echo false)"
  for ((i=0; i<index; i++)); do
    [ "$i" -eq 0 ] || printf ','
    printf '{"id":'; json_quote "${IDS[i]}"
    printf ',"required":%s,"passed":%s,"duration_ms":%s,"evidence":' "${REQUIRED[i]}" "${PASSED[i]}" "${DURATIONS[i]}"
    json_quote "${EVIDENCE[i]}"; printf '}'
  done
  printf ']}\n'
}

if [ "$JSON" -eq 1 ]; then emit_json; fi
for ((i=0; i<index; i++)); do
  mark=PASS; [ "${PASSED[i]}" = true ] || mark=FAIL
  printf 'gate: %-4s %-22s required=%-5s %sms - %s\n' "$mark" "${IDS[i]}" "${REQUIRED[i]}" "${DURATIONS[i]}" "${EVIDENCE[i]}" >&2
done
if [ "$required_failed" -eq 0 ]; then
  echo "gate: PASS profile=$PROFILE" >&2
  exit 0
fi
echo "gate: FAIL profile=$PROFILE (required check failed)" >&2
exit 1
