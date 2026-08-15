#!/usr/bin/env bash
# Common operational gate. Results are always derived from deploy/gates.tsv.
set -uo pipefail

ROOT=${VG_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
MANIFEST=${VG_GATE_MANIFEST:-$ROOT/deploy/gates.tsv}
PROFILE=central
JSON=0
BASE=${VG_SMOKE_BASE:-}

usage() {
  echo "usage: deploy/run-gates.sh [--profile pre-push|central] [--base URL] [--json]" >&2
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) PROFILE=${2:-}; shift 2 ;;
    --base) BASE=${2:-}; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$PROFILE" in pre-push|central) ;; *) usage; exit 2 ;; esac
[ -r "$MANIFEST" ] || { echo "gate manifest unreadable: $MANIFEST" >&2; exit 2; }

DOCKER_BIN=${VG_GATE_DOCKER_BIN:-docker}
CURL_BIN=${VG_GATE_CURL_BIN:-curl}
PHP_BIN=${VG_GATE_PHP_BIN:-php}
MIGRATE_SCRIPT=${VG_GATE_MIGRATE_SCRIPT:-$ROOT/deploy/migrate.sh}
SMOKE_SCRIPT=${VG_GATE_SMOKE_SCRIPT:-$ROOT/tests/smoke.sh}
MIGRATION_TEST=${VG_GATE_MIGRATION_TEST:-$ROOT/tests/migration_rehearsal_test.sh}
BACKUP_TEST=${VG_GATE_BACKUP_TEST:-$ROOT/tests/backup_restore_test.sh}

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
DB_CONTAINER=${VG_DB_CONTAINER:-vulnagent-db-dev}
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
check_migration_current() {
  [ -f "$MIGRATE_SCRIPT" ] || { echo "migration runner missing: $MIGRATE_SCRIPT"; return 1; }
  bash "$MIGRATE_SCRIPT" "$DB_CONTAINER"
}
check_smoke() {
  [ -x "$SMOKE_SCRIPT" ] || { echo "required smoke is missing or not executable: $SMOKE_SCRIPT"; return 1; }
  "$SMOKE_SCRIPT" "$BASE"
}
check_schedule_unit() {
  if command -v "$PHP_BIN" >/dev/null 2>&1; then
    "$PHP_BIN" "$ROOT/tests/schedule_test.php"
  else
    "$DOCKER_BIN" run --rm -v "$ROOT:/work:ro" -w /work "${VG_GATE_APP_IMAGE:-vulnagent-app:latest}" php tests/schedule_test.php
  fi
}
check_migration_rehearsal() { bash "$MIGRATION_TEST"; }
check_backup_restore() { bash "$BACKUP_TEST"; }

run_check() {
  case "$1" in
    docker-engine) check_docker_engine ;;
    web-stack) check_web_stack ;;
    web-http) check_web_http ;;
    migration-current) check_migration_current ;;
    smoke) check_smoke ;;
    schedule-unit) check_schedule_unit ;;
    migration-rehearsal) check_migration_rehearsal ;;
    backup-restore) check_backup_restore ;;
    *) echo "unknown gate id: $1"; return 1 ;;
  esac
}

now_ms() {
  local n
  n=$(date +%s%3N 2>/dev/null || true)
  case "$n" in *N*|'') echo $(( $(date +%s) * 1000 )) ;; *) echo "$n" ;; esac
}

index=0
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
  elif run_check "$id" >"$out" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  end=$(now_ms)
  DURATIONS[index]=$((end - start))
  evidence=$(tr '\r\n\t' '   ' < "$out" | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//' | cut -c1-1000)
  EVIDENCE[index]=${evidence:-"exit=$rc"}
  if [ "$rc" -eq 0 ]; then PASSED[index]=true; STATUS[$id]=passed; else PASSED[index]=false; STATUS[$id]=failed; fi
  index=$((index + 1))
done < "$MANIFEST"

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
