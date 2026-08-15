#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/migrations" "$TMP/state"

cat > "$TMP/migrations/20260815000000_rehearsal.sql" <<'SQL'
CREATE TABLE IF NOT EXISTS tb_rehearsal (id INT PRIMARY KEY);
SQL
printf 'rehearsal backup\n' | gzip > "$TMP/backup.sql.gz"

cat > "$TMP/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
state=${VG_FAKE_STATE:?}
if [ "${1:-}" = inspect ]; then
  if printf '%s\n' "$*" | grep -q 'Config.Env'; then
    printf 'MYSQL_DATABASE=%s\n' "${FAKE_CONTAINER_DB:-vulnagent}"
  else
    printf 'healthy\n'
  fi
  exit 0
fi
[ "${1:-}" = exec ] || exit 1
args="$*"
if printf '%s' "$args" | grep -q 'df -Pk'; then printf '1048576\n'; exit 0; fi
if printf '%s' "$args" | grep -q 'SCHEMA_NAME'; then printf '1\n'; exit 0; fi
if printf '%s' "$args" | grep -q 'SELECT 1 FROM tb_schema_migrations'; then
  [ -f "$state/history" ] && printf '1\n'
  exit 0
fi
if printf '%s' "$args" | grep -q 'INSERT INTO tb_schema_migrations'; then
  if [ "${FAKE_HISTORY_FAIL_ONCE:-0}" = 1 ] && [ ! -f "$state/failed_once" ]; then
    touch "$state/failed_once"
    exit 1
  fi
  touch "$state/history"
  exit 0
fi
if ! printf '%s' "$args" | grep -q -- '-e'; then
  cat >/dev/null
  touch "$state/ddl"
fi
exit 0
SH
chmod +x "$TMP/bin/docker"

run_migrate() {
  PATH="$TMP/bin:$PATH" VG_FAKE_STATE="$TMP/state" MIG_DIR="$TMP/migrations" \
    MIGRATION_REQUIRE_BACKUP=1 MIGRATION_BACKUP_FILE="$TMP/backup.sql.gz" \
    MYSQL_DATABASE="${MYSQL_DATABASE:-vulnagent}" \
    bash "$ROOT/deploy/migrate.sh" fake-db
}

if MYSQL_DATABASE=wrong FAKE_CONTAINER_DB=vulnagent run_migrate >"$TMP/mismatch.log" 2>&1; then
  echo "migration_rehearsal_test: DB name mismatch 미검출" >&2
  exit 1
fi
grep -q 'MYSQL_DATABASE' "$TMP/mismatch.log"

rm -f "$TMP/state"/*
FAKE_CONTAINER_DB=vulnagent run_migrate
FAKE_CONTAINER_DB=vulnagent run_migrate
[ -f "$TMP/state/ddl" ] && [ -f "$TMP/state/history" ]

rm -f "$TMP/state"/*
if FAKE_CONTAINER_DB=vulnagent FAKE_HISTORY_FAIL_ONCE=1 run_migrate; then
  echo "migration_rehearsal_test: 이력 기록 실패가 success 로 종료됨" >&2
  exit 1
fi
[ -f "$TMP/state/ddl" ] && [ ! -f "$TMP/state/history" ]
FAKE_CONTAINER_DB=vulnagent FAKE_HISTORY_FAIL_ONCE=1 run_migrate
[ -f "$TMP/state/history" ]

echo "migration_rehearsal_test: 전부 통과"
