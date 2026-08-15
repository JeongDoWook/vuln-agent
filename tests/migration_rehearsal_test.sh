#!/usr/bin/env bash
# Required migration gate: initialize the real db/*.sql baseline and apply every
# tracked migration inside an isolated MySQL. Never point branch SQL at shared dev.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

fail() { printf 'migration_rehearsal_test: FAIL: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail 'docker가 없어 disposable MySQL 검사를 실행할 수 없습니다'
docker info >/dev/null 2>&1 || fail 'Docker daemon이 응답하지 않습니다(성공/skip으로 처리하지 않음)'

TMP=$(mktemp -d)
CONTAINER="vg-migration-rehearsal-$$-${RANDOM}"
case "$CONTAINER" in vg-migration-rehearsal-*) ;; *) fail "안전하지 않은 컨테이너 이름: $CONTAINER" ;; esac

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  case "$TMP" in "${TMPDIR:-/tmp}"/*|/tmp/*) rm -rf -- "$TMP" ;; esac
}
trap cleanup EXIT

printf '%s' 'vg-migration-rehearsal-disposable-only' > "$TMP/mysql_root_password"
if command -v cygpath >/dev/null 2>&1; then
  DB_MOUNT=$(cygpath -w "$ROOT/db")
  SECRET_MOUNT=$(cygpath -w "$TMP/mysql_root_password")
else
  DB_MOUNT="$ROOT/db"
  SECRET_MOUNT="$TMP/mysql_root_password"
fi

MSYS_NO_PATHCONV=1 docker run -d --name "$CONTAINER" \
  --tmpfs /var/lib/mysql:rw,noexec,nosuid,size=1g \
  -e MYSQL_DATABASE=vulnagent \
  -e MYSQL_ROOT_PASSWORD_FILE=/run/secrets/mysql_root_password \
  -v "$DB_MOUNT:/docker-entrypoint-initdb.d:ro" \
  -v "$SECRET_MOUNT:/run/secrets/mysql_root_password:ro" \
  mysql:8.0 >/dev/null

ready=0
for _ in $(seq 1 90); do
  # During image initialization the entrypoint starts a temporary mysqld that
  # also answers SELECT 1, then stops it before exec'ing the final PID 1. Requiring
  # mysqld as PID 1 prevents the gate from racing that shutdown window.
  if docker exec "$CONTAINER" sh -c \
      'case "$(cat /proc/1/comm)" in mysqld*) ;; *) exit 1 ;; esac; MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot -N -B -e "SELECT 1"' \
      >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [ "$ready" != 1 ]; then
  docker logs "$CONTAINER" >&2
  fail 'disposable MySQL 준비 실패'
fi

mysql_query() {
  docker exec "$CONTAINER" sh -c \
    'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot -N -B --database=vulnagent -e "$1"' _ "$1"
}

# The image entrypoint must have initialized the real baseline, rather than a
# synthetic empty schema that would let migrations pass without their parents.
core_tables=$(mysql_query "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='vulnagent' AND TABLE_NAME IN ('tb_hosts','tb_scans')")
[ "$core_tables" = 2 ] || fail "real init schema incomplete(core_tables=$core_tables)"

# Preflight must still bind the requested schema to the container's canonical DB.
if MYSQL_DATABASE=wrong MIGRATION_MIN_FREE_KB=131072 \
    bash deploy/migrate.sh "$CONTAINER" --preflight >"$TMP/mismatch.log" 2>&1; then
  fail 'DB name mismatch가 success로 종료됨'
fi
grep -q 'MYSQL_DATABASE' "$TMP/mismatch.log" || fail 'DB name mismatch 근거가 출력되지 않음'

# Supply real recovery evidence to the preflight, then apply the complete set.
docker exec "$CONTAINER" sh -c \
  'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysqldump -h127.0.0.1 -uroot --no-data vulnagent' |
  gzip > "$TMP/pre-migration.sql.gz"
gzip -t "$TMP/pre-migration.sql.gz" || fail 'pre-migration dump가 유효한 gzip이 아님'

run_migrate() {
  MYSQL_DATABASE=vulnagent MIGRATION_MIN_FREE_KB=131072 MIGRATION_REQUIRE_BACKUP=1 \
    MIGRATION_BACKUP_FILE="$TMP/pre-migration.sql.gz" \
    bash deploy/migrate.sh "$CONTAINER"
}

run_migrate > "$TMP/first.log"
migration_files=$(find db/migrations -maxdepth 1 -type f -name '*.sql' | wc -l | tr -d '[:space:]')
history_rows=$(mysql_query 'SELECT COUNT(*) FROM tb_schema_migrations')
[ "$history_rows" = "$migration_files" ] || {
  fail "migration history mismatch(files=$migration_files rows=$history_rows)"
}

# A complete rerun must be a no-op against the real schema.
run_migrate > "$TMP/second.log"
grep -Eq '적용[[:space:]]+0[[:space:]]+·[[:space:]]+스킵[[:space:]]+' "$TMP/second.log" || {
  fail 'complete migration rerun was not a no-op'
}

# Rehearse the real DDL/history gap: remove one history row, rerun that migration,
# and require the runner to restore the row without damaging the initialized DB.
gap_file=$(find db/migrations -maxdepth 1 -type f -name '*.sql' -printf '%f\n' | sort | tail -1)
[ -n "$gap_file" ] || fail 'migration file이 없음'
mysql_query "DELETE FROM tb_schema_migrations WHERE filename='$gap_file'" >/dev/null
run_migrate > "$TMP/gap.log"
gap_rows=$(mysql_query "SELECT COUNT(*) FROM tb_schema_migrations WHERE filename='$gap_file'")
[ "$gap_rows" = 1 ] || fail "history-gap recovery failed(file=$gap_file)"

printf 'migration_rehearsal_test: ok (disposable MySQL init + %s migrations + rerun + history-gap)\n' "$migration_files"
