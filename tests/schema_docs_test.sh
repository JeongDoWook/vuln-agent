#!/usr/bin/env bash
# Required W2 gate: build an isolated MySQL schema, then compare every tracked
# schema document with that disposable database's information_schema.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail() { printf 'schema docs test: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail 'docker가 없어 required information_schema 검사를 실행할 수 없습니다'
docker info >/dev/null 2>&1 || fail 'Docker daemon이 응답하지 않습니다(성공/skip으로 처리하지 않음)'
if command -v python >/dev/null 2>&1; then
  python_cmd=python
elif command -v python.exe >/dev/null 2>&1; then
  python_cmd=python.exe
else
  fail 'python이 없어 문서 생성기를 실행할 수 없습니다'
fi

tmp="$(mktemp -d)"
container="vg-schema-docs-$$-${RANDOM}"
case "$container" in vg-schema-docs-*) ;; *) fail "안전하지 않은 컨테이너 이름: $container" ;; esac

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  case "$tmp" in "${TMPDIR:-/tmp}"/*|/tmp/*) rm -rf -- "$tmp" ;; esac
}
trap cleanup EXIT

printf '%s' 'vg-schema-docs-disposable-only' > "$tmp/mysql_root_password"
if command -v cygpath >/dev/null 2>&1; then
  db_mount="$(cygpath -w "$root/db")"
  secret_mount="$(cygpath -w "$tmp/mysql_root_password")"
else
  db_mount="$root/db"
  secret_mount="$tmp/mysql_root_password"
fi

MSYS_NO_PATHCONV=1 docker run -d --name "$container" \
  --tmpfs /var/lib/mysql:rw,noexec,nosuid,size=1g \
  -e MYSQL_DATABASE=vulnagent \
  -e MYSQL_ROOT_PASSWORD_FILE=/run/secrets/mysql_root_password \
  -v "$db_mount:/docker-entrypoint-initdb.d:ro" \
  -v "$secret_mount:/run/secrets/mysql_root_password:ro" \
  mysql:8.0 >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$container" sh -c \
      'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot -N -B -e "SELECT 1"' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
[ "$ready" = 1 ] || { docker logs "$container" >&2; fail 'disposable MySQL 준비 실패'; }

# initdb DDL is already applied by the image. Apply the complete migration set
# twice so the snapshot also covers the real runner's ordering/idempotency.
MIGRATION_MIN_FREE_KB=131072 bash deploy/migrate.sh "$container" >/dev/null
MIGRATION_MIN_FREE_KB=131072 bash deploy/migrate.sh "$container" >/dev/null

mode_args=(--check)
if [ "${SCHEMA_DOCS_UPDATE:-0}" = 1 ]; then mode_args=(); fi
"$python_cmd" docs/specs/gen_table_spec.py \
  --source information-schema --mysql-container "$container" --database vulnagent "${mode_args[@]}"
"$python_cmd" docs/specs/gen_table_spec.py \
  --source information-schema --mysql-container "$container" --database vulnagent --check

printf 'schema docs test: ok (disposable information_schema)\n'
