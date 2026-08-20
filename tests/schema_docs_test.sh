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
# 60회에서 90회로 늘렸다. 아래 PID 1 가드 때문에 준비 판정이 임시 mysqld 구간만큼
# 뒤로 밀리므로 여유를 준다 — tests/migration_rehearsal_test.sh 와 같은 90회(x2초)다.
for _ in $(seq 1 90); do
  # 이미지 초기화 중 entrypoint 는 임시 mysqld 를 먼저 띄우는데, 그 임시 서버도
  # SELECT 1 에 답한다. 그것만 보고 준비 완료로 판정하면, 임시 서버가 내려가고
  # 최종 mysqld 가 아직 안 뜬 구간에 migrate.sh 가 걸려 ERROR 2002 로 죽는다.
  # PID 1 이 mysqld 인지 먼저 확인해 그 종료 구간을 건너뛴다 — 불필요한 검사가 아니다.
  # 같은 가드가 tests/migration_rehearsal_test.sh 에도 있다(방식을 둘로 가르지 않는다).
  if docker exec "$container" sh -c \
      'case "$(cat /proc/1/comm)" in mysqld*) ;; *) exit 1 ;; esac; MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot -N -B -e "SELECT 1"' \
      >/dev/null 2>&1; then
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
