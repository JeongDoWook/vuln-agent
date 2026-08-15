#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

cat > "$TMP/good.sql" <<'SQL'
CREATE TABLE tb_host (host_id BIGINT PRIMARY KEY);
CREATE TABLE tb_scan (scan_id BIGINT PRIMARY KEY);
SQL
gzip -c "$TMP/good.sql" > "$TMP/good.sql.gz"
printf 'not-a-gzip' > "$TMP/broken.sql.gz"

cat > "$TMP/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = inspect ]; then
  if printf '%s\n' "$*" | grep -q 'Config.Env'; then printf 'MYSQL_DATABASE=vulnagent\n'; else printf 'healthy\n'; fi
  exit 0
fi
if [ "${1:-}" = exec ]; then
  if printf '%s\n' "$*" | grep -q 'COUNT'; then printf '2\n'; else cat >/dev/null || true; fi
  exit 0
fi
exit 1
SH
chmod +x "$TMP/bin/docker"

PATH="$TMP/bin:$PATH" bash "$ROOT/deploy/backup_db.sh" --verify "$TMP/good.sql.gz" fake-db
if PATH="$TMP/bin:$PATH" bash "$ROOT/deploy/backup_db.sh" --verify "$TMP/broken.sql.gz" fake-db; then
  echo "backup_restore_test: 손상 dump 검증이 success 로 종료됨" >&2
  exit 1
fi

echo "backup_restore_test: 전부 통과"
