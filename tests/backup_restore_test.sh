#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state"

cat > "$TMP/good.sql" <<'SQL'
CREATE TABLE tb_host (
  host_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  fqdn VARCHAR(255) NOT NULL,
  PRIMARY KEY (host_id),
  UNIQUE KEY uq_host_fqdn (fqdn)
);
CREATE TABLE tb_scan (
  scan_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (scan_id),
  CONSTRAINT fk_scan_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE
);
INSERT INTO tb_host (host_id, fqdn) VALUES (1, 'backup-fixture.example');
INSERT INTO tb_scan (scan_id, host_id) VALUES (10, 1);
SQL
cat > "$TMP/missing-data.sql" <<'SQL'
-- NO_CORE_ROWS
CREATE TABLE tb_host (host_id BIGINT UNSIGNED NOT NULL PRIMARY KEY, fqdn VARCHAR(255) NOT NULL, UNIQUE KEY uq_host_fqdn (fqdn));
CREATE TABLE tb_scan (scan_id BIGINT UNSIGNED NOT NULL PRIMARY KEY, host_id BIGINT UNSIGNED NOT NULL,
  CONSTRAINT fk_scan_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE);
SQL
cat > "$TMP/missing-constraint.sql" <<'SQL'
-- MISSING_UNIQUE
CREATE TABLE tb_host (host_id BIGINT UNSIGNED NOT NULL PRIMARY KEY, fqdn VARCHAR(255) NOT NULL);
CREATE TABLE tb_scan (scan_id BIGINT UNSIGNED NOT NULL PRIMARY KEY, host_id BIGINT UNSIGNED NOT NULL,
  CONSTRAINT fk_scan_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE);
INSERT INTO tb_host (host_id, fqdn) VALUES (1, 'backup-fixture.example');
INSERT INTO tb_scan (scan_id, host_id) VALUES (10, 1);
SQL
gzip -c "$TMP/good.sql" > "$TMP/good.sql.gz"
gzip -c "$TMP/missing-data.sql" > "$TMP/missing-data.sql.gz"
gzip -c "$TMP/missing-constraint.sql" > "$TMP/missing-constraint.sql.gz"
printf 'not-a-gzip' > "$TMP/broken.sql.gz"

cat > "$TMP/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s\n' "$*" >> "$MOCK_LOG"
}

manifest() {
  printf '%s\n' \
    $'COLUMN\t74625F686F7374\t000001\t686F73745F6964\t626967696E7420756E7369676E6564\t4E4F\t-\t6175746F5F696E6372656D656E74' \
    $'COLUMN\t74625F7363616E\t000001\t7363616E5F6964\t626967696E7420756E7369676E6564\t4E4F\t-\t6175746F5F696E6372656D656E74' \
    $'FOREIGN_KEY\t74625F7363616E\t666B5F7363616E5F686F7374\t000001\t686F73745F6964\t74625F686F7374\t686F73745F6964\t5245535452494354\t43415343414445' \
    $'NOT_NULL\t74625F686F7374\t000001\t686F73745F6964' \
    $'NOT_NULL\t74625F7363616E\t000001\t7363616E5F6964' \
    $'PRIMARY_KEY\t74625F686F7374\t5052494D415259\t000001\t686F73745F6964' \
    $'PRIMARY_KEY\t74625F7363616E\t5052494D415259\t000001\t7363616E5F6964' \
    $'TABLE\t74625F686F7374\t42415345205441424C45\t496E6E6F4442\t757466386D62345F756E69636F64655F6369' \
    $'TABLE\t74625F7363616E\t42415345205441424C45\t496E6E6F4442\t757466386D62345F756E69636F64655F6369'
  if ! grep -q 'MISSING_UNIQUE' "$MOCK_STATE/import.sql" 2>/dev/null; then
    printf '%s\n' $'UNIQUE\t74625F686F7374\t75715F686F73745F6671646E\t000001\t6671646E'
  fi
}

log "$@"
case "${1:-}" in
  inspect)
    if printf '%s\n' "$*" | grep -q 'Config.Env'; then
      printf 'MYSQL_DATABASE=vulnagent\n'
    elif printf '%s\n' "$*" | grep -q 'Config.Image'; then
      printf 'mysql:test\n'
    else
      printf 'true\n'
    fi
    ;;
  run)
    printf 'abc123\n'
    ;;
  info)
    # 디스크 사전 확인이 보는 docker 데이터 경로. 실제로 존재하는 경로여야 df 가 돈다.
    printf '%s\n' "$MOCK_STATE"
    ;;
  rm)
    ;;
  exec)
    shift
    while [ "${1:-}" = "-i" ]; do shift; done
    target=${1:-}
    shift || true
    command_line="$*"
    if printf '%s\n' "$command_line" | grep -q 'information_schema.SCHEMATA'; then
      printf 'vulnagent\n'
      exit 0
    fi
    if [ "$target" = fake-db ]; then
      if printf '%s\n' "$command_line" | grep -q 'mysqldump'; then
        cat "$MOCK_DUMP_FILE"
      elif printf '%s\n' "$command_line" | grep -q 'AS db_size'; then
        # 원본 DB 크기(바이트). MOCK_DB_BYTES 를 키우면 디스크 사전 확인 실패를 재현한다.
        printf '%s\n' "${MOCK_DB_BYTES:-1048576}"
      elif printf '%s\n' "$command_line" | grep -q 'AS manifest'; then
        # Source is the canonical current schema. It must never depend on the untrusted import marker.
        saved="$MOCK_STATE/import.sql"
        mv "$saved" "$saved.tmp" 2>/dev/null || true
        manifest
        mv "$saved.tmp" "$saved" 2>/dev/null || true
      elif printf '%s\n' "$command_line" | grep -q 'AS core_data'; then
        printf 'orphan_scans\t0\ntb_host\t1\ntb_scan\t1\n'
      else
        log "SOURCE_UNEXPECTED $command_line"
        cat >/dev/null || true
        exit 97
      fi
    elif printf '%s\n' "$command_line" | grep -q 'AS manifest'; then
      manifest
    elif printf '%s\n' "$command_line" | grep -q 'AS core_data'; then
      if grep -q 'NO_CORE_ROWS' "$MOCK_STATE/import.sql" 2>/dev/null; then
        printf 'orphan_scans\t0\ntb_host\t0\ntb_scan\t0\n'
      else
        printf 'orphan_scans\t0\ntb_host\t1\ntb_scan\t1\n'
      fi
    else
      cat > "$MOCK_STATE/import.sql"
      log "IMPORT target=$target"
    fi
    ;;
  *)
    exit 1
    ;;
esac
SH
chmod +x "$TMP/bin/docker"

export MOCK_LOG="$TMP/docker.log"
export MOCK_STATE="$TMP/state"
export MOCK_DUMP_FILE="$TMP/good.sql"

run_verify() {
  PATH="$TMP/bin:$PATH" bash "$ROOT/deploy/backup_db.sh" --verify "$1" fake-db
}

run_verify "$TMP/good.sql.gz"
if grep -q '^SOURCE_UNEXPECTED' "$MOCK_LOG"; then
  echo "backup_restore_test: untrusted dump가 source DB exec로 전달됨" >&2
  exit 1
fi
run_line=$(grep '^run ' "$MOCK_LOG" | head -1)
case "$run_line" in
  *'--network none'*'-v /var/lib/mysql '*'--env MYSQL_ALLOW_EMPTY_PASSWORD=yes'*'mysql:test'*) ;;
  *) echo "backup_restore_test: disposable isolation 옵션 누락: $run_line" >&2; exit 1 ;;
esac
# 검증 DB 는 RAM(tmpfs)이 아니라 디스크여야 한다 — 운영 DB 크기만큼 RAM 을 먹어 호스트가
# 마비된 2026-08-16 사고의 재발 방지선이다.
case "$run_line" in
  *'--tmpfs /var/lib/mysql'*)
    echo "backup_restore_test: /var/lib/mysql 이 다시 tmpfs(RAM) 로 돌아감: $run_line" >&2; exit 1 ;;
esac
# 익명 볼륨은 -v 없는 docker rm 으로 안 지워진다. 정리 경로가 rm -fv 인지 본다.
if ! grep -q '^rm -fv ' "$MOCK_LOG"; then
  echo "backup_restore_test: 검증 컨테이너 정리가 rm -fv 가 아님(익명 볼륨이 디스크에 남는다)" >&2
  exit 1
fi
if printf '%s\n' "$run_line" | grep -Eq 'fake-db|/run/secrets|vulnagent[_-]db'; then
  echo "backup_restore_test: disposable 컨테이너가 운영 DB/secret을 참조함: $run_line" >&2
  exit 1
fi
if ! grep -q '^IMPORT target=abc123$' "$MOCK_LOG"; then
  echo "backup_restore_test: dump가 disposable 컨테이너로 전달되지 않음" >&2
  exit 1
fi

if run_verify "$TMP/broken.sql.gz"; then
  echo "backup_restore_test: 손상 dump 검증이 success 로 종료됨" >&2
  exit 1
fi
if run_verify "$TMP/missing-data.sql.gz"; then
  echo "backup_restore_test: 핵심 데이터 없는 dump 검증이 success 로 종료됨" >&2
  exit 1
fi
if run_verify "$TMP/missing-constraint.sql.gz"; then
  echo "backup_restore_test: UNIQUE 제약 누락 dump 검증이 success 로 종료됨" >&2
  exit 1
fi

# 디스크 사전 확인: 여유보다 많이 요구하면 **컨테이너를 띄우기 전에** 실패해야 한다.
# (다 채운 뒤 'table is full' 로 죽는 것보다 낫다 — 2026-08-16 운영 배포 중단의 교훈)
: > "$MOCK_LOG"
if VERIFY_DISK_HEADROOM_MULT=100000000 run_verify "$TMP/good.sql.gz"; then
  echo "backup_restore_test: 디스크 부족인데 검증이 success 로 종료됨" >&2
  exit 1
fi
if grep -q '^run ' "$MOCK_LOG"; then
  echo "backup_restore_test: 디스크 사전 확인 실패인데 검증 컨테이너가 떴음" >&2
  exit 1
fi
: > "$MOCK_LOG"

# 실패 quarantine도 정상 백업 KEEP(7)과 같은 수만 남아야 한다. 기존 9개 + 새 실패 1개에서
# 가장 오래된 3개가 제거되고, 실패한 새 dump는 정상 .sql.gz 패턴 밖에 남는지 함께 본다.
BACKUP_DIR="$TMP/backups"
mkdir -p "$BACKUP_DIR"
for i in 1 2 3 4 5 6 7 8 9; do
  old="$BACKUP_DIR/vulnagent_20200101_00000${i}.sql.gz.failed"
  printf 'old failed dump %s\n' "$i" > "$old"
  touch -t "20200101000${i}" "$old"
done
export MOCK_DUMP_FILE="$TMP/missing-data.sql"
if PATH="$TMP/bin:$PATH" DB_CONTAINER=fake-db BACKUP_DIR="$BACKUP_DIR" \
    bash "$ROOT/deploy/backup_db.sh"; then
  echo "backup_restore_test: restore 검증 실패 backup이 success 로 종료됨" >&2
  exit 1
fi
failed_count=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'vulnagent_*.sql.gz.failed' | wc -l | tr -d ' ')
if [ "$failed_count" != 7 ]; then
  echo "backup_restore_test: failed quarantine 보존 수 불일치($failed_count/7)" >&2
  exit 1
fi
if [ -e "$BACKUP_DIR/vulnagent_20200101_000001.sql.gz.failed" ]; then
  echo "backup_restore_test: 가장 오래된 failed quarantine이 정리되지 않음" >&2
  exit 1
fi
if find "$BACKUP_DIR" -maxdepth 1 -type f -name 'vulnagent_*.sql.gz' | grep -q .; then
  echo "backup_restore_test: 검증 실패 dump가 정상 backup 패턴에 남음" >&2
  exit 1
fi

echo "backup_restore_test: 전부 통과"
