#!/usr/bin/env bash
# =============================================================================
# vuln-agent · DB 백업 (호스트에서 cron 으로 실행)
# =============================================================================
# 컨테이너 안에서 mysqldump 로 덤프해 호스트에서 gzip 압축, $BACKUP_DIR 에 저장한다.
# 오래된 자동 백업(vulnagent_*.sql.gz)은 최신 KEEP 개만 남기고 정리한다.
#
# 설치: crontab -e 로 다음 줄 추가
#   0 4 * * * /apps/vulnagent/app/deploy/backup_db.sh >> /apps/vulnagent/backups/cron.log 2>&1
#   매일 돌리고 KEEP 개(=7일치)만 남긴다. 예전엔 3일 주기(*/3)에 30일치였는데, */3 은
#   일(day-of-month) 필드라 월 경계에서 리셋돼 간격이 들쭉날쭉했다(30일 실행 후 다음은
#   다음 달 3일). 매일이면 그 함정 자체가 없고 복구 시점도 최대 하루 전으로 좁혀진다.
#
# 로컬 dev 에서 시험하려면:
#   DB_CONTAINER=vulnagent-db-dev BACKUP_DIR=/tmp/vg-backup-test bash deploy/backup_db.sh
# 기존 dump만 격리 복원 검증하려면(운영 DB에는 읽기 전용 metadata query만 실행):
#   bash deploy/backup_db.sh --verify /path/to/dump.sql.gz [db컨테이너명]
# =============================================================================
set -euo pipefail
umask 077   # 이후 생성되는 모든 파일(LOCK, 덤프 .sql.gz)을 처음부터 소유자 전용 권한으로

VERIFY_FILE=""
if [ "${1:-}" = "--verify" ]; then
  VERIFY_FILE=${2:-}
  [ -n "$VERIFY_FILE" ] || { echo "usage: backup_db.sh --verify DUMP [DB_CONTAINER]" >&2; exit 2; }
  DB_CONTAINER=${3:-${DB_CONTAINER:-vulnagent-db}}
else
  DB_CONTAINER="${DB_CONTAINER:-vulnagent-db}"
fi
BACKUP_DIR="${BACKUP_DIR:-/apps/vulnagent/backups}"
KEEP=7    # 매일 주기 기준 7일치 보관. vulnagent_*.sql.gz 패턴만 대상(수동 백업은 안 건드림).
          # 나이(mtime)가 아니라 **개수** 기준인 게 의도적이다 — 백업이 며칠 연속 실패해도
          # 마지막 7개는 남는다. 나이 기준이면 실패가 이어질 때 남은 것까지 다 지워 0개가 된다.
FAILED_KEEP=$KEEP  # 실패 dump도 조사에 필요한 최신 KEEP개만 보존(민감정보·디스크 무제한 누적 방지).
VERIFY_READY_TIMEOUT="${VERIFY_READY_TIMEOUT:-90}"
VERIFY_CONTAINER_ID=""

case "$VERIFY_READY_TIMEOUT" in
  ''|*[!0-9]*|0) echo "backup: VERIFY_READY_TIMEOUT은 양의 정수여야 함" >&2; exit 2 ;;
esac

container_database() {
  local env_lines container_db requested
  env_lines=$(docker inspect "$DB_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}')
  container_db=$(printf '%s\n' "$env_lines" | sed -n 's/^MYSQL_DATABASE=//p' | head -1)
  requested=${MYSQL_DATABASE:-$container_db}
  if [ -z "$container_db" ] || [ "$requested" != "$container_db" ]; then
    echo "backup: MYSQL_DATABASE 불일치 또는 누락(요청=${requested:-none}, 컨테이너=${container_db:-none})" >&2
    return 1
  fi
  case "$container_db" in ''|*[!A-Za-z0-9_]*) echo "backup: 안전하지 않은 MYSQL_DATABASE=$container_db" >&2; return 1 ;; esac
  printf '%s\n' "$container_db"
}

root_mysql() {
  docker exec -i "$DB_CONTAINER" sh -c \
    'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot "$@"' _ "$@"
}

verify_mysql() {
  docker exec -i "$VERIFY_CONTAINER_ID" mysql -uroot "$@"
}

cleanup_verify_container() {
  if [ -n "$VERIFY_CONTAINER_ID" ]; then
    docker rm -f "$VERIFY_CONTAINER_ID" >/dev/null 2>&1 || true
    VERIFY_CONTAINER_ID=""
  fi
}

trap cleanup_verify_container EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

schema_manifest_sql() {
  local db="$1"
  # 값은 HEX로 정규화해 탭·개행·collation 차이 없이 현재 운영 schema와 격리 복원본을
  # byte-for-byte 비교한다. TABLE/COLUMN 외에 요구되는 제약 네 종류를 각각 manifest에 둔다.
  printf '%s\n' "
SELECT line FROM (
  SELECT CONCAT_WS(CHAR(9), 'TABLE', HEX(TABLE_NAME), HEX(TABLE_TYPE),
                   COALESCE(HEX(ENGINE), '-'), COALESCE(HEX(TABLE_COLLATION), '-')) AS line
    FROM information_schema.TABLES
   WHERE TABLE_SCHEMA = '$db'
  UNION ALL
  SELECT CONCAT_WS(CHAR(9), 'COLUMN', HEX(TABLE_NAME), LPAD(ORDINAL_POSITION, 6, '0'),
                   HEX(COLUMN_NAME), HEX(COLUMN_TYPE), HEX(IS_NULLABLE),
                   COALESCE(HEX(CAST(COLUMN_DEFAULT AS CHAR)), '-'), HEX(EXTRA))
    FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = '$db'
  UNION ALL
  SELECT CONCAT_WS(CHAR(9), 'NOT_NULL', HEX(TABLE_NAME), LPAD(ORDINAL_POSITION, 6, '0'),
                   HEX(COLUMN_NAME))
    FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = '$db' AND IS_NULLABLE = 'NO'
  UNION ALL
  SELECT CONCAT_WS(CHAR(9), 'PRIMARY_KEY', HEX(k.TABLE_NAME), HEX(k.CONSTRAINT_NAME),
                   LPAD(k.ORDINAL_POSITION, 6, '0'), HEX(k.COLUMN_NAME))
    FROM information_schema.TABLE_CONSTRAINTS c
    JOIN information_schema.KEY_COLUMN_USAGE k
      ON k.CONSTRAINT_SCHEMA = c.CONSTRAINT_SCHEMA
     AND k.TABLE_NAME = c.TABLE_NAME
     AND k.CONSTRAINT_NAME = c.CONSTRAINT_NAME
   WHERE c.CONSTRAINT_SCHEMA = '$db' AND c.CONSTRAINT_TYPE = 'PRIMARY KEY'
  UNION ALL
  SELECT CONCAT_WS(CHAR(9), 'UNIQUE', HEX(k.TABLE_NAME), HEX(k.CONSTRAINT_NAME),
                   LPAD(k.ORDINAL_POSITION, 6, '0'), HEX(k.COLUMN_NAME))
    FROM information_schema.TABLE_CONSTRAINTS c
    JOIN information_schema.KEY_COLUMN_USAGE k
      ON k.CONSTRAINT_SCHEMA = c.CONSTRAINT_SCHEMA
     AND k.TABLE_NAME = c.TABLE_NAME
     AND k.CONSTRAINT_NAME = c.CONSTRAINT_NAME
   WHERE c.CONSTRAINT_SCHEMA = '$db' AND c.CONSTRAINT_TYPE = 'UNIQUE'
  UNION ALL
  SELECT CONCAT_WS(CHAR(9), 'FOREIGN_KEY', HEX(k.TABLE_NAME), HEX(k.CONSTRAINT_NAME),
                   LPAD(k.ORDINAL_POSITION, 6, '0'), HEX(k.COLUMN_NAME),
                   HEX(k.REFERENCED_TABLE_NAME), HEX(k.REFERENCED_COLUMN_NAME),
                   HEX(r.UPDATE_RULE), HEX(r.DELETE_RULE))
    FROM information_schema.TABLE_CONSTRAINTS c
    JOIN information_schema.KEY_COLUMN_USAGE k
      ON k.CONSTRAINT_SCHEMA = c.CONSTRAINT_SCHEMA
     AND k.TABLE_NAME = c.TABLE_NAME
     AND k.CONSTRAINT_NAME = c.CONSTRAINT_NAME
    JOIN information_schema.REFERENTIAL_CONSTRAINTS r
      ON r.CONSTRAINT_SCHEMA = c.CONSTRAINT_SCHEMA
     AND r.TABLE_NAME = c.TABLE_NAME
     AND r.CONSTRAINT_NAME = c.CONSTRAINT_NAME
   WHERE c.CONSTRAINT_SCHEMA = '$db' AND c.CONSTRAINT_TYPE = 'FOREIGN KEY'
) AS manifest
ORDER BY line"
}

core_data_sql() {
  local db="$1"
  printf '%s\n' "
SELECT metric, value FROM (
  SELECT 'orphan_scans' AS metric, COUNT(*) AS value
    FROM \`$db\`.tb_scan s
    LEFT JOIN \`$db\`.tb_host h ON h.host_id = s.host_id
   WHERE h.host_id IS NULL
  UNION ALL
  SELECT 'tb_host', COUNT(*) FROM \`$db\`.tb_host
  UNION ALL
  SELECT 'tb_scan', COUNT(*) FROM \`$db\`.tb_scan
) AS core_data
ORDER BY metric"
}

require_manifest_kinds() {
  local manifest="$1" label="$2" kind
  for kind in TABLE COLUMN PRIMARY_KEY UNIQUE FOREIGN_KEY NOT_NULL; do
    if ! awk -F '\t' -v wanted="$kind" '$1 == wanted { found=1 } END { exit(found ? 0 : 1) }' "$manifest"; then
      echo "backup verify: $label manifest에 $kind 항목이 없음" >&2
      return 1
    fi
  done
}

validate_core_data() {
  local report="$1" label="$2" hosts scans orphans
  hosts=$(awk -F '\t' '$1 == "tb_host" { print $2 }' "$report")
  scans=$(awk -F '\t' '$1 == "tb_scan" { print $2 }' "$report")
  orphans=$(awk -F '\t' '$1 == "orphan_scans" { print $2 }' "$report")
  case "$hosts" in ''|*[!0-9]*|0) echo "backup verify: $label tb_host 핵심 행이 없음" >&2; return 1 ;; esac
  case "$scans" in ''|*[!0-9]*|0) echo "backup verify: $label tb_scan 핵심 행이 없음" >&2; return 1 ;; esac
  if [ "$orphans" != 0 ]; then
    echo "backup verify: $label orphan tb_scan=$orphans" >&2
    return 1
  fi
  printf '%s/%s\n' "$hosts" "$scans"
}

verify_restore() {
  local dump="$1" source_db source_image verify_name verify_dir ready i
  local source_core restored_core source_summary restored_summary
  [ -s "$dump" ] || { echo "backup verify: dump가 비었음($dump)" >&2; return 1; }
  gzip -t "$dump" 2>/dev/null || { echo "backup verify: gzip 손상($dump)" >&2; return 1; }
  source_db=$(container_database) || return 1
  if ! source_image=$(docker inspect "$DB_CONTAINER" --format '{{.Config.Image}}'); then
    echo "backup verify: source DB image 확인 실패($DB_CONTAINER)" >&2
    return 1
  fi
  case "$source_image" in ''|*$'\n'*) echo "backup verify: 안전하지 않은 source DB image" >&2; return 1 ;; esac

  if ! verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/vg-backup-verify.XXXXXX"); then
    echo "backup verify: manifest 임시 디렉터리 생성 실패" >&2
    return 1
  fi
  if ! root_mysql --batch --raw --skip-column-names -e "$(schema_manifest_sql "$source_db")" > "$verify_dir/source.manifest"; then
    rm -rf "$verify_dir"
    echo "backup verify: 현재 schema manifest 조회 실패($source_db)" >&2
    return 1
  fi
  if ! require_manifest_kinds "$verify_dir/source.manifest" "source"; then
    rm -rf "$verify_dir"
    return 1
  fi
  if ! root_mysql --batch --raw --skip-column-names -e "$(core_data_sql "$source_db")" > "$verify_dir/source.core"; then
    rm -rf "$verify_dir"
    echo "backup verify: 현재 core data 조회 실패($source_db)" >&2
    return 1
  fi
  if ! source_summary=$(validate_core_data "$verify_dir/source.core" "source"); then
    rm -rf "$verify_dir"
    return 1
  fi

  verify_name="vg-backup-verify-$(date +%Y%m%d%H%M%S)-$$"
  # 검증 대상 SQL은 신뢰하지 않는다. 운영 컨테이너의 image만 재사용하고 network, volume,
  # secret을 전혀 공유하지 않는 일회용 MySQL에 넣는다. /var/lib/mysql도 tmpfs라 종료 즉시 사라진다.
  if ! VERIFY_CONTAINER_ID=$(docker run --detach --rm \
      --name "$verify_name" \
      --network none \
      --tmpfs /var/lib/mysql:rw,nosuid,nodev \
      --tmpfs /var/run/mysqld:rw,nosuid,nodev \
      --tmpfs /tmp:rw,nosuid,nodev,noexec \
      --label vuln-agent.backup-verify=true \
      --env MYSQL_ALLOW_EMPTY_PASSWORD=yes \
      --env "MYSQL_DATABASE=$source_db" \
      "$source_image" --skip-log-bin --skip-name-resolve); then
    rm -rf "$verify_dir"
    echo "backup verify: 격리 DB 시작 실패(image=$source_image)" >&2
    return 1
  fi

  ready=0
  i=0
  while [ "$i" -lt "$VERIFY_READY_TIMEOUT" ]; do
    # mysqladmin ping은 entrypoint의 임시 초기화 server에도 성공한다. MYSQL_DATABASE 생성까지
    # 확인해야 그 직후 restore가 "Unknown database"로 간헐 실패하지 않는다.
    if [ "$(verify_mysql --batch --raw --skip-column-names -e \
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='$source_db'" 2>/dev/null || true)" = "$source_db" ]; then
      ready=1
      break
    fi
    i=$((i + 1))
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    cleanup_verify_container
    rm -rf "$verify_dir"
    echo "backup verify: 격리 DB readiness timeout(${VERIFY_READY_TIMEOUT}s)" >&2
    return 1
  fi

  if ! gzip -dc "$dump" | verify_mysql "$source_db"; then
    cleanup_verify_container
    rm -rf "$verify_dir"
    echo "backup verify: 격리 DB restore 실패($verify_name)" >&2
    return 1
  fi
  if ! verify_mysql --batch --raw --skip-column-names -e "$(schema_manifest_sql "$source_db")" > "$verify_dir/restored.manifest"; then
    cleanup_verify_container
    rm -rf "$verify_dir"
    echo "backup verify: 복원 schema manifest 조회 실패" >&2
    return 1
  fi
  if ! require_manifest_kinds "$verify_dir/restored.manifest" "restored"; then
    cleanup_verify_container
    rm -rf "$verify_dir"
    return 1
  fi
  if ! cmp -s "$verify_dir/source.manifest" "$verify_dir/restored.manifest"; then
    source_core=$(cksum "$verify_dir/source.manifest" | awk '{ print $1 ":" $2 }')
    restored_core=$(cksum "$verify_dir/restored.manifest" | awk '{ print $1 ":" $2 }')
    cleanup_verify_container
    rm -rf "$verify_dir"
    echo "backup verify: 현재 schema/table/PK/FK/UNIQUE/NOT NULL manifest 불일치(source=$source_core restored=$restored_core)" >&2
    return 1
  fi
  if ! verify_mysql --batch --raw --skip-column-names -e "$(core_data_sql "$source_db")" > "$verify_dir/restored.core"; then
    cleanup_verify_container
    rm -rf "$verify_dir"
    echo "backup verify: 복원 core data 조회 실패" >&2
    return 1
  fi
  if ! restored_summary=$(validate_core_data "$verify_dir/restored.core" "restored"); then
    cleanup_verify_container
    rm -rf "$verify_dir"
    return 1
  fi

  cleanup_verify_container
  rm -rf "$verify_dir"
  echo "backup verify: PASS dump=$(basename "$dump") isolation=container/network-none manifest=current core_rows(source/restored)=$source_summary/$restored_summary constraints=PK,FK,UNIQUE,NOT_NULL"
}

if [ -n "$VERIFY_FILE" ]; then
  verify_restore "$VERIFY_FILE"
  exit $?
fi

mkdir -p "$BACKUP_DIR"

# ---------- 중복 실행 방지 (수동 실행과 cron 겹침 대비, agent/vuln-inventory-agent.sh 와 동일 패턴) ----------
#   fd 열기 실패(sudo 등 일부 환경)를 flock 실패로 오탐하지 않도록, 열기 성공을 먼저 확인한다.
#   world-writable 인 /tmp 대신 BACKUP_DIR(소유자만 쓰기 가능) 안에 둔다 — /tmp 는 누구나
#   파일을 만들 수 있어, root 크론 실행 전에 심볼릭 링크를 미리 심어 그 대상을 truncate
#   시키는 CWE-377 여지가 있다.
LOCK="$BACKUP_DIR/.lock"
if command -v flock >/dev/null 2>&1; then
  if exec 9>"$LOCK"; then
    flock -n 9 || { echo ">> 이미 실행 중입니다. 종료합니다." >&2; exit 0; }
  else
    echo ">> 락 파일 열기 실패($LOCK) — 락 없이 진행합니다." >&2
  fi
fi

LOG_FILE="$BACKUP_DIR/backup.log"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="$BACKUP_DIR/vulnagent_${STAMP}.sql.gz"

cleanup_failed_quarantine() {
  # 파일명은 이 스크립트가 만든 고정 패턴이라 개행/옵션 주입이 없다. 성공·실패 어느 경로든
  # 실행해 업그레이드 전에 무제한 누적된 quarantine도 최신 FAILED_KEEP개로 수렴시킨다.
  { ls -1t "$BACKUP_DIR"/vulnagent_*.sql.gz.failed 2>/dev/null || true; } \
    | tail -n +$((FAILED_KEEP + 1)) \
    | while IFS= read -r old; do
        rm -f "$old"
        echo "$(date -Iseconds) OK quarantine-cleanup removed=$(basename "$old")" >> "$LOG_FILE"
      done
}

fail() {
  # 실패 산출물은 정상 보관 패턴(vulnagent_*.sql.gz) 밖으로 격리한다. 자동 복구에는 쓰이지
  # 않지만 restore 실패 원인 분석은 가능하고, 권한은 umask 077 그대로다. 최신 KEEP개보다
  # 오래된 실패 dump는 민감정보·디스크가 무제한 누적되지 않도록 함께 정리한다.
  failed_file=""
  if [ -s "$OUT_FILE" ]; then
    failed_file="$OUT_FILE.failed"
    mv -f "$OUT_FILE" "$failed_file"
  else
    rm -f "$OUT_FILE"
  fi
  echo "$(date -Iseconds) FAIL $* quarantined=${failed_file:-none}" >> "$LOG_FILE"
  cleanup_failed_quarantine
  exit 1
}

trap 'fail "예상치 못한 오류(라인 $LINENO)"' ERR

DB_NAME=$(container_database)
docker exec "$DB_CONTAINER" sh -c \
  'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysqldump --single-transaction --routines -uroot "$1"' _ "$DB_NAME" \
  | gzip > "$OUT_FILE"

chmod 600 "$OUT_FILE"   # umask 077 로 이미 600 이지만 방어적으로 재확인
verify_restore "$OUT_FILE" || fail "restore rehearsal 실패"
SIZE=$(du -h "$OUT_FILE" | cut -f1)
echo "$(date -Iseconds) OK size=$SIZE file=$(basename "$OUT_FILE") restore=pass isolation=container manifest=current constraints=PK,FK,UNIQUE,NOT_NULL" >> "$LOG_FILE"
cleanup_failed_quarantine

# 보관 정책: vulnagent_*.sql.gz 중 최신 KEEP개만 남기고 삭제(수동 백업 pre_*.sql 은 패턴 밖).
ls -1t "$BACKUP_DIR"/vulnagent_*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
  rm -f "$old"
  echo "$(date -Iseconds) OK cleanup removed=$(basename "$old")" >> "$LOG_FILE"
done
