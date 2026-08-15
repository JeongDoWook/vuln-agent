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
# 기존 dump만 복원 검증하려면:
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

verify_restore() {
  local dump="$1" source_db scratch core_count
  [ -s "$dump" ] || { echo "backup verify: dump가 비었음($dump)" >&2; return 1; }
  gzip -t "$dump" 2>/dev/null || { echo "backup verify: gzip 손상($dump)" >&2; return 1; }
  source_db=$(container_database) || return 1
  scratch="vg_restore_$(date +%Y%m%d%H%M%S)_$$"
  root_mysql -e "CREATE DATABASE \`$scratch\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" || return 1
  if ! gzip -dc "$dump" | docker exec -i "$DB_CONTAINER" sh -c \
      'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot "$1"' _ "$scratch"; then
    root_mysql -e "DROP DATABASE IF EXISTS \`$scratch\`" >/dev/null 2>&1 || true
    echo "backup verify: disposable DB restore 실패($scratch)" >&2
    return 1
  fi
  core_count=$(root_mysql -N -B -e "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='$scratch' AND TABLE_NAME IN ('tb_host','tb_scan')") || core_count=0
  if ! root_mysql -e "DROP DATABASE IF EXISTS \`$scratch\`" >/dev/null; then
    echo "backup verify: disposable DB cleanup 실패($scratch)" >&2
    return 1
  fi
  if [ "$core_count" != 2 ]; then
    echo "backup verify: core schema sanity 실패(tb_host/tb_scan=$core_count/2, source=$source_db)" >&2
    return 1
  fi
  echo "backup verify: PASS dump=$(basename "$dump") disposable_db=$scratch core_tables=2/2"
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

fail() {
  # 실패 산출물은 정상 보관 패턴(vulnagent_*.sql.gz) 밖으로 격리한다. 자동 복구에는 쓰이지
  # 않지만 restore 실패 원인 분석은 가능하고, 권한은 umask 077 그대로다.
  failed_file=""
  if [ -s "$OUT_FILE" ]; then
    failed_file="$OUT_FILE.failed"
    mv -f "$OUT_FILE" "$failed_file"
  else
    rm -f "$OUT_FILE"
  fi
  echo "$(date -Iseconds) FAIL $* quarantined=${failed_file:-none}" >> "$LOG_FILE"
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
echo "$(date -Iseconds) OK size=$SIZE file=$(basename "$OUT_FILE") restore=pass core_tables=2/2" >> "$LOG_FILE"

# 보관 정책: vulnagent_*.sql.gz 중 최신 KEEP개만 남기고 삭제(수동 백업 pre_*.sql 은 패턴 밖).
ls -1t "$BACKUP_DIR"/vulnagent_*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
  rm -f "$old"
  echo "$(date -Iseconds) OK cleanup removed=$(basename "$old")" >> "$LOG_FILE"
done
