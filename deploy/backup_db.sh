#!/usr/bin/env bash
# =============================================================================
# vuln-agent · DB 백업 (호스트에서 cron 으로 실행)
# =============================================================================
# 컨테이너 안에서 mysqldump 로 덤프해 호스트에서 gzip 압축, $BACKUP_DIR 에 저장한다.
# 오래된 자동 백업(vulnagent_*.sql.gz)은 최신 KEEP 개만 남기고 정리한다.
#
# 설치: crontab -e 로 다음 줄 추가
#   0 4 */3 * * /apps/vulnagent/app/deploy/backup_db.sh >> /apps/vulnagent/backups/cron.log 2>&1
#
# 로컬 dev 에서 시험하려면:
#   DB_CONTAINER=vulnagent-db-dev BACKUP_DIR=/tmp/vg-backup-test bash deploy/backup_db.sh
# =============================================================================
set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-vulnagent-db}"
BACKUP_DIR="${BACKUP_DIR:-/apps/vulnagent/backups}"
KEEP=10   # 3일 주기 기준 약 30일치 보관. vulnagent_*.sql.gz 패턴만 대상(수동 백업은 안 건드림).

mkdir -p "$BACKUP_DIR"
LOG_FILE="$BACKUP_DIR/backup.log"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="$BACKUP_DIR/vulnagent_${STAMP}.sql.gz"

fail() {
  echo "$(date -Iseconds) FAIL $*" >> "$LOG_FILE"
  exit 1
}

trap 'fail "예상치 못한 오류(라인 $LINENO)"' ERR

docker exec "$DB_CONTAINER" sh -c \
  'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysqldump --single-transaction --routines -uroot "$MYSQL_DATABASE"' \
  | gzip > "$OUT_FILE"

SIZE=$(du -h "$OUT_FILE" | cut -f1)
echo "$(date -Iseconds) OK size=$SIZE file=$(basename "$OUT_FILE")" >> "$LOG_FILE"

# 보관 정책: vulnagent_*.sql.gz 중 최신 KEEP개만 남기고 삭제(수동 백업 pre_*.sql 은 패턴 밖).
ls -1t "$BACKUP_DIR"/vulnagent_*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
  rm -f "$old"
  echo "$(date -Iseconds) OK cleanup removed=$(basename "$old")" >> "$LOG_FILE"
done
