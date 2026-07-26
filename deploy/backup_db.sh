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
# =============================================================================
set -euo pipefail
umask 077   # 이후 생성되는 모든 파일(LOCK, 덤프 .sql.gz)을 처음부터 소유자 전용 권한으로

DB_CONTAINER="${DB_CONTAINER:-vulnagent-db}"
BACKUP_DIR="${BACKUP_DIR:-/apps/vulnagent/backups}"
KEEP=7    # 매일 주기 기준 7일치 보관. vulnagent_*.sql.gz 패턴만 대상(수동 백업은 안 건드림).
          # 나이(mtime)가 아니라 **개수** 기준인 게 의도적이다 — 백업이 며칠 연속 실패해도
          # 마지막 7개는 남는다. 나이 기준이면 실패가 이어질 때 남은 것까지 다 지워 0개가 된다.

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
  # 중간에 실패하면 쓰다 만 손상된 .sql.gz 가 남아 다음 정리 로직이 이걸 "최신 백업"으로
  # 착각해 보관할 수 있다 — 실패 시에는 반드시 지운다.
  rm -f "$OUT_FILE"
  echo "$(date -Iseconds) FAIL $*" >> "$LOG_FILE"
  exit 1
}

trap 'fail "예상치 못한 오류(라인 $LINENO)"' ERR

docker exec "$DB_CONTAINER" sh -c \
  'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysqldump --single-transaction --routines -uroot "$MYSQL_DATABASE"' \
  | gzip > "$OUT_FILE"

chmod 600 "$OUT_FILE"   # umask 077 로 이미 600 이지만 방어적으로 재확인
SIZE=$(du -h "$OUT_FILE" | cut -f1)
echo "$(date -Iseconds) OK size=$SIZE file=$(basename "$OUT_FILE")" >> "$LOG_FILE"

# 보관 정책: vulnagent_*.sql.gz 중 최신 KEEP개만 남기고 삭제(수동 백업 pre_*.sql 은 패턴 밖).
ls -1t "$BACKUP_DIR"/vulnagent_*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
  rm -f "$old"
  echo "$(date -Iseconds) OK cleanup removed=$(basename "$old")" >> "$LOG_FILE"
done
