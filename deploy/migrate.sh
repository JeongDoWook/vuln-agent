#!/usr/bin/env bash
# =============================================================================
# vuln-agent · DB 마이그레이션 러너 (Flyway-lite, 순수 bash + mysql)
# =============================================================================
# db/migrations/*.sql 중 "아직 안 든 것"만 순서대로 적용하고 이력을 남긴다.
#   추적: tb_schema_migrations(filename, applied_at). 파일명 기준 멱등.
#   적용: db 컨테이너 안의 mysql 로 파일을 파이프(수동 apply 와 동일 경로).
#
#   왜 db/migrations/ 만 보나: db/*.sql(최상위)은 빈 볼륨 initdb 전용이라 러너 대상이
#   아니다. 기존 볼륨에 반영할 증분 변경은 전부 db/migrations/ 에 둔다.
#
#   호출: compose_runner.sh 가 `up` 뒤에, update.sh 가 배포 뒤에 자동 실행.
#   수동: bash deploy/migrate.sh [db컨테이너명]   (기본 vulnagent-db)
# =============================================================================
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # 저장소 루트

DB_CONTAINER="${1:-vulnagent-db}"
MIG_DIR="db/migrations"

C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

# --- 동시 실행 방지 ---------------------------------------------------------
# 같은 DB 를 두 프로세스가 동시에 마이그레이션하면 깨진다(실제로 발생했다):
#   둘 다 SELECT 로 "미적용"을 확인 → 둘 다 파일을 실행 → 한쪽이 INSERT 에서
#   "Duplicate entry ... for key PRIMARY" 로 죽는다. set -e 라 배포가 거기서 멈춘다.
# 파일 락으로 직렬화한다. 락은 **DB 컨테이너별**이라 워크트리 스택끼리는 서로 막지 않는다.
LOCK_FILE="${TMPDIR:-/tmp}/vg-migrate-${DB_CONTAINER}.lock"
if command -v flock >/dev/null 2>&1 && exec 9>"$LOCK_FILE" 2>/dev/null; then
  if ! flock -w 300 9; then
    printf "${R}마이그레이션 중단: 다른 프로세스가 '%s' 를 마이그레이션 중(5분 대기 초과)${N}\n" \
      "$DB_CONTAINER" >&2
    exit 1
  fi
else
  printf "${Y}⚠ flock 을 쓸 수 없어 동시 실행 보호 없이 진행합니다${N}\n" >&2
fi

# --- DB 컨테이너 준비 대기 (healthcheck 있으면 healthy, 없으면 running) ------
ok=0
for _ in $(seq 1 30); do
  st=$(docker inspect "$DB_CONTAINER" \
        --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        2>/dev/null || echo missing)
  case "$st" in healthy|running) ok=1; break ;; esac
  sleep 2
done
if [ "$ok" != 1 ]; then
  printf "${R}마이그레이션 중단: DB 컨테이너 '%s' 준비 안 됨(state=%s)${N}\n" "$DB_CONTAINER" "${st:-?}" >&2
  exit 1
fi

# 컨테이너 안에서 root 로 mysql. 인자·표준입력을 그대로 전달(파일 파이프 겸용).
#   MYSQL_PWD 로 비번을 넘겨 "password on CLI" 경고를 피한다(-p 대신).
db_mysql() {
  docker exec -i "$DB_CONTAINER" sh -c \
    'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot vulnagent "$@"' _ "$@"
}

# 추적 테이블 보장(멱등).
db_mysql -e "CREATE TABLE IF NOT EXISTS tb_schema_migrations (
  filename   VARCHAR(191) NOT NULL PRIMARY KEY,
  applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"

applied=0; skipped=0
shopt -s nullglob
for f in "$MIG_DIR"/*.sql; do
  name="$(basename "$f")"
  case "$name" in *\'*) printf "${Y}건너뜀(파일명에 따옴표): %s${N}\n" "$name"; continue ;; esac
  done_row="$(db_mysql -N -B -e "SELECT 1 FROM tb_schema_migrations WHERE filename='$name' LIMIT 1")"
  if [ -n "$done_row" ]; then skipped=$((skipped + 1)); continue; fi
  printf "  ${C}적용${N}: %s\n" "$name"
  db_mysql < "$f"                                              # 파일 실행(실패하면 set -e 로 중단 → 기록 안 함)
  # INSERT IGNORE: 락이 없는 환경에서 경쟁이 나더라도 여기서 죽지 않는다.
  #   마이그레이션 파일은 멱등하게 쓰기로 돼 있으므로(db/migrations/README.md) 두 번 실행돼도
  #   스키마는 안전하다. 죽어서 배포를 멈추는 것보다 낫다.
  db_mysql -e "INSERT IGNORE INTO tb_schema_migrations (filename) VALUES ('$name')"
  applied=$((applied + 1))
done

printf "${G}마이그레이션 완료${N} — 적용 %d · 스킵 %d\n" "$applied" "$skipped"
