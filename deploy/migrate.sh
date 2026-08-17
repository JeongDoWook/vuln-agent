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
#   수동: bash deploy/migrate.sh [db컨테이너명] [--preflight|--pending]   (기본 vulnagent-db)
#
#   --pending: 아무것도 적용하지 않고 **미적용 파일명만** 한 줄씩 stdout 에 낸다(사람용 줄은
#     전부 stderr). update.sh 가 "백업·검증이 필요한 배포인가"를 이걸로 판정한다 — 판정 기준을
#     호출자에 복사하면 두 벌이 되어 갈라지므로, 기준은 이 파일의 pending_names() 하나뿐이다.
# =============================================================================
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # 저장소 루트

DB_CONTAINER="${1:-vulnagent-db}"
PREFLIGHT_ONLY=0
PENDING_ONLY=0
case "${2:-}" in
  --preflight) PREFLIGHT_ONLY=1 ;;
  --pending)   PENDING_ONLY=1 ;;
esac
MIG_DIR="${MIG_DIR:-db/migrations}"

C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

# --- 동시 실행 방지 ---------------------------------------------------------
# 같은 DB 를 두 프로세스가 동시에 마이그레이션하면 깨진다(실제로 발생했다):
#   둘 다 SELECT 로 "미적용"을 확인 → 둘 다 파일을 실행 → 한쪽이 INSERT 에서
#   "Duplicate entry ... for key PRIMARY" 로 죽는다. set -e 라 배포가 거기서 멈춘다.
# 파일 락으로 직렬화한다. 락은 **DB 컨테이너별**이라 워크트리 스택끼리는 서로 막지 않는다.
LOCK_FILE="${TMPDIR:-/tmp}/vg-migrate-${DB_CONTAINER}.lock"
# `2>/dev/null` 은 **반드시 그룹 `{ }` 에만** 건다. 예전엔 `exec 9>"$LOCK_FILE" 2>/dev/null` 이었는데,
# 명령 없는 exec 은 리다이렉션을 **현재 셸에 영구 적용**하므로 fd 9 뿐 아니라 `2>/dev/null` 까지
# 스크립트 끝까지 남아 **이후 모든 stderr(= mysql 오류)가 사라졌다.** 그래서 운영 DB 가
# 2026-08-06 부터 마이그레이션에 실패하고 있었는데도 로그엔 "적용: …" 한 줄만 찍혔다(2026-08-08 발견).
# 그룹에 걸면 억제 범위가 fd 9 여는 그 순간뿐이고(열기 실패 메시지만 숨김), fd 9 는 셸에 그대로 남는다.
if command -v flock >/dev/null 2>&1 && { exec 9>"$LOCK_FILE"; } 2>/dev/null; then
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

# --- preflight: DB 이름/존재/공간/복구 지점 ---------------------------------
# compose 의 MYSQL_DATABASE가 canonical이다. 예전 하드코딩(vulnagent)은 .env 값과 달라도
# 다른 schema에 조용히 적용할 수 있었다. 호출자가 값을 줬다면 컨테이너 값과 정확히 같아야 한다.
container_env=$(docker inspect "$DB_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}')
CONTAINER_DB=$(printf '%s\n' "$container_env" | sed -n 's/^MYSQL_DATABASE=//p' | head -1)
REQUESTED_DB="${MYSQL_DATABASE:-$CONTAINER_DB}"
if [ -z "$CONTAINER_DB" ] || [ -z "$REQUESTED_DB" ]; then
  printf "${R}마이그레이션 중단: 컨테이너 MYSQL_DATABASE를 확인할 수 없음${N}\n" >&2
  exit 1
fi
if [ "$REQUESTED_DB" != "$CONTAINER_DB" ]; then
  printf "${R}마이그레이션 중단: MYSQL_DATABASE 불일치(요청=%s, 컨테이너=%s)${N}\n" "$REQUESTED_DB" "$CONTAINER_DB" >&2
  exit 1
fi
case "$CONTAINER_DB" in
  ''|*[!A-Za-z0-9_]*) printf "${R}마이그레이션 중단: 안전하지 않은 MYSQL_DATABASE=%s${N}\n" "$CONTAINER_DB" >&2; exit 1 ;;
esac
DB_NAME=$CONTAINER_DB

# 컨테이너 안에서 root 로 mysql. 인자·표준입력을 그대로 전달(파일 파이프 겸용).
# MYSQL_PWD 로 비번을 넘기고, 모든 schema 명령은 검증한 DB_NAME으로 고정한다.
db_mysql_server() {
  docker exec -i "$DB_CONTAINER" sh -c \
    'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot "$@"' _ "$@"
}
db_mysql() {
  docker exec -i "$DB_CONTAINER" sh -c \
    'db="$1"; shift; MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot --database="$db" "$@"' _ "$DB_NAME" "$@"
}

exists=$(db_mysql_server -N -B -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='$DB_NAME'")
if [ "$exists" != 1 ]; then
  printf "${R}마이그레이션 중단: database '%s' 없음${N}\n" "$DB_NAME" >&2
  exit 1
fi

free_kb=$(docker exec "$DB_CONTAINER" sh -c "df -Pk /var/lib/mysql | tail -1 | tr -s ' ' | cut -d ' ' -f 4")
min_free_kb=${MIGRATION_MIN_FREE_KB:-1048576}
case "$free_kb:$min_free_kb" in *[!0-9:]*|:*) printf "${R}마이그레이션 중단: DB 여유 공간 판정 실패${N}\n" >&2; exit 1 ;; esac
if [ "$free_kb" -lt "$min_free_kb" ]; then
  printf "${R}마이그레이션 중단: DB 여유 공간 부족(%s KiB < %s KiB)${N}\n" "$free_kb" "$min_free_kb" >&2
  exit 1
fi

if [ "${MIGRATION_REQUIRE_BACKUP:-0}" = 1 ]; then
  backup=${MIGRATION_BACKUP_FILE:-}
  if [ -z "$backup" ] || [ ! -s "$backup" ] || ! gzip -t "$backup" 2>/dev/null; then
    printf "${R}마이그레이션 중단: 복원 가능한 gzip backup 증거 필요(MIGRATION_BACKUP_FILE)${N}\n" >&2
    exit 1
  fi
fi

# 추적 테이블 보장(멱등).
db_mysql -e "CREATE TABLE IF NOT EXISTS tb_schema_migrations (
  filename   VARCHAR(191) NOT NULL PRIMARY KEY,
  applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"

latest=$(db_mysql -N -B -e "SELECT COALESCE(MAX(filename), 'none') FROM tb_schema_migrations")
# --pending 모드에서 stdout 은 "미적용 목록" 전용이다 — 사람이 읽는 줄은 fd 3(=stderr)로 보낸다.
# (bare `exec` 리다이렉션이 문제가 됐던 건 `2>/dev/null` 로 오류를 **버릴** 때였다. 여기는
#  fd 3 을 여는 것뿐이라 stderr 는 그대로 살아 있다.)
if [ "$PENDING_ONLY" = 1 ]; then exec 3>&2; else exec 3>&1; fi
printf "  ${C}preflight${N}: db=%s · schema_version=%s · free_kb=%s · backup=%s\n" \
  "$DB_NAME" "${latest:-none}" "$free_kb" "${MIGRATION_BACKUP_FILE:-not-required}" >&3
if [ "$PREFLIGHT_ONLY" = 1 ]; then exit 0; fi

# --- 미적용 판정 (SSOT) ------------------------------------------------------
# db/migrations/*.sql 중 tb_schema_migrations 에 없는 파일명을 한 줄씩 낸다.
# 적용 루프도, update.sh 의 `--pending` 조회도 전부 이 함수만 쓴다 — 기준이 갈라지면
# "백업을 건너뛰었는데 사실은 적용할 게 있었다" 가 된다.
# 파일마다 SELECT 하지 않고 적용 목록을 **한 번에** 받아 비교한다(질의 1회).
pending_names() {
  local applied_rows f name
  applied_rows="$(db_mysql -N -B -e "SELECT filename FROM tb_schema_migrations")"
  for f in "$MIG_DIR"/*.sql; do
    name="$(basename "$f")"
    case "$name" in *\'*) printf "${Y}건너뜀(파일명에 따옴표): %s${N}\n" "$name" >&2; continue ;; esac
    printf '%s\n' "$applied_rows" | grep -qxF -- "$name" || printf '%s\n' "$name"
  done
}

shopt -s nullglob
PENDING=()
while IFS= read -r name; do
  PENDING+=("$name")
done < <(pending_names)

# 빈 배열 전개는 옛 bash + `set -u` 에서 unbound 로 죽는다 → ${arr[@]+"${arr[@]}"} 로 감싼다.
if [ "$PENDING_ONLY" = 1 ]; then
  if [ "${#PENDING[@]}" -gt 0 ]; then printf '%s\n' "${PENDING[@]}"; fi
  exit 0
fi

total=0
for f in "$MIG_DIR"/*.sql; do total=$((total + 1)); done
applied=0; skipped=$((total - ${#PENDING[@]}))
for name in ${PENDING[@]+"${PENDING[@]}"}; do
  f="$MIG_DIR/$name"
  printf "  ${C}적용${N}: %s\n" "$name"
  # 파일 실행(실패하면 여기서 중단 → 기록 안 함). mysql 의 상세 오류는 stderr 로 그대로 나가고,
  # 그와 별개로 "어느 파일에서 멈췄는지"를 stdout 에도 한 줄 남긴다 — stderr 를 버리는 호출자
  # (로그 파이프라인)가 있어도 실패 사실 자체는 보이게.
  if ! db_mysql < "$f"; then
    printf "${R}마이그레이션 실패${N}: %s 적용 중 중단 (원인은 위 mysql 오류 참조) — 적용 %d · 스킵 %d 까지 진행\n" \
      "$name" "$applied" "$skipped"
    exit 1
  fi
  # DDL 성공과 이력 기록은 MySQL DDL 특성상 한 트랜잭션이 아니다. 이력 실패를 숨기면 다음
  # 배포가 schema version을 잘못 읽는다. 명시적으로 실패시키고, 멱등 migration을 재실행해
  # 복구할 수 있도록 파일명을 남긴다. 경쟁 insert는 ON DUPLICATE KEY로 성공 처리한다.
  if ! db_mysql -e "INSERT INTO tb_schema_migrations (filename) VALUES ('$name') ON DUPLICATE KEY UPDATE filename=VALUES(filename)"; then
    printf "${R}마이그레이션 이력 기록 실패${N}: %s (DDL은 적용됐을 수 있음; 같은 명령을 재실행해 멱등 복구)\n" "$name" >&2
    exit 1
  fi
  applied=$((applied + 1))
done

printf "${G}마이그레이션 완료${N} — 적용 %d · 스킵 %d\n" "$applied" "$skipped"
