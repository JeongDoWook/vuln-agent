#!/usr/bin/env bash
# =============================================================================
# vuln-agent 서버 업데이트 (운영 중앙 서버에서 실행)
# =============================================================================
# 로컬에서 git push 한 뒤, 서버에서 이 한 줄:
#     bash deploy/update.sh
#
# 바뀐 파일을 보고 스스로 갈라진다.
#   server/ 만 바뀜         → git pull 로 끝. 재빌드도 재시작도 없다(다운타임 0초).
#                             소스가 읽기전용으로 마운트돼 있고, opcache 가 2초마다
#                             파일 mtime 을 다시 확인하기 때문이다.
#   Dockerfile/compose/caddy → 이미지 재빌드 + 컨테이너 재생성(다운타임 수십 초).
#   db/migrations/          → 코드 반영 **전에** 자동 적용(스키마가 코드보다 먼저 와야 안전).
#   최상위 db/*.sql         → 자동 적용하지 않는다(빈 볼륨 initdb 전용). 경고만 한다.
#
# .env.prod / secrets/*.txt 는 gitignore 라 pull 로 덮이지 않는다.
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."   # 저장소 루트

C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
say() { printf "\n${C}== %s${N}\n" "$*"; }

# 반영 방법은 셋으로 갈린다 — 뭉뚱그리면 쉘 스크립트 한 줄 고치고도 운영이 재빌드된다.
#   1) 재빌드(--build)  : **이미지 안에 들어가는 것**만. Dockerfile, caddy(build: ./caddy).
#   2) 재생성(up -d)    : compose 정의·바인드마운트되는 설정. 이미지는 그대로, 컨테이너만 다시.
#                         (deploy/config/mysql/my.cnf 는 `./config/...:ro` 로 마운트된다 → 빌드 불필요)
#   3) 아무것도 안 함   : PHP(소스는 ../server 라이브 마운트 → opcache 가 2초 안에 로드),
#                         그리고 **deploy/compose_runner.sh**(쉘 래퍼라 이미지·컨테이너와 무관).
#                         예전엔 이게 재빌드 목록에 있어서, 러너 한 줄 고친 배포가 수십 초 다운타임을 먹었다.
# README 같은 운영 문서는 이미지 입력이 아니다. 디렉터리 전체를 잡으면 문서 수정만으로도
# 웹·Caddy를 재생성한다. 실제 Docker build context에서 COPY/RUN하는 파일만 열거한다.
BUILD_RE='^(server/Dockerfile|deploy/caddy/(Dockerfile|Caddyfile))$'
RECREATE_RE='^deploy/(compose[^/]*\.yml|config/)'
DB_RE='^db/'
# deploy/config/mysql/my.cnf 는 db 컨테이너에 바인드마운트(:ro)되지만, docker compose 의
# 재생성 판단은 compose 서비스 정의(볼륨 매핑 경로) 변경 여부만 보고 마운트된 호스트 파일의
# '내용' 변경은 보지 않는다 — 매핑 자체는 안 바뀌므로 일반 `up -d` 는 db 컨테이너를 그대로
# 둔다. mysqld 는 conf.d 를 기동 시점에만 읽으므로, 내용만 바뀐 my.cnf 는 db 를 명시적으로
# force-recreate 하지 않으면 조용히 반영 안 된 채 남는다(2026-07-21 binlog 만료 미반영 재발 방지).
DB_CONFIG_RE='^deploy/config/mysql/'

say "[1/6] 사전 점검"
if [ -n "$(git status --porcelain)" ]; then
  printf "${R}저장소가 깨끗하지 않습니다. 운영 서버에서 직접 수정하지 마세요.${N}\n"
  git status --short
  exit 1
fi
# 소스 마운트가 실제로 붙어 있는지 확인. 없으면 pull 만 해봐야 컨테이너 코드는 그대로다.
MOUNTED=$(docker inspect vulnagent-web \
  --format '{{range .Mounts}}{{if eq .Destination "/var/www/html"}}yes{{end}}{{end}}' 2>/dev/null || true)
if [ "$MOUNTED" = "yes" ]; then
  echo "  소스 마운트: 있음 → PHP 변경은 pull 로 반영됨"
else
  printf "  ${Y}소스 마운트: 없음${N} → 이번엔 재빌드가 필요합니다(마운트를 붙이는 배포)\n"
fi

say "[2/6] 최신 코드 받기"
OLD=$(git rev-parse HEAD)
git fetch --prune origin
git merge --ff-only origin/main
NEW=$(git rev-parse HEAD)

if [ "$OLD" = "$NEW" ] && [ "$MOUNTED" = "yes" ]; then
  echo "  이미 최신입니다 ($(git log --oneline -1))"
  # 코드가 다른 경로(직접 git pull·다른 세션 배포)로 먼저 도착해 마이그레이션만 밀렸을 수 있다.
  # 그때 여기서 그냥 exit 하면 스키마가 영영 안 붙어 새 코드가 없는 테이블/컬럼을 찾아 500 이 난다
  # (실제로 tb_package_summary 누락으로 packages.php 가 500 이었다). migrate.sh 는 파일명 기준
  # 멱등이라 적용할 게 없으면 즉시 끝난다 → "최신"이어도 항상 미적용분을 적용하고 나간다.
  if docker inspect vulnagent-db --format '{{.State.Status}}' 2>/dev/null | grep -q running; then
    bash deploy/migrate.sh vulnagent-db
  fi
  exit 0
fi
echo "  $(git rev-parse --short "$OLD") → $(git rev-parse --short "$NEW")"

CHANGED=$(git diff --name-only "$OLD" "$NEW" || true)
echo "  변경 파일 $(printf '%s' "$CHANGED" | grep -c . || true)개"

say "[3/6] 무엇을 해야 하나"
NEED_BUILD=0
NEED_RECREATE=0
NEED_DB_RECREATE=0
# 소스 마운트가 없으면 코드가 이미지 안에 있다 → 새 코드를 넣으려면 굽는 수밖에 없다.
[ "$MOUNTED" = "yes" ] || NEED_BUILD=1
if printf '%s\n' "$CHANGED" | grep -qE "$BUILD_RE"; then
  NEED_BUILD=1
  echo "  이미지 변경 감지(재빌드 필요):"
  printf '%s\n' "$CHANGED" | grep -E "$BUILD_RE" | sed 's/^/    /'
fi
if printf '%s\n' "$CHANGED" | grep -qE "$RECREATE_RE"; then
  NEED_RECREATE=1
  echo "  compose/설정 변경 감지(재생성만, 빌드는 불필요):"
  printf '%s\n' "$CHANGED" | grep -E "$RECREATE_RE" | sed 's/^/    /'
fi
if printf '%s\n' "$CHANGED" | grep -qE "$DB_CONFIG_RE"; then
  NEED_DB_RECREATE=1
  echo "  MySQL 설정(my.cnf) 변경 감지(db 컨테이너 강제 재생성 필요):"
  printf '%s\n' "$CHANGED" | grep -E "$DB_CONFIG_RE" | sed 's/^/    /'
fi
if printf '%s\n' "$CHANGED" | grep -qE "$DB_RE"; then
  echo "  DB 변경 감지:"
  printf '%s\n' "$CHANGED" | grep -E "$DB_RE" | sed 's/^/    /'
  # db/migrations/ 는 [4/6]에서 **코드 반영보다 먼저** 자동 적용한다.
  # 최상위 db/*.sql 은 빈 볼륨 initdb 전용이라 기존 볼륨엔 안 들어간다.
  if printf '%s\n' "$CHANGED" | grep -qE '^db/migrations/'; then
    echo "  → db/migrations/ 는 [4/6]에서 자동 적용됩니다(코드 반영보다 먼저)."
  fi
  if printf '%s\n' "$CHANGED" | grep -qE '^db/[0-9]'; then
    printf "  ${Y}참고: 최상위 db/*.sql 변경은 자동 적용되지 않습니다(빈 볼륨 initdb 전용).${N}\n"
    printf "  ${Y}      기존 볼륨에 반영하려면 db/migrations/ 에 파일을 추가하세요.${N}\n"
  fi
fi

say "[4/6] DB 마이그레이션 (코드 반영보다 **먼저**)"
# 왜 먼저인가: [2/6] 의 git merge 로 새 PHP 코드는 **이미 디스크에 있다**. 소스가 라이브
# 마운트라 opcache 가 2초 안에 새 코드를 로드한다. 스키마를 뒤에 올리면 그 사이(healthy
# 대기까지 하면 수십 초) 들어온 수집이 "Unknown column …" 으로 500 이 난다 — 실제로 겪었다.
# 반대로 스키마를 먼저 올리는 건 안전하다: 컬럼 추가·인덱스 확장은 옛 코드에 무해하다.
MIGRATED=0
if docker inspect vulnagent-db --format '{{.State.Status}}' 2>/dev/null | grep -q running; then
  bash deploy/migrate.sh vulnagent-db
  MIGRATED=1
else
  echo "  DB 컨테이너가 아직 없음 → 반영 후에 적용합니다."
fi

say "[5/6] 반영"
if [ "$NEED_BUILD" = 1 ]; then
  echo "  재빌드 + 재생성 (다운타임 수십 초)"
  bash deploy/compose_runner.sh prod up -d --build
elif [ "$NEED_RECREATE" = 1 ]; then
  echo "  재생성만 (이미지는 그대로 — 바뀐 서비스만 몇 초 내려갔다 올라온다)"
  bash deploy/compose_runner.sh prod up -d
else
  echo "  PHP 만 변경 → 재시작 없음. opcache 가 2초 안에 새 코드를 로드합니다."
  # 오래 도는 프로세스(백필 워커 등)는 이미 옛 코드를 메모리에 올렸다. 있으면 알려준다.
  #   grep -c 는 매치 0건이면 exit 1 이라 "|| echo 0" 이 같이 실행돼 "0\n0" 이 나온다.
  #   grep 안에서 "|| true" 로 삼키고 숫자만 남긴다.
  RUNNING=$(docker exec vulnagent-web sh -c "ps -eo args | grep -c '^php /var/www/html/bin/' || true" 2>/dev/null | tr -dc '0-9')
  if [ "${RUNNING:-0}" -gt 0 ]; then
    printf "  ${Y}참고:${N} 실행 중인 bin 스크립트 %s개는 옛 코드로 계속 돕니다.\n" "$RUNNING"
  fi
  sleep 3
fi
if [ "$NEED_DB_RECREATE" = 1 ]; then
  echo "  my.cnf 내용 변경은 위 up -d 가 자동 감지하지 못한다(바인드마운트 경로는 안 바뀌므로) → db 컨테이너 강제 재생성"
  bash deploy/compose_runner.sh prod up -d --force-recreate db
fi

say "[6/6] 검증"
DB_SRC=$(docker inspect vulnagent-db \
  --format '{{range .Mounts}}{{if eq .Destination "/var/lib/mysql"}}{{.Source}}{{end}}{{end}}')
if [ "$DB_SRC" != "/apps/vulnagent/data/mysql" ]; then
  printf "  ${R}치명적: DB 가 바인드 마운트가 아닙니다 ($DB_SRC). 빈 DB 로 떴을 수 있습니다.${N}\n"
  exit 1
fi
echo "  DB 데이터: $DB_SRC"

for _ in $(seq 1 20); do
  docker inspect vulnagent-db --format '{{.State.Health.Status}}' | grep -q healthy && break
  sleep 2
done
docker ps --format '  {{.Names}}\t{{.Status}}' | grep vulnagent

# DB 컨테이너가 없어서 [4/6] 에서 못 돌린 경우(최초 기동)만 여기서 적용한다.
if [ "$MIGRATED" != 1 ]; then
  bash deploy/migrate.sh vulnagent-db
fi

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:8081/ || echo 000)
if [ "$code" = "302" ] || [ "$code" = "200" ]; then
  printf "  ${G}web(8081) HTTP %s${N}\n" "$code"
else
  printf "  ${R}web 이상 (HTTP %s)${N}\n" "$code"
  exit 1
fi

echo "  적용된 커밋: $(git log --oneline -1)"
printf "\n${G}>> 업데이트 완료.${N}\n"
