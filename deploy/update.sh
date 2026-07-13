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
#   db/*.sql                → 자동 적용하지 않는다. 경고만 하고 사람이 판단한다.
#
# .env.prod / secrets/*.txt 는 gitignore 라 pull 로 덮이지 않는다.
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."   # 저장소 루트

C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
say() { printf "\n${C}== %s${N}\n" "$*"; }

# 재빌드가 필요한 경로. 이 목록 밖의 server/ 변경은 PHP 로 간주한다.
INFRA_RE='^(server/Dockerfile|deploy/(compose[^/]*\.yml|compose_runner\.sh|caddy/|config/))'
DB_RE='^db/'

say "[1/5] 사전 점검"
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

say "[2/5] 최신 코드 받기"
OLD=$(git rev-parse HEAD)
git fetch --prune origin
git merge --ff-only origin/main
NEW=$(git rev-parse HEAD)

if [ "$OLD" = "$NEW" ] && [ "$MOUNTED" = "yes" ]; then
  echo "  이미 최신입니다 ($(git log --oneline -1))"
  exit 0
fi
echo "  $(git rev-parse --short "$OLD") → $(git rev-parse --short "$NEW")"

CHANGED=$(git diff --name-only "$OLD" "$NEW" || true)
echo "  변경 파일 $(printf '%s' "$CHANGED" | grep -c . || true)개"

say "[3/5] 무엇을 해야 하나"
NEED_BUILD=0
[ "$MOUNTED" = "yes" ] || NEED_BUILD=1
if printf '%s\n' "$CHANGED" | grep -qE "$INFRA_RE"; then
  NEED_BUILD=1
  echo "  인프라 변경 감지:"
  printf '%s\n' "$CHANGED" | grep -E "$INFRA_RE" | sed 's/^/    /'
fi
if printf '%s\n' "$CHANGED" | grep -qE "$DB_RE"; then
  echo "  DB 변경 감지:"
  printf '%s\n' "$CHANGED" | grep -E "$DB_RE" | sed 's/^/    /'
  # db/migrations/ 는 아래 [5/5]에서 러너가 자동 적용한다.
  # 최상위 db/*.sql 은 빈 볼륨 initdb 전용이라 기존 볼륨엔 안 들어간다.
  if printf '%s\n' "$CHANGED" | grep -qE '^db/migrations/'; then
    echo "  → db/migrations/ 는 [5/5]에서 자동 적용됩니다."
  fi
  if printf '%s\n' "$CHANGED" | grep -qE '^db/[0-9]'; then
    printf "  ${Y}참고: 최상위 db/*.sql 변경은 자동 적용되지 않습니다(빈 볼륨 initdb 전용).${N}\n"
    printf "  ${Y}      기존 볼륨에 반영하려면 db/migrations/ 에 파일을 추가하세요.${N}\n"
  fi
fi

say "[4/5] 반영"
if [ "$NEED_BUILD" = 1 ]; then
  echo "  재빌드 + 재생성 (다운타임 수십 초)"
  bash deploy/compose_runner.sh prod up -d --build
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

say "[5/5] 검증"
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

# DB 마이그레이션: db/migrations/ 중 아직 안 든 것 자동 적용(멱등).
bash deploy/migrate.sh vulnagent-db

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:8081/ || echo 000)
if [ "$code" = "302" ] || [ "$code" = "200" ]; then
  printf "  ${G}web(8081) HTTP %s${N}\n" "$code"
else
  printf "  ${R}web 이상 (HTTP %s)${N}\n" "$code"
  exit 1
fi

echo "  적용된 커밋: $(git log --oneline -1)"
printf "\n${G}>> 업데이트 완료.${N}\n"
