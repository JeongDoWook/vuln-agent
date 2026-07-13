#!/usr/bin/env bash
# =============================================================================
# vuln-agent · Docker Compose Runner
# =============================================================================
# 환경별 compose 파일을 자동으로 조합해 실행하는 스크립트.
#
# [파일 구조]
#   compose.yml         서비스 정의 (db=MySQL, web=PHP/Apache)
#   compose.common.yml  공통 런타임 (restart, 로깅, pids_limit)
#   compose.dev.yml     개발: 소스 마운트 + DB 포트 노출
#   compose.prod.yml    운영: 이미지 코드 + DB 포트 미노출
#   .env.dev / .env.prod  (각 *.template 에서 복사)
#
# [사용법]
#   ./compose_runner.sh init             # .env.dev/.env.prod 생성(템플릿 복사)
#   ./compose_runner.sh doctor           # 사전 점검
#   ./compose_runner.sh dev  up -d           # 개발 환경 기동(이미지는 재사용, Dockerfile 바뀔 때만 --build)
#   ./compose_runner.sh dev  down            # 개발 환경 중지
#   ./compose_runner.sh dev  logs -f         # 로그
#   ./compose_runner.sh prod up -d --build   # 운영 환경 기동
#   ./compose_runner.sh prod ps              # 상태
#
# [git pull 뒤에는 `dev up -d` 를 한 번 더]
#   dev 는 ../server 를 라이브 마운트하므로 pull 하는 순간 코드는 컨테이너 안에서 즉시 바뀐다.
#   그런데 DB 스키마는 안 따라온다 — 남이 머지한 마이그레이션이 있으면 새 코드가 없는 컬럼을
#   찾아 500 이 난다(Unknown column …). `up -d` 가 migrate.sh 를 불러 미적용분만 적용한다.
#   (컨테이너는 그대로 재사용하므로 싸다. 재빌드도 필요 없다.)
#
# [dev DB 를 비우려면 — `down -v` 는 듣지 않는다]
#   dev 의 DB 는 named volume 이 아니라 .env.dev 의 DB_DATA(=../data/mysql) **바인드마운트**다.
#   compose 는 named volume 만 -v 로 지우므로, `down -v` 를 해도 데이터가 그대로 남는다
#   (안 쓰이는 vulnagent-dev_db_data 볼륨이 남아 있어 더 헷갈린다).
#       ./compose_runner.sh dev down
#       rm -rf ../data/mysql                 # ← 실제 DB 는 여기다
#       ./compose_runner.sh dev up -d        # initdb + 마이그레이션이 처음부터 돈다
#
#   왜 신경 써야 하나: pre-push 훅의 스모크가 기본값으로 8080(메인 dev 스택)을 친다.
#   메인 dev DB 를 오래 쓰면 실제 피드가 시드 데이터를 덮어 스모크가 깨지고, 코드가 멀쩡해도
#   아무 브랜치나 push 가 막힌다(2026-07-13 실제 발생 — 깨끗한 볼륨에선 43/43 통과).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
say() { printf "%b\n" "$1"; }

BASE_FILE="compose.yml"
COMMON_FILE="compose.common.yml"

# --- 워크트리 감지 -----------------------------------------------------------
# 이 스크립트가 wt/<이름>/deploy/ 안에 있으면 그 워크트리 전용 dev 스택으로 띄운다.
#   프로젝트명·컨테이너명·이미지태그에 -<이름> 접미사를 붙여 메인 dev 스택과 격리.
#   (compose 의 상대경로 ../server, ../db, ../secrets 는 이미 이 트리를 가리킨다)
TREE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WT_NAME=""
if [ "$(basename "$(dirname "$TREE_ROOT")")" = "wt" ]; then
  WT_NAME="$(basename "$TREE_ROOT")"
fi
WT_SUFFIX="${WT_NAME:+-$WT_NAME}"

show_help() {
  say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  say "${CYAN}  vuln-agent · Compose Runner${NC}"
  say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  say "${YELLOW}사용법:${NC} $0 [환경|명령] [docker compose 인자...]"
  echo ""
  say "${YELLOW}특수 명령:${NC}"
  say "  ${GREEN}init${NC}     - .env.dev / .env.prod 를 템플릿에서 생성"
  say "  ${GREEN}doctor${NC}   - Docker/파일/포트 사전 점검"
  echo ""
  say "${YELLOW}환경:${NC}"
  say "  ${GREEN}dev${NC}      - 개발(소스 라이브 마운트, DB 포트 노출)"
  say "  ${GREEN}prod${NC}     - 운영(이미지 코드, DB 포트 미노출)"
  echo ""
  say "${YELLOW}예시:${NC}"
  say "  $0 ${GREEN}init${NC}"
  say "  $0 ${GREEN}dev${NC} up -d"
  say "  $0 ${GREEN}dev${NC} down"
  say "  $0 ${GREEN}prod${NC} up -d --build"
  say "  $0 ${GREEN}prod${NC} logs -f web"
  echo ""
}

check_file() {
  if [ ! -f "$1" ]; then
    say "${RED}오류: $1 파일이 없습니다.${NC}"; exit 1
  fi
}

# 강한 랜덤값 1줄 생성 (openssl 없으면 대체)
#   주의: Windows 에선 개행이 \r\n 이라 \r 까지 제거해야 함(안 그러면 비번/토큰에 CR 혼입).
#   또한 base64 의 +,/,= 는 URL/헤더에서 성가시므로 영숫자만 남긴다.
gen_secret() {
  local raw
  if command -v openssl >/dev/null 2>&1; then
    raw="$(openssl rand -base64 32)"
  else
    raw="$(head -c 24 /dev/urandom | base64)"
  fi
  printf '%s' "$raw" | tr -d '\r\n' | tr -dc 'A-Za-z0-9' | head -c 32
}

# --- init : env 파일 + secrets txt 생성 -------------------------------------
run_init() {
  say "${CYAN}== 초기 설정 ==${NC}"
  local ok=1

  # 1) env 파일 (비밀값 없음)
  for env in dev prod; do
    local tpl=".env.${env}.template" dst=".env.${env}"
    if [ -f "$dst" ]; then
      say "  ${BLUE}→${NC} 존재: $dst (유지)"
    elif [ -f "$tpl" ]; then
      cp "$tpl" "$dst"
      say "  ${GREEN}✓${NC} 생성: $dst"
    else
      say "  ${RED}✗${NC} 템플릿 없음: $tpl"; ok=0
    fi
  done

  # 2) secrets txt (강한 랜덤값 자동 생성, 있으면 유지)
  mkdir -p ../secrets
  for name in mysql_root_password mysql_password ingest_token admin_password; do
    local f="../secrets/${name}.txt"
    if [ -s "$f" ]; then
      say "  ${BLUE}→${NC} 존재: $f (유지)"
    else
      gen_secret > "$f"
      # 0644: 컨테이너의 www-data(Apache)가 읽어야 함. non-swarm compose 는 시크릿을
      #       호스트 권한대로 마운트하므로 world-read 가 아니면 www-data 가 못 읽는다.
      #       (내부 단일관리 서버 전제. git 에는 안 올라가고 네트워크 노출도 없음)
      chmod 644 "$f" 2>/dev/null || true
      say "  ${GREEN}✓${NC} 생성: $f  ${YELLOW}(랜덤 비밀값)${NC}"
    fi
  done

  # DuckDNS 토큰(운영 HTTPS용) — 랜덤 아님. 실제 토큰을 사용자가 직접 넣어야 함.
  local df="../secrets/duckdns_token.txt"
  if [ -s "$df" ]; then
    say "  ${BLUE}→${NC} 존재: $df (유지)"
  else
    : > "$df"; chmod 644 "$df" 2>/dev/null || true
    say "  ${YELLOW}⚠${NC} 생성(빈값): $df — HTTPS(prod) 쓰려면 DuckDNS 토큰 입력 필요:"
    say "      ${CYAN}printf %s 'DuckDNS-토큰' > $df${NC}"
  fi

  # 3) 검증 게이트(pre-push) 설치 — core.hooksPath 를 저장소 안 deploy/hooks 로 돌린다.
  #    전에는 .git/hooks/pre-push 에 손으로 넣어 뒀는데, .git 은 git 이 추적하지 않는다.
  #    즉 새로 clone 하면 CLAUDE.md 가 "강제" 라고 적은 게이트가 아예 없었다.
  #    (core.hooksPath 는 .git/config 에 들어가므로 모든 워크트리가 함께 쓴다 — 한 번만 하면 된다.)
  if git rev-parse --git-dir >/dev/null 2>&1; then
    local cur; cur="$(git config --get core.hooksPath 2>/dev/null || true)"
    if [ "$cur" = "deploy/hooks" ]; then
      say "  ${BLUE}→${NC} 존재: 검증 게이트(core.hooksPath=deploy/hooks)"
    else
      git config core.hooksPath deploy/hooks
      say "  ${GREEN}✓${NC} 설치: 검증 게이트 ${CYAN}core.hooksPath=deploy/hooks${NC}  (pre-push: php -l · bash -n · smoke)"
    fi
  fi

  echo ""
  if [ "$ok" = 1 ]; then
    say "${GREEN}완료.${NC} 다음: ${CYAN}$0 dev up -d${NC}"
    say "  에이전트 전송 토큰(--token) 값:  ${CYAN}cat ../secrets/ingest_token.txt${NC}"
  fi
}

# --- doctor : 가벼운 사전 점검 ----------------------------------------------
run_doctor() {
  say "${CYAN}== 사전 점검 ==${NC}"
  local issues=0
  if command -v docker >/dev/null 2>&1; then
    say "  ${GREEN}✓${NC} docker: $(docker --version | awk '{print $3}' | sed 's/,//')"
  else
    say "  ${RED}✗${NC} docker 미설치"; issues=$((issues+1))
  fi
  if docker compose version >/dev/null 2>&1; then
    say "  ${GREEN}✓${NC} docker compose: $(docker compose version --short 2>/dev/null)"
  else
    say "  ${RED}✗${NC} docker compose 미설치"; issues=$((issues+1))
  fi
  for f in "$BASE_FILE" "$COMMON_FILE" compose.dev.yml compose.prod.yml; do
    if [ -f "$f" ]; then say "  ${GREEN}✓${NC} $f"; else say "  ${RED}✗${NC} $f 없음"; issues=$((issues+1)); fi
  done
  for f in .env.dev .env.prod; do
    if [ -f "$f" ]; then say "  ${GREEN}✓${NC} $f"; else say "  ${YELLOW}⚠${NC} $f 없음 (init 실행 필요)"; fi
  done
  for f in ../secrets/mysql_root_password.txt ../secrets/mysql_password.txt ../secrets/ingest_token.txt ../secrets/admin_password.txt; do
    if [ -s "$f" ]; then say "  ${GREEN}✓${NC} $f"; else say "  ${YELLOW}⚠${NC} $f 없음/빈값 (init 실행 필요)"; fi
  done
  if [ -s ../secrets/duckdns_token.txt ]; then say "  ${GREEN}✓${NC} ../secrets/duckdns_token.txt"; else say "  ${YELLOW}⚠${NC} ../secrets/duckdns_token.txt 없음/빈값 (운영 HTTPS 쓰려면 DuckDNS 토큰 입력)"; fi

  # 검증 게이트가 실제로 걸려 있나. CLAUDE.md 는 "강제" 라고 하지만, 설치가 안 됐으면
  # 조용히 없는 상태가 된다 — 있다고 믿는 게 제일 위험하다.
  if [ "$(git config --get core.hooksPath 2>/dev/null || true)" = "deploy/hooks" ] && [ -x hooks/pre-push ]; then
    say "  ${GREEN}✓${NC} 검증 게이트 (pre-push: php -l · bash -n · smoke)"
  else
    say "  ${YELLOW}⚠${NC} 검증 게이트 미설치 — ${CYAN}$0 init${NC} 실행 (지금은 lint·smoke 없이 push 된다)"
  fi

  echo ""
  if [ "$issues" -eq 0 ]; then
    say "${GREEN}점검 통과.${NC}"
  else
    say "${YELLOW}${issues}개 문제 발견 — 위 항목을 확인하세요.${NC}"
  fi
  return "$issues"
}

# --- 특수 명령 처리 ---------------------------------------------------------
if [ $# -eq 0 ] || [ "${1:-}" = "help" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  show_help; exit 0
fi
case "$1" in
  init)   run_init;   exit 0 ;;
  doctor) run_doctor; exit $? ;;
esac

# --- 환경 선택 --------------------------------------------------------------
ENV="$1"; shift
case "$ENV" in
  dev|development)
    ENV_FILE="compose.dev.yml"; ENV_VAR_FILE=".env.dev"
    PROJECT="vulnagent-dev${WT_SUFFIX}"
    ENV_DISPLAY="Development${WT_NAME:+ · wt/$WT_NAME}"
    # compose 파일이 참조하는 이름들. 워크트리가 아니면 접미사가 비어 기존 이름 그대로다.
    export DB_CONTAINER="vulnagent-db-dev${WT_SUFFIX}"
    export WEB_CONTAINER="vulnagent-web-dev${WT_SUFFIX}"
    export SCHEDULER_CONTAINER="vulnagent-scheduler-dev${WT_SUFFIX}"
    # dev 이미지는 **모든 워크트리가 공유한다**(태그 고정).
    #   dev 는 ../server 를 바인드 마운트하므로 이미지 안의 코드는 어차피 덮인다 —
    #   워크트리마다 이미지를 따로 구울 이유가 없다. 예전엔 APP_TAG=워크트리명이라
    #   워크트리를 팔 때마다 504MB 이미지가 새로 생겼다(실측: 태그 47개).
    #   Dockerfile(server/Dockerfile)을 바꾼 브랜치에서만 `--build` 를 붙이면 된다.
    export APP_TAG="dev" ;;
  prod|production)
    # 워크트리에서 운영 스택을 건드리는 건 사고다. 메인 트리에서만 허용.
    if [ -n "$WT_NAME" ]; then
      say "${RED}오류: 워크트리(wt/$WT_NAME)에서는 prod 를 띄울 수 없습니다.${NC}"
      say "메인 트리에서 실행하세요."; exit 1
    fi
    ENV_FILE="compose.prod.yml"; ENV_VAR_FILE=".env.prod"
    PROJECT="vulnagent";         ENV_DISPLAY="Production"
    export DB_CONTAINER="vulnagent-db" ;;
  *)
    say "${RED}오류: 알 수 없는 환경 '$ENV'${NC}"
    say "사용 가능: ${GREEN}dev${NC}, ${GREEN}prod${NC}"; echo ""; show_help; exit 1 ;;
esac

check_file "$BASE_FILE"; check_file "$COMMON_FILE"; check_file "$ENV_FILE"
if [ ! -f "$ENV_VAR_FILE" ]; then
  say "${RED}오류: $ENV_VAR_FILE 이 없습니다.${NC} 먼저 ${CYAN}$0 init${NC} 을 실행하세요."
  exit 1
fi

# docker compose 명령 조합 (--env-file 로 변수 주입, -p 로 환경 격리)
COMPOSE=(docker compose
  --env-file "$ENV_VAR_FILE"
  -p "$PROJECT"
  -f "$BASE_FILE" -f "$COMMON_FILE" -f "$ENV_FILE")

say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
say "  환경 : ${GREEN}${ENV_DISPLAY}${NC}  (project: ${PROJECT})"
say "  파일 : $BASE_FILE + $COMMON_FILE + $ENV_FILE"
say "  변수 : $ENV_VAR_FILE"
say "  실행 : ${GREEN}docker compose ... $*${NC}"
say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# `up` 이면 기동 후 DB 마이그레이션을 이어서 적용한다(fresh 볼륨의 증분 스키마 반영).
#   그 외 명령(down/logs/ps…)은 그대로 exec. migrate 는 DB healthy 를 스스로 기다린다.
if [ "${1:-}" = "up" ]; then
  "${COMPOSE[@]}" "$@"
  say ""
  say "${CYAN}== DB 마이그레이션 ==${NC}"
  bash "$SCRIPT_DIR/migrate.sh" "$DB_CONTAINER"
else
  exec "${COMPOSE[@]}" "$@"
fi
