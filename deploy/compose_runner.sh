#!/usr/bin/env bash
# =============================================================================
# vuln-agent · Docker Compose Runner
# =============================================================================
# 환경별 compose 파일을 자동으로 조합해 실행하는 스크립트.
#
# [파일 구조]
#   compose.yml         서비스 정의 (db=MySQL, web=PHP/Apache)
#   compose.common.yml  공통 런타임 (restart, 로깅, pids_limit)
#   compose.dev.yml     개발: web+scheduler (소스 마운트) — 워크트리별 독립 프로젝트로 뜬다
#   compose.dev-db.yml  개발: db (포트 노출) — 메인 트리 전용, 워크트리 프로젝트엔 안 들어간다
#   compose.dev-net.yml 개발: 위 둘이 컨테이너명으로 서로 찾을 외부 네트워크(vulnagent-dev-net)
#   compose.prod.yml    운영: 이미지 코드 + DB 포트 미노출
#   .env.dev / .env.prod  (각 *.template 에서 복사)
#
# [dev 는 "web+scheduler 는 워크트리별 독립, DB 는 공용 하나"다]
#   메인 트리에서 `dev up -d` → db+web+scheduler 전부(프로젝트 vulnagent-dev, 기존과 동일).
#   워크트리에서 `dev up -d` → 그 워크트리 전용 프로젝트(vulnagent-dev-<이름>)로 web+scheduler 만
#   뜨고, DB 는 안 건드린다(메인 트리의 vulnagent-db-dev 를 외부 네트워크로 그대로 쓴다) — 그래서
#   메인 트리·워크트리끼리, 워크트리끼리 서로 스택을 빼앗지 않는다(컨테이너명이 애초에 안 겹친다).
#   전제: 공용 DB(메인 트리 스택)가 먼저 떠 있어야 워크트리 web/scheduler 가 DB 에 붙는다.
#
# [사용법]
#   ./compose_runner.sh init             # .env.dev/.env.prod 생성(템플릿 복사) + dev 네트워크 생성
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
#   왜 신경 써야 하나: pre-push 훅의 스모크가 기본값으로 8000(메인 dev 스택)을 친다.
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
# **dev 는 web+scheduler 는 워크트리별 독립, DB 는 공용 하나다.** 워크트리에서 `dev up -d` 를
#   하면 그 워크트리 전용 컴포즈 프로젝트(vulnagent-dev-<이름>)로 web/scheduler 만 새로 뜨고
#   (컨테이너명도 접미사가 붙어 고유하다), DB 는 메인 트리의 공용 컨테이너(vulnagent-db-dev)를
#   외부 네트워크(compose.dev-net.yml)로 그대로 쓴다 — db 서비스는 워크트리 컴포즈 대상에 아예
#   포함되지 않는다(`up -d --no-deps web scheduler`). 그래서 워크트리끼리, 그리고 워크트리와
#   메인 트리끼리 서로 스택을 빼앗지 않는다 — 컨테이너명이 애초에 겹치지 않기 때문이다.
TREE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WT_NAME=""
if [ "$(basename "$(dirname "$TREE_ROOT")")" = "wt" ]; then
  WT_NAME="$(basename "$TREE_ROOT")"
fi
# 메인 트리 = 워크트리면 두 단계 위(main/wt/<이름> → main), 아니면 자기 자신.
MAIN_ROOT="$TREE_ROOT"
[ -n "$WT_NAME" ] && MAIN_ROOT="$(cd "$TREE_ROOT/../.." && pwd)"

# dev 컨테이너들이 서로 이름으로 찾아갈 외부 네트워크. 없으면 만든다(멱등) — init/doctor 뿐
# 아니라 dev 실행 시점에도 방어적으로 보장한다(예전에 init 을 안 돌린 저장소도 있을 수 있음).
ensure_dev_net() {
  command -v docker >/dev/null 2>&1 || return 0
  docker network inspect vulnagent-dev-net >/dev/null 2>&1 \
    || docker network create vulnagent-dev-net >/dev/null
}

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
  for name in mysql_root_password mysql_password admin_password; do
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

  # 2.5) dev 공유 네트워크 — db(메인 트리)와 web/scheduler(워크트리별)가 서로 이름으로 찾아갈
  #      외부 네트워크. 없으면 만든다(멱등, 한 번만 하면 모든 워크트리가 함께 쓴다).
  if command -v docker >/dev/null 2>&1; then
    if docker network inspect vulnagent-dev-net >/dev/null 2>&1; then
      say "  ${BLUE}→${NC} 존재: docker network vulnagent-dev-net (유지)"
    else
      docker network create vulnagent-dev-net >/dev/null
      say "  ${GREEN}✓${NC} 생성: docker network vulnagent-dev-net"
    fi
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
    say "  호스트별 수집 토큰은 웹의 에이전트 키 화면에서 발급합니다."
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
  for f in "$BASE_FILE" "$COMMON_FILE" compose.dev.yml compose.dev-db.yml compose.dev-net.yml compose.prod.yml; do
    if [ -f "$f" ]; then say "  ${GREEN}✓${NC} $f"; else say "  ${RED}✗${NC} $f 없음"; issues=$((issues+1)); fi
  done
  for f in .env.dev .env.prod; do
    if [ -f "$f" ]; then say "  ${GREEN}✓${NC} $f"; else say "  ${YELLOW}⚠${NC} $f 없음 (init 실행 필요)"; fi
  done
  # prod 의 Caddy 사이트 주소. 없으면 `prod up` 이 compose 단계에서 거부되고(${PROD_DOMAIN:?…}),
  # 뚫려도 Caddy 가 빈 주소로 기동에 실패한다 → 뜨기 전에 여기서 알려 준다.
  if [ -f .env.prod ]; then
    if grep -Eq '^[[:space:]]*PROD_DOMAIN=[^[:space:]]' .env.prod; then
      say "  ${GREEN}✓${NC} .env.prod: PROD_DOMAIN"
    else
      say "  ${YELLOW}⚠${NC} .env.prod 에 PROD_DOMAIN 없음/빈값 (운영 Caddy 사이트 주소 — 없으면 prod up 이 거부된다)"
    fi
  fi
  if command -v docker >/dev/null 2>&1; then
    if docker network inspect vulnagent-dev-net >/dev/null 2>&1; then
      say "  ${GREEN}✓${NC} docker network vulnagent-dev-net"
    else
      say "  ${YELLOW}⚠${NC} docker network vulnagent-dev-net 없음 (init 실행 필요 — dev up -d 가 자동 생성도 함)"
    fi
  fi
  for f in ../secrets/mysql_root_password.txt ../secrets/mysql_password.txt ../secrets/admin_password.txt; do
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
    ensure_dev_net
    # MYSQL_DATABASE/USER/VERSION 같은 공통값은 항상 메인 트리의 .env.dev 에서 읽는다(DB 는 공용).
    ENV_VAR_FILE="$MAIN_ROOT/deploy/.env.dev"
    # dev 이미지는 **모든 워크트리가 공유한다**(태그 고정).
    #   dev 는 ../server 를 바인드 마운트하므로 이미지 안의 코드는 어차피 덮인다 —
    #   워크트리마다 이미지를 따로 구울 이유가 없다. 예전엔 APP_TAG=워크트리명이라
    #   워크트리를 팔 때마다 504MB 이미지가 새로 생겼다(실측: 태그 47개).
    #   Dockerfile(server/Dockerfile)을 바꾼 브랜치에서만 `--build` 를 붙이면 된다.
    export APP_TAG="dev"
    # DB 컨테이너명은 트리와 무관하게 항상 이 하나 — web/scheduler 가 외부 네트워크로 찾아간다.
    export DB_CONTAINER="vulnagent-db-dev"
    # DB_DATA 도 항상 메인 트리 절대경로로 고정한다(워크트리는 db 서비스를 아예 안 띄우지만,
    #   --env-file 의 상대경로(../data/mysql)가 "컴포즈 파일이 있는 트리" 기준으로 풀려 실수로
    #   워크트리 밑을 가리키는 걸 막는 방어선 — db 를 절대 안 띄우는 게 1차 방어, 이건 2차 방어).
    #   pwd -W 는 git-bash 에서 윈도 경로(C:/…)를 준다. 리눅스면 실패하니 pwd 로 떨어진다.
    export DB_DATA="$( (cd "$MAIN_ROOT" && pwd -W 2>/dev/null) || printf '%s' "$MAIN_ROOT" )/data/mysql"

    if [ -n "$WT_NAME" ]; then
      # --- 워크트리: web+scheduler 만 이 워크트리 전용 프로젝트로 뜬다. DB 는 안 건드린다. ---
      ENV_FILE_ARGS=(-f compose.dev.yml -f compose.dev-net.yml)
      PROJECT="vulnagent-dev-$WT_NAME"
      ENV_DISPLAY="Development · wt/$WT_NAME (web+scheduler 독립, DB 는 공용)"
      # 컨테이너명에 워크트리 접미사 — 같은 호스트에서 이름이 겹치면 충돌하므로 필수.
      export WEB_CONTAINER="vulnagent-web-dev-$WT_NAME"
      export SCHEDULER_CONTAINER="vulnagent-scheduler-dev-$WT_NAME"
      # WEB_PORT 만 이 워크트리 로컬 .env.dev 에서 읽는다(wt.sh add 가 만듦) — 그 외 값은
      #   메인 트리 것을 그대로 쓴다(쉘 환경변수가 --env-file 값보다 우선한다).
      WT_ENV_FILE="$TREE_ROOT/deploy/.env.dev"
      if [ ! -f "$WT_ENV_FILE" ]; then
        say "${RED}오류: $WT_ENV_FILE 이 없습니다.${NC} ${CYAN}./deploy/wt.sh add${NC} 로 만든 워크트리만 dev 를 쓸 수 있습니다."
        exit 1
      fi
      WT_WEB_PORT="$(sed -n 's/^WEB_PORT=\([0-9]\+\).*/\1/p' "$WT_ENV_FILE" | head -1)"
      if [ -z "$WT_WEB_PORT" ]; then
        say "${RED}오류: $WT_ENV_FILE 에 WEB_PORT 가 없습니다.${NC}"
        exit 1
      fi
      export WEB_PORT="$WT_WEB_PORT"
      # web/scheduler 가 DB_HOST=db(서비스명) 대신 공용 db 컨테이너명을 직접 가리키게 한다 —
      #   외부 네트워크의 서비스 별칭에 기대는 대신 명시적으로 고정한다(server/src/config.php 가
      #   DB_HOST 를 env 로 이미 읽으므로 이 값만 얹으면 된다. 새 추상화 불필요).
      export DB_HOST="vulnagent-db-dev"
    else
      # --- 메인 트리: 지금처럼 db+web+scheduler 전부 한 프로젝트(vulnagent-dev)로 뜬다. ---
      ENV_FILE_ARGS=(-f compose.dev.yml -f compose.dev-db.yml -f compose.dev-net.yml)
      PROJECT="vulnagent-dev"
      ENV_DISPLAY="Development (db+web+scheduler)"
      export WEB_CONTAINER="vulnagent-web-dev"
      export SCHEDULER_CONTAINER="vulnagent-scheduler-dev"
      # DB_DATA(위에서 이미 메인 트리 절대경로로 고정) 는 named volume 이 아니라 바인드마운트다 —
      #   기존 dev 데이터(수백 MB)를 그대로 쓰고, 디스크에서 눈으로 확인·백업할 수 있다.
    fi ;;
  prod|production)
    # 워크트리에서 운영 스택을 건드리는 건 사고다. 메인 트리에서만 허용.
    if [ -n "$WT_NAME" ]; then
      say "${RED}오류: 워크트리(wt/$WT_NAME)에서는 prod 를 띄울 수 없습니다.${NC}"
      say "메인 트리에서 실행하세요."; exit 1
    fi
    ENV_FILE_ARGS=(-f compose.prod.yml); ENV_VAR_FILE=".env.prod"
    PROJECT="vulnagent";         ENV_DISPLAY="Production"
    export DB_CONTAINER="vulnagent-db" ;;
  *)
    say "${RED}오류: 알 수 없는 환경 '$ENV'${NC}"
    say "사용 가능: ${GREEN}dev${NC}, ${GREEN}prod${NC}"; echo ""; show_help; exit 1 ;;
esac

check_file "$BASE_FILE"; check_file "$COMMON_FILE"
for f in "${ENV_FILE_ARGS[@]}"; do [ "$f" = "-f" ] || check_file "$f"; done
if [ ! -f "$ENV_VAR_FILE" ]; then
  say "${RED}오류: $ENV_VAR_FILE 이 없습니다.${NC} 먼저 ${CYAN}$0 init${NC} 을 실행하세요."
  exit 1
fi

# docker compose 명령 조합 (--env-file 로 변수 주입, -p 로 환경 격리)
COMPOSE=(docker compose
  --env-file "$ENV_VAR_FILE"
  -p "$PROJECT"
  -f "$BASE_FILE" -f "$COMMON_FILE" "${ENV_FILE_ARGS[@]}")

say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
say "  환경 : ${GREEN}${ENV_DISPLAY}${NC}  (project: ${PROJECT})"
say "  파일 : $BASE_FILE + $COMMON_FILE + ${ENV_FILE_ARGS[*]}"
say "  변수 : $ENV_VAR_FILE"
say "  실행 : ${GREEN}docker compose ... $*${NC}"
say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# 워크트리 dev 프로젝트엔 db 서비스가 기본 대상엔 없지만(compose.dev.yml 에 web/scheduler만
#   등장), BASE_FILE(compose.yml)에는 db 서비스 정의 자체가 있다 — 그래서 사용자가 인자로
#   "db" 를 직접 주면 docker compose 가 그걸 명시적 대상으로 받아들여 그대로 시도한다. db 는
#   메인 트리 프로젝트 소유라 워크트리 프로젝트로 뜨면 컨테이너명이 vulnagent-db-dev 로
#   충돌하거나, 메인 스택이 안 떠 있을 때 워크트리가 공용 DB 를 잘못 소유해 버린다.
#   검사 대상 서브커맨드를 스택 라이프사이클(up/down/restart/stop/start)로 한정한다 — exec/run
#   은 서비스 위치 뒤에 컨테이너 내부 명령·옵션 인자가 그대로 붙어서(예: `exec web mysql -h db`)
#   "db" 라는 토큰이 서비스가 아니라 그 명령의 인자값으로도 나타날 수 있어 전체 스캔이 오탐을
#   낸다. logs/ps 등 정보 조회용도 같은 이유로 제외한다(컨테이너를 새로 만들거나 상태를 바꾸지
#   않으니 사고 리스크가 낮다).
case "${1:-}" in
  up|down|restart|stop|start)
    if [ "$ENV" = "dev" ] && [ -n "$WT_NAME" ]; then
      for a in "$@"; do
        if [ "$a" = "db" ]; then
          say "${RED}오류: 워크트리에서는 db 를 다룰 수 없습니다.${NC} 공용 DB 는 메인 트리에서 관리하세요."
          exit 1
        fi
      done
    fi
    ;;
esac

# `up` 이면 기동 후 DB 마이그레이션을 이어서 적용한다(fresh 볼륨의 증분 스키마 반영).
#   그 외 명령(down/logs/ps…)은 그대로 exec. migrate 는 DB healthy 를 스스로 기다린다.
#   워크트리 dev 는 web/scheduler 만 대상으로 한다("db" 인자는 위에서 이미 걸렀다) —
#   사용자가 web/scheduler 중 일부를 인자로 직접 지정하면(예: `dev up -d scheduler`, 특정
#   서비스만 재기동) 그 지정을 존중해 기본값을 덧붙이지 않는다. 아무 서비스도 지정하지
#   않았을 때만 web scheduler 둘 다를 기본으로 띄운다(뒤에 붙이는 자리라 "$@" 끝이 값을 요구하는
#   옵션이면 그 값으로 먹힐 수 있지만, 이 저장소 dev 워크플로우에선 그런 옵션을 쓰지 않는다).
#   svcs 는 배열이 아니라 문자열 플래그로 둔다 — 빈 배열의 `${#arr[@]}` 참조가 구버전 bash
#   (Windows git-bash 구성에 따라 남아 있을 수 있는 4.3 이하)에서 `set -u` 와 부딪혀
#   unbound variable 로 죽는 사례가 있어, 배열 확장 자체를 피한다. 마이그레이션은 그대로
#   돌린다: DB_CONTAINER 가 트리와 무관하게 항상 vulnagent-db-dev 라 어느 워크트리에서 걸어도
#   공용 DB에 적용된다(migrate.sh 의 flock 이 DB_CONTAINER 이름 기준 호스트 로컬 락이라 동시
#   실행도 안전 — 모든 워크트리가 같은 호스트에 있다는 전제).
if [ "${1:-}" = "up" ]; then
  if [ "$ENV" = "dev" ] && [ -n "$WT_NAME" ]; then
    shift
    svcs=""
    for a in "$@"; do
      case "$a" in
        web|scheduler) svcs="y" ;;
      esac
    done
    if [ -z "$svcs" ]; then
      "${COMPOSE[@]}" up --no-deps "$@" web scheduler
    else
      "${COMPOSE[@]}" up --no-deps "$@"
    fi
  else
    "${COMPOSE[@]}" "$@"
  fi
  say ""
  say "${CYAN}== DB 마이그레이션 ==${NC}"
  bash "$SCRIPT_DIR/migrate.sh" "$DB_CONTAINER"
else
  exec "${COMPOSE[@]}" "$@"
fi
