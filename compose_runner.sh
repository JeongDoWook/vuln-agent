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
#   ./compose_runner.sh dev  up -d --build   # 개발 환경 기동
#   ./compose_runner.sh dev  down            # 개발 환경 중지
#   ./compose_runner.sh dev  logs -f         # 로그
#   ./compose_runner.sh prod up -d --build   # 운영 환경 기동
#   ./compose_runner.sh prod ps              # 상태
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
say() { printf "%b\n" "$1"; }

BASE_FILE="compose.yml"
COMMON_FILE="compose.common.yml"

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
  say "  $0 ${GREEN}dev${NC} up -d --build"
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
  mkdir -p secrets
  for name in mysql_root_password mysql_password ingest_token admin_password; do
    local f="secrets/${name}.txt"
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

  echo ""
  if [ "$ok" = 1 ]; then
    say "${GREEN}완료.${NC} 다음: ${CYAN}$0 dev up -d --build${NC}"
    say "  에이전트 전송 토큰(--token) 값:  ${CYAN}cat secrets/ingest_token.txt${NC}"
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
  for f in secrets/mysql_root_password.txt secrets/mysql_password.txt secrets/ingest_token.txt secrets/admin_password.txt; do
    if [ -s "$f" ]; then say "  ${GREEN}✓${NC} $f"; else say "  ${YELLOW}⚠${NC} $f 없음/빈값 (init 실행 필요)"; fi
  done
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
    PROJECT="vulnagent-dev";    ENV_DISPLAY="Development" ;;
  prod|production)
    ENV_FILE="compose.prod.yml"; ENV_VAR_FILE=".env.prod"
    PROJECT="vulnagent";         ENV_DISPLAY="Production" ;;
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

exec "${COMPOSE[@]}" "$@"
