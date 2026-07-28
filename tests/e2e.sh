#!/usr/bin/env bash
# =============================================================================
# vuln-agent · 브라우저 E2E (Playwright, 컨테이너 실행)
# =============================================================================
# 실행 중인 스택을 대상으로 **클라이언트 JS 동작**을 검증한다.
#   사용:  ./tests/e2e.sh [BASE_URL]     (기본 http://localhost:8000)
#   사전:  ./deploy/compose_runner.sh dev up -d 로 이 트리 스택이 떠 있어야 함.
#          비밀값은 secrets/admin_password.txt 에서 읽는다.
#
# 왜 있나: smoke.sh 는 curl 이라 HTML 만 받는다 — assets/app.js(테마·밀도·모바일 내비 등)가
#   통째로 깨져도 전부 통과한다. 그 구멍 하나만 덮는다. "화면이 뜨는지"는 smoke 가 이미 본다.
# 게이트(pre-push·smoke)에는 **넣지 않는다** — 브라우저 기동이 느려 매 push 가 굼떠진다.
#
# ⚠ 알려진 flaky 요인: 이 테스트는 admin 으로 로그인한다. auth.php 는 로그인마다
#   session_token 을 덮어써 "새 로그인 = 이전 세션 강제종료" 라, 다른 창에서 admin 으로
#   보던 세션이 튕긴다(dev DB 는 워크트리 공용이라 다른 트리도 마찬가지). 계정을 바꾸려면
#   VG_E2E_USER 로 넘긴다(smoke.sh 가 워크트리마다 만들어 두는 admin-<트리> 등).
# 종료코드: 실패가 하나라도 있으면 1, 사전조건 미충족이면 2.
# =============================================================================
set -uo pipefail

BASE="${1:-http://localhost:8000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMG="vulnagent-e2e:pw"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
pass=0; fail=0
ok() { printf "  ${GREEN}✓${NC} %s\n" "$1"; pass=$((pass+1)); }
no() { printf "  ${RED}✗${NC} %s\n" "$1"; fail=$((fail+1)); }

# 컨테이너에 넘길 경로는 git-bash 에서 윈도 형식이어야 한다(smoke.sh run_phpunit 과 동일).
win_path() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }

PWFILE="$ROOT/secrets/admin_password.txt"
[ -s "$PWFILE" ] || { echo "secrets 없음: $PWFILE — 먼저 ./deploy/compose_runner.sh init"; exit 2; }

printf "${CYAN}== vuln-agent browser e2e @ %s ==${NC}\n" "$BASE"

# --- 이 트리의 web 컨테이너가 떠 있나 -----------------------------------------
# 컨테이너명이 워크트리마다 고유하므로(vulnagent-web-dev-<워크트리>, 메인 트리는 접미사 없음)
# 그 이름이 떠 있는지만 보면 된다 — smoke.sh 의 assert_my_stack 과 같은 판정이다.
WT_NAME=""
if [ "$(basename "$(dirname "$ROOT")")" = "wt" ]; then
  WT_NAME="$(basename "$ROOT")"
fi
WEB_CONTAINER="${VG_WEB_CONTAINER:-vulnagent-web-dev${WT_NAME:+-$WT_NAME}}"
if [ "${VG_E2E_ANY:-0}" != "1" ] && command -v docker >/dev/null 2>&1; then
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Running}}{{end}}' \
       "$WEB_CONTAINER" 2>/dev/null)
  case "$st" in
    healthy|true) ;;
    *)
      printf "${RED}✗ 이 트리의 web 컨테이너(%s)가 떠 있지 않습니다 — E2E 를 중단합니다.${NC}\n" "$WEB_CONTAINER" >&2
      printf "    올리려면: ./deploy/compose_runner.sh dev up -d\n" >&2
      printf "    (일부러 다른 대상을 칠 때만 VG_E2E_ANY=1)\n" >&2
      exit 2
      ;;
  esac
fi

# --- 전용 이미지 --------------------------------------------------------------
# 베이스 이미지엔 브라우저만 있고 playwright 패키지가 없다 → 얇게 얹어 굽는다(Dockerfile 주석 참고).
# render.sh 와 같은 방식이라 레이어 캐시가 먹고, 두 번째 실행부터는 사실상 즉시 끝난다.
printf "  전용 이미지 준비: %s\n" "$IMG"
if ! MSYS_NO_PATHCONV=1 docker build -q -t "$IMG" "$(win_path "$ROOT/tests/e2e")" >/dev/null; then
  printf "${RED}✗ E2E 이미지 빌드 실패 — docker build -t %s tests/e2e 로 확인하세요.${NC}\n" "$IMG" >&2
  exit 2
fi

# 컨테이너에서 본 호스트 주소로 바꾼다. --add-host 로 host.docker.internal 을 게이트웨이에 붙인다.
CBASE="$(printf '%s' "$BASE" | sed -e 's#://localhost#://host.docker.internal#' \
                                   -e 's#://127\.0\.0\.1#://host.docker.internal#')"

# 비밀번호는 값 없는 -e 로 넘긴다 — `-e NAME=값` 은 프로세스 목록(ps)에 그대로 남는다.
export VG_E2E_PASSWORD; VG_E2E_PASSWORD="$(cat "$PWFILE")"
E2E_USER="${VG_E2E_USER:-admin}"
printf "  로그인 계정: %s (이 계정의 다른 세션은 튕긴다 — 헤더 주석 참고)\n" "$E2E_USER"

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

MSYS_NO_PATHCONV=1 docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$(win_path "$ROOT/tests/e2e"):/w" -w /w \
  -e NODE_PATH=/usr/lib/node_modules \
  -e VG_E2E_BASE="$CBASE" \
  -e VG_E2E_USER="$E2E_USER" \
  -e VG_E2E_PASSWORD \
  "$IMG" node run.cjs >"$OUT" 2>&1
rc=$?

# run.cjs 는 PASS|/FAIL| 한 줄씩만 내고, ✓/✗ 렌더와 집계는 여기서 한다(smoke.sh 와 같은 형식).
printf "\n[시나리오]\n"
while IFS= read -r line; do
  case "$line" in
    "PASS|"*) ok "${line#PASS|}" ;;
    "FAIL|"*) no "${line#FAIL|}" ;;
    "")       ;;
    *)        printf "    %s\n" "$line" ;;   # 그 밖의 출력(스택트레이스 등)은 그대로 보여준다
  esac
done < "$OUT"

# 컨테이너가 단언을 내기도 전에 죽으면(이미지·네트워크 문제) 실패가 0건인데 rc 만 0이 아니다.
if [ "$rc" -ne 0 ] && [ "$fail" -eq 0 ]; then
  no "E2E 컨테이너가 비정상 종료 (rc=$rc, 위 출력 참고)"
fi

printf "\n${CYAN}== 결과: ${GREEN}%d 통과${NC}, ${RED}%d 실패${NC} ==\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
