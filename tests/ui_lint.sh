#!/usr/bin/env bash
# =============================================================================
# vuln-agent · UI 정적 검사 (서버 없이 도는 검사 — smoke.sh 가 맨 앞에서 부른다)
# =============================================================================
# 왜 있나: 사람 눈으로 못 잡아서 실제로 쌓였던 결함들을 기계가 잡게 한다.
#   · changes.php 가 <div class="err"> 로 오류를 감쌌는데 app.css 에 .err 가 없었다
#     → 오류가 스타일 없는 맨텍스트로 뜨고 있었다(아무도 못 알아챘다).
#   · PHP 안에 style="…" 이 흩어져 있었다 — CLAUDE.md 가 금지한 규칙인데도.
#
#   사용:  ./tests/ui_lint.sh
#   종료코드: 위반이 하나라도 있으면 1.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUB="$ROOT/server/public"
CSS="$PUB/assets/app.css"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
pass=0; fail=0
ok() { printf "  ${GREEN}✓${NC} %s\n" "$1"; pass=$((pass+1)); }
no() { printf "  ${RED}✗${NC} %s\n" "$1"; fail=$((fail+1)); }

printf "${CYAN}== UI 정적 검사 ==${NC}\n"

[ -f "$CSS" ] || { echo "app.css 없음: $CSS"; exit 2; }

# --- 1) 죽은 클래스 --------------------------------------------------------
# PHP 가 class="..." 로 쓰는데 app.css 에 정의가 없는 것. 화면이 조용히 안 입혀진다.
#   .tone-* 은 톤 어휘라 tone-crit 등으로 조합돼 쓰인다 — CSS 에 개별 선택자가 있으므로 그대로 검사된다.
dead=""
classes=$(grep -ohE 'class="[a-z0-9 _-]+"' "$PUB"/*.php \
          | sed 's/class="//; s/"//' | tr ' ' '\n' | sort -u | grep -vE '^$')
for c in $classes; do
  grep -qE "\.$c([^a-z0-9_-]|$)" "$CSS" || dead="$dead $c"
done
if [ -z "$dead" ]; then
  ok "죽은 CSS 클래스 없음 (PHP 가 쓰는 클래스는 전부 app.css 에 있다)"
else
  no "app.css 에 없는 클래스:$dead"
fi

# --- 2) 인라인 style -------------------------------------------------------
# 색·레이아웃은 app.css 가 소유한다(CLAUDE.md). 폭 계산(width:N%)만 예외 — 게이지·미터가 쓴다.
inline=$(grep -nE 'style="' "$PUB"/*.php | grep -vE 'style="width:[^"]*%' || true)
if [ -z "$inline" ]; then
  ok "PHP 안에 인라인 style 없음 (폭 계산 제외)"
else
  no "인라인 style 발견:"
  printf '      %s\n' "$inline"
fi

# --- 3) 조용히 잘리는 목록 --------------------------------------------------
# LIMIT 을 쓰면서 OFFSET 도 vg_page_nav 도 없으면, 사용자는 "더 있다" 는 걸 알 수 없다.
#   LIMIT 1 (단건 조회)과 상수 상한(VG_URGENT_TOP 처럼 이름 붙이고 총건수를 함께 보여주는 것)은 예외.
silent=""
for f in "$PUB"/*.php; do
  grep -qE 'LIMIT [0-9]{1,}' "$f" || continue
  grep -qE 'LIMIT 1\b|LIMIT \$|LIMIT " \. VG_|OFFSET' "$f" && continue
  grep -q 'vg_page_nav' "$f" && continue
  silent="$silent $(basename "$f")"
done
if [ -z "$silent" ]; then
  ok "페이저 없이 잘리는 목록 없음"
else
  no "LIMIT 으로 자르는데 페이저도 총건수도 없는 파일:$silent"
fi

printf "\n${CYAN}== UI 검사: ${GREEN}%d 통과${NC}, ${RED}%d 실패${NC} ==${NC}\n" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
