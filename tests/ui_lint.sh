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
SRC="$ROOT/server/src"
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
# 색·레이아웃은 app.css 가 소유한다(CLAUDE.md). 폭 계산(width:…)만 예외 — 게이지·미터,
# 표 컬럼 너비(vg_table() 의 $width, rem/px 단위)가 쓴다. width 하나만 있고 다른 속성이
# 안 섞였는지까지 본다 — 'width:10px;color:red' 처럼 얹혀 오는 건 여전히 잡아야 하므로.
#   공용 헬퍼(server/src/view.php 의 vg_table())도 style="…" 을 만들 수 있으므로 server/src 도 본다
#   — 예전엔 $PUB 만 봐서 vg_table() 의 text-align 인라인 style 이 그대로 새고 있었다.
inline=$(grep -nE 'style="' "$PUB"/*.php "$SRC"/*.php | grep -vE 'style="width:[^";]*;?"' || true)
if [ -z "$inline" ]; then
  ok "PHP 안에 인라인 style 없음 (폭 계산 제외)"
else
  no "인라인 style 발견:"
  printf '      %s\n' "$inline"
fi

# --- 3) 정의되지 않은 CSS 변수 ----------------------------------------------
# app.css 가 var(--X) 로 쓰는데 어디에도 --X: 선언이 없는 것. 그 선언은 통째로 무효라
#   브라우저 기본값으로 조용히 떨어진다(색이 안 칠해져도 오류가 안 난다).
#   실제로: 리스킨 레이어가 var(--primary)·var(--line-strong) 을 썼는데 토큰명은
#   --accent·--line-2 였다 — 권한설정 체크박스의 accent-color 가 무효가 돼 브라우저
#   기본색으로 떴고, 아무도 못 알아챘다.
undef=""
declared=$(grep -oE '^[[:space:]]*--[a-z0-9-]+[[:space:]]*:' "$CSS" | tr -d ' :' | sort -u)
for v in $(grep -oE 'var\([[:space:]]*--[a-z0-9-]+' "$CSS" | grep -oE '\-\-[a-z0-9-]+' | sort -u); do
  printf '%s\n' "$declared" | grep -qx -- "$v" || undef="$undef $v"
done
if [ -z "$undef" ]; then
  ok "정의되지 않은 CSS 변수 없음 (app.css 의 var(--…) 는 전부 선언돼 있다)"
else
  no "app.css 에 선언이 없는 CSS 변수:$undef"
fi

# --- 4) 조용히 잘리는 목록 --------------------------------------------------
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
