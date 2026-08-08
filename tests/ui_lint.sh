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

# --- 5) 역방향: 정의됐는데 아무도 안 쓰는 클래스 (경고 — 실패로 세지 않는다) -----
# 1) 은 PHP→CSS 한 방향만 본다(쓰는데 정의가 없는 것). 반대 방향은 아무도 안 봐서
#   화면이 사라져도 규칙만 app.css 에 남았다 — 실제로 #387 이 수동 경계/재매칭 화면을
#   지웠는데 .check-row·.setting-card 규칙은 그대로 남아 있었다(1949줄까지 불어난 원인).
#
#   왜 경고(비차단)인가: 이 검사는 리터럴 일치라 동적 조립을 원리적으로 다 못 본다.
#   차단으로 두면 정상적인 신규 클래스 추가가 게이트에서 막힌다. 사람이 보고 판단하게 한다.
#
#   [예외 접두사] 코드가 문자열로 조립해서 만드는 클래스 — 리터럴로는 절대 안 잡힌다.
#   접두사 하나당 "누가 만드는가" 를 적어 둔다. 새 동적 클래스를 만들면 여기에 추가한다.
DYNAMIC_PREFIXES=(
  'page--'        # view/layout.php  : 'page--' . basename($_SERVER['SCRIPT_NAME'])
  'hero--'        # view/components.php vg_hero()  : 'hero--' . $riskTone
  'meter--'       # format.php vg_meter()          : 'meter--' . $tone
  'alert--'       # view/components.php vg_alert() : 'alert--' . $type
  'tone-'         # format.php vg_badge()/vg_sev_bar(), view/charts.php : 'tone-' . $tone
  'sev-'          # format.php vg_sev_row()        : 'sev-' . VG_TONE_SEV[...]
  'is-'           # assets/app.js : 'collection-item is-' + command.status, classList.toggle
  'chart__lbl--'  # view/charts.php : 'chart__lbl--' . $edge (start|end)
)

# 정의: app.css 의 선택자에 나오는 클래스. 주석과 url(...)·content:"..." 은 걷어낸다
#   — 주석 속 `.page--<스크립트>` 나 데이터 URI 의 `www.w3.org` 가 클래스로 잡히던 것.
css_src=$(awk '
  # 한 줄짜리 주석·데이터 URI. 주석 패턴은 C 주석 정본형 — `[^*]*` 로 줄이면 본문에 `*` 가
  #   든 주석(`.badge.tone-*` 같은 설명)에서 끊겨 뒤 줄의 실제 규칙까지 주석으로 먹는다.
  { gsub(/url\([^)]*\)/, ""); gsub(/\/\*([^*]|\*+[^*\/])*\*+\//, "") }
  /\/\*/ { sub(/\/\*.*/, ""); print; inc=1; next }               # 여러 줄 주석 시작
  inc && /\*\// { sub(/.*\*\//, ""); inc=0; print; next }        # 그 끝
  inc { next }
  { print }
' "$CSS" | grep -oE '\.[A-Za-z][A-Za-z0-9_-]*' | tr -d '.' | sort -u)

# 사용: PHP·JS·HTML 어디든. vendor(flatpickr) JS 도 본다 — app.css 가 그 클래스를
#   재스타일하므로 vendor 를 빼면 flatpickr-* 23개가 통째로 오탐이 된다.
use_blob=$(mktemp)
find "$PUB" "$SRC" -type f \( -name '*.php' -o -name '*.js' -o -name '*.html' \) \
     ! -name 'app.css' -exec cat {} + > "$use_blob" 2>/dev/null

orphan=""
for c in $css_src; do
  skip=""
  for p in "${DYNAMIC_PREFIXES[@]}"; do
    case "$c" in "$p"*) skip=1; break;; esac
  done
  [ -n "$skip" ] && continue
  grep -qE "(^|[^A-Za-z0-9_-])$c([^A-Za-z0-9_-]|$)" "$use_blob" || orphan="$orphan $c"
done
rm -f "$use_blob"

if [ -z "$orphan" ]; then
  ok "안 쓰이는 CSS 클래스 없음 (app.css 정의가 전부 코드에서 참조된다)"
else
  printf "  ${CYAN}!${NC} 경고: 참조가 안 보이는 app.css 클래스:%s\n" "$orphan"
  printf "      동적 조립이면 DYNAMIC_PREFIXES 에 사유와 함께 추가하고, 아니면 규칙을 지운다.\n"
fi

printf "\n${CYAN}== UI 검사: ${GREEN}%d 통과${NC}, ${RED}%d 실패${NC} ==${NC}\n" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
