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

# 줄 목록("a\nb")을 " a b" 로 접는다. 결과는 전역 WS 에 담는다 — 명령치환($(...))은
# 서브셸 fork 라, 아래 검사들이 프로세스 수를 줄이려는 마당에 다시 늘릴 이유가 없다.
WS=""
ws_list() { WS=""; local x; while read -r x; do [ -n "$x" ] && WS+=" $x"; done <<< "$1"; }

printf "${CYAN}== UI 정적 검사 ==${NC}\n"

[ -f "$CSS" ] || { echo "app.css 없음: $CSS"; exit 2; }

# --- 1) 죽은 클래스 --------------------------------------------------------
# PHP 가 class="..." 로 쓰는데 app.css 에 정의가 없는 것. 화면이 조용히 안 입혀진다.
#   .tone-* 은 톤 어휘라 tone-crit 등으로 조합돼 쓰인다 — CSS 에 개별 선택자가 있으므로 그대로 검사된다.
#   구현: 클래스마다 grep 을 부르지 않고 **집합 차집합**으로 한 번에 낸다.
#   왜: Windows git-bash 는 fork 한 번이 44~48ms 라, 125개 클래스 × grep = 6초가 통째로
#   프로세스 기동에 쓰였다(PR #587 과 같은 함정). 측정은 docs/dev/smoke-timing-profiling.md.
#   동치인 이유: 원래 정규식 `\.$c([^a-z0-9_-]|$)` 는 "c 가 CSS 안에서 점 뒤의 **온전한**
#   토큰으로 나오는가" 다([a-z0-9_-] 가 이어지면 안 되므로). 아래 추출이 그 토큰 집합 자체다.
dead=""
classes=$(grep -ohE 'class="[a-z0-9 _-]+"' "$PUB"/*.php \
          | sed 's/class="//; s/"//' | tr ' ' '\n' | grep -vE '^$' | LC_ALL=C sort -u)
css_tokens=$(grep -ohE '\.[A-Za-z0-9_][A-Za-z0-9_-]*' "$CSS" | tr -d '.' | LC_ALL=C sort -u)
ws_list "$(LC_ALL=C comm -23 <(printf '%s\n' "$classes") <(printf '%s\n' "$css_tokens"))"
dead="$WS"
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
#   구현은 1) 과 같은 이유로 집합 차집합이다(변수마다 grep 을 부르면 70×2 fork = 6초).
declared=$(grep -oE '^[[:space:]]*--[a-z0-9-]+[[:space:]]*:' "$CSS" | tr -d ' :' | LC_ALL=C sort -u)
used=$(grep -oE 'var\([[:space:]]*--[a-z0-9-]+' "$CSS" | grep -oE '\-\-[a-z0-9-]+' | LC_ALL=C sort -u)
ws_list "$(LC_ALL=C comm -23 <(printf '%s\n' "$used") <(printf '%s\n' "$declared"))"
undef="$WS"
if [ -z "$undef" ]; then
  ok "정의되지 않은 CSS 변수 없음 (app.css 의 var(--…) 는 전부 선언돼 있다)"
else
  no "app.css 에 선언이 없는 CSS 변수:$undef"
fi

# --- 4) 조용히 잘리는 목록 --------------------------------------------------
# LIMIT 을 쓰면서 OFFSET 도 vg_page_nav 도 없으면, 사용자는 "더 있다" 는 걸 알 수 없다.
#   LIMIT 1 (단건 조회)과 상수 상한(VG_URGENT_TOP 처럼 이름 붙이고 총건수를 함께 보여주는 것)은 예외.
#   구현: 파일마다 grep 3번(45파일 = 135 fork ≈ 6초) 대신 **전체 파일을 한 번씩 훑는
#   grep -l 3회**로 목록 3개를 만들고 차집합을 낸다. 판정 논리는 파일별 검사와 동일하다.
lim_hit=$(grep -lE 'LIMIT [0-9]{1,}' "$PUB"/*.php 2>/dev/null | LC_ALL=C sort -u || true)
lim_ok=$( { grep -lE 'LIMIT 1\b|LIMIT \$|LIMIT " \. VG_|OFFSET' "$PUB"/*.php 2>/dev/null || true
            grep -l 'vg_page_nav' "$PUB"/*.php 2>/dev/null || true; } | LC_ALL=C sort -u)
silent=""
ws_list "$(LC_ALL=C comm -23 <(printf '%s\n' "$lim_hit") <(printf '%s\n' "$lim_ok") \
           | sed 's#.*/##')"
silent="$WS"
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
  'verdict--'     # view/components.php vg_verdict() : 'verdict verdict--' . $tone
  'verdict__stat--' # view/components.php vg_verdict() : 'verdict__stat--' . $s['tone']
  'funnel__step--'  # index.php 퍼널 : 'funnel__step--s' . ($i + 1) (칸 순서로 무게가 커진다)
)

# 정의: app.css 의 선택자에 나오는 클래스. 주석과 url(...) 은 걷어낸다 — 주석 속
#   `.page--<스크립트>` 나 데이터 URI 의 `www.w3.org` 가 클래스로 잡히던 것.
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
# 여기가 이 스크립트에서 제일 비쌌다(전체 45초 중 30초). 두 가지가 겹쳐 있었다.
#   ① 클래스 363개마다 합본 파일을 grep 으로 다시 훑었다 — fork 363회(git-bash 는 fork 1회가
#      44~48ms, PR #587)에 총 835MB 재스캔.
#   ② 그 합본을 임시 파일로 새로 만들어 읽었다 — **갓 쓴 임시 파일의 첫 읽기**가 Windows 에서
#      1.9MB에 9.7초였다(백신 실시간 검사로 보인다). 두 번째 읽기부터는 0.3초다.
#   그래서 합본을 만들지 않는다: 원본 파일들을 awk 한 번으로 훑어 **토큰 집합만** 뽑는다.
#   원본은 앞 검사들이 이미 읽어 캐시가 더워져 있고, 출력도 35만 줄이 아니라 7천 줄이다.
#   동치인 이유: 원래 정규식의 경계가 `[^A-Za-z0-9_-]` 였으므로 "그 문자집합으로 자른 온전한
#   토큰인가" 와 같은 판정이다.
use_files=()
while IFS= read -r f; do use_files+=("$f"); done < <(
  find "$PUB" "$SRC" -type f \( -name '*.php' -o -name '*.js' -o -name '*.html' \) ! -name 'app.css'
)
BLOB_TOK="$(mktemp)"
awk '{ n = split($0, tok, /[^A-Za-z0-9_-]+/)
       for (i = 1; i <= n; i++) if (tok[i] != "") seen[tok[i]] = 1 }
     END { for (k in seen) print k }' "${use_files[@]}" 2>/dev/null \
  | LC_ALL=C sort -u > "$BLOB_TOK"

# 동적 조립 클래스는 리터럴로 못 잡으므로 비교 전에 뺀다(bash 내장 — 프로세스 없음).
cand=""
for c in $css_src; do
  skip=""
  for p in "${DYNAMIC_PREFIXES[@]}"; do
    case "$c" in "$p"*) skip=1; break;; esac
  done
  [ -n "$skip" ] || cand="$cand$c"$'\n'
done
ws_list "$(LC_ALL=C comm -23 <(printf '%s' "$cand" | LC_ALL=C sort -u) "$BLOB_TOK")"
orphan="$WS"
rm -f "$BLOB_TOK"

if [ -z "$orphan" ]; then
  ok "안 쓰이는 CSS 클래스 없음 (app.css 정의가 전부 코드에서 참조된다)"
else
  printf "  ${CYAN}!${NC} 경고: 참조가 안 보이는 app.css 클래스:%s\n" "$orphan"
  printf "      동적 조립이면 DYNAMIC_PREFIXES 에 사유와 함께 추가하고, 아니면 규칙을 지운다.\n"
fi

printf "\n${CYAN}== UI 검사: ${GREEN}%d 통과${NC}, ${RED}%d 실패${NC} ==${NC}\n" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
