#!/usr/bin/env bash
# =============================================================================
# block-main-push.sh — main 브랜치 직접 commit/push 차단 (PreToolUse 훅)
# =============================================================================
# 동작: Bash/PowerShell 도구 호출 직전, 커맨드에서 아래를 감지하면 exit 2 로 차단
#   1) origin main 직접 push
#   2) 현재 브랜치가 main 일 때의 git commit
# → 항상 브랜치를 만들어 작업하고 PR 로 병합하게 강제.
#
# 판단 기준: "이 명령이 실제로 향하는 저장소·브랜치".
#   예전엔 명령 문자열만 grep 하고 브랜치는 훅 자신의 cwd 에서 봤다. 그래서
#     · 무관한 저장소(termkeep)에서 main 에 커밋하려는데 이 훅이 막았고,
#     · 메인 트리 cwd 에서 `cd wt/foo && git commit` 을 치면 대상은 워크트리인데
#       메인 트리의 main 을 보고 막았다.
#   지금은 훅 입력의 cwd + 명령 안의 cd/git -C 로 대상 디렉토리를 정하고, 그게
#   이 훅이 속한 저장소(= vuln-agent)일 때만 검사한다. 다른 저장소면 그냥 통과.
#
# ── 왜 정규식이 아니라 토크나이저인가 (보안 리뷰가 재현한 우회 3건) ─────────────
# 정규식으로 커맨드 "텍스트 전체"를 훑던 판이 세 방향으로 뚫렸다:
#   #1 `V=/c/…/vuln-agent && cd "$V" && git commit` → 훅은 `$V` 를 못 풀어 cwd 로
#      폴백했고, cwd 가 다른 저장소라 통과했다. 실제 셸은 변수를 확장해 vuln-agent
#      main 에 커밋한다. "해석 실패 → cwd 폴백" 은 그 자체가 상시 우회 통로다.
#   #2 `cd vuln-agent && git commit -m a; cd termkeep && git commit -m b` → 서로 다른
#      문장을 "마지막 cd" 하나로 뭉개서, 첫 문장의 main 커밋을 놓쳤다.
#   #3 `git commit -m "설명: git -C /tmp/repoB 참고"` → 커밋 메시지 본문을 실제 -C
#      옵션으로 오인해 대상을 그쪽으로 바꿨다. 아무 저장소 경로나 적으면 뚫렸다.
# 뿌리는 하나다: 정규식은 텍스트를 볼 뿐 "이게 명령 위치인지, 인자 속 산문인지"를
# 모른다. 그래서 파싱을 두 가지로 바꿨다.
#   · 따옴표를 아는 토크나이저로 커맨드를 단순명령(simple command)으로 쪼갠다.
#     `-m "…"` 안의 산문은 토큰 하나에 갇히므로 명령·경로로 승격될 수 없다(#3 해결).
#   · cwd 를 단순명령 순서대로 따라간다. cd 는 이후 문장에도 이어지고(#2 해결),
#     `cd A && cd B && commit` 은 자연히 B 기준이 된다.
#   · 경로가 안 풀리면(변수·명령치환·`~`·없는 경로) cwd 로 폴백하지 않고 대상을
#     "모름"으로 두고, 모르는 채로 git commit/push 를 만나면 차단한다(#1 해결).
#
# 안전 방향: 파싱은 완벽하지 않아도 된다. 애매하면 차단 쪽(보수적)으로 간다 —
#   오탐(막아서 사람이 확인)은 미탐(main 이 오염됨)보다 훨씬 싸다.
#   커밋 메시지 산문 때문에 막히면 `git commit -F <파일>` 을 쓴다(이 저장소 권장 방식).
# =============================================================================
unset CDPATH
INPUT=$(cat)

# --- JSON 에서 문자열 필드 하나 뽑기 (순수 bash/grep/sed — jq·python 의존 금지) ---
# 훅 입력은 snake_case JSON: {"cwd":"...","tool_name":"Bash","tool_input":{"command":"..."}}
json_str() {
  printf '%s' "$INPUT" \
    | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"([^\"\\\\]|\\\\.)*\"" \
    | head -n 1 \
    | sed -E "s/^\"$1\"[[:space:]]*:[[:space:]]*\"//; s/\"\$//" \
    | sed -e 's/\\\\/\x01/g' -e 's/\\"/"/g' -e 's/\\[nrt]/ /g' -e 's|\\/|/|g' -e 's/\x01/\\/g'
}

HOOK_CWD=$(json_str cwd)
CMD=$(json_str command)

[ -n "$HOOK_CWD" ] || HOOK_CWD=$(pwd)
HOOK_CWD=$(printf '%s' "$HOOK_CWD" | tr '\\' '/')

# 커맨드를 못 뽑았는데 입력에 git commit/push 흔적이 있으면 판단 근거가 없으니 차단한다.
# (예전엔 입력 전체를 grep 하는 폴백이었다 — 근거 없는 판정보다 차단이 맞다.)
if [ -z "$CMD" ]; then
  printf '%s' "$INPUT" | grep -qE 'git[^"]*(commit|push)' || exit 0
  echo "🚫 git commit/push 차단 — 훅이 명령을 해석할 수 없습니다." >&2
  echo "   해당 저장소에서 명령을 직접 실행하세요." >&2
  exit 2
fi

# 값싼 사전 필터: 차단 대상이라면 반드시 이 단어들이 들어 있다.
printf '%s' "$CMD" | grep -qE 'commit|push' || exit 0

# --- 저장소 동일성 ---
# git-common-dir 의 부모(= 메인 루트)로 본다. 워크트리는 메인과 common-dir 을 공유하므로
# 이 방법이면 wt/* 까지 같은 저장소로 묶인다(--show-toplevel 은 워크트리마다 달라진다).
# 경로는 둘 다 `pwd -P` 를 거치므로 표기(C:/ vs /c/, 심링크)가 정규화된다. 대소문자만 따로
# 낮춘다(Windows FS 는 대소문자 무시). 하드코딩 절대경로는 쓰지 않는다 — clone 위치가 바뀌면 깨진다.
repo_root() {
  local dir="$1" common
  [ -n "$dir" ] || return 1
  common=$( cd "$dir" 2>/dev/null && git rev-parse --git-common-dir 2>/dev/null ) || return 1
  [ -n "$common" ] || return 1
  common=$( cd "$dir" 2>/dev/null && cd "$common" 2>/dev/null && pwd -P ) || return 1
  [ -n "$common" ] || return 1
  dirname "$common" | tr '[:upper:]' '[:lower:]'
}

SELF_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P )
SELF_REPO=$(repo_root "$SELF_DIR")

# --- 경로 해석 ---
# 반환: 절대경로, 또는 "?"(= 대상 모름). 모름은 아래에서 차단으로 이어진다.
# 셸 확장 문자가 남아 있으면 훅은 그 값을 알 수 없다 — 실제 셸은 확장해서 잘 들어가므로
# 여기서 리터럴로 cd 를 시도해봐야 의미가 없다. 바로 "모름".
resolve_dir() {
  local base="$1" raw="$2" d
  [ "$base" != "?" ] || { printf '?'; return 0; }
  [ -n "$raw" ] || { printf '?'; return 0; }
  case "$raw" in *'$'*|*'`'*|*'~'*) printf '?'; return 0 ;; esac
  raw=$(printf '%s' "$raw" | tr '\\' '/')
  d=$( cd "$base" 2>/dev/null && cd "$raw" 2>/dev/null && pwd -P ) || d=''
  [ -n "$d" ] && printf '%s' "$d" || printf '?'
}

# --- 차단 판정: 이 git 명령이 향하는 디렉토리 기준 ---
check_target() {
  local dir="$1" kind="$2" repo br
  if [ -z "$SELF_REPO" ]; then
    echo "🚫 git $kind 차단 — 훅이 자기 저장소를 판정하지 못했습니다." >&2
    exit 2
  fi
  if [ "$dir" = "?" ] || [ -z "$dir" ]; then
    echo "🚫 git $kind 차단 — 이 명령이 어느 저장소로 가는지 판단할 수 없습니다." >&2
    echo "   경로에 변수·명령치환(\$…, \`…\`, ~)이 있거나 경로를 열 수 없습니다." >&2
    echo "   경로를 리터럴로 쓰거나 해당 저장소에서 직접 실행하세요." >&2
    exit 2
  fi
  repo=$(repo_root "$dir")
  if [ -z "$repo" ]; then
    echo "🚫 git $kind 차단 — 대상($dir)이 git 저장소가 아닙니다." >&2
    exit 2
  fi
  # 다른 저장소면 이 훅의 관심사가 아니다. 그대로 통과.
  [ "$repo" = "$SELF_REPO" ] || return 0

  if [ "$kind" = push ]; then
    echo "🚫 main 직접 push 차단 — 작업 브랜치에서 push 후 PR 로 병합하세요." >&2
    exit 2
  fi
  br=$( cd "$dir" 2>/dev/null && git branch --show-current 2>/dev/null )
  if [ "$br" = "main" ]; then
    echo "🚫 main 브랜치 직접 commit 차단 — git switch -c <브랜치> 로 작업하세요." >&2
    exit 2
  fi
  return 0
}

# --- 단순명령 하나 처리 ---
# CUR(현재 디렉토리)를 명령 순서대로 갱신하고, git commit/push 를 만나면 그 시점의 CUR 로 판정.
# 경로는 오직 `cd`/`git -C` **토큰 바로 뒤의 인자**에서만 뽑는다 — 인자 속 산문은 못 건드린다.
handle_cmd() {
  local -a t=("$@")
  local n=${#t[@]} i=0 j k lc0 raw sub gitc dir kind

  # 앞쪽 환경변수 대입 건너뛰기: `MSYS_NO_PATHCONV=1 git -C x commit`
  while [ $i -lt $n ] && printf '%s' "${t[$i]}" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*='; do
    i=$((i + 1))
  done
  [ $i -lt $n ] || return 0

  lc0=$(printf '%s' "${t[$i]}" | tr '[:upper:]' '[:lower:]')

  case "$lc0" in
    cd|set-location)
      raw=''
      j=$((i + 1))
      while [ $j -lt $n ]; do
        case "${t[$j]}" in -*) j=$((j + 1)) ;; *) raw=${t[$j]}; break ;; esac
      done
      # 인자 없는 `cd` 는 HOME 으로 간다 — 훅은 그 의도를 모르니 "모름".
      CUR=$(resolve_dir "$CUR" "$raw")
      return 0 ;;
    git|git.exe|*/git|*/git.exe) ;;
    *) return 0 ;;
  esac

  # git 전역 옵션을 지나 서브커맨드와 -C 를 찾는다.
  sub=''; gitc=''
  j=$((i + 1))
  while [ $j -lt $n ]; do
    case "${t[$j]}" in
      -C)  j=$((j + 1)); gitc=${t[$j]:-} ;;
      -C*) gitc=${t[$j]#-C} ;;
      -c|--git-dir|--work-tree|--namespace|--exec-path) j=$((j + 1)) ;;
      -*)  ;;
      *)   sub=${t[$j]}; break ;;
    esac
    j=$((j + 1))
  done
  [ -n "$sub" ] || return 0

  kind=''
  if [ "$sub" = commit ]; then
    kind=commit
  elif [ "$sub" = push ]; then
    # `push` 뒤 위치인자만 모아 `origin main`(refspec 포함) 인지 본다.
    local -a pos=()
    k=$((j + 1))
    while [ $k -lt $n ]; do
      case "${t[$k]}" in -*) ;; *) pos+=("${t[$k]}") ;; esac
      k=$((k + 1))
    done
    if [ "${pos[0]:-}" = origin ]; then
      case "${pos[1]:-}" in main|*:main) kind=push ;; esac
    fi
  fi
  [ -n "$kind" ] || return 0

  # `git -C` 는 이 명령에만 적용된다(CUR 을 바꾸지 않는다).
  dir="$CUR"
  [ -z "$gitc" ] || dir=$(resolve_dir "$CUR" "$gitc")
  check_target "$dir" "$kind"
  return 0
}

# --- 토크나이저 ---
# 따옴표를 인식해 커맨드를 단순명령으로 쪼갠다. 구분자: ; & | 개행 ( ) { }
# (`&&`/`||` 도 여기서 갈리지만, CUR 을 순서대로 이어가므로 "한 체인에서 마지막 cd 가 이긴다"
#  는 성질이 저절로 유지된다. 별도 처리 불필요 — KISS.)
# 서브셸 `( … )` 은 cwd 를 되돌리므로 CUR 을 스택에 넣었다 뺀다. `{ … }` 는 안 되돌린다.
# 따옴표 밖 백슬래시는 이스케이프가 아니라 리터럴로 둔다 — 이 훅은 PowerShell 커맨드도 받고,
# Windows 경로(`cd C:\APM\x`)가 더 흔하다. 대신 `a\ b` 같은 이스케이프 공백은 경로가 안 풀려
# "모름 → 차단" 으로 떨어진다(보수적).
declare -a TOKS=() DSTACK=()
TOK=''; TOKED=0
CUR=$( cd "$HOOK_CWD" 2>/dev/null && pwd -P ) || CUR=''
[ -n "$CUR" ] || CUR='?'

flush_tok() { [ "$TOKED" = 1 ] || return 0; TOKS+=("$TOK"); TOK=''; TOKED=0; }
flush_cmd() {
  flush_tok
  [ ${#TOKS[@]} -gt 0 ] || return 0
  handle_cmd "${TOKS[@]}"
  TOKS=()
}

scan() {
  local s="$1" n=${#1} i=0 c q='' nx
  while [ $i -lt $n ]; do
    c=${s:$i:1}
    if [ -n "$q" ]; then
      if [ "$c" = "$q" ]; then
        q=''
      elif [ "$q" = '"' ] && [ "$c" = '\' ]; then
        # 큰따옴표 안에서 백슬래시는 " \ $ ` 앞에서만 이스케이프다(실제 bash 규칙).
        # 그 외(C:\APM 의 \A 등)는 백슬래시가 그대로 남는다.
        nx=${s:$((i + 1)):1}
        case "$nx" in
          '"'|'\'|'$'|'`') TOK+="$nx"; i=$((i + 1)) ;;
          *) TOK+="$c" ;;
        esac
        TOKED=1
      else
        TOK+="$c"; TOKED=1
      fi
      i=$((i + 1)); continue
    fi
    case "$c" in
      \'|\") q=$c; TOKED=1 ;;
      ' '|$'\t') flush_tok ;;
      ';'|'&'|'|'|$'\n'|$'\r'|'{'|'}') flush_cmd ;;
      '(') flush_cmd; DSTACK+=("$CUR") ;;
      ')') flush_cmd
           if [ ${#DSTACK[@]} -gt 0 ]; then
             CUR=${DSTACK[${#DSTACK[@]} - 1]}
             unset "DSTACK[${#DSTACK[@]} - 1]"
           fi ;;
      *) TOK+="$c"; TOKED=1 ;;
    esac
    i=$((i + 1))
  done
  flush_cmd
}

# handle_cmd 가 차단 시 exit 2 로 스크립트를 끝낸다(서브셸·파이프 없이 호출하므로 전파된다).
scan "$CMD"
exit 0
