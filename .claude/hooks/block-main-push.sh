#!/usr/bin/env bash
# =============================================================================
# block-main-push.sh — main 브랜치 직접 commit/push 차단 (PreToolUse 훅)
# =============================================================================
# claude-pipeline .claude/hooks/block-main-deploy.sh 를 vuln-agent 용으로 단순화.
# GitLab p-release 예외·python3 파싱 제거 → 순수 bash grep (python/jq/node 불요).
#
# 동작: Bash/PowerShell 도구 호출 직전, 커맨드에서 아래를 감지하면 exit 2 로 차단
#   1) origin main 직접 push
#   2) 현재 브랜치가 main 일 때의 git commit
# → 항상 브랜치를 만들어 작업하고 PR 로 병합하게 강제.
#
# 판단 기준: "이 명령이 실제로 향하는 저장소·브랜치".
#   예전엔 명령 문자열만 grep 하고 브랜치는 훅 자신의 cwd 에서 봤다. 그래서
#     · 사용자가 전혀 무관한 저장소(termkeep)에서 main 에 커밋하려는데 이 훅이 막았고
#       (push 규칙은 아예 16개 저장소를 다 가로막았다),
#     · 메인 트리 cwd 에서 `cd wt/foo && git commit` 을 치면 실제 대상은 워크트리인데
#       메인 트리의 main 을 보고 막았다.
#   지금은 훅 입력의 cwd + 명령 안의 cd/git -C 로 대상 디렉토리를 정하고, 그게
#   이 훅이 속한 저장소(= vuln-agent)일 때만 검사한다. 다른 저장소면 그냥 통과.
#
# 안전 방향: 경로 파싱은 완벽하지 않아도 된다. 애매하면 차단 쪽(보수적)으로 간다 —
#   오탐(막아서 사람이 확인)은 미탐(main 이 오염됨)보다 훨씬 싸다.
# =============================================================================
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

# 못 뽑으면 안전한 쪽(기존 동작)으로 폴백: 커맨드 대신 입력 전체를 grep 하고, 대상은 훅의 cwd.
[ -n "$CMD" ] || CMD="$INPUT"
[ -n "$HOOK_CWD" ] || HOOK_CWD=$(pwd)

# --- 이 커맨드가 애초에 검사 대상인지 (git commit / git push origin main) ---
# `git -C <경로>` 접두는 허용해서 통과시키지 않는다.
GIT_C='git([[:space:]]+-C[[:space:]]+[^[:space:]]+)*[[:space:]]+'
RE_COMMIT="${GIT_C}commit"
RE_PUSH="${GIT_C}push([[:space:]]+-[^[:space:]]+)*[[:space:]]+origin[[:space:]]+main([^A-Za-z0-9_/.-]|\\\\|\$)"

HIT_COMMIT=0; HIT_PUSH=0
printf '%s' "$CMD" | grep -qE "$RE_COMMIT" && HIT_COMMIT=1
printf '%s' "$CMD" | grep -qE "$RE_PUSH"   && HIT_PUSH=1
[ "$HIT_COMMIT" = 1 ] || [ "$HIT_PUSH" = 1 ] || exit 0

# --- 명령이 실제로 향하는 디렉토리 정하기 ---
# 우선순위: git -C <경로>  >  마지막 cd/Set-Location <경로>  >  훅 입력 cwd.
# (`cd /a && git -C /b commit` 이면 git 은 /b 에서 돈다.)
unquote() { sed -E 's/^"(.*)"$/\1/; s/^'\''(.*)'\''$/\1/'; }

TARGET_RAW=$(printf '%s' "$CMD" \
  | grep -oE "git[[:space:]]+-C[[:space:]]+(\"[^\"]*\"|'[^']*'|[^[:space:];&|]+)" \
  | tail -n 1 | sed -E 's/^git[[:space:]]+-C[[:space:]]+//' | unquote)

if [ -z "$TARGET_RAW" ]; then
  TARGET_RAW=$(printf '%s' "$CMD" \
    | grep -oiE "(^|[[:space:];&|(])(cd|set-location)[[:space:]]+(\"[^\"]*\"|'[^']*'|[^[:space:];&|]+)" \
    | tail -n 1 | sed -E 's/^[[:space:];&|(]*[Cc][Dd][[:space:]]+//; s/^[[:space:];&|(]*[Ss]et-[Ll]ocation[[:space:]]+//' | unquote)
fi

# Windows 표기(C:\a\b)를 git-bash 가 cd 할 수 있는 형태로. 상대경로는 cwd 기준으로 푼다.
TARGET_DIR=""
if [ -n "$TARGET_RAW" ]; then
  TARGET_RAW=$(printf '%s' "$TARGET_RAW" | tr '\\' '/')
  TARGET_DIR=$( cd "$HOOK_CWD" 2>/dev/null && cd "$TARGET_RAW" 2>/dev/null && pwd -P )
fi
# 못 풀면 cwd 로 폴백한다. 이 정규식은 커맨드 문자열을 볼 뿐이라 산문 속 `cd`/`git -C`
# 언급(커밋 메시지·문서·echo)까지 경로로 집어올 수 있다 — 실제로 이 훅을 고친 커밋 메시지에
# 들어 있던 "…git -C 로 대상을 정한다" 가 `로` 를 경로로 잡아 커밋을 막았다. 안 풀리는 경로는
# 애초에 그 명령도 못 쓰는 경로이므로, 판단은 cwd 에 맡기는 게 맞다(차단 근거는 아래에서 다시 본다).
if [ -z "$TARGET_DIR" ]; then
  TARGET_RAW="$HOOK_CWD"
  TARGET_DIR=$( cd "$HOOK_CWD" 2>/dev/null && pwd -P )
fi

# --- 그 디렉토리가 이 훅이 속한 저장소(vuln-agent)인지 ---
# 저장소 동일성은 git-common-dir 의 부모(= 메인 루트)로 본다. 워크트리는 메인과 common-dir 을
# 공유하므로, 이 방법이면 wt/* 까지 같은 저장소로 묶인다(--show-toplevel 은 워크트리마다 달라진다).
# 경로는 둘 다 같은 `pwd -P` 를 거치므로 표기(C:/ vs /c/, 심링크)가 정규화된다. 대소문자만 따로
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
TARGET_REPO=$(repo_root "$TARGET_DIR")

if [ -z "$TARGET_REPO" ] || [ -z "$SELF_REPO" ]; then
  # 대상 저장소를 알 수 없다(경로 해석 실패·git 저장소 아님). 판단 근거가 없으니 안전한 쪽.
  echo "🚫 git commit/push 차단 — 이 명령이 어느 저장소로 가는지 판단할 수 없습니다." >&2
  echo "   (대상 디렉토리: ${TARGET_RAW:-?}) 경로를 명확히 하거나 해당 저장소에서 직접 실행하세요." >&2
  exit 2
fi

# 다른 저장소면 이 훅의 관심사가 아니다. 그대로 통과.
[ "$TARGET_REPO" = "$SELF_REPO" ] || exit 0

# --- 여기부터 vuln-agent 저장소 대상. 기존 가드레일 그대로. ---
if [ "$HIT_PUSH" = 1 ]; then
  echo "🚫 main 직접 push 차단 — 작업 브랜치에서 push 후 PR 로 병합하세요." >&2
  exit 2
fi

if [ "$HIT_COMMIT" = 1 ]; then
  BR=$( cd "$TARGET_DIR" 2>/dev/null && git branch --show-current 2>/dev/null )
  if [ "$BR" = "main" ]; then
    echo "🚫 main 브랜치 직접 commit 차단 — git switch -c <브랜치> 로 작업하세요." >&2
    exit 2
  fi
fi

exit 0
