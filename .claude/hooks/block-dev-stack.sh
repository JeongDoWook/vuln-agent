#!/usr/bin/env bash
# =============================================================================
# block-dev-stack.sh — 메인 트리 dev 스택 up/down 직접 실행 차단 (PreToolUse 훅)
# =============================================================================
# CLAUDE.md 가 "에이전트는 dev up -d 를 실행하지 않는다" 를 여러 번 문서로 적어뒀지만,
# 문서는 강제력이 없다 — 과거 세션들이 그 문구를 무시하고 직접 커맨드를 쳐서 dev 스택을
# 자기 트리로 끌어오는 바람에 다른 세션의 스모크·작업이 계속 끊겼다. 이 훅이 그 문서 규칙을
# 코드로 강제한다(block-main-push.sh 와 같은 패턴).
#
# 차단 범위를 "메인 트리" 로 좁혔다(사용자와 합의된 완화). 합의된 범위:
#   · 허용: 워크트리(wt/<이름>) 를 대상으로 한 dev up|down.
#   · 차단: 메인 트리를 대상으로 한 dev up|down (공용 DB + 모든 트리가 공유하는 스택).
# 왜 좁혔나: 워커가 server/** 를 고치면 스모크가 자기 트리 컨테이너를 못 찾아 exit 2 로 멈추고,
#   규칙대로 사람을 기다린다 — 워커 N 개면 사람 개입도 N 번이라 병렬 오케스트레이션이 사람 손에
#   병목이 됐다. 왜 안전한가: 워크트리 컴포즈 대상은 compose.dev.yml + compose.dev-net.yml 뿐이라
#   **db 서비스가 아예 포함되지 않고**, 프로젝트명(vulnagent-dev-<wt>)·컨테이너명
#   (vulnagent-web-dev-<wt>)이 트리마다 고유해 다른 트리를 건드릴 수 없다.
#
# 동작: Bash/PowerShell 도구 호출 직전, 커맨드에서 compose_runner.sh/.ps1 를 dev 환경의
#   up/down 서브커맨드로 부르는 패턴을 감지하고, 대상이 워크트리가 아니면 exit 2 로 차단한다.
#   dev doctor/init/logs/ps, prod(운영 배포)는 막지 않는다 — 이 훅은 "dev 스택 기동/전환"만
#   금지 대상이다(CLAUDE.md 가드레일과 동일 범위).
#
# -----------------------------------------------------------------------------
# 판정이 무엇을 보고 무엇을 안 보는가 — 실제 사고로 배운 것
# -----------------------------------------------------------------------------
# 이 훅의 첫 판은 stdin JSON **전체**에서 wt/<이름> 조각을 찾아 있으면 통과시켰다. 주석엔
# "메인 트리 대상은 cwd 에도 커맨드에도 wt/ 조각이 없으므로 그대로 차단된다" 고 적혀 있었지만
# **그 전제가 틀렸다.** stdin JSON 엔 cwd·command 말고 다른 필드도 들어 있다. 실측 결과
# 메인 트리 cwd + 메인 트리 대상 명령이 이렇게 셋이나 통과했다:
#   · description 이 "wt/foo 워커용 스택 기동" → 통과. description 은 사람이 읽는 라벨일 뿐인데
#     거기 적힌 워크트리 이름 때문에 공용 DB 스택이 올라간다. 공격이 아니라 **사고**다 —
#     에이전트가 평범하게 일하다 우연히 밟는다.
#   · 커맨드 끝의 주석 `# wt/foo 확인용` → 통과.
#   · `ls wt/foo && ./deploy/compose_runner.sh dev up -d` → 통과.
# 뿌리는 하나다: **신호(문자열 어딘가의 wt/)와 실제 대상(작업 디렉터리)이 분리돼 있었다.**
# 실제 대상 트리는 compose_runner.sh 가 자기 위치로 정한다(TREE_ROOT/WT_NAME — 부모 디렉터리
# 이름이 wt 면 워크트리). 그래서 판정도 "문자열이 어디든 나오는가" 가 아니라 **"이 명령이 실제로
# 어느 트리에서 도는가"** 를 봐야 한다. 지금 판정은:
#   1) 판정에 쓸 필드를 cwd 와 tool_input.command **둘로만** 좁힌다. description 등 나머지는
#      절대 보지 않는다 — 라벨은 대상을 바꾸지 못한다.
#   2) 커맨드 안의 wt/ 도 "아무 데나" 는 안 된다. 명령 **맨 앞의 `cd <워크트리> &&` 프리픽스**,
#      즉 실제로 작업 디렉터리를 옮기는 형태만 인정한다(앵커가 없으면 위의 주석·ls 케이스가
#      다시 열린다). 이 예외가 필요한 이유는 딱 하나 — wt.sh 의 stack_down_if_serving() 이
#      메인 트리 cwd 에서 `( cd "$WT_ROOT/<이름>" && ./deploy/compose_runner.sh dev down )`
#      으로 워크트리 스택을 회수하기 때문이다(deploy/wt.sh). 그 형태만 통과시킨다.
#   3) 러너를 부르는 경로도 effective dir 기준의 `./deploy/compose_runner.sh` 형태여야 한다.
#      `../../deploy/…` 나 절대경로는 cwd 와 대상이 또 갈라지므로(예: 워크트리 안에서
#      `../../deploy/compose_runner.sh dev up` 은 대상이 메인 트리다) 판정 불가로 보고 차단한다.
#   4) 애매하면 차단(fail-closed). 가드레일은 열어주는 쪽으로 실수하면 안 된다.
# 다음 사람에게: 이걸 "간단하게" 전체 훑기로 되돌리지 말 것. 위 세 케이스가 그대로 되살아난다.
# =============================================================================
INPUT=$(cat)

# 이 훅의 관심사인 커맨드 형태 — compose_runner 를 dev 환경의 up/down 으로 부르는 것.
RUNNER_DEV_UPDOWN='compose_runner\.(sh|ps1)[^|;&]*\bdev\b[^|;&]*\b(up|down)\b'

block() {
  echo "🚫 메인 트리 dev 컨테이너 기동/전환(dev up|down) 차단 — 공용 DB 와 모든 트리가 공유하는" >&2
  echo "   스택이라 기동/중지는 항상 사용자가 직접 한다. 필요하면 사용자에게 요청하고 기다리세요." >&2
  echo "   (워크트리 wt/<이름> 안에서 자기 트리 스택을 올리는 건 허용된다 — db 가 안 뜨고" >&2
  echo "    컨테이너명이 트리마다 고유해 다른 트리를 건드릴 수 없다.)" >&2
  exit 2
}

# JSON 문자열 필드 하나를 꺼낸다(jq 없이 — 이 저장소의 훅은 grep/sed 만 쓴다).
#   키 앞을 [{,공백] 으로 못박는 게 핵심이다: description 안에 이스케이프된 \"command\" 가
#   들어 있어도 앞 문자가 백슬래시라 걸리지 않는다.
json_str() {
  printf '%s' "$INPUT" \
    | grep -oE "[{,[:space:]]\"$1\"[[:space:]]*:[[:space:]]*\"([^\"\\\\]|\\\\.)*\"" \
    | head -n1 \
    | sed -E "s/^[{,[:space:]]\"$1\"[[:space:]]*:[[:space:]]*\"//; s/\"$//"
}

# JSON 이스케이프를 풀고(\" → " , \\ → \) 경로 구분자를 / 로 통일한다.
#   cwd 는 윈도 경로라 훅에는 C:\\APM\\…\\wt\\foo 로 들어온다 — 이 정규화를 거쳐야
#   아래 경로 판정이 슬래시 하나로 끝난다.
unescape_path() {
  printf '%s' "$1" | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g' -e 's/\\/\//g'
}

# 워크트리 경로인가 — 경로에 wt/<이름> 세그먼트가 있어야 한다.
#   'wt' 앞은 경로 시작이거나 / 여야 한다: …/mywt/foo 같은 우연한 일치를 배제한다.
is_worktree_path() {
  printf '%s' "$1" | grep -qE '(^|/)wt/[^/]+'
}

CMD=$(unescape_path "$(json_str command)")

# 커맨드를 못 읽었는데 원문엔 패턴이 보인다 → 대상을 판정할 수 없다 → 차단(fail-closed).
if [ -z "$CMD" ]; then
  printf '%s' "$INPUT" | grep -qE "$RUNNER_DEV_UPDOWN" && block
  exit 0
fi

# dev up|down 이 아니면 이 훅의 관심사가 아니다.
printf '%s' "$CMD" | grep -qE "$RUNNER_DEV_UPDOWN" || exit 0

# 러너 경로가 effective dir 기준의 ./deploy/compose_runner.* 형태가 아니면 대상이 갈라진다 → 차단.
printf '%s' "$CMD" | grep -qE '(^|[^A-Za-z0-9._/-])\.?/?deploy/compose_runner\.(sh|ps1)' || block

# 이 명령이 실제로 도는 디렉터리 = 맨 앞 `cd <경로> &&` 가 있으면 그 경로, 없으면 cwd.
#   여는 괄호는 허용한다 — wt.sh 의 회수 호출이 서브셸 `( cd … && … )` 형태다.
CD_DIR=$(printf '%s' "$CMD" \
  | sed -nE 's/^[[:space:]]*\(?[[:space:]]*cd[[:space:]]+"?([^"[:space:]]+)"?[[:space:]]*&&.*/\1/p')

TARGET="$CD_DIR"
[ -z "$TARGET" ] && TARGET=$(unescape_path "$(json_str cwd)")

# 대상이 워크트리면 통과, 아니면(메인 트리이거나 판정 불가면) 차단.
is_worktree_path "$TARGET" && exit 0
block
