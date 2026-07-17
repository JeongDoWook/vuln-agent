#!/usr/bin/env bash
# =============================================================================
# vuln-agent · wt — 브랜치별 격리 작업트리(git worktree)
# =============================================================================
# 왜 필요한가:
#   한 트리에서 여러 세션이 작업하면 HEAD 를 공유한다. A 세션이 브랜치를 갈아타면
#   B 세션의 커밋이 엉뚱한 브랜치에 얹히고, push 는 빈 push 가 된다(실제로 겪음).
#   worktree 는 폴더마다 HEAD 를 따로 갖고, git 이 같은 브랜치의 중복 체크아웃을
#   거부한다 → 브랜치 섞임이 구조적으로 불가능해진다.
#
# 이 스크립트가 하는 일 (worktree 만으론 부족한 부분):
#   1) wt/<이름>/ 에 워크트리 생성 (기본 기점 origin/main — 낡은 로컬 main 방지)
#   2) secrets/*.txt 복사 (gitignore 라 워크트리에 안 딸려온다)
#   3) 안 쓰는 WEB_PORT 를 하나 골라 이 워크트리 전용 deploy/.env.dev 에 박아둔다
#      (DB_DATA·MYSQL_* 등 공용값은 메인 트리 것을 그대로 쓴다 — DB 는 공용 하나)
#   compose_runner.sh 가 wt/ 를 감지해 프로젝트명·컨테이너명·포트를 워크트리별로 분리한다
#   (web+scheduler 만 — DB 는 항상 메인 트리 소유의 vulnagent-db-dev 하나).
#
# 사용법:
#   ./deploy/wt.sh add feat/cve-list          # wt/cve-list 생성 (origin/main 기점)
#   ./deploy/wt.sh add fix/foo origin/main    # 기점 명시
#   ./deploy/wt.sh list                       # 워크트리 + 할당 포트
#   ./deploy/wt.sh rm cve-list                # 스택 내리고 워크트리 + 병합된 브랜치 제거
#   ./deploy/wt.sh sweep                      # 병합된 워크트리를 한 번에 정리
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
say() { printf "%b\n" "$1"; }
die() { say "${RED}오류: $1${NC}"; exit 1; }

# 메인 트리 루트 = .git 공용 디렉터리의 부모. (워크트리 안에서 실행해도 정확)
GIT_COMMON="$(git rev-parse --git-common-dir 2>/dev/null)" || die "git 저장소가 아닙니다."
MAIN_ROOT="$(cd "$(dirname "$GIT_COMMON")" && pwd)"
WT_ROOT="$MAIN_ROOT/wt"

SECRET_FILES=(mysql_root_password mysql_password ingest_token admin_password duckdns_token)

# --- WEB_PORT 할당 -----------------------------------------------------------
# web+scheduler 는 이제 워크트리별로 독립된 컨테이너로 뜬다(compose_runner.sh) — 포트가
# 겹치면 안 되므로, 메인 트리 포트(보통 8000)와 다른 워크트리에 이미 준 포트를 피해 하나 고른다.
# 파일이 없으면 sed 가 비영(0 이 아닌) 종료코드를 낸다 — set -e/pipefail 아래서 이 함수를 부르는
#   쪽까지 조용히 죽지 않도록 `|| true` 로 항상 0 을 반환한다(WEB_PORT 못 찾으면 빈 문자열).
main_web_port() {
  sed -n 's/^WEB_PORT=\([0-9]\+\).*/\1/p' "$MAIN_ROOT/deploy/.env.dev" 2>/dev/null | head -1 || true
}
wt_web_port() {  # $1 = 워크트리 디렉터리
  sed -n 's/^WEB_PORT=\([0-9]\+\).*/\1/p' "$1/deploy/.env.dev" 2>/dev/null | head -1 || true
}
alloc_web_port() {
  local used port d p mainport
  mainport="$(main_web_port)"
  used=" ${mainport:-8000} "
  if [ -d "$WT_ROOT" ]; then
    for d in "$WT_ROOT"/*/; do
      [ -d "$d" ] || continue
      p="$(wt_web_port "${d%/}")"
      [ -n "$p" ] && used="$used $p "
    done
  fi
  port=8090
  while printf '%s' "$used" | grep -q " $port "; do
    port=$((port + 1))
  done
  printf '%s' "$port"
}

# 이 워크트리의 web 컨테이너가 지금 떠 있나(컨테이너명이 워크트리 접미사로 고유하므로,
#   존재하면 그게 곧 이 워크트리다 — 옛 러너 시절의 마운트 대조가 더 이상 필요 없다).
wt_web_container() { printf 'vulnagent-web-dev-%s' "$1"; }
wt_stack_up() {
  docker inspect "$(wt_web_container "$1")" >/dev/null 2>&1
}

usage() {
  say "${CYAN}vuln-agent · wt${NC}"
  echo ""
  say "  ${GREEN}add${NC} <브랜치> [기점]   wt/<이름> 워크트리 생성 (기점 기본 origin/main)"
  say "  ${GREEN}list${NC}                  워크트리 + 할당 포트"
  say "  ${GREEN}rm${NC} <이름>             이 트리 스택 회수(떠 있으면) + 워크트리 + 병합된 브랜치 제거"
  say "  ${GREEN}sweep${NC}                 병합된 워크트리를 한 번에 정리 (미병합·미커밋은 유지)"
  echo ""
  say "예: ${CYAN}./deploy/wt.sh add feat/cve-list${NC}  →  wt/cve-list"
  say "예: ${CYAN}./deploy/wt.sh sweep${NC}  →  origin/main 에 병합된 워크트리 모두 제거"
}

# --- add --------------------------------------------------------------------
cmd_add() {
  local branch="${1:-}" start="${2:-origin/main}"
  [ -n "$branch" ] || { usage; exit 1; }

  local name="${branch##*/}"                    # feat/cve-list → cve-list
  local dir="$WT_ROOT/$name"
  [ -e "$dir" ] && die "이미 있습니다: $dir"

  say "${CYAN}== wt add · $branch → wt/$name ==${NC}"
  git -C "$MAIN_ROOT" fetch origin --quiet || say "  ${YELLOW}⚠${NC} fetch 실패 — 로컬 ref 로 진행"

  # 브랜치가 이미 있으면 그걸 체크아웃, 없으면 기점에서 새로 만든다.
  if git -C "$MAIN_ROOT" show-ref --verify --quiet "refs/heads/$branch"; then
    git -C "$MAIN_ROOT" worktree add "$dir" "$branch"
    say "  ${BLUE}→${NC} 기존 브랜치 체크아웃: $branch"
  else
    git -C "$MAIN_ROOT" worktree add -b "$branch" "$dir" "$start"
    say "  ${GREEN}✓${NC} 새 브랜치: $branch (기점 $start)"
  fi

  # sweep 이 "커밋 0개인 갓 만든 브랜치"를 "병합됨"으로 오판하지 않도록, 갈라져 나온
  #   시점의 HEAD sha 를 마커로 남긴다. 워크트리 로컬 파일(wt/ 전체가 gitignore 대상)이라
  #   커밋되지 않는다.
  git -C "$dir" rev-parse HEAD > "$dir/.wt-base-sha"

  # secrets: gitignore 라 워크트리엔 없다. 메인 트리에서 복사.
  mkdir -p "$dir/secrets"
  local n copied=0
  for n in "${SECRET_FILES[@]}"; do
    if [ -f "$MAIN_ROOT/secrets/$n.txt" ]; then
      cp "$MAIN_ROOT/secrets/$n.txt" "$dir/secrets/$n.txt"
      chmod 644 "$dir/secrets/$n.txt" 2>/dev/null || true
      copied=$((copied + 1))
    fi
  done
  if [ "$copied" -eq 0 ]; then
    say "  ${YELLOW}⚠${NC} secrets/*.txt 없음 — 메인 트리에서 ${CYAN}./deploy/compose_runner.sh init${NC} 먼저"
  else
    say "  ${GREEN}✓${NC} secrets ${copied}개 복사"
  fi

  # .env.dev 는 이 워크트리 전용 WEB_PORT 만 담는다(gitignore, 매번 새로 만듦) — 나머지 값
  #   (MYSQL_*·DB_DATA 등)은 메인 트리의 .env.dev 를 그대로 쓴다(DB 는 공용, compose_runner.sh).
  [ -f "$MAIN_ROOT/deploy/.env.dev" ] || die "메인 트리에 deploy/.env.dev 가 없습니다. 먼저 init 하세요."
  local web_port; web_port="$(alloc_web_port)"
  mkdir -p "$dir/deploy"
  cat > "$dir/deploy/.env.dev" <<EOF
# 이 워크트리 전용 dev 포트 (gitignore — wt.sh add 가 매번 새로 만든다)
# 나머지 값(MYSQL_*·DB_DATA 등)은 메인 트리의 deploy/.env.dev 를 그대로 쓴다 — DB 는 공용.
WEB_PORT=$web_port
EOF
  say "  ${GREEN}✓${NC} 이 워크트리 WEB_PORT=$web_port 할당 (deploy/.env.dev, DB 는 공용)"

  echo ""
  say "${GREEN}완료.${NC} 다음:"
  say "  ${CYAN}cd wt/$name${NC}"
  say "  server/·db/·tests/ 를 건드릴 때만 이 워크트리 전용 web/scheduler 를 띄운다(DB 는 공용 유지):"
  say "  ${CYAN}./deploy/compose_runner.sh dev up -d${NC}   # 이 워크트리만의 새 스택 — 다른 트리엔 영향 없음"
  say "  ${CYAN}./tests/smoke.sh http://localhost:$web_port${NC}"
}

# --- list -------------------------------------------------------------------
cmd_list() {
  git -C "$MAIN_ROOT" worktree list
  echo ""
  say "${CYAN}메인 트리 · 공용 DB${NC}"
  if docker inspect vulnagent-db-dev >/dev/null 2>&1; then
    say "  ${GREEN}✓${NC} db 떠 있음 (vulnagent-db-dev)"
  else
    say "  ${YELLOW}⚠${NC} db 안 떠 있음 — 메인 트리에서 ${GREEN}dev up -d${NC} 해야 워크트리 web/scheduler 가 붙는다"
  fi
  echo ""
  say "${CYAN}워크트리별 web/scheduler · 포트${NC}"
  [ -d "$WT_ROOT" ] || { say "  (없음)"; return 0; }
  local d name port
  for d in "$WT_ROOT"/*/; do
    [ -d "$d" ] || continue
    d="${d%/}"; name="${d##*/}"
    port="$(wt_web_port "$d")"
    if wt_stack_up "$name"; then
      say "  ${GREEN}✓${NC} $name — http://localhost:${port:-?} (기동 중)"
    else
      say "  ${BLUE}→${NC} $name — 포트 ${port:-미할당} (내려가 있음)"
    fi
  done
}

# 이 워크트리의 web/scheduler 스택이 떠 있으면 워크트리를 지우기 **전에** 내린다(회수).
#   워크트리마다 컨테이너명이 고유해서(vulnagent-web-dev-<이름>) 그 이름이 떠 있는지만 보면
#   곧 이 워크트리 얘기다 — 대조할 다른 트리가 없다(옛 러너 시절의 마운트 대조가 불필요).
#   예전엔 안내만 출력하고 실제 down 은 사람에게 미뤘다. 그런데 워커가 자기 트리 스택을 스스로
#   올릴 수 있게 된 뒤로는(block-dev-stack.sh 완화) 그게 곧 메모리 단조 증가가 된다 — 워크트리를
#   지워도 web/scheduler 가 남아, 마운트 원본이 사라진 채 500 을 내며 자리만 차지한다.
#   내리는 대상은 이 트리 전용 프로젝트(vulnagent-dev-<이름>)의 web+scheduler 뿐이다.
#   공용 db 는 이 프로젝트에 애초에 포함되지 않는다(compose.dev.yml + compose.dev-net.yml).
stack_down_if_serving() {
  local name="$1" dir="$WT_ROOT/$1"
  wt_stack_up "$name" || return 0
  say "  ${BLUE}→${NC} 이 워크트리 스택 회수 중 (vulnagent-dev-$name)…"
  if ( cd "$dir" && ./deploy/compose_runner.sh dev down >/dev/null 2>&1 ); then
    say "  ${GREEN}✓${NC} web/scheduler 내림 (공용 DB 는 그대로)"
  else
    say "  ${YELLOW}⚠${NC} 스택 내리기 실패 — 남은 컨테이너를 확인하세요:"
    say "     ${CYAN}docker ps -a --filter name=vulnagent-.*-dev-$name${NC}"
  fi
}

# --- 병합 판정 ---------------------------------------------------------------
# 이 저장소는 squash 머지를 쓴다(PR 하나 = 커밋 하나). squash 는 새 커밋 객체를 만들므로
#   원래 브랜치 tip 은 영원히 origin/main 의 조상이 되지 않는다 → "tip 이 조상인가"(merge-base
#   --is-ancestor)는 **항상 거짓**이고, 그 판정만 쓰던 시절 sweep 은 사실상 죽은 기능이었다.
#   그래서 1순위는 gh 로 본 PR 상태다(squash·rebase 에도 정확). gh 가 없거나 미인증이면 옛
#   판정으로 폴백한다 — 나빠지진 않되, 폴백에 떨어졌다는 사실은 반드시 알린다(조용히 폴백하면
#   "무동작인데 이유를 모르는" 원래 상태로 돌아간다).
GH_CHECKED=0
GH_OK=0
# gh 존재·인증 확인은 비싸다(인증은 네트워크를 탄다) → 딱 한 번만 하고 결과를 재사용한다.
#   sweep 은 워크트리마다 이 함수를 부르므로, 캐시가 없으면 트리 10개에 인증 조회가 10번 나간다.
gh_available() {
  if [ "$GH_CHECKED" -eq 0 ]; then
    GH_CHECKED=1
    if ! command -v gh >/dev/null 2>&1; then
      say "  ${YELLOW}⚠${NC} gh(GitHub CLI) 없음 — PR 상태를 못 봐 옛 판정(tip 이 origin/main 의 조상인가)으로 폴백합니다."
      say "     이 저장소는 squash 머지라 그 판정은 거의 항상 '미병합' 입니다 — 병합된 브랜치가 안 지워질 수 있습니다."
      say "     설치: ${CYAN}winget install --id GitHub.cli -e${NC}"
    elif ! gh auth status >/dev/null 2>&1; then
      say "  ${YELLOW}⚠${NC} gh 인증 안 됨 — PR 상태를 못 봐 옛 판정으로 폴백합니다(squash 머지는 '미병합' 으로 잡힙니다)."
      say "     인증: ${CYAN}gh auth login${NC}"
    else
      GH_OK=1
    fi
  fi
  [ "$GH_OK" -eq 1 ]
}

# 브랜치가 병합됐나 → 0(병합됨) / 1(아님·불확실). 불확실하면 1 — 지우지 않는 쪽으로 기운다.
#   $1 = 브랜치명, $2 = 브랜치 tip sha(폴백 판정에만 쓴다)
is_merged() {
  local branch="$1" sha="$2" out
  if gh_available; then
    # 같은 head 로 PR 이 여러 개일 수 있다(#227 MERGED / #228 CLOSED 처럼 재생성된 이력이 실제로
    #   있다) → --state merged 로 걸러 **하나라도 있으면** 병합됨으로 본다.
    #   PR 이 없으면 빈 배열([])이고, 조회 실패(네트워크·권한)면 비영 종료다. set -e 아래서
    #   죽지 않도록 `|| out=''` 로 받고, 그 경우는 "병합 아님"(=유지)으로 다룬다.
    out="$(gh pr list --head "$branch" --state merged --json number 2>/dev/null)" || out=''
    case "$out" in
      *'"number"'*) return 0 ;;
      *)            return 1 ;;
    esac
  fi
  git -C "$MAIN_ROOT" merge-base --is-ancestor "$sha" origin/main
}

# --- rm ---------------------------------------------------------------------
# 워크트리를 지워도 브랜치는 남아 목록이 계속 불어난다. PR 이 병합됐으면 로컬·원격 모두 정리한다.
#   병합 판정은 is_merged() — 불확실하면 남긴다. 안 지워서 손해볼 건 브랜치 하나지만 잘못
#   지우면 커밋이 날아간다.
branch_cleanup() {
  local branch="$1" sha="$2"
  case "$branch" in
    ''|HEAD)      say "  ${YELLOW}⚠${NC} detached HEAD — 브랜치 정리 생략"; return 0 ;;
    main|master)  say "  ${YELLOW}⚠${NC} '$branch' 는 지우지 않습니다"; return 0 ;;
  esac

  if ! git -C "$MAIN_ROOT" fetch origin --quiet; then
    say "  ${YELLOW}⚠${NC} fetch 실패 — 병합 여부를 못 믿어 브랜치 '$branch' 유지"
    return 0
  fi

  if ! is_merged "$branch" "$sha"; then
    say "  ${YELLOW}⚠${NC} '$branch' 의 병합된 PR 을 못 찾았습니다 — 브랜치 유지"
    say "     확인 후 직접: ${CYAN}git branch -D $branch && git push origin --delete $branch${NC}"
    return 0
  fi

  if git -C "$MAIN_ROOT" branch -d "$branch" >/dev/null 2>&1; then
    say "  ${GREEN}✓${NC} 로컬 브랜치 삭제: $branch"
  else
    say "  ${YELLOW}⚠${NC} 로컬 브랜치 삭제 실패: $branch"
  fi

  if [ -z "$(git -C "$MAIN_ROOT" ls-remote --heads origin "$branch")" ]; then
    say "  ${BLUE}→${NC} 원격엔 이미 없음: origin/$branch"
  elif git -C "$MAIN_ROOT" push --quiet origin --delete "$branch"; then
    say "  ${GREEN}✓${NC} 원격 브랜치 삭제: origin/$branch"
  else
    say "  ${YELLOW}⚠${NC} 원격 브랜치 삭제 실패: origin/$branch"
  fi
}

cmd_rm() {
  local name="${1:-}"
  [ -n "$name" ] || { usage; exit 1; }
  local dir="$WT_ROOT/$name"
  [ -d "$dir" ] || die "없습니다: $dir"

  # 워크트리가 사라지면 어떤 브랜치였는지 알 수 없다 → 지우기 전에 붙잡아 둔다.
  local branch sha
  branch="$(git -C "$dir" rev-parse --abbrev-ref HEAD)"
  sha="$(git -C "$dir" rev-parse HEAD)"

  # 커밋 안 된 변경이 있으면 멈춘다(추적 파일 기준. secrets/data 는 원래 untracked).
  if [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
    say "${RED}커밋되지 않은 변경이 있습니다:${NC}"
    git -C "$dir" status --short --untracked-files=no
    die "커밋하거나 되돌린 뒤 다시 실행하세요."
  fi

  # 이 워크트리의 web/scheduler 가 떠 있으면 지우기 전에 내린다(컨테이너 회수).
  stack_down_if_serving "$name"

  # secrets/·data/ 는 untracked 라 --force 없이는 remove 가 거부한다.
  git -C "$MAIN_ROOT" worktree remove --force "$dir"
  say "${GREEN}✓${NC} 제거: wt/$name"

  branch_cleanup "$branch" "$sha"
}

# $1 이 정말 이 저장소의 워크트리 루트인가.
#   `git -C "$dir" ...` 의 실패를 가드로 쓸 수 없다: git 은 저장소를 못 찾으면 상위로 거슬러
#   올라가므로, wt/ 밑의 워크트리 아닌 디렉터리에서도 부모 저장소(vuln-agent/.git)를 찾아
#   성공하고 'main' 을 돌려준다. 그래서 고아 디렉터리가 "메인 트리라 보호됨" 으로 오인됐다.
#   대신 git 이 본 루트가 $dir 자신인지를 본다 — 새면 루트가 부모 저장소로 잡힌다.
#   양쪽을 pwd 로 통과시키는 이유: git 은 Windows 표기(C:/…)를, 셸은 MSYS 표기(/c/…)를 내므로
#   생경로끼리 비교하면 멀쩡한 워크트리까지 전부 고아로 판정된다(git-bash 실측).
is_worktree_root() {
  local dir="$1" top
  top="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || return 1
  [ "$(cd "$top" && pwd)" = "$(cd "$dir" && pwd)" ]
}

# --- sweep -------------------------------------------------------------------
# "머지했어 / 다음" — 병합된 워크트리를 한 번에 정리한다. rm 을 트리마다 치는 수고를 없앤다.
#   각 wt/* 에 대해:
#     · 워크트리가 아니면 → 비었으면 제거, 내용이 있으면 경고만(is_worktree_root).
#     · 커밋 안 된 변경 있으면 → 유지(날리지 않는다).
#     · main/master/detached 는 → 유지.
#     · 브랜치가 병합됐으면(is_merged) → 워크트리+브랜치 제거, 아니면 유지.
#   병합 판정·브랜치 정리는 rm 과 동일한 함수를 쓴다(is_merged/branch_cleanup).
cmd_sweep() {
  [ -d "$WT_ROOT" ] || { say "${YELLOW}wt/ 없음 — 정리할 워크트리가 없습니다.${NC}"; return 0; }

  # 병합 여부를 믿으려면 origin/main 이 최신이어야 한다. 한 번만 fetch.
  git -C "$MAIN_ROOT" fetch origin --quiet \
    || die "fetch 실패 — 병합 여부를 못 믿어 sweep 중단"

  say "${CYAN}== wt sweep · 병합된 워크트리 정리 ==${NC}"
  local removed=0 kept=0 dir name branch sha
  for dir in "$WT_ROOT"/*/; do
    [ -d "$dir" ] || continue                     # glob 매치 없으면 리터럴로 남는다
    dir="${dir%/}"; name="${dir##*/}"

    # 워크트리가 아니면 남은 쓰레기다. 비었으면 지우고(잃을 게 없다), 내용이 있으면
    #   사람이 안 본 파일을 지우지 않는다 — 경고만.
    #   빈 여부를 rmdir 성공으로 판정하지 않는 이유: 빈 디렉터리도 다른 프로세스가 cwd 로
    #   잡고 있으면 rmdir 이 "Device or resource busy" 로 실패한다(실측 — wt/rematch-timeout).
    #   그걸 "내용 있음" 으로 보고하면 사용자가 없는 파일을 찾게 된다.
    if ! is_worktree_root "$dir"; then
      if [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
        say "  ${YELLOW}⚠${NC} $name — 워크트리 아님(내용 있음), 유지 — 확인 후 직접 지우세요: ${CYAN}$dir${NC}"
        kept=$((kept+1))
      elif rmdir "$dir" 2>/dev/null; then
        say "  ${GREEN}✓${NC} $name — 워크트리 아닌 빈 디렉터리, 제거"
        removed=$((removed+1))
      else
        say "  ${YELLOW}⚠${NC} $name — 워크트리 아닌 빈 디렉터리지만 제거 실패(다른 셸이 이 폴더에 머무는 중?), 유지"
        kept=$((kept+1))
      fi
      continue
    fi

    branch="$(git -C "$dir" rev-parse --abbrev-ref HEAD 2>/dev/null)" \
      || { say "  ${YELLOW}⚠${NC} $name — HEAD 를 읽을 수 없음, 유지"; kept=$((kept+1)); continue; }
    sha="$(git -C "$dir" rev-parse HEAD 2>/dev/null)" || { kept=$((kept+1)); continue; }

    case "$branch" in
      ''|HEAD|main|master)
        say "  ${YELLOW}⚠${NC} $name — '$branch' 는 sweep 대상 아님, 유지"
        kept=$((kept+1)); continue ;;
    esac

    if [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
      say "  ${YELLOW}⚠${NC} $name ($branch) — 커밋 안 된 변경, 유지"
      kept=$((kept+1)); continue
    fi

    # 갈라져 나온 시점 sha 와 현재 HEAD sha 가 같으면 커밋을 하나도 안 한 갓 만든
    #   브랜치다 — origin/main 기점이라 폴백 판정(is-ancestor)이 참이 되어버려 "병합됨"으로
    #   오판하는 걸 막는다(마커 없는 옛 워크트리는 기존 로직 그대로 둔다).
    #   gh 경로에선 PR 이 없어 어차피 미병합이지만, 폴백에 떨어졌을 때를 위해 그대로 둔다.
    if [ -f "$dir/.wt-base-sha" ] && [ "$(cat "$dir/.wt-base-sha")" = "$sha" ]; then
      say "  ${BLUE}→${NC} $name ($branch) — 아직 커밋 없음(갓 생성), 유지"
      kept=$((kept+1)); continue
    fi

    if ! is_merged "$branch" "$sha"; then
      say "  ${BLUE}→${NC} $name ($branch) — 아직 병합 안 됨, 유지"
      kept=$((kept+1)); continue
    fi

    say "${CYAN}-- $name ($branch) 병합됨 → 제거 --${NC}"
    stack_down_if_serving "$name"
    git -C "$MAIN_ROOT" worktree remove --force "$dir"
    say "  ${GREEN}✓${NC} 제거: wt/$name"
    branch_cleanup "$branch" "$sha"
    removed=$((removed+1))
  done

  echo ""
  say "${GREEN}sweep 완료${NC}: 제거 ${removed} · 유지 ${kept}"
}

case "${1:-}" in
  add)   shift; cmd_add "$@" ;;
  list)  cmd_list ;;
  rm)    shift; cmd_rm "$@" ;;
  sweep) cmd_sweep ;;
  *)     usage ;;
esac
