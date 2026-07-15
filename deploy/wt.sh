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
#   2) secrets/*.txt · deploy/.env.dev 복사 (gitignore 라 워크트리에 안 딸려온다)
#   3) 안 쓰는 WEB_PORT/DB_PORT 를 골라 그 워크트리의 .env.dev 에 박아둔다
#   compose_runner.sh 가 wt/ 를 감지해 프로젝트명·컨테이너명·이미지태그를 분리한다.
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

# (포트 탐색기는 없앴다 — dev 스택이 저장소에 하나뿐이라 워크트리끼리 포트가 겹칠 일이 없다.)

# dev 스택이 지금 **어느 트리의 server/ 를 마운트하고 있나**(안 떠 있으면 빈 문자열).
#   파일 표식을 두지 않는다 — 옛 러너로 스택을 옮기면 갱신되지 않아 낡은 값이 남는다.
#   진실은 컨테이너의 마운트뿐이다. (tests/smoke.sh·pre-push 도 같은 방식으로 대조한다.)
dev_stack_src() {
  docker inspect vulnagent-web-dev \
    --format '{{range .Mounts}}{{if eq .Destination "/var/www/html"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true
}
# 윈도는 역슬래시로 주므로 비교 전에 정규화한다.
norm_path() { printf '%s' "$1" | tr '\\' '/' | tr 'A-Z' 'a-z' | sed 's:/*$::'; }

usage() {
  say "${CYAN}vuln-agent · wt${NC}"
  echo ""
  say "  ${GREEN}add${NC} <브랜치> [기점]   wt/<이름> 워크트리 생성 (기점 기본 origin/main)"
  say "  ${GREEN}list${NC}                  워크트리 + 할당 포트"
  say "  ${GREEN}rm${NC} <이름>             dev 스택 내리고 워크트리 + 병합된 브랜치 제거"
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

  # .env.dev 는 **복사하지 않는다.** dev 스택은 하나뿐이고, 포트·DB 는 트리 속성이 아니라
  #   스택 속성이라 compose_runner 가 **메인 트리의 .env.dev** 만 읽는다. 워크트리에 사본을
  #   두면 "여기 값을 고치면 반영되겠지" 하는 착각만 만든다(실제로 옛 사본의 포트 8101 때문에
  #   스모크가 엉뚱한 포트를 쳐서 46개가 터졌다).
  [ -f "$MAIN_ROOT/deploy/.env.dev" ] || die "메인 트리에 deploy/.env.dev 가 없습니다. 먼저 init 하세요."
  say "  ${GREEN}✓${NC} dev 설정은 메인 트리의 .env.dev 를 공유(포트 8080 · DB 공용)"

  echo ""
  say "${GREEN}완료.${NC} 다음:"
  say "  ${CYAN}cd wt/$name${NC}"
  say "  server/·db/·tests/ 를 건드릴 때만 스택을 이 트리로 가져온다:"
  say "  ${CYAN}./deploy/compose_runner.sh dev up -d${NC}   # 스택은 하나뿐 — 새로 안 생기고 옮겨온다"
  say "  ${CYAN}./tests/smoke.sh http://localhost:8080${NC}"
}

# --- list -------------------------------------------------------------------
cmd_list() {
  git -C "$MAIN_ROOT" worktree list
  echo ""
  # dev 스택은 하나뿐이다 — 중요한 건 "포트"가 아니라 **지금 어느 트리를 서빙 중인가** 다.
  #   윈도 경로의 역슬래시를 그대로 출력하면 say(echo -e)가 \v 를 이스케이프로 먹는다 → 슬래시로.
  local tree; tree="$(dev_stack_src | tr '\\' '/')"
  if [ -n "$tree" ]; then
    say "${CYAN}dev 스택(vulnagent-dev)이 서빙 중${NC}: $tree"
  else
    say "${CYAN}dev 스택${NC}: 내려가 있음(또는 옛 러너로 띄움). 작업 트리에서 ${GREEN}dev up -d${NC}."
  fi
}

# dev 스택이 이 워크트리를 서빙 중이면 내린다(볼륨은 공용이라 -v 금지). 다른 트리면 손대지 않는다.
#   마운트 원본이 사라지면 500 만 뜨므로, 지울 트리를 서빙 중일 때만 미리 내린다.
stack_down_if_serving() {
  local dir="$1" mine
  mine="$( (cd "$dir" && pwd -W 2>/dev/null) || printf '%s' "$dir" )/server"
  if [ "$(norm_path "$(dev_stack_src)")" = "$(norm_path "$mine")" ]; then
    say "${BLUE}→${NC} dev 스택이 이 워크트리를 서빙 중 → 내립니다(볼륨은 보존)..."
    ( cd "$dir/deploy" \
      && docker compose --env-file "$MAIN_ROOT/deploy/.env.dev" -p vulnagent-dev \
           -f compose.yml -f compose.common.yml -f compose.dev.yml down \
    ) || say "  ${YELLOW}⚠${NC} 스택 중지 실패(이미 내려갔을 수 있음)"
    say "  ${YELLOW}!${NC} 다음 작업 트리에서 ${CYAN}./deploy/compose_runner.sh dev up -d${NC} 로 다시 올리세요."
  fi
}

# --- rm ---------------------------------------------------------------------
# 워크트리를 지워도 브랜치는 남아 목록이 계속 불어난다. PR 이 병합됐으면 로컬·원격 모두 정리한다.
#
# 병합 판정은 "브랜치 tip 이 origin/main 의 조상인가". merge 커밋 방식(이 저장소의 기본)에선
# 정확하다. squash·rebase 병합은 tip 이 조상이 아니라 '미병합' 으로 잡히는데, 그때는 지우지
# 않고 남긴다 — 안 지워서 손해볼 건 브랜치 하나지만 잘못 지우면 커밋이 날아간다.
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

  if ! git -C "$MAIN_ROOT" merge-base --is-ancestor "$sha" origin/main; then
    say "  ${YELLOW}⚠${NC} '$branch' 가 origin/main 에 안 보입니다 — 브랜치 유지"
    say "     병합했는데도 이 메시지가 뜨면 squash·rebase 병합입니다."
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

  # dev 스택은 저장소에 하나뿐이고 **DB 볼륨도 공용**이다 → 여기서 `down -v` 를 하면
  #   남의 세션 DB 까지 날아간다. 절대 -v 를 붙이지 않는다(stack_down_if_serving 이 -v 없이 내린다).
  stack_down_if_serving "$dir"

  # secrets/·data/ 는 untracked 라 --force 없이는 remove 가 거부한다.
  git -C "$MAIN_ROOT" worktree remove --force "$dir"
  say "${GREEN}✓${NC} 제거: wt/$name"

  branch_cleanup "$branch" "$sha"
}

# --- sweep -------------------------------------------------------------------
# "머지했어 / 다음" — 병합된 워크트리를 한 번에 정리한다. rm 을 트리마다 치는 수고를 없앤다.
#   각 wt/* 에 대해:
#     · 커밋 안 된 변경 있으면 → 유지(날리지 않는다).
#     · main/master/detached 는 → 유지.
#     · 브랜치 tip 이 origin/main 의 조상(=병합됨)이면 → 워크트리+브랜치 제거, 아니면 유지.
#   병합 판정·브랜치 정리는 rm 과 동일한 함수를 쓴다(merge 커밋 방식에서 정확, squash·rebase 는 유지).
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

    branch="$(git -C "$dir" rev-parse --abbrev-ref HEAD 2>/dev/null)" \
      || { say "  ${YELLOW}⚠${NC} $name — git 워크트리 아님, 유지"; kept=$((kept+1)); continue; }
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
    #   브랜치다 — origin/main 기점이라 is-ancestor 가 참이 되어버려 "병합됨"으로
    #   오판하는 걸 막는다(마커 없는 옛 워크트리는 기존 로직 그대로 둔다).
    if [ -f "$dir/.wt-base-sha" ] && [ "$(cat "$dir/.wt-base-sha")" = "$sha" ]; then
      say "  ${BLUE}→${NC} $name ($branch) — 아직 커밋 없음(갓 생성), 유지"
      kept=$((kept+1)); continue
    fi

    if ! git -C "$MAIN_ROOT" merge-base --is-ancestor "$sha" origin/main; then
      say "  ${BLUE}→${NC} $name ($branch) — 아직 origin/main 에 없음, 유지"
      kept=$((kept+1)); continue
    fi

    say "${CYAN}-- $name ($branch) 병합됨 → 제거 --${NC}"
    stack_down_if_serving "$dir"
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
