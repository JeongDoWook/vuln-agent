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

SECRET_FILES=(mysql_root_password mysql_password admin_password)

# 개발 도구: 대회 제출 저장소에서는 .gitignore 로 추적 제외됐다(README "출품 범위" 참고) —
#   git worktree add 는 추적 파일만 가져오므로 워크트리엔 이 경로들이 없다. secrets 와 같은
#   이유로 메인 트리에서 직접 복사한다(디렉터리 5개 + 파일 6개).
DEV_TOOL_PATHS=(
  kit .claude .codex scripts deploy/orchestrator
  CLAUDE.md AGENTS.md AGENTS-review-kit.md
  .review-kit.json .review-kit-manifest.json .pipeline.json
)

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

# --- 살아있는 워커 감지 -------------------------------------------------------
# 워크트리를 지울 때 그 안의 claude(런처의 손자 프로세스)가 아직 살아 있으면, git 이 폴더를
#   지운 뒤에도 그 프로세스의 OMC 훅이 .omc/state/hud-*.json 을 다시 써 `.git` 없는 껍데기가
#   되살아난다(2026-07-17 실측 — matcher-deadlock 등 5개). stop-worker.ps1 의
#   Stop-WorkerProcessTree 와 같은 근거로 판정한다: 우리가 만든 런처의 경로가 커맨드라인에
#   그대로 박혀 있다(`-File <워크트리>\.launch.ps1`). 워크트리 경로는 트리마다 고유하므로
#   PID 로 짐작하지 않고도 이 워크트리 것임이 자명하다.
#   프로세스 나열은 PowerShell(Win32_Process)만 할 수 있어 트리마다 부르면 매번 수백 ms 가
#   드니, sweep 처럼 여러 트리를 도는 호출에서도 한 번만 묻고 재사용한다(gh_available 과 같은 캐시 패턴).
WORKER_CMDLINES_CACHED=0
WORKER_CMDLINES=""
WORKER_CHECK_FAILED=0
worker_cmdlines() {
  if [ "$WORKER_CMDLINES_CACHED" -eq 0 ]; then
    WORKER_CMDLINES_CACHED=1
    if command -v powershell.exe >/dev/null 2>&1; then
      if ! WORKER_CMDLINES="$(powershell.exe -NoProfile -Command '(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -and $_.CommandLine -like "*.launch.ps1*" }).CommandLine' 2>/dev/null)"; then
        WORKER_CMDLINES=""
        WORKER_CHECK_FAILED=1
      fi
    else
      WORKER_CHECK_FAILED=1
    fi
    if [ "$WORKER_CHECK_FAILED" -eq 1 ]; then
      say "  ${YELLOW}⚠${NC} 워커 생존 여부를 확인할 수 없습니다(PowerShell 실행 실패/부재) — 안전하게 모든 대상을 '살아있을 수 있음'으로 간주해 건너뜁니다."
    fi
  fi
  printf '%s' "$WORKER_CMDLINES"
}

# 이 워크트리를 가리키는 살아있는 워커 런처가 있나. 확인 자체가 불가능하면(PowerShell 부재
#   등) 지우지 않는 쪽(=살아있다고 간주)으로 기운다 — is_merged 와 같은 원칙("불확실하면 유지").
wt_worker_alive() {
  local dir="$1" win_dir needle cmdlines
  cmdlines="$(worker_cmdlines)"
  [ "$WORKER_CHECK_FAILED" -eq 1 ] && return 0
  win_dir="$(cd "$dir" 2>/dev/null && pwd -W)" || return 0
  needle="${win_dir//\//\\}\\.launch.ps1"
  printf '%s\n' "$cmdlines" | grep -qF "$needle"
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

  # 개발 도구(kit/·.claude/·CLAUDE.md 등): git 미추적이라 worktree add 가 안 가져다준다.
  #   메인 트리에 있으면 통째로 복사 — 없으면 다음 워크트리부터 이 프로젝트의 개발 방식
  #   (오케스트레이터·codelore 조회 규약·리뷰 킷) 자체가 사라진다.
  local dt_item dt_dst dt_copied=0
  for dt_item in "${DEV_TOOL_PATHS[@]}"; do
    [ -e "$MAIN_ROOT/$dt_item" ] || continue
    dt_dst="$dir/$dt_item"
    mkdir -p "$(dirname "$dt_dst")"
    if [ -d "$MAIN_ROOT/$dt_item" ]; then
      cp -r "$MAIN_ROOT/$dt_item" "$dt_dst"
    else
      cp "$MAIN_ROOT/$dt_item" "$dt_dst"
    fi
    dt_copied=$((dt_copied + 1))
  done
  if [ "$dt_copied" -eq 0 ]; then
    say "  ${YELLOW}⚠${NC} 개발 도구(kit·.claude·CLAUDE.md 등) 없음 — 메인 트리 상태를 확인하세요"
  else
    say "  ${GREEN}✓${NC} 개발 도구 ${dt_copied}개 복사 (kit·.claude·CLAUDE.md 등, git 미추적)"
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

# --- 공용 dev DB 의 이 워크트리 e2e 잔재 정리 --------------------------------
# tests/smoke.sh 는 공용 dev DB(vulnagent-db-dev)에 **워크트리 이름이 박힌** 데이터를 만든다:
#   호스트 web01~03.<라벨>.example.com · 로그인 계정 admin-<라벨> (트리별 세션 격리용)
# 그런데 워크트리를 지워도 DB 는 공용이라 그 데이터가 영원히 남는다 — 아무도 자기 것 말고는
#   못 치운다. 2026-08-12 측정: 호스트 213대 중 118대가 이미 사라진 워크트리 것이었고, 딸려온
#   tb_finding 이 40만 행까지 불어 compliance 화면 12.4초·web auth 6.4초가 나왔다(손으로 지운 뒤
#   3.1초·2.2초). 워커 5개를 띄웠다 회수한 것만으로 15대가 다시 쌓였다 → 구조적으로 반복된다.
#   그래서 "워크트리를 회수할 때 그 워크트리 것도 같이 회수한다".
DEV_DB_CONTAINER="vulnagent-db-dev"   # 공용 dev DB 하나만 대상. prod 는 이 스크립트가 아예 모른다.

# tests/smoke.sh 의 WT_LABEL 과 **같은 변환**이어야 한다(비-DNS 문자는 '-' 로). 정본은 smoke 쪽이다.
wt_db_label() { printf '%s' "$1" | tr -c 'a-zA-Z0-9-' '-'; }

# 컨테이너 안에서 root 로 mysql (deploy/migrate.sh 와 같은 방식 — 비번은 Docker Secret 파일).
dev_db_mysql() {
  docker exec -i "$DEV_DB_CONTAINER" sh -c \
    'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot vulnagent "$@"' _ "$@" </dev/null
}

# $1 = 워크트리 이름. 이 워크트리 이름이 박힌 행만 지운다.
#   지우는 곳은 tb_host 와 tb_user 두 곳뿐이다 — tb_host 의 FK 가 ON DELETE CASCADE 라
#   tb_scan → tb_finding → tb_finding_evidence, tb_package·tb_container·tb_exposure 등이 따라 지워진다.
#   실패는 절대 워크트리 제거를 막지 않는다(경고 한 줄) — 못 지운 워크트리를 사람이 손으로
#   치우게 만드는 쪽이 훨씬 나쁘다. 그래서 이 함수는 언제나 0 으로 끝난다.
db_cleanup_worktree() {
  local name="${1:-}" label pattern user fqdn hosts n_host=0 n_user=0

  # 가드 ①: 이름이 비었거나 메인 트리를 가리키면 **아무것도 하지 않는다.**
  #   메인 트리의 web01~03.main.example.com 과 admin 계정은 상시 쓰는 데이터다.
  case "$name" in ''|main|master) return 0 ;; esac
  label="$(wt_db_label "$name")"
  case "$label" in ''|main|master) return 0 ;; esac
  # 가드 ②: 라벨은 [a-zA-Z0-9-] 만 남는 변환을 거쳤으므로 LIKE 와일드카드(% _)가 들어올 수 없다.
  #   그래도 변환이 바뀌었을 때 남의 데이터를 긁지 않도록 명시적으로 확인하고, 아니면 건너뛴다.
  case "$label" in *[!a-zA-Z0-9-]*) return 0 ;; esac

  docker inspect "$DEV_DB_CONTAINER" >/dev/null 2>&1 || {
    say "  ${YELLOW}⚠${NC} 공용 DB($DEV_DB_CONTAINER)가 없어 e2e 데이터 정리를 건너뜁니다(워크트리 제거는 완료)."
    return 0
  }

  # 라벨은 점으로 감싸여 있고 라벨 안에는 점이 없다 → 이 패턴은 이 워크트리 fqdn 만 문다.
  #   (web01~03 뿐 아니라 스모크가 남길 수 있는 다른 <무엇>.<라벨>.example.com 도 함께 걷는다.)
  pattern="%.$label.example.com"
  user="admin-$label"

  # 한 트랜잭션에 몰아넣지 않는다 — 호스트 하나당 CASCADE 로 수천 행이 딸려가므로 끊어서 지운다.
  hosts="$(dev_db_mysql -N -B -e "SELECT fqdn FROM tb_host WHERE fqdn LIKE '$pattern'" 2>/dev/null)" || {
    say "  ${YELLOW}⚠${NC} 공용 DB 조회 실패 — e2e 데이터 정리를 건너뜁니다(워크트리 제거는 완료)."
    return 0
  }
  while IFS= read -r fqdn; do
    [ -n "$fqdn" ] || continue
    if dev_db_mysql -e "DELETE FROM tb_host WHERE fqdn = '$fqdn'" >/dev/null 2>&1; then
      n_host=$((n_host + 1))
    else
      say "  ${YELLOW}⚠${NC} 호스트 삭제 실패: $fqdn"
    fi
  done <<< "$hosts"

  if dev_db_mysql -N -B -e "DELETE FROM tb_user WHERE username = '$user'; SELECT ROW_COUNT()" 2>/dev/null \
       | grep -q '^1$'; then
    n_user=1
  fi

  if [ "$n_host" -gt 0 ] || [ "$n_user" -gt 0 ]; then
    say "  ${GREEN}✓${NC} 공용 DB 정리: 호스트 ${n_host}대(스캔·발견 CASCADE) · 계정 ${n_user}개 (${label} 것만)"
  fi
  return 0
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
#   $1 = 브랜치명, $2 = 브랜치 tip sha
is_merged() {
  local branch="$1" sha="$2" out oid
  if gh_available; then
    # "이 이름으로 병합된 PR 이 있었나" 로는 부족하다 — 이 저장소는 브랜치명을 재사용한다
    #   (fix/rematch-timeout 은 워커가 두 번 스폰돼 PR #227 MERGED / #228 CLOSED 가 함께 있다).
    #   이름만 보면 같은 슬러그로 새로 판 브랜치의 **방금 연 PR** 이 병합됨으로 오판되고, 원격
    #   브랜치가 push --delete 로 날아간다. 그래서 지금 tip sha 가 병합된 PR 의 head 와 같은지까지
    #   본다. squash 머지에서도 headRefOid 는 병합 당시의 브랜치 tip 이라 이 비교가 정확하다.
    #   새 커밋이 얹히면 sha 가 달라져 자동으로 미병합이 된다.
    #   PR 이 없으면 출력이 비고, 조회 실패(네트워크·권한)면 비영 종료다. set -e 아래서
    #   죽지 않도록 `|| out=''` 로 받고, 그 경우는 "병합 아님"(=유지)으로 다룬다.
    out="$(gh pr list --head "$branch" --state merged --json headRefOid -q '.[].headRefOid' 2>/dev/null)" || out=''
    while IFS= read -r oid; do
      if [ -n "$oid" ] && [ "$oid" = "$sha" ]; then return 0; fi
    done <<< "$out"
    return 1
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

  # 살아있는 워커가 쓰는 트리는 지우지 않는다 — git 이 폴더를 지운 뒤에도 그 안의 claude 가
  #   .omc/ 를 되살려 `.git` 없는 껍데기만 남는다.
  if wt_worker_alive "$dir"; then
    die "'$name' 을(를) 쓰는 워커가 아직 살아 있습니다 — 지금 지우면 그 워커가 .omc/ 를 되살려 껍데기만 남습니다. 먼저 세션을 닫으세요: deploy/orchestrator/stop-worker.ps1 -Task $name"
  fi

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

  # 워크트리를 실제로 지운 뒤에 DB 잔재를 걷는다 — 이 순서라면 DB 정리가 어떻게 실패해도
  #   워크트리 제거는 이미 끝나 있다(안전 규칙: 정리 실패가 회수를 막지 않는다).
  db_cleanup_worktree "$name"

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
#   한 트리의 제거가 실패해도 경고만 하고 다음 트리로 넘어간다 — 요약은 어떤 경우에도 찍힌다.
#   그게 "끝까지 돌았다" 는 유일한 신호다.
cmd_sweep() {
  [ -d "$WT_ROOT" ] || { say "${YELLOW}wt/ 없음 — 정리할 워크트리가 없습니다.${NC}"; return 0; }

  # 병합 여부를 믿으려면 origin/main 이 최신이어야 한다. 한 번만 fetch.
  git -C "$MAIN_ROOT" fetch origin --quiet \
    || die "fetch 실패 — 병합 여부를 못 믿어 sweep 중단"

  say "${CYAN}== wt sweep · 병합된 워크트리 정리 ==${NC}"
  local removed=0 kept=0 failed=0 dir name branch sha
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

    # 살아있는 워커가 쓰는 트리는 건드리지 않는다(위 wt_worker_alive 참고) — 병합됐어도 예외 없음.
    if wt_worker_alive "$dir"; then
      say "  ${YELLOW}⚠${NC} $name ($branch) — 아직 살아있는 워커가 씁니다, 유지 — 먼저 닫으세요: ${CYAN}deploy/orchestrator/stop-worker.ps1 -Task $name${NC}"
      kept=$((kept+1)); continue
    fi

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
    # 제거 실패를 반드시 받는다. 안 받으면 set -e(:26) 가 sweep 을 통째로 죽여, 뒤의 워크트리는
    #   검사조차 안 된 채 요약도 안 찍힌다 — 사용자는 경고 몇 줄만 보고 "돌았다" 고 읽는다(실측).
    #   실패의 실제 원인은 대개 다른 셸/세션이 그 폴더를 cwd 로 붙들고 있는 것이다(Windows 는
    #   사용 중인 디렉터리를 못 지운다) → 사람이 닫아야 풀린다. 강제로 뚫지 않는다.
    if ! git -C "$MAIN_ROOT" worktree remove --force "$dir"; then
      say "  ${YELLOW}⚠${NC} $name — 워크트리 제거 실패(다른 셸이 이 폴더에 머무는 중?), 유지"
      say "     그 폴더를 쓰는 셸/탭을 닫고 다시: ${CYAN}./deploy/wt.sh sweep${NC}"
      # 워크트리가 남았는데 브랜치를 지우면 그 워크트리가 브랜치 없는 상태로 고아가 된다(실측 —
      #   fix/stop-worker-close-session 이 로컬 브랜치만 남아 사람이 손으로 지웠다).
      say "     브랜치 '$branch' 도 함께 남깁니다 — 워크트리가 있는데 브랜치를 지우면 고아가 됩니다."
      kept=$((kept+1)); failed=$((failed+1)); continue
    fi
    say "  ${GREEN}✓${NC} 제거: wt/$name"
    # rm 과 같은 정리를 트리마다 한다. 이 함수는 실패해도 0 으로 끝나므로 한 트리가 잘못돼도
    #   sweep 의 나머지 정리가 멈추지 않는다.
    db_cleanup_worktree "$name"
    branch_cleanup "$branch" "$sha"
    removed=$((removed+1))
  done

  echo ""
  say "${GREEN}sweep 완료${NC}: 제거 ${removed} · 유지 ${kept}"
  if [ "$failed" -gt 0 ]; then
    say "  ${YELLOW}⚠${NC} 그중 ${failed}개는 제거하려다 실패했습니다 — 그 폴더를 쓰는 셸/탭을 닫고 다시 sweep 하세요."
  fi
  # 부분 실패여도 0 으로 끝낸다. 근거: sweep 에서 "유지" 는 정상 결과의 일부고(미병합·미커밋도
  #   유지다), 제거 실패는 그중 한 종류일 뿐이다 — 다음 실행이 그대로 재시도하므로 멱등하게
  #   회복된다. 비영으로 끝내면 set -e 를 쓰는 상위 스크립트에서 sweep 이 다시 중간에 죽어,
  #   방금 없앤 "조용히 중단" 을 되살린다. 사람에겐 위 경고와 요약으로 이미 드러난다.
  return 0
}

case "${1:-}" in
  add)   shift; cmd_add "$@" ;;
  list)  cmd_list ;;
  rm)    shift; cmd_rm "$@" ;;
  sweep) cmd_sweep ;;
  *)     usage ;;
esac
