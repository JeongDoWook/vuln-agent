#!/usr/bin/env bash
# =============================================================================
# block-main-push.sh — main 브랜치 직접 commit/push 차단 (PreToolUse:Bash 훅)
# =============================================================================
# claude-pipeline .claude/hooks/block-main-deploy.sh 를 vuln-agent 용으로 단순화.
# GitLab p-release 예외·python3 파싱 제거 → 순수 bash grep (python/jq/node 불요).
#
# 동작: Bash 도구 호출 직전, 커맨드에서 아래를 감지하면 exit 2 로 차단
#   1) origin main 직접 push
#   2) 현재 브랜치가 main 일 때의 git commit
# → 항상 /wt 로 worktree 브랜치를 만들어 작업하고 PR 로 병합하게 강제.
# =============================================================================
INPUT=$(cat)

# 1) main 직접 push 차단 (git push [-flags] origin main)
if printf '%s' "$INPUT" | grep -qE 'git[[:space:]]+push([[:space:]]+-[^[:space:]]+)*[[:space:]]+origin[[:space:]]+main([^A-Za-z0-9_/.-]|\\|$)'; then
  echo "🚫 main 직접 push 차단 — feature worktree 브랜치에서 작업 후 /wt-push(PR)로 병합하세요." >&2
  exit 2
fi

# 2) main 브랜치에서 commit 차단
if printf '%s' "$INPUT" | grep -qE 'git[[:space:]]+commit'; then
  BR=$(git branch --show-current 2>/dev/null)
  if [ "$BR" = "main" ]; then
    echo "🚫 main 브랜치 직접 commit 차단 — /wt 로 worktree 브랜치를 만들어 작업하세요." >&2
    exit 2
  fi
fi

exit 0
