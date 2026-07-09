---
name: wt-push
description: Use when the user types "/wt-push". QA(Gate 2) 통과 후 활성 worktree 브랜치를 push 하고 GitHub PR 을 생성한다(Step 8). claude-pipeline 의 MR 자리. vuln-agent 전용.
---

# wt-push — push + GitHub PR 생성 (Step 8)

QA 완료(Gate 2) 후 호출된다. 브랜치를 origin 에 push 하고 `gh` 로 PR 을 만든다.
**claude-pipeline 의 GitLab MR 을 GitHub PR 로 대체**한다.

---

## 진입 즉시

```bash
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
ACTIVE=$(cat "$MAIN/wt/.active" 2>/dev/null)
WT_DIR="$MAIN/wt/$ACTIVE"; SLUG="${ACTIVE#*-}"; PIPE="$WT_DIR/.pipe/$SLUG"
BRANCH=$(git -C "$WT_DIR" rev-parse --abbrev-ref HEAD)

# 커밋되지 않은 변경 확인
git -C "$WT_DIR" status --short
# QA 산출물 확인 (Gate 2 통과 근거)
ls "$PIPE"/qa-*.html "$PIPE"/report-*.html 2>/dev/null || echo "⚠️ QA 리포트 없음 — /wt-qa 완료 여부 확인"

# gh 인증 확인
gh auth status >/dev/null 2>&1 || echo "⚠️ gh 미인증 — 'gh auth login' 필요 (또는 push 까지만)"
```

미커밋 변경이 있으면 먼저 커밋하도록 안내.

---

## Step 8-1 — push

```bash
git -C "$WT_DIR" push -u origin "$BRANCH"
```

---

## Step 8-2 — PR description 초안 → 🔴 Gate 3

spec.yaml + QA 결과로 PR 본문 초안을 작성해 `$PIPE/pr-body.md` 에 Write:

```markdown
## 요약
{이슈 제목 — 한 줄}

## 변경 내용
- {주요 변경 1}
- {주요 변경 2}

## 완료 조건 (AC)
- [x] AC-1: {설명} — {QA 검증 결과}
- [x] AC-2: ...

## 검증
- 정적검사: php -l pass / bash -n pass
- 3관점 리뷰: {score}점 ({PASS|CAUTION}) — Critical {N}, Warning {N}
- 스모크: {pass|해당없음}

## 리뷰 포인트
{리뷰어가 특히 볼 곳 — 있으면}

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

초안을 사용자에게 보여주고 **Gate 3**:

```
🔴 Gate 3 — PR description 초안입니다 (.pipe/{slug}/pr-body.md).
수정 의견을 주시거나 '진행'/'생성'/'OK' 로 응답하면 PR 을 생성합니다.
```

사용자 명시 승인 전까지 PR 생성 금지.

---

## Step 8-3 — PR 생성 (승인 후)

```bash
gh pr create --repo JeongDoWook/vuln-agent \
  --base main --head "$BRANCH" \
  --title "{type}: {이슈 제목}" \
  --body-file "$PIPE/pr-body.md"
```

생성된 PR URL 을 conversation.jsonl 에 기록:
```jsonl
{"ts":"{nowISO9}","step":"8","actor":"agent","event":"pr_created","content":"{PR URL} — {type}/{slug}"}
```

---

## 🔴 Gate 4 — 완료 안내

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ PR 생성 완료
  PR    : {PR URL}
  브랜치: {type}/{slug} → main

GitHub 에서 리뷰·Approve 후 merge 하세요.
merge 완료 후 정리하려면 → /wt-done
  (worktree 제거 + 로컬 브랜치 정리)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

- **PR merge 는 자동 실행 금지** — 사용자가 GitHub 에서 직접.

## Non-Goals
- PR 자동 merge
- gh 미설치 환경 강제 (그 경우 push 까지만 + 수동 PR 안내)
