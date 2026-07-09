---
name: wt-done
description: Use when the user types "/wt-done" or "이슈정리". PR merge 후 활성 worktree 를 제거하고 로컬 브랜치를 정리한다(Step 9). vuln-agent 전용.
---

# wt-done — 정리 (Step 9) · worktree 제거

PR 이 merge 된 후 호출된다. worktree 를 제거하고 브랜치를 정리한다.
(claude-pipeline 의 "GitLab 이슈 close + work/ 삭제" 자리.)

---

## 진입 게이트 — merge 확인 (필수)

```bash
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
ACTIVE=$(cat "$MAIN/wt/.active" 2>/dev/null)
WT_DIR="$MAIN/wt/$ACTIVE"; SLUG="${ACTIVE#*-}"; PIPE="$WT_DIR/.pipe/$SLUG"
BRANCH=$(git -C "$WT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null)

# PR merge 상태 확인 (gh 있으면)
gh pr view "$BRANCH" --repo JeongDoWook/vuln-agent --json state,mergedAt 2>/dev/null \
  || echo "gh 확인 불가 — 사용자에게 merge 완료 여부 확인"
```

- PR `state == MERGED` → 정상 진행
- `OPEN` → **즉시 중단**: "PR 아직 merge 안 됨. GitHub 에서 merge 후 다시 실행하세요."
- gh 확인 불가 → 사용자에게 "merge 완료했나요?" 확인 후 진행

---

## Step 9 — 정리

> 항상 git 명령만 사용. 직접 `rm -rf` 금지 (worktree 는 `git worktree remove` 로).

```bash
# 1. 산출물 보존: .pipe/ 를 main 저장소 히스토리 폴더로 이동 (감사 추적용)
ARCHIVE="$MAIN/wt/.archive/$ACTIVE"
mkdir -p "$ARCHIVE"
cp -r "$PIPE" "$ARCHIVE/" 2>/dev/null && echo "📦 산출물 보존: wt/.archive/$ACTIVE/"

# 2. main 최신화 (merge 반영)
git -C "$MAIN" fetch origin main --quiet && git -C "$MAIN" pull --ff-only origin main 2>/dev/null || true

# 3. worktree 제거
git -C "$MAIN" worktree remove "$WT_DIR" --force
echo "🗑️  worktree 제거: $WT_DIR"

# 4. merge 된 로컬 브랜치 삭제
git -C "$MAIN" branch -d "$BRANCH" 2>/dev/null || git -C "$MAIN" branch -D "$BRANCH"

# 5. 활성 포인터 정리
rm -f "$MAIN/wt/.active"

# 6. worktree 메타 정리
git -C "$MAIN" worktree prune
```

conversation.jsonl 최종 기록(보존본에):
```jsonl
{"ts":"{nowISO9}","step":"9","actor":"agent","event":"cleaned_up","content":"{slug} merge 후 worktree·브랜치 정리 완료"}
```

---

## 완료 보고

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ 정리 완료 — {slug}
  worktree : 제거됨
  브랜치   : {type}/{slug} 삭제됨
  산출물   : wt/.archive/{MMDD}-{slug}/ 보존 (spec·리뷰·QA 리포트)

작업 완료. 새 작업은 /wt 로 시작하세요.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 산출물 보존 원칙
- `report-*.html`, `review.json`, `qa.json`, `spec.yaml`, `conversation.jsonl` 은 `wt/.archive/` 에 남긴다 (감사 추적).
- worktree 소스는 브랜치가 main 에 merge 되었으므로 삭제 안전.

## Non-Goals
- merge 안 된 브랜치 강제 정리 (Gate 에서 차단)
- 원격 브랜치 삭제 (GitHub 설정/사용자 재량 — 필요 시 `gh pr merge --delete-branch` 안내)
