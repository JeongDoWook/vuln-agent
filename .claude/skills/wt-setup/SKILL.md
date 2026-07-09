---
name: wt-setup
description: Use when the user types "/wt-setup". Phase 1 요구사항 확정 후, git worktree + 브랜치를 생성(claude-pipeline 의 GitLab 이슈 생성 자리)하고 spec.yaml·conversation.jsonl 을 기록한다. vuln-agent 전용.
---

# wt-setup — 작업 환경 셋팅 (Phase 2) · worktree + 브랜치 생성

`/wt` Phase 1 요구사항 확정 후 호출된다.
**claude-pipeline 의 `mx.js issue mock`(GitLab 이슈 생성)을 `git worktree add -b`(브랜치 생성)로 대체**한다.

---

## 진입 즉시 — 대화 컨텍스트 확인

현재 대화에서 아래를 추출한다 (Phase 1 Gate 출력에 있음):

| 항목 | 출처 |
|------|------|
| 이슈 제목 | Phase 1 파싱 |
| type | feature / fix / refactor / chore |
| slug | Phase 1 파싱 (kebab, 3~5 단어) |
| complexity | trivial / simple / normal / complex (난이도 판정) |
| 요구사항 상세 | Phase 1 분석·논의 확정본 |
| 관련 파일 | Full 분석 시 SA 결과 (없으면 빈 배열) |

없으면 사용자에게 1줄로 재확인 후 진행.

---

## 2-1. git worktree + 브랜치 생성  ← GitLab 이슈 자리

```bash
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
MMDD=$(date +%m%d)
SLUG="{slug}"
TYPE="{feature|fix|refactor|chore}"
BRANCH="${TYPE}/${SLUG}"
WT_DIR="$MAIN/wt/${MMDD}-${SLUG}"

# main 최신화 (실패해도 계속 — 오프라인 가능)
git -C "$MAIN" fetch origin main --quiet 2>/dev/null || true

# 브랜치+폴더 동시 생성. base 는 origin/main (없으면 로컬 main)
BASE=$(git -C "$MAIN" rev-parse --verify --quiet origin/main >/dev/null 2>&1 && echo origin/main || echo main)
git -C "$MAIN" worktree add -b "$BRANCH" "$WT_DIR" "$BASE"
# 이미 브랜치가 있으면(재시도) → git -C "$MAIN" worktree add "$WT_DIR" "$BRANCH"

# 산출물 디렉토리 (브랜치에 커밋되지 않도록 local exclude 등록)
PIPE="$WT_DIR/.pipe/${SLUG}"
mkdir -p "$PIPE"
# ⚠️ linked worktree 는 .git 이 파일이므로 info/exclude 경로를 git 이 해석하게 한다
EXCL=$(git -C "$WT_DIR" rev-parse --git-path info/exclude)
mkdir -p "$(dirname "$EXCL")"
grep -qxF '.pipe/' "$EXCL" 2>/dev/null || echo '.pipe/' >> "$EXCL"

# 활성 worktree 포인터 기록 (이후 wt-spec/impl/qa/push 가 읽음)
echo "${MMDD}-${SLUG}" > "$MAIN/wt/.active"

echo "✅ worktree: $WT_DIR  (branch: $BRANCH, base: $BASE)"
```

> - `.git/info/exclude` 는 그 worktree 로컬 전용 무시목록 → `.pipe/` 산출물은 절대 커밋되지 않음.
> - main 저장소에서 `wt/` 전체는 이미 `.gitignore` 처리됨.

---

## 2-2. spec.yaml 작성

Write 툴로 `$PIPE/spec.yaml` (= `$WT_DIR/.pipe/{slug}/spec.yaml`) 저장:

```yaml
title: "{이슈 제목}"
slug: "{slug}"
type: "{feature|fix|refactor|chore}"
branch: "{type}/{slug}"
complexity: "{trivial|simple|normal|complex}"
description: |
  {요구사항 상세 — 사용자 입력 그대로}
affected_files: []          # wt-spec 에서 코드 읽고 채움 (Full 분석 결과 있으면 미리 기입)
acceptance_criteria:
  - id: AC-1
    description: "{요구사항에서 파생한 핵심 완료 조건 한 줄}"
notes: "{track 안내 — Nano/Fast/Full}"
```

> - **trivial** 이면 `notes: "Nano Track — wt-spec·3관점분석 생략"`.
> - Full 분석에서 파악한 파일이 있으면 `affected_files` 에 `{path, symbol, change}` 로 미리 기입.

---

## 2-3. conversation.jsonl — Phase 1 논의 이관

Write 툴로 `$PIPE/conversation.jsonl` 저장 (한 줄 = 한 이벤트, 개행 없는 JSON):

```jsonl
{"ts":"{nowISO9}","step":"0","actor":"agent","event":"task_created","content":"worktree 생성 — {slug} (branch: {type}/{slug})"}
{"ts":"{nowISO9}","step":"1","actor":"agent","event":"difficulty","content":"난이도 {L0-L3} / {Nano|Fast|Full} · 명확도 {CLEAR|UNCLEAR}"}
{"ts":"{nowISO9}","step":"1","actor":"agent","event":"code_context","content":"{Full 분석에서 파악한 관련 파일·함수 요약 (없으면 생략)}"}
{"ts":"{nowISO9}","step":"2","actor":"user","event":"requirements_approved","content":"{확정 요구사항 한 줄 요약}"}
{"ts":"{nowISO9}","step":"2","actor":"agent","event":"branch_created","content":"{type}/{slug} — {이슈 제목}"}
```

> `{nowISO9}`: `date +%Y-%m-%dT%H:%M:%S+09:00`. code_context 는 wt-spec/impl 에서 참조하므로 파일·함수명 구체적으로.

---

## 완료 보고 (같은 세션 계속)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ 작업 환경 셋팅 완료

  worktree : wt/{MMDD}-{slug}/     (= $WT_DIR)
  브랜치   : {type}/{slug}  (base: {origin/main|main})
  산출물   : .pipe/{slug}/  (spec.yaml, conversation.jsonl)
  난이도   : {L0-L3} / {Nano|Fast|Full}

같은 세션에서 이어서 진행하세요:
  · 설계·분석부터 → /wt-spec
  · (Nano/명확) 바로 구현 → /wt-impl
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

> **같은 세션 원칙**: 별도 Claude 세션을 띄우지 않는다. 이후 모든 wt 스킬은
> `$MAIN/wt/.active` 로 활성 worktree 를 찾아 `git -C "$WT_DIR"` 로 조작한다
> (Bash cwd 는 매 호출 main 으로 리셋되므로 절대경로/`-C` 사용).

---

## 에러 처리

| 상황 | 처리 |
|------|------|
| 브랜치 이미 존재 | `worktree add "$WT_DIR" "$BRANCH"` (신규 -b 생략) 로 재시도 |
| worktree 경로 이미 존재 | 사용자에게 기존 것 재사용/삭제 확인 (`git worktree remove`) |
| `origin/main` 없음(오프라인) | 로컬 `main` 을 base 로 진행 (경고 1줄) |
| main dirty | worktree 는 독립이므로 영향 없음 — 그대로 진행 |

## Non-Goals
- GitLab/GitHub 이슈 생성 (브랜치로 대체)
- 별도 세션 launch (같은 세션 진행)
