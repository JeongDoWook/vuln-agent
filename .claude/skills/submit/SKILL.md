---
name: submit
description: Use when the work is ready for review — validates target branch and drift, syncs with origin, pushes, drafts the PR body for human confirmation at a gate, then opens the PR. Supports an explicit review-skipped mode for WIP pushes.
---

# submit — 드리프트 검증 → sync → push → PR 본문 확인(Gate) → PR 생성

**순서를 바꾸지 않는다.** 드리프트를 확인하기 전에 push하면 원격 커밋을 덮거나 거부당하고,
사람이 PR 본문을 보기 전에 PR을 만들면 게이트가 사라진다.

---

## Step 0 — 진입 게이트 (최우선 · read-only)

```bash
node scripts/px.js branch resolve-target --json     # → { target, reason }
node scripts/px.js branch drift-check --target {target} --json
```

- `drift-check`가 **`exit 2`면 즉시 멈춘다.** 출력된 `ahead`/`behind`를 사용자에게 보고하고,
  Step 1의 sync로 해소한 뒤 **drift-check를 재실행**한다. 통과할 때까지 push하지 않는다.
- `target`은 `resolve-target`이 반환한 값만 쓴다. **`develop`/`main`을 가정하지 않는다** —
  마일스톤 브랜치를 대상으로 하는 작업이 있고, 어댑터가 레포별로 base를 다르게 줄 수 있다.
- 커밋 안 된 변경·미해결 충돌·보호 브랜치 위 작업이면 중단한다(`git status --porcelain`).

### 리뷰 컷라인 전제

이 스킬은 **`code-review` 컷라인 통과를 전제**로 한다.

```bash
cat {paths.reviewOutDir}/report.json     # score · grade · cutline
cat {paths.qaOutDir}/qa.json             # static_check.test 가 pass 인지
```

| 상태 | 처리 |
|---|---|
| `grade: PASS` | 그대로 진행 |
| `grade: CAUTION` | 경고를 출력하고 진행(사용자 확인 불필요) |
| `grade: BLOCKED` | **중단** — code-review에서 이미 멈췄어야 하는 상태다 |
| report.json 없음 | 중단하고 `/code-review` 안내. 단, 아래 리뷰 생략 모드는 예외 |
| `qa.json`의 `static_check.test != pass` | 중단 — `self-qa` Step 4를 먼저 끝낸다 |

### 리뷰 생략 모드 (명시적 옵션)

사용자가 "리뷰 없이 push", "WIP push", "드라이 푸시"처럼 **명시적으로 요청했을 때만** 활성화한다.
스스로 판단해 켜지 않는다.

- 리뷰 컷라인 전제를 건너뛰되, **Step 0의 drift-check는 건너뛰지 않는다.**
- PR을 만든다면 `--draft`로 만들고, **PR 본문 맨 위에 다음 줄을 남긴다**:
  `> ⚠️ 코드리뷰 미수행 상태로 제출됨 (리뷰 생략 모드). 승인 전 최소 1회 code-review 필요.`
- 매번 사용자에게 같은 사실을 알린다. 이 모드로 만든 PR을 승인 단계로 넘기지 않는다.

---

## Step 1 — origin 병합

```bash
node scripts/px.js branch sync --target {target} --json
```

- `conflicts`가 비어 있지 않으면 **여기서 멈춘다.** 충돌 파일 목록을 보고하고 수동 해결을
  요청한다. 해결 후 Step 0의 drift-check부터 다시 시작한다.
- 이미 최신이면 `merged: false`로 조용히 통과한다(에러 아님).

---

## Step 2 — 2차 push

```bash
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git push origin "${BRANCH}:${BRANCH}"
```

> **명시 refspec을 쓴다.** 작업 공간의 upstream이 feature가 아니라 base로 잡혀 있는 경우가 있어,
> 맨 `git push`는 **base 브랜치로 직행**할 수 있다.

push 실패(non-fast-forward)면 재시도하지 않고 Step 0으로 돌아간다 — 그 사이에 원격이 앞섰다는 뜻이다.

---

## Step 3 — PR 본문 초안 · 🔴 사람 확인 게이트

`{paths.prTemplate}` 형식으로 본문 초안을 만든다(템플릿이 없으면 아래 최소 골격):

```markdown
## 개요        {이슈 ref} — {한 줄 요약}
## 변경 사항   - {파일군}: {무엇을, 왜}
## 검증        AC {pass}/{total} · 테스트 {결과} · 리뷰 {score}/100 [{grade}]
## 리스크      - {accepted-risk로 남긴 Warning, 후속 이슈}
```

초안 전문을 사용자에게 그대로 보여주고 **명시적 승인을 받는다.** 승인 전에는 `pr create`를
호출하지 않는다 — 이게 이 스킬의 유일한 사람 게이트다.

---

## Step 4 — PR 생성

```bash
node scripts/px.js pr create \
  --source "{BRANCH}" --target "{target}" \
  --title "{title}" --body "{승인받은 본문}" \
  --json
```

- 멱등이다. 같은 source의 PR이 이미 있으면 기존 PR이 반환된다 — 실패로 보지 않고 본문 갱신
  필요 여부만 사용자에게 확인한다.
- `exit 3`(트래커가 PR을 지원하지 않음, 예: `local`) → PR 없이 push까지만 완료로 보고하고
  수동 처리 절차를 안내한다.

```bash
node scripts/px.js ws stage {slug} PR
node scripts/px.js notify send --event pr_created --text "{title}" --url "{pr.url}"
```

> **알림 실패로 멈추지 않는다.** `notify`는 부수 효과이며, `sent:false`도 정상 응답이다.

**PR 자동 merge 금지** — 병합은 사람이 트래커 UI에서 한다.

---

## 완료

```
✅ submit 완료
   target : {target} ({reason})
   push   : {BRANCH} → origin
   PR     : #{ref} {url}   [리뷰 {score}/100 {grade} | 리뷰 생략 모드]

다음: 승인·병합 후 /finish (이슈 종료 + 작업공간 정리)
```

## 어댑터가 채워야 하는 값

| 키 | 의미 |
|---|---|
| `paths.reviewOutDir` / `paths.qaOutDir` | `report.json` / `qa.json` 위치 (진입 게이트 판정 근거) |
| `paths.prTemplate` | PR 본문 템플릿 경로 (없으면 위 최소 골격) |
| `pr.titlePattern` | PR 제목 형식 (예: `{issue} {type}: {title}`) |
| `pr.draftOnReviewSkip` | 리뷰 생략 모드에서 draft로 만들지 (기본 true) |

## Reference

- `kit/contract/provider-contract.md` §2.2 `pr` · §2.3 `branch` · §2.5 `notify`
- `kit/workflow/guardrails.md` §2(부수효과 전 상태 확인) · §3(사람의 최종 승인은 대체하지 않는다)
- `kit/skills/code-review/SKILL.md` — 컷라인 산출(`report.json`)의 SSOT
- `kit/skills/finish/SKILL.md` — 병합 후 다음 단계
