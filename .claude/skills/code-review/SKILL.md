---
name: code-review
description: Use before pushing/opening a PR, once implementation is done. Runs 5-perspective adversarial parallel review (Quality/Security/Regression/Code-Audit/Runtime-Trap), triages with an independent critic, drives Critical to 0, then gates on a per-track score cutline.
---

# code-review — 5관점 적대적 리뷰 + Critic + 점수 게이트

호출자(main session)가 5개 서브에이전트를 **직접 병렬 호출**한다. 중간 오케스트레이터 레이어 없음.

---

## Step 1 — Diff 수집

```bash
DIFF_BASE={git.diffBase}     # 어댑터 값, 없으면 사용자에게 확인
git diff ${DIFF_BASE}...HEAD --name-only
git diff ${DIFF_BASE}...HEAD --stat
git diff ${DIFF_BASE}...HEAD
```

변경 파일 전체를 Read해 diff만으로는 부족한 맥락을 보완한다. Regression 관점을 위해 마이그레이션
파일·관련 테스트 파일도 추가로 Read한다.

---

## Step 2~3 — 실행 경로 분기

Workflow tool 을 쓸 수 있으면 `kit/workflows/code-review-find.js` 로 Step 2~3 을 돌린다 —
관점 수·**관점별 최소 2건 제출**·critic 판정·**`dropped` 의 코드 근거 재확인**이 코드로 강제된다
(`.review-kit.json` 을 파싱해 `args.adapter` 로 넘긴다). 반환값의 `shortfall` / `demotedFromDropped`
가 비어 있지 않으면 그대로 사용자에게 보고한다.

없으면 아래 산문 절차를 그대로 수행한다 — 결과는 같고 강제가 없을 뿐이다.

---

## Step 2 — 5관점 병렬 리뷰

> **적대적 스탠스 원칙(모든 에이전트 공통)**: "이 코드는 프로덕션에서 실패한다"는 전제에서 출발한다.
> 임무는 문제를 찾는 게 아니라 **실패 메커니즘을 증명**하는 것. 발견 0개는 허용되지 않는다 — 정말
> 결함이 없다고 판단되면 "왜 안전한가"를 Critical 항목으로 방어해야 한다.

단일 메시지에서 5개 에이전트를 동시에 dispatch한다 (agent 파일: `quality-reviewer` /
`security-reviewer` / `regression-reviewer` / `code-auditor` / `runtime-trap-hunter`).

각 에이전트는 sentinel(`---Q_S---`/`---S_S---`/`---R_S---`/`---CA_S---`/`---RT_S---`) 사이에
YAML을 출력한다. 필드 규칙:

- `loc`: `path/filename:linenumber`
- `patch`: unified diff (`-` 제거 / `+` 추가), 변경 없으면 생략
- `auto`: 단일 파일·비로직 변경으로 완결되면 `true`

전체 완료 후 집계 테이블 출력:

```
┌──────────────────┬──────────┬─────────┬──────┐
│ Perspective      │ Critical │ Warning │ Info │
├──────────────────┼──────────┼─────────┼──────┤
│ Quality          │    N     │    N    │  N   │
│ Security         │    N     │    N    │  N   │
│ Regression       │    N     │    N    │  N   │
│ Code Audit       │    N     │    N    │  N   │
│ Runtime Trap     │    N     │    N    │  N   │
├──────────────────┼──────────┼─────────┼──────┤
│ Total            │    N     │    N    │  N   │
└──────────────────┴──────────┴─────────┴──────┘
```

**Assemble `review.json`** from merged items → `node scripts/gen-review.js {reviewOutDir}/review.json` →
open HTML.

---

## Step 3 — Critic dispatch + Verdict 처리

HTML 생성 직후, 사용자가 검토하는 동안 `review-critic`을 background로 dispatch한다(저자≠검증자 —
critic은 리뷰 대상 코드를 절대 쓰지 않는다, 쓰기 도구 없음).

사용자가 HTML에서 결정을 붙여넣으면:

1. Critic의 `"DONE: critic"` 수신 대기, sentinel(`---VERDICT_S---`/`---VERDICT_E---`) 파싱
2. `auto_fix` 항목 → 파일별 병렬 fix agent → commit
3. `human_review` 중 `severity: critical` → Step 4 (Critical loop)
4. `human_review` 중 `severity: warning` → Step 5 (Warning 처리)
5. 둘 다 없으면 → 점수 계산으로 바로 이동

---

## Step 4 — Critical Loop

**Critical은 0이어야 한다. 남아있는 한 다음 단계로 못 간다.**

```
iteration = 0
while Critical > 0:
  iteration += 1
  fix all Critical items (executor agent)
  Critical이 있었던 관점만 선별 재호출 (narrowed file list)
  if iteration >= {criticalLoop.maxIterations}:
    센티넬 파일 생성 → 중단, 잔여 Critical 목록 출력, 수동 개입 대기
```

Team 기능(`{criticalLoop.agentTeamsEnvFlag}=1`)이 있는 환경에서는 fixer↔reviewer 상주 팀으로 맥락을
보존하며 반복 — 없으면 매 iteration마다 새로 spawn(폴백, 기본 경로).

---

## Step 5 — Warning 처리 + 점수 계산

`human_review` 중 `severity: warning` 항목을 영향도(High/Medium/Low)로 자동 평가 후:

- Low → 자동 accept
- Medium → 사용자 선택(Fix / PR 코멘트로 등록 / Accept + 사유)
- High → Fix 권장, 거부 시 사유 필수

처리 결과를 `report.json`의 `warning_results[]`에 채운다. **점수는 직접 계산하지 않는다** —
어댑터 감점표 적용은 스크립트가 한다:

```bash
node scripts/gen-score.js {reviewOutDir}/report.json --write
```

`score`/`grade`/`cutline`/`deductions`가 채워진다. `--write` 없이 실행하면 검산 모드로,
이미 적힌 값과 다르면 `exit 2`로 실패한다.

컷라인 미달 시 최대 `{scoreRetry.maxIterations}`회까지 자동 재시도(수정 가능한 Warning fix →
재리뷰 → `gen-score.js` 재계산). 소진 후에도 미달이면 `score_unresolved`를 기록하고 중단한다.

---

## 완료

`node scripts/gen-report.js {reviewOutDir}/report.json` → HTML open.

```
✅ code-review complete
   Critical fixed: N (iterations N) | Warning: fix N / comment N / accept N
   📊 Score: N/100 [PASS|CAUTION|BLOCKED]  ({TRACK})
```

---

## 어댑터가 채워야 하는 값

| 키 | 의미 |
|---|---|
| `git.diffBase` | 리뷰 diff 기준 브랜치 |
| `paths.reviewOutDir` / `paths.fallbackOutDirs` | review.json/report.json 저장 경로 |
| `tracks.*` | 트랙(FE/BE 등)별 점수 컷라인·가중치·감점표 |
| `runtimeTrapTaxonomy` | runtime-trap-hunter 함정 패턴 (스택별 교체) |
| `codingGuard.nonStandardTag` / `ssotTag` | Decision-traceability 체크에 쓸 태그 마커 (없으면 해당 체크 skip) |
| `criticalLoop.maxIterations` / `scoreRetry.maxIterations` | 재시도 상한 |

## Reference

- `kit/workflow/code-review-algorithm.md` — Critical loop, Warning 처리, 점수식, 산출물 스키마 전체
- `kit/workflow/guardrails.md` — 봇은 게이트가 아니라 도구다·결함 클래스 단위 sweep·검증 강도 하한(§5)·전역 설정 양방향 감사
- `.claude/agents/quality-reviewer.md` 외 4개 + `review-critic.md`
- `scripts/gen-review.js` / `scripts/gen-score.js` / `scripts/gen-report.js`
