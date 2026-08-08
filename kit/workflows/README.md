# kit/workflows — 절차를 코드로 강제하는 결정론적 스크립트

> 이 킷의 절차는 대부분 **산문**이다. 산문은 프롬프트가 한 줄을 놓치면 조용히 통과한다 —
> 관점 하나가 빠져도, 제출이 0건이어도, `dropped` 가 근거 없이 붙어도 아무도 막지 않는다.
> 여기 스크립트들은 그 중 **기계로 셀 수 있는 부분만** 골라 코드로 옮긴 것이다.
> Workflow tool 이 있는 환경(Claude Code)에서만 쓰고, 없으면 각 스킬의 산문 절차를 그대로 수행한다.
> **결과물은 같고, 강제가 없을 뿐이다.**

**절차의 SSOT 는 스크립트가 아니라 `kit/skills/*/SKILL.md` 와 `kit/workflow/*-algorithm.md` 다.**
스크립트가 문서와 어긋나면 문서가 맞다 — 스크립트를 고친다.

---

## 5개 스크립트

| 스크립트 | 무엇을 강제하는가 | 집행하는 문서 | 주요 args | 반환 |
|---|---|---|---|---|
| `code-review-find.js` | 관점 N개 전원 실행 · **관점별 최소 2건 제출**(미달 시 1회 재호출) · critic 판정 · **`dropped` 는 코드 근거 재확인, 없으면 human_review 로 강등** | `kit/skills/code-review/SKILL.md` Step 2~3 · `kit/workflow/code-review-algorithm.md` 「Critic 판정 기준」 | `cwd` `reviewJsonPath` `verdictPath` `title` `date` `context` `diffBase` `adapter` | `{ counts, failedPerspectives, shortfall, autoFixCount, humanReviewCount, droppedCount, demotedFromDropped }` |
| `spec-analyze.js` | 구현 방향 **2안 이상** + 단기/장기 축 전부 기입 · 3관점 라운드1 각 **최소 2건** · 라운드2 반박 교차 · **한 관점이라도 open 이면 미합의로 남김** | `kit/skills/spec/SKILL.md` Step 2 · `kit/skills/design-review/SKILL.md` Step 2 · `kit/workflow/design-review-algorithm.md` | `cwd` `specPath` `codePath` `complexity` `adapter` | `{ options, debate, openIssues, specUpdates, failedRoles, shortfall }` |
| `impl-phases.js` | 페이즈 경계(A→B→C) 순차 · 페이즈 안에서만 동시 · **대상 파일이 겹치는 작업 자동 직렬화** · 에이전트의 전체 테스트 실행 금지 · 페이즈 끝 검사 1회 | `kit/skills/implement/SKILL.md` Step 4~5 | `cwd` `phaseA` `phaseB` `phaseC` `issueRef` `repo` `specPath` `planPath` `adapter` | `{ phases:[{id,total,ok,serializedGroups}], skippedChecks, totalTasks, totalOk }` |
| `test-matrix.js` | 카테고리별 케이스 설계 · **AC 미커버 판정을 스크립트가 수행**(에이전트의 "다 덮었습니다"를 믿지 않음) · 산출 경로 임시 디렉터리 금지 | `kit/skills/self-qa/SKILL.md` Step 3~4 | `cwd` `specPath` `outPath` `acIds` `targetFiles` `track` `adapter` | `{ outPath, counts, coverage, uncoveredAc, failedCategories }` |
| `explore.js` | 대상별 병렬 탐색 · **`relevant:'no'` 에 근거 강제** · `yes` 인데 files 가 비면 1회 재호출 · 읽기 전용 | `kit/skills/spec/SKILL.md` Step 3 · `kit/workflow/guardrails.md` §1 | `req` `hint` `targets[{id,dir,hint}]` `cwd` `adapter` | `{ results, dropped, relevantCount, fileCount }` |

---

## 공통 규약

### 1. 어댑터는 **args 로 주입한다**

Workflow 스크립트는 **파일시스템에 접근하지 못한다**(`fs` 없음). 그래서 `.review-kit.json` 을
스크립트가 직접 읽을 수 없다 — **호출자가 파싱해 `args.adapter` 로 넘긴다.**

```js
Workflow({
  scriptPath: 'kit/workflows/code-review-find.js',
  args: { cwd: '/abs/path', reviewJsonPath: '...', verdictPath: '...',
          adapter: /* .review-kit.json 을 파싱한 객체 */ }
})
```

어댑터에 키가 없으면 **안전한 기본값으로 떨어지고 그 사실을 `log()` 한다.** 진행 로그에
`어댑터에 X 없음 — 기본값 사용: …` 이 보이면, 그 값은 프로젝트 값이 아니라 킷 기본값이다.

스크립트가 읽는 어댑터 키:

| 키 | 쓰는 스크립트 | 없을 때 |
|---|---|---|
| `git.diffBase` | code-review-find | `HEAD~1` |
| `runtimeTrapTaxonomy` | code-review-find · spec-analyze | 빈 목록(일반 함정만) |
| `codingGuard.nonStandardTag` / `ssotTag` | code-review-find | decision-traceability 체크 skip |
| `perspectives` (선택 override) | code-review-find | 킷 기본 5관점 |
| `paths.specFile` / `paths.planFile` | impl-phases | 경로 미지정 (에이전트가 문서를 못 읽음) |
| `tests.categories` / `tests.categoriesByTrack.{track}` | test-matrix | 스택 중립 4카테고리(UT/IT/SC/RG) |
| `tests.perspectives` | test-matrix | 기본 8관점 |
| `explore.hints` | explore | 대상별 힌트 없음 |

> `tests.*` 와 `explore.hints` 는 **이 스크립트들이 처음 요구하는 선택 키**다. 없어도 동작하고,
> 스택에 맞는 카테고리를 쓰고 싶을 때만 어댑터에 추가한다.

### 2. 역할 브리핑은 복제하지 않는다

리뷰어·설계 검증자의 판정 기준은 `.claude/agents/*.md` 가 SSOT다. 스크립트는 그 파일 **경로를
프롬프트에 넣어 Read 시킬 뿐** 본문을 복사하지 않는다. 브리핑을 고치면 스크립트를 고치지 않아도
동작이 바뀐다. 경로 기준은 `args.agentsRoot`(기본 `.claude/agents`)다 — 알고리즘 문서를 읽는
`args.kitRoot`(기본 `kit`)와 별개인 이유는, 브리핑만 Claude Code 가 훑는 자리에 설치되기 때문이다.

### 3. 외부 접점은 프로바이더 계약뿐

스크립트와 그 에이전트는 트래커·CI·메신저를 직접 만지지 않는다. 필요하면
`node scripts/px.js <group> <verb>` 만 부른다(`kit/contract/provider-contract.md`).
`exit 3` = 그 프로바이더가 해당 동사를 지원하지 않음 → 건너뛰고 **무엇을 건너뛰었는지 남긴다**.

### 4. 실패는 조용히 삼키지 않는다

- 필수 args 누락 → **즉시 throw**. 임의 경로에 파일을 쓰는 것보다 멈추는 게 낫다.
- 에이전트가 죽어 관점이 빠지면 `failedPerspectives` / `dropped` / `failedCategories` 로 반환하고 `log()` 한다.
- 하한 미달(제출 건수·옵션 수·AC 커버리지)은 **반환값에 남긴다.** 호출 스킬은 이걸 받고도
  "완료"로 보고하면 안 된다.

### 5. 스크립트는 방법론을 만들지 않는다

새 관점·새 게이트·새 점수식을 스크립트에서 발명하지 않는다. 점수 계산은 여전히
`node scripts/gen-score.js` 의 일이고(이 저장소의 두 기계적 게이트 중 하나), 스크립트는 그
입력이 되는 `review.json` 까지만 만든다.

---

## Workflow tool 이 없는 환경

Codex CLI·단일 세션 실행 등 Workflow tool 이 없는 환경에서는 **이 디렉터리를 쓰지 않는다.**
각 스킬 문서의 산문 절차가 그대로 폴백 경로이며, 그것이 원본 절차다:

| 이 스크립트 | 폴백 |
|---|---|
| `code-review-find.js` | `kit/skills/code-review/SKILL.md` Step 2~3 을 순서대로 수행 (5관점 동시 dispatch → 집계표 → critic) |
| `spec-analyze.js` | `kit/skills/spec/SKILL.md` Step 2 → `kit/skills/design-review/SKILL.md` Step 2 (단일 패스 또는 팀 토론) |
| `impl-phases.js` | `kit/skills/implement/SKILL.md` Step 4 — 분해가 애매하면 **순차 구현이 기본값**이다 |
| `test-matrix.js` | `kit/skills/self-qa/SKILL.md` Step 3~4 — AC 항목마다 코드 근거를 붙여 직접 판정 |
| `explore.js` | 스펙 Step 3 에서 코드를 직접 Read해 영향 파일 후보를 채운다 |

폴백 경로에서 **검증 강도를 낮추지 않는다**(`kit/workflow/guardrails.md` §5). 도구가 없으면
강제가 없을 뿐, 관점 수와 최소 제출 건수는 사람이 지켜야 하는 값 그대로다.

## Reference

- `kit/workflow/code-review-algorithm.md` · `kit/workflow/design-review-algorithm.md` — 집행 대상 알고리즘
- `kit/workflow/guardrails.md` §1(역할 분리) · §5(검증 강도 하한)
- `kit/contract/provider-contract.md` — 유일한 외부 접점
- `.claude/agents/*.md` — 역할 브리핑 SSOT (설치 위치. 킷 저장소 안에서는 `kit/agents/`)
