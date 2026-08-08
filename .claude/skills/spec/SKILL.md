---
name: spec
description: Use after work-start, once a workspace exists and implementation has not begun. Turns the raw request into a written spec + plan, diverges on 2–3 implementation directions before converging, then delegates the risk analysis to the design-review skill and folds its result back into the spec.
---

# spec — 스펙·Plan 확정 (design-review를 감싸는 껍데기)

> 이 스킬은 **`design-review`를 대체하지 않는다.** 리스크 분석의 절차·관점 수·게이트 문구는
> `kit/skills/design-review/SKILL.md`가 SSOT이고, 여기에 복붙하지 않는다.
> 이 스킬이 하는 일은 셋뿐이다 — **(1) 분석할 스펙 문서를 만든다 · (2) design-review를 호출한다 ·
> (3) 그 결과를 스펙과 Plan에 반영한다.**
>
> `px` = `node scripts/px.js`. 종료코드 `2`는 정지 후 보고, `3`은 수동 처리 요청 후 계속.

---

## Step 1 — 입력 확인

```bash
node scripts/px.js ws resolve --cwd . --json
node scripts/px.js issue get {ref} --json        # exit 3 이면 사용자 입력으로 대체
cat {paths.specFile} 2>/dev/null
```

- `work-start`가 남긴 초안이 있으면 그것을 출발점으로 삼는다.
- 초안이 없으면 작업 단위 본문과 작업 공간의 코드를 근거로 여기서 새로 쓴다.
- 초안에 "Nano"가 표시돼 있으면 **이 스킬 전체를 건너뛰고** `implement`로 안내한다.

---

## Step 2~4 — 실행 경로 분기

Workflow tool 을 쓸 수 있으면 `kit/workflows/spec-analyze.js` 로 Step 2 와 Step 4 를 한 번에 돌린다 —
구현 방향 **2안 이상**과 단기/장기 축 기입, 3관점 각 **최소 2건**, 라운드2 반박 교차와 미합의 쟁점
판정이 코드로 강제된다(`.review-kit.json` 을 파싱해 `args.adapter` 로 넘긴다). 반환값의
`openIssues` / `specUpdates` 를 Step 5 에서 그대로 쓴다.
영향 파일 후보 탐색(Step 3)에는 `kit/workflows/explore.js` 를 쓸 수 있다.

없으면 아래 산문 절차를 그대로 수행한다 — 결과는 같고 강제가 없을 뿐이다.

---

## Step 2 — 구현 방향 발산 (Normal·Complex 한정)

곧장 "어떻게 짤까"로 수렴하면 최소 패치 쪽으로 구조적 편향이 생긴다. 수렴 **전에** 서로 다른
구현 방향 2~3개를 **단기 vs 장기** 축으로 펼친다:

| 축 | 각 방향마다 기록할 것 |
|---|---|
| `cost_now` | 지금 드는 비용 (low/medium/high) |
| `cost_to_change_later` | 나중에 바꿀 때 드는 비용 |
| `forecloses` | 이 선택이 **막아버리는** 미래 선택지 |
| `reversibility` | easy / medium / hard |
| `recommend_when` | 이 방향이 맞는 조건 한 줄 |

추천 1개를 함께 제시하고 **사용자가 방향을 고른 뒤에** 다음 단계로 간다. 혼합·수정 의견이면
반영한다. Simple 이하 변경이면 이 Step 전체를 skip한다 — 방향이 하나뿐인 변경에 선택지를
만들어내지 않는다.

선택된 방향을 `{paths.specFile}`에 **확정 구현 방향**으로 명시한다. 이후 design-review는 이
방향을 전제로 리스크를 본다.

---

## Step 3 — 스펙 초안 완성

`{paths.specFile}`에 아래를 채운다. 여기서 리스크 분석을 흉내내지 않는다.

- 제목 · 작업 단위 ref · 변경 규모(simple/normal/complex)
- 요구사항 상세(원문 보존) · 확정 구현 방향(Step 2)
- 영향 파일 후보 — 작업 공간의 코드를 직접 읽어 채운다
- 완료 조건(AC) — 검증 가능한 문장으로, 각 항목에 id 부여

---

## Step 4 — design-review 호출

```
Skill({ skill: "design-review" })
```

단일 세션 CLI(Codex 등)라면 `kit/workflow/design-review-algorithm.md`를 그대로 따른다 —
도구만 다르고 알고리즘은 하나다. 어느 쪽이든 **검증 강도를 낮추지 않는다**
(`guardrails.md` §5 — 약하게 돈 설계 검증은 거짓 안전감만 남긴다).

design-review가 돌려주는 것: 3관점 분석 · 미합의 쟁점 · `spec_updates`.

---

## Step 5 — 결과 반영

1. `spec_updates`(field/action/value)를 `{paths.specFile}`에 반영한다. 비어 있으면 초안을 그대로 확정.
2. **미합의 쟁점**은 지우지 말고 스펙에 남긴다 — 구현 중에 다시 부딪히는 지점이다.
3. Plan을 `{paths.planFile}`에 쓴다: 구현 순서, 단계별 체크리스트, TDD 적용 대상, 리스크 항목.
4. 작업 단위 본문을 확정 스펙으로 갱신한다:

```bash
node scripts/px.js issue update {ref} --body "{스펙 요약}"    # exit 3 이면 skip + 안내
node scripts/px.js ws stage {slug} SPEC
```

---

## Step 6 — Gate

design-review가 이미 승인 게이트를 세운다. 이 스킬은 그 게이트를 **다시 만들지 않고**, 승인 이후
다음 단계만 안내한다:

```
스펙·Plan 확정 — {paths.specFile} / {paths.planFile}
[미합의 쟁점 {N}건 — 있을 때만]

승인하면 /implement 로 구현을 시작합니다.
```

**사용자 승인 없이 구현으로 자동 진행하지 않는다.**

---

## 어댑터가 채워야 하는 값

| 키 | 파일 | 의미 |
|---|---|---|
| `paths.specFile` / `paths.planFile` | `.review-kit.json` | 스펙·Plan 산출물 경로 |
| `paths.codeContextFile` | `.review-kit.json` | design-review에 넘길 코드 맥락 파일(선택) |
| `providers.tracker` | `.pipeline.json` | Step 5의 작업 단위 본문 갱신 가능 여부 |

## Reference

- `kit/skills/design-review/SKILL.md` — 리스크 분석 절차 SSOT (이 스킬이 호출하는 대상)
- `kit/workflow/design-review-algorithm.md` — 팀 토론 P2P 프로토콜 (단일 세션 CLI용 동일 알고리즘)
- `kit/workflow/guardrails.md` §1 · §5 — 분석 스킬은 코드를 고치지 않는다 · 검증 강도 하한
- `kit/contract/provider-contract.md` §2.1 `issue` · §2.4 `ws stage`
