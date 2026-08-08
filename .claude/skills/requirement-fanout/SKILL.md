---
name: requirement-fanout
description: Use first, before design-review, whenever a feature request/ticket is loose or touches multiple stakeholders. Dispatches one agent per persona defined in the adapter (planner/admin/user by default) to independently define requirements, then merges them and gates on any conflicts before design-review starts.
---

# requirement-fanout — 다중 페르소나 요구사항 정의 + 상충 Gate

> **목적**: 기획을 한 사람(또는 단일 관점)이 쓰면 다른 이해관계자의 요구가 암묵적으로 누락된다.
> 각 페르소나가 **독립적으로** 요구를 정의하게 하고, 겹치는 곳은 합치고 **부딪히는 곳은 숨기지 않는다.**
> 코드리뷰가 계속 같은 종류의 지적을 반복한다면, 그 원인의 상당수는 이 단계 없이 바로 구현에
> 들어가서 생긴 미결정 사항이다.

간단한 변경(파일 몇 개, 단일 이해관계자만 관련)에는 과합니다 — `design-review`로 바로 가도 됩니다.
**여러 이해관계자가 얽히거나, 요구사항이 한 줄짜리 티켓 수준으로 헐거울 때** 이 단계를 먼저 돕니다.

---

## Step 1 — 페르소나 목록 확인

```bash
cat .review-kit.json | grep -A 20 '"personas"'
```

어댑터에 `personas`가 없으면 기본값(기획자/관리자/사용자) 3개를 쓰고, 이 사실을 사용자에게 한 줄로
알린다 — 조용히 기본값으로 진행하지 않는다.

---

## Step 2 — 페르소나별 병렬 dispatch

`personas` 배열의 각 항목마다 `persona-fanout` 에이전트를 **단일 메시지에서 동시에** 호출한다.
각 호출에 해당 페르소나의 `id`/`name`/`concerns`를 프롬프트에 주입한다.

```
parallel [단일 메시지]:
  Agent(subagent_type="persona-fanout", name="persona-{id}")
    persona: {id, name, concerns}
    requirement_source: {요구사항 원문 — 이슈/티켓/사용자 발화}
    → sentinel ---P_{id}_S--- / ---P_{id}_E---
```

전원 완료 후 각 sentinel YAML을 파싱한다.

---

## Step 3 — 병합 + 충돌 탐지

`requirement-synthesizer` 에이전트에 전원의 출력을 넘겨 병합 스펙 초안(`{paths.specFile}`)을 쓰게 한다.
이 에이전트는 **충돌을 대신 해결하지 않는다** — 병합만 하고, 상충 항목은 목록으로 뽑아 돌려준다.

---

## Step 4 — 상충 즉시 Gate

`conflicts` 목록이 비어있지 않으면, **design-review로 넘어가기 전에** 반드시 여기서 사용자 결정을 받는다:

```
👥 다중 페르소나 요구사항 정의 완료 — {N}명 관점, 합의된 요구사항 {N}건

⚠️ 상충 항목 — {N}건 (결정 필요)
  1. [{persona_a} vs {persona_b}] {상충 지점 한 줄}
     {persona_a}: {side_a}
     {persona_b}: {side_b}
     → 어느 쪽으로 갈까요? (A / B / 혼합 또는 직접 입력)
  ...

결정해주시면 병합 스펙에 즉시 반영하고 design-review로 넘어갑니다.
```

사용자 응답을 받으면 각 결정을 병합 스펙(`{paths.specFile}`)에 반영하고, `conversation.jsonl` 류
이력이 있는 프로젝트면 `{"event":"persona_conflict_resolved","content":"{id}: {결정 요약}"}` 형태로 남긴다.

`conflicts`가 처음부터 비어있으면 이 Gate는 자동 skip — 조용히 design-review로 진행.

---

## Step 4.5 — 요구사항 원장 기록 (선택, `requirementsLedger.enabled: true`일 때만)

기본값은 off — 이 Step 자체가 존재하지 않는 것처럼 skip한다(하위호환). 어댑터가 켜져 있으면,
Step 4에서 **사람이 결정한 항목만** `requirementsLedger.path`(기본 `.review-kit-requirements.jsonl`)에
한 줄씩 append한다:

```json
{"id":"R-{n}","topic":"...","decided_at":"<호스트 시계/커밋해시>","resolution":"A|B|혼합","from_personas":["planner","user"],"conflict":true}
```

충돌 없이 자동 반영된 요구사항은 원장에 남기지 않는다 — 전체 목록은 이미 `{paths.specFile}`에
있다. 원장은 append-only, 기존 줄은 절대 수정하지 않는다. 스키마 SSOT는
`kit/workflow/pipeline-algorithm.md` "요구사항 원장" 절.

---

## Step 5 — design-review로 핸드오프

병합 스펙(모든 충돌 해소 완료 상태)을 `design-review` 스킬의 입력으로 넘긴다. design-review는 이
상세 스펙을 놓고 3(또는 5)관점 **리스크** 분석을 수행한다 — 요구사항을 다시 발산하지 않는다.

---

## 어댑터가 채워야 하는 값

| 키 | 의미 | 기본값 |
|---|---|---|
| `personas` | `[{id, name, concerns}, ...]` | 기획자/관리자/사용자 3개 |
| `requirementsLedger.enabled` | Step 4.5(사람이 결정한 항목의 append-only 원장) 활성화 여부 | `false` |
| `requirementsLedger.path` | 원장 파일 경로 | `.review-kit-requirements.jsonl` |

## Reference

- `kit/workflow/requirement-fanout-algorithm.md` — 병합·충돌탐지 상세, 출력 스키마
- `.claude/agents/persona-fanout.md` / `requirement-synthesizer.md`
