# requirement-fanout — Algorithm Detail

> `kit/skills/requirement-fanout/SKILL.md`의 병합·충돌탐지 상세.

---

## 왜 "병합 담당"과 "충돌 결정"을 분리하는가

`requirement-synthesizer`가 충돌까지 대신 정하면, 그 순간부터 다시 "LLM이 애매한 걸 자신 있게
메운다" 문제로 돌아간다. 병합 에이전트의 권한은 **명백히 안 겹치는 것을 합치는 것**까지고, 겹치는데
방향이 다른 것은 반드시 사람에게 올라간다.

---

## 충돌 탐지 — 명시적 vs 암묵적

```
명시적 충돌: 페르소나 스스로 conflicts_with_others에 적어낸 것
  → synthesizer는 이 목록을 그대로 결정 요청에 옮긴다 (재해석 최소화)

암묵적 충돌: 페르소나가 각자 인지 못 했지만, 두 requirement/constraint를 나란히 놓고 보면
             동시에 만족 불가능한 것
  → synthesizer가 전원의 requirements+constraints를 교차 대조해 찾아낸다
  → implicit: true 로 표시 (명시적 충돌보다 오탐 가능성이 높다는 신호)
```

예시(암묵적): 관리자 페르소나가 "모든 사용자 활동 로그를 전체 열람"을 requirement로 냈고,
사용자 페르소나가 "타 사용자에게 내 활동이 노출되지 않음"을 constraint로 냈다면, 둘 다
`conflicts_with_others`를 스스로 채우지 않았어도 synthesizer가 교차 대조에서 잡아내야 한다.

---

## 병합 규칙

1. 의미가 같은 requirement/constraint는 하나로 합치되 `from: [persona_id, ...]`를 남긴다
   (여러 페르소나가 독립적으로 같은 걸 원했다는 사실 자체가 우선순위 근거가 된다 — 합치면서 지우지 않는다).
2. 반증 불가능한 표현("적절히", "필요시", "합리적으로")이 남아있으면 구체적 조건으로 재작성하거나,
   재작성 불가하면 그 자체를 결정 요청 목록에 올린다.
3. `priority: must`인데 다른 페르소나의 어떤 항목과도 충돌하지 않는 것은 자동으로 스펙에 반영한다
   (여기까지는 사람이 개입할 필요가 없다 — Gate는 충돌에만 쓴다).

---

## Gate 응답 처리

사용자가 상충 항목 결정(A/B/혼합)을 주면:

```
for each resolved conflict:
  merged_spec에 결정된 방향을 requirement/constraint로 반영
  반대쪽 방향은 spec에 "고려했으나 {이유}로 미채택"으로 짧게 남긴다
    → 나중에 design-review나 code-review 단계에서 "왜 이렇게 안 했나"는 재질문이 나오는 걸 막는다
```

---

## 요구사항 원장 (선택)

`requirementsLedger.enabled: true`일 때 Step 4.5에서 append하는 스키마는
`kit/workflow/pipeline-algorithm.md` "요구사항 원장" 절이 SSOT — 여기서 중복 정의하지 않는다.
기본은 off이며, 켜져 있어도 **사람이 결정한 상충 항목만** 남긴다(자동 반영된 요구사항은 제외).

---

## 출력 스키마

### persona-fanout (페르소나당 1개)

```yaml
persona: "{id}"
requirements:
  - { id: "R1", statement: "...", rationale: "...", priority: "must|should|nice" }
constraints:
  - { id: "C1", statement: "..." }
edge_cases: ["..."]
conflicts_with_others:
  - { target_persona: "{id}", about: "..." }   # 선택
```

### requirement-synthesizer (전체 1개)

```yaml
merged_requirements: N
conflicts:
  - id: "X1"
    between: ["persona_a", "persona_b"]
    about: "..."
    side_a: "..."
    side_b: "..."
    implicit: true|false
```

병합 스펙 본문은 `{paths.specFile}`에 Write — 이후 `design-review` 스킬이 그대로 입력으로 받는다.
