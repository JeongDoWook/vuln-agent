---
name: milestone
description: Use when the user wants to drive many issues across a milestone rather than a single issue — planning waves, dispatching work into parallel workspaces up to a slot limit, watching progress, and advancing as items merge. Triggers on "마일스톤 진행", "다음 작업 착수", "Wave 진행", "/ms", or any request to orchestrate multiple pipeline runs at once. Reads `.review-kit.json`'s `milestone` section and touches the outside world only through the provider contract (`px`).
---

# milestone — 다중 작업 오케스트레이터

> 이 스킬은 `pipeline`을 **대체하지 않는다.** 항목마다 `pipeline` 한 주기를 착수시키고,
> 슬롯·의존·게이트만 관리하는 층이다. **직접 구현하지 않는다** — 코드 변경은 전부
> 각 작업공간의 `pipeline` 세션이 한다.
>
> 절차·판정 규칙의 SSOT는 `kit/workflow/milestone-algorithm.md`다. 아래에 다시 쓰지 않는다 —
> 판단이 필요한 순간에는 그 문서를 읽는다. Codex 등 단일 세션 CLI도 같은 문서를 그대로 따르면
> 동일한 결과를 낸다(도구만 다르고 알고리즘은 하나).

---

## 사전 확인

```bash
node scripts/px.js doctor        # 프로바이더가 깨져 있으면 어떤 서브커맨드도 신뢰할 수 없다
node scripts/ms.js status
```

`.review-kit.json`에 `milestone` 절이 없으면 여기서 멈추고, 알고리즘 문서의 "어댑터 설정"
형태를 사용자에게 보여준 뒤 채워달라고 한다 — **값을 추측해 만들지 않는다.**

## 서브커맨드

| 입력 | 동작 |
|---|---|
| `/milestone` | `ms status` 출력 후 다음 행동을 제안 |
| `/milestone plan` | 항목 수집 → Wave 제안 → **사용자 승인** → `--apply` |
| `/milestone dispatch` | 빈 슬롯 × 우선순위 × 의존 충족 → 작업공간 생성 → `pipeline` 착수 |
| `/milestone watch` | 진행 관측 → Gate 도달 시 검토 → 승인/반려 |
| `/milestone advance` | 완료 감지 → 슬롯 회수 → 다음 후보 제시 |
| `/milestone report` | 진행 표 · HTML 생성 |

**`--apply` 없는 기본은 항상 dry-run이다.** 어떤 서브커맨드든 먼저 dry-run으로 출력을 읽고,
사용자에게 보여준 뒤에 `--apply`를 붙인다.

---

## Step 1 — `plan`

```bash
node scripts/ms.js plan
```

1. 출력된 **경고를 반드시 읽고 사용자에게 그대로 전달한다.** 오펀 보존 · 명시적 제외 ·
   삭제 거부 · 흡수 · 중복 소유권 충돌 · 끊어진 선행 참조 — 각각이 뜻하는 바와 대응은
   알고리즘 문서 "병합 규칙" 절에 있다. 경고를 요약해 뭉개지 않는다.
2. `refHints`는 **힌트일 뿐이다.** 실제 선후관계는 이슈 본문과 프로젝트의 계약 문서로 확인해
   `dependsOn`을 확정하고 state 파일에 직접 적는다(Edit).
3. Wave 표를 사용자에게 제시하고 **승인을 받는다.**
4. 승인 후에만 `node scripts/ms.js plan --apply`.
   삭제 거부된 in-flight 항목을 정말 지워야 할 때만 `--force`를 덧붙인다 —
   **무엇이 지워지는지 먼저 사용자에게 보여주고 확인을 받는다.**

## Step 2 — `dispatch`

착수할 항목마다 **먼저 스펙을 실측한다.** 이슈 본문은 오래된 전제를 담고 있는 경우가 흔하다 —
계약 문서·실제 코드와 대조하고, 불일치가 있으면 `px issue update`로 본문에 정정을 남긴다.
그 뒤 state에 `slug`를 확정해 적는다(`specVerified: true`, `status: specced`).

```bash
node scripts/ms.js dispatch            # dry-run — 실행될 px 명령 확인
node scripts/ms.js dispatch --apply
```

- **slug가 무효한 항목은 명령 자체가 만들어지지 않는다.** 경고를 읽고 state를 고친 뒤 다시
  실행한다 — **절대 손으로 slug를 추측해 명령을 채워 넣지 않는다.**
- 드리프트 게이트(exit 2)에 걸리면 후보 전원이 보류된다. 착수를 시도하지 말고
  base 동기화가 먼저다.
- 착수된 작업공간에는 `pipeline` 한 주기를 지시한다. Gate에서 멈추고 승인을 기다리게 하고,
  **PR 병합은 사용자 승인 없이 자동 실행하지 않는다.**

## Step 3 — `watch` / `advance`

```bash
node scripts/ms.js watch               # dry-run — 관측만
node scripts/ms.js advance
```

- 전이가 감지되면 **Gate 검토를 먼저 하고** `--apply`한다.
- `── 전이 거부 ──`·`관측 불가`·`⛔ blocked` 섹션은 전부 사용자에게 전달한다. 이 셋은
  각각 원인이 다르다(수기 편집/데이터 문제/증거 부족) — 알고리즘 문서 `watch` 절 참고.
- `blocked`는 자동 복귀하지 않는다. 원인을 해결한 뒤 사람이 state를 `blockedFrom`으로
  직접 되돌린다.

## Step 4 — `report`

```bash
node scripts/ms.js report --apply
```

Wave 표·슬롯 점유·의존 그래프·경고를 자기완결적 HTML로 만든다. 매 라운드 자동으로 열지
않는다 — 사용자가 요청하거나 Wave가 끝난 시점에만 안내한다.

---

## 어댑터가 채워야 하는 값

`.review-kit.json`의 `milestone` 절 — 키와 기본값의 정본은
`kit/workflow/milestone-algorithm.md` "어댑터 설정"이다. 트래커·저장소·라벨 이름은
**전부 거기서 온다** — 스킬 본문에도 구현에도 하드코딩된 값이 없다.

## Reference

- `kit/workflow/milestone-algorithm.md` — 용어, 병합 규칙, 게이트 순서, 승격 규칙, state 방어, 어댑터 설정
- `kit/contract/provider-contract.md` — 외부로 나가는 유일한 문 (`px`)
- `kit/skills/pipeline/SKILL.md` — 이 층이 각 작업공간에서 착수시키는 이슈 1건 주기
- `scripts/ms.js` · `scripts/gen-milestone.js` · `scripts/schema/milestone-state.schema.json`
