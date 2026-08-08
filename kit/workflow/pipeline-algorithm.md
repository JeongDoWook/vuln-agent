# pipeline — Algorithm Detail

> `kit/skills/pipeline/SKILL.md`(Claude Code) / `AGENTS.md`("파이프라인 단계 루프" 절, Codex 등)
> 양쪽이 공유하는 스테이지 체인 규칙. 도구 전용 기능(Agent tool, background dispatch)에 의존하지
> 않는 순수 서술 — 이 문서 자체는 어느 쪽에서 읽어도 같다.

---

## 왜 이 층이 필요한가

`requirement-fanout → design-review → code-review`는 이미 서로를 순서대로 소비하는 체인이다
(fanout의 병합 스펙 → design-review 입력, design-review 승인된 스펙 → 구현 → code-review 입력).
하지만 지금까지는 "이 셀 순서로 흐른다"는 사실이 각 SKILL.md 하단의 "핸드오프" 한 줄로만
흩어져 있었고, **호스트 프로젝트가 소유한 스테이지(구현·배포 등)가 이 체인의 어디에 끼는지**를
review-kit 쪽에서 표현할 방법이 없었다. `pipeline` 스테이지 목록은 그 틀만 표준화한다 —
review-kit이 모르는 일(구현·MR·배포)까지 대신 하겠다는 뜻이 아니다.

---

## 스테이지 타입 3종

```
type: gate      진행 전 반드시 사용자 승인/결정을 받는다. review-kit이 소유.
                예: requirements(충돌 시), spec(설계 승인), code-review(점수 컷라인)
type: auto      완료되면 사용자 재입력 없이 다음 스테이지로 넘어간다. review-kit이 소유.
                예: work-start(작업공간 생성), implement(Plan 실행), work-sync(base 최신화)
type: external  review-kit이 실행하지 않는 스테이지. 순서상 자리만 기억한다.
                두 가지가 있고 `wait`로 가른다:
                  wait: false (기본) — 안내 한 줄 후 **멈추지 않고** 다음 스테이지로 통과.
                                       호스트가 그 자리에서 바로 처리하는 단계.
                  wait: true        — 안내 후 **정지하고 사용자 신호를 기다린다.**
                                       사람/외부 시스템이 끝내야만 다음이 성립하는 단계.
```

**`external`에 `wait`가 왜 필요한가.** 초기 설계는 external을 전부 무정지 통과로 두었다.
호스트가 그 자리에서 곧바로 처리하는 단계(구현 등)라면 맞지만, **"사람이 PR을 리뷰하고
병합한다"** 처럼 몇 시간~며칠 뒤에 끝나는 단계에는 틀리다. 무정지로 통과시키면 파이프라인이
곧장 `finish`(이슈 종료 + 작업공간 삭제)로 넘어가고, `finish`는 병합 검증에서 막혀 실패한다 —
즉 **파이프라인이 정상 흐름에서 반드시 실패하는 자리**가 생긴다. `wait: true`는 그 구멍을
메운다. 생략하면 `false`이므로 기존 어댑터의 동작은 바뀌지 않는다.

**규칙**: 스테이지 사이에 이 목록 밖의 게이트를 임의로 만들지 않는다(`.review-kit.json`의
`pipeline.stages`가 게이트 위치의 SSOT). 반대로, 목록에 `type: gate`로 명시된 지점은
어떤 이유로도 스킵하지 않는다 — "이번엔 간단해 보여서" 같은 판단으로 사용자 승인을
대신하지 않는다.

---

## 스테이지 체인 두 프리셋

이 킷은 설치 범위가 두 가지라, 체인도 두 가지다. **어느 쪽인지는 `.pipeline.json`의 존재로
갈린다** — 라이프사이클 스킬은 프로바이더 계약 없이는 동작할 수 없기 때문이다.

### 프리셋 A — 검증 전용 (기본값, `.pipeline.json` 없음)

1층(검증 방법론)만 설치한 프로젝트. 어댑터에 `pipeline.stages`가 없을 때 쓰는 **기본값**이다.

```
requirements(optional, gate) → design(gate) → code-review(gate)
```

구현·배포는 호스트가 자기 도구로 하므로 `external`(wait 없음)로 자리만 잡거나, 아예 빼도 된다.

### 프리셋 B — 라이프사이클 전 주기 (`.pipeline.json` 있음)

2·3층(라이프사이클 스킬 + 프로바이더 계약)까지 설치한 프로젝트. `example-adapter/.review-kit.json`이
이 형태다.

| # | id | skill | type | 이 타입인 근거 |
|---|---|---|---|---|
| 1 | `work-start` | `work-start` | `auto` | 작업 단위 확인 + 작업공간 생성. 사람이 결정할 분기가 없다(모호하면 스킬이 자체적으로 되묻는다) |
| 2 | `requirements` | `requirement-fanout` | `gate` (optional) | 페르소나 간 **상충은 사람만 결정할 수 있다**. 이해관계자가 하나면 `skipCondition`으로 건너뛴다 |
| 3 | `spec` | `spec` | `gate` | 스펙·Plan 확정. **`design-review`를 내부에서 호출**하므로 별도 스테이지로 두지 않는다 |
| 4 | `implement` | `implement` | `auto` | 승인된 Plan의 실행. 새 결정이 필요하면 그건 Plan이 헐거웠다는 뜻이라 스킬이 되묻는다 |
| 5 | `self-qa` | `self-qa` | `gate` | 스킬 자체가 게이트로 끝난다 — AC 미충족을 사람이 보고 넘어갈지 정한다 |
| 6 | `sync` | `work-sync` | `auto` | 리뷰 **전에** base를 최신화한다. 낡은 base로 리뷰하면 충돌·회귀를 리뷰가 못 본다. 충돌이 나면 리뷰 예산을 쓰기 전에 멈추는 편이 싸다. 멱등이라 이미 최신이면 무동작 |
| 7 | `code-review` | `code-review` | `gate` (`cutlineGate`) | 점수 컷라인이 게이트. CAUTION/BLOCKED면 통과 자체를 보류 |
| 8 | `submit` | `submit` | `gate` | `drift-check` `exit 2`면 정지. PR 본문은 사람이 확인한 뒤에만 생성 |
| 9 | `merge` | — | `external` **`wait: true`** | **사람이 PR을 리뷰·병합한다.** review-kit은 어떤 경우에도 병합하지 않는다. 여기서 기다리지 않으면 10번이 반드시 실패한다 |
| 10 | `finish` | `finish` | `auto` | 병합 확인 → 이슈 종료 → 작업공간 정리. 파괴적 동작의 확인은 **스킬 안에** 있으므로 스테이지 레벨에서 게이트를 한 번 더 두지 않는다 |

**체인에 넣지 않는 스킬 3개:**

- `design-review` — 3번 `spec`이 내부에서 부른다. 스테이지로도 두면 **두 번 돈다.**
  검증 전용 설치(프리셋 A)에는 `spec` 스킬이 없으므로 그때만 독립 스테이지가 된다.
- `release` — 축이 다르다. 이 체인은 **이슈 하나**의 주기이고, 릴리스는 **여러 이슈가 병합된
  뒤**에 도는 별개 주기다. 같은 목록에 넣으면 이슈마다 릴리스를 끊게 된다.
  필요하면 어댑터에 `pipeline.releaseStages`처럼 **별도 체인**으로 둔다.
- `dev-env` — 스테이지가 아니라 아무 시점에나 부르는 유틸이다(서버 기동/중지).

---

## 실행 루프

```
stages = adapter.pipeline.stages  (없으면 프리셋 A: requirements(optional,gate) → design(gate) → code-review(gate))
state  = read(adapter.pipeline.statePath) 또는 {current: 0, history: []}

for stage in stages[state.current:]:
  if stage.type == "external":
    if not stage.wait:                                  # 기본값
      안내 한 줄: "→ {stage.id}는 호스트 프로젝트 스테이지 — review-kit 미실행. 완료되면 계속 진행하세요."
      state.history.append({id: stage.id, status: "external_skipped"})
      state.current += 1
      write(adapter.pipeline.statePath, state)
      continue   # 사용자 재입력 없이 바로 다음 스테이지 목록으로

    # wait: true — 외부에서 끝나야 다음이 성립한다
    state.history.append({id: stage.id, status: "external_wait"})
    write(adapter.pipeline.statePath, state)            # 정지 전에 먼저 영속화 — gate와 같은 이유
    안내 한 줄 + 무엇을 기다리는지(stage.note) 제시 → 정지, 사용자 신호 대기
    # 사용자가 "끝났다"고 알린 후에만:
    state.history[-1] = {id: stage.id, status: "external_done", at: <호스트가 채움>}
    state.current += 1
    write(adapter.pipeline.statePath, state)
    continue

  if stage.optional and skipCondition 충족:
    한 줄 안내 후 skip
    state.history.append({id: stage.id, status: "skipped", reason: "..."})
    state.current += 1
    write(adapter.pipeline.statePath, state)
    continue

  stage.skill 실행 (Claude Code: Skill tool로 해당 SKILL.md 진입 / Codex: AGENTS.md 해당 절 순차 수행)

  if stage.type == "gate":
    state.history.append({id: stage.id, status: "gate_wait"})
    write(adapter.pipeline.statePath, state)   # 승인 전 상태를 먼저 영속화 — 승인 대기 중 끊겨도 재개 시 "미승인"임을 안다
    사용자에게 결과 보고 + 다음 스테이지 진행 여부/승인 요청 → 정지, 응답 대기
    (case: code-review 이면서 cutlineGate=true → CAUTION/BLOCKED 등급은 게이트 통과 자체를 보류)
    # 사용자 승인 응답을 받은 후에만 아래를 수행:
    state.history[-1] = {id: stage.id, status: "done", gate_approved_at: <승인 시점 — 호스트가 채움>}
    state.current += 1
    write(adapter.pipeline.statePath, state)
  else:  # type == "auto"
    state.current += 1
    state.history.append({id: stage.id, status: "done", at: <스테이지 완료 시각 — 호스트가 채움>})
    write(adapter.pipeline.statePath, state)
    # 재입력 없이 루프 계속
```

- **`skip`·`external`도 `state.current`를 올리고 즉시 write한다.** 초기 버전은 이 두 분기에서
  history만 append하고 `current`를 그대로 뒀는데, 그러면 재개한 세션이 이미 지나간 스테이지를
  다시 가리켜 무한히 같은 자리를 맴돈다. 루프를 빠져나가는 **모든 경로**가 `current`를
  전진시켜야 한다(단 `gate`·`external wait`는 정지 시점이 아니라 **승인/신호 수신 후**에 올린다).
- 타임스탬프는 이 문서가 강제하지 않는다 — 호스트가 가진 시계/커밋해시 등으로 채운다.
- `state.history`는 append-only(단, 마지막 항목이 `gate_wait`일 때 그 항목을 `done`으로
  **덮어쓰는 것만** 예외 — 새 줄을 추가하지 않는다). 재실행 시 완료된 스테이지를 다시 돌리지
  않는다(멱등성 — 이미 `done`인 stage.id는 skip하고 다음으로).
- 재개 시 마지막 history 항목이 `gate_wait`이면, 해당 스테이지는 **이미 실행됐고 승인만
  대기 중**이다 — `stage.skill`을 다시 실행하지 않고, 곧바로 승인 요청만 다시 사용자에게
  보여준다. 마지막 항목이 `external_wait`이면 **외부 완료 신호만 대기 중**이다 — 실행할 것이
  애초에 없으므로 무엇을 기다리는지만 다시 보여준다.
- Claude Code 쪽에서 여러 스테이지가 이미 `type: gate` 없이 연쇄 실행 중이라면(예: fanout에
  충돌이 없어 자동 skip → design-review 진입), 각 전환 시점에 한 문장으로만 알린다 —
  단계마다 장문 보고를 반복하지 않는다.

---

## 상태 파일 스키마 (`pipeline.statePath`, 기본 `.review-kit-state.json`)

```json
{
  "current": 6,
  "history": [
    { "id": "work-start",   "status": "done",    "at": "2026-08-07" },
    { "id": "requirements", "status": "skipped", "reason": "단일 이해관계자" },
    { "id": "spec",         "status": "done",    "gate_approved_at": "commit:abc1234 또는 날짜" },
    { "id": "implement",    "status": "done",    "at": "commit:def5678" },
    { "id": "self-qa",      "status": "done",    "gate_approved_at": "2026-08-07" },
    { "id": "sync",         "status": "done",    "at": "2026-08-07" }
  ]
}
```

게이트 승인 대기 중(정지 상태)에 저장되는 형태는 마지막 history 항목만 다르다 —
`current`는 아직 그 스테이지를 가리키고, `at`/`gate_approved_at`은 없다:

```json
{
  "current": 2,
  "history": [
    { "id": "work-start",   "status": "done", "at": "2026-08-07" },
    { "id": "requirements", "status": "skipped", "reason": "단일 이해관계자" },
    { "id": "spec",         "status": "gate_wait" }
  ]
}
```

`status` 값:

| 값 | 뜻 | `current`가 이미 전진했는가 |
|---|---|---|
| `done` | 완료 (gate면 승인까지 받음) | 예 |
| `skipped` | `optional` + `skipCondition` 충족으로 건너뜀 | 예 |
| `external_skipped` | `external`(`wait` 없음) — 자리만 지나감 | 예 |
| `external_done` | `external wait: true` — 외부 완료 신호를 받음 | 예 |
| `gate_wait` | 스테이지는 실행됐고 **승인 대기 중** | **아니오** |
| `external_wait` | **외부 완료 신호 대기 중** (실행할 것 없음) | **아니오** |
이 파일은 review-kit이 유일하게 쓰는 영속 상태다 — HTML을 직접 들고 다니지 않는다. HTML로 보고
싶으면 `node scripts/gen-status.js {statePath}`로 그때 렌더링한다(자기완결적 산출물, 상태 파일
자체는 항상 JSON).

---

## 그래프 실행 모델 (v2)

위의 「실행 루프」·「상태 파일 스키마」는 **선형 모델(v1)** 이다 — 스테이지가 배열이고 진행은
`current` 정수 하나다. v2는 그것을 지우지 않는다. **v2는 v1의 상위집합**이고, `dependsOn`이
하나도 없는 평평한 배열은 v2 엔진에서 "각 노드가 직전 노드에 의존하는 사슬"로 승격되어
v1과 똑같이 돈다. 기존 어댑터·기존 상태 파일을 고치지 않아도 된다.

**왜 그래프가 필요한가.** 선형 모델은 세 가지를 표현하지 못한다.
(1) **동시에 돌아도 되는 스테이지** — `current`는 정수라 "지금 실행 가능한 것"이 항상 하나다.
(2) **optional을 껐을 때 하위가 어떻게 되는지** — v1은 `skipped`를 기록만 하고, 그 산출물을
소비하기로 되어 있던 다음 스테이지가 무엇을 못 받았는지 남기지 않는다.
(3) **실패** — v1 `status`에는 실패가 아예 없어서, 막힌 파이프라인과 아직 안 돈 파이프라인이
파일상 구분되지 않는다.

순수 함수 구현은 `scripts/lib/pipeline/graph.js`, 상태 파일 형식은
`scripts/schema/pipeline-state.schema.json`(v1·v2 둘 다 유효한 `oneOf`)이다.

### 노드

```
id            (필수) 노드 식별자. 그래프 안에서 유일하다.
skill         실행할 스킬 이름. external 노드는 null.
type          auto | gate | external      — 위 「스테이지 타입 3종」과 같은 의미다.
group         묶어서 보여줄 그룹 이름(표시·이해 단위). 실행 순서에는 영향이 없다.
dependsOn     []  이 노드가 소비하는 상위 노드 id 들. 비면 뿌리다.
activation    required | optional          — v1의 `optional: true` 는 optional 로 읽는다.
wait          external 노드가 외부 완료 신호를 기다리는가 (기본 false).
cutlineGate   gate 노드가 점수 컷라인으로 통과를 보류하는가.
skipCondition optional 노드를 건너뛰는 조건(사람이 읽는 서술).
```

`group`은 순서를 만들지 않는다 — 순서를 만드는 것은 `dependsOn` 뿐이다. 그룹을 실행 단위로
겸하게 하면 "같은 그룹이니 순서가 있겠지"라는 암묵 의존이 생겨, 정의에 없는 순서에 기대는
파이프라인이 만들어진다.

**v1 승격 규칙**: **한 노드도 `dependsOn`을 선언하지 않았을 때만** 배열 순서를 의존으로 읽어
각 노드에 `dependsOn: [직전 노드]`를 넣는다. 하나라도 선언했으면 전부 v2로 읽고, 미선언 노드는
뿌리가 된다. 섞어서 해석하지 않는 이유는, `dependsOn`을 한 곳만 적은 어댑터에서 나머지가
조용히 직렬로 묶여 **작성자가 그리지 않은 그래프**가 나오기 때문이다.

### 노드 상태

```
ready          의존이 전부 정착했고 아직 착수하지 않았다 — 지금 돌릴 수 있다
running        착수해서 진행 중
done           완료 (gate면 승인까지 받음)
gate_wait      실행은 끝났고 사람의 승인을 기다린다
external_wait  외부 완료 신호를 기다린다 (실행할 것이 애초에 없다)
skipped        optional + skipCondition 충족, 또는 external(wait 없음)로 자리만 지나감
bypassed       상위가 전부 산출물 없이 지나가, 소비할 입력이 없어 자동으로 내려간 상태
failed         실행이 실패했다
```

`ready`는 **저장하지 않는다.** 그래프와 다른 노드의 상태에서 매번 파생되는 값이라, 파일에
쓰면 진실이 둘이 되고 둘이 어긋나는 순간을 아무도 못 잡는다. 상태 파일에 남는 값은 나머지
일곱 개다.

`skipped`와 `bypassed`는 **누가 결정했는가**로 갈린다. `skipped`는 사람 또는 `skipCondition`이
"이번엔 안 한다"고 정한 것이고, `bypassed`는 아무도 정하지 않았는데 상위가 비어서 할 일이
사라진 것이다. 둘을 한 값으로 합치면 "왜 이 노드가 안 돌았나"를 나중에 재구성할 수 없다.

**v1 status와의 대응표**

| v1 `status` | v2 `state` | 비고 |
|---|---|---|
| `done` | `done` | 그대로 |
| `skipped` | `skipped` | 그대로 |
| `external_skipped` | `skipped` | v2는 "왜 지나갔나"를 노드의 `type: external`이 이미 갖고 있어, 상태 값에 중복해 담지 않는다 |
| `external_done` | `done` | 상동 |
| `gate_wait` | `gate_wait` | 그대로 |
| `external_wait` | `external_wait` | 그대로 |
| — | `ready` | v1에 없음. `current`가 대신했고, 그래서 하나 이상을 가리킬 수 없었다 |
| — | `running` | v1에 없음. 단일 진행이라 표현할 필요가 없었다 |
| — | `bypassed` | v1에 없음. optional 전파 개념 자체가 없었다 |
| — | `failed` | v1에 없음. 실패가 상태로 남지 않았다 |

대응이 한 방향뿐인 칸(`external_skipped`/`external_done`)이 있으므로, v1 → v2는 손실 없이
가지만 v2 → v1은 일반적으로 되돌릴 수 없다. v2를 쓰기 시작하면 그 실행은 v2로 끝낸다.

### 정착 · 부재 · 착수

- **정착(settled)** = `done · skipped · bypassed · failed`. 하위 노드가 더 기다릴 이유가 없는 상태.
- **부재(absent)** = `skipped · bypassed`, 그리고 **optional 노드의 `failed`**. 정착했지만
  소비할 산출물을 남기지 않은 상태.
- `readyNodes`는 **의존이 전부 정착한 미착수 노드 전부**를 돌려준다. 원소가 둘 이상이면
  그 노드들은 서로 독립이므로 동시에 돌려도 된다 — 이것이 배열인 이유다.

### bypass 전파 규칙

**optional 노드를 skip하면, 그 노드에만 의존하던 하위 노드는 차단되지 않고 통과한다.**

근거: `activation: optional`은 "이 산출물이 없어도 파이프라인이 성립한다"는 선언이다. 그
노드를 껐다고 하위를 막으면 optional과 required가 실행상 구분되지 않는다 — skip이 파이프라인을
끝내는 대신 **정지 지점을 한 칸 아래로 옮기기만** 한다. 그러면 `optional`을 선언한 의미가
사라지고, 실무에서는 "optional을 끄면 파이프라인이 멈춘다"는 이유로 아무도 끄지 않게 된다.

전파는 두 갈래다.

1. **하위가 `required`** → 그대로 `ready`가 된다. 입력이 덜 찬 채로 돈다는 사실은
   그 노드의 `bypassedDeps`에 빠진 상위 id를 적어 남긴다. 조용히 잃지 않는 것이 요점이다 —
   "왜 이 노드의 결과가 얕은가"를 나중에 이 필드로 설명할 수 있어야 한다.
2. **하위도 `optional`이고 의존이 전부 부재** → `bypassed`로 내린다. 소비할 입력이 하나도
   없는 optional 노드는 돌려봤자 빈 산출물이고, 그 빈 산출물이 다시 아래로 흘러가면
   "실행했는데 아무것도 없음"과 "안 했음"이 섞인다. 고정점까지 반복하므로 optional 사슬
   전체가 한 번에 정리된다.

의존이 **하나도 없는** optional 노드는 자동으로 bypass되지 않는다 — 부재를 물려받을 상위가
없으므로, 그 노드를 끌지 말지는 `skipCondition`이나 사람이 정한다.

**required 노드가 `failed`면 하위는 blocked다.** required는 "없으면 파이프라인이 성립하지
않는다"는 선언이므로, 그 자리가 비면 아래로 갈 수 없다. blocked는 상태가 아니라 **파생값**이다
(실패한 required 노드의 하위 전이 폐포). 상태로 저장하지 않는 이유는, 실패를 고쳐 재실행하면
차단이 저절로 풀려야 하는데 저장해 두면 일일이 되돌려야 하기 때문이다.

**optional 노드의 `failed`는 차단하지 않는다.** 하위가 받는 입력 관점에서 optional의 실패는
skip과 똑같이 "없음"이다. 실패 기록 자체는 지우지 않되(무슨 일이 있었는지는 남는다),
전파는 bypass와 같게 취급한다.

### 사이클

`dependsOn`에 순환이 있으면 **실행 전에 거부한다.** 부분 실행하고 막히는 쪽을 고르지 않는 이유는,
순환은 실행 중에 고칠 수 있는 상태가 아니라 정의의 오류이기 때문이다 — 중간까지 돌려 두면
그 부분 산출물을 어떻게 처리할지가 새 문제로 남는다. `detectCycles`는 순환에 **참여한** 노드만
돌려준다(순환의 하류는 피해자일 뿐 원인이 아니라, 고칠 자리를 가리켜야 한다).

### `run_id` / `revision`

- **`runId`** — 실행 회차. 같은 파이프라인을 다시 도는 일은 흔하다(리뷰에서 되돌아오거나,
  같은 그래프로 다음 이슈를 처리하거나). 회차 축이 없으면 두 번째 실행이 첫 번째의 기록을
  덮어써, "지난번엔 어디서 막혔나"가 사라진다.
- **`revision`** — 같은 `runId` 안에서 그래프 정의가 바뀐 횟수. 어댑터의 `pipeline`은 실행
  도중에도 바뀔 수 있다(노드를 하나 더 넣는 등). 상태 파일은 실행 시작 시점의 정의를
  `pipeline`에 스냅샷으로 품고, 정의가 바뀌면 `revision`을 올린다. 그래서 **이미 기록된
  노드 상태가 어떤 그래프를 기준으로 한 것인지**가 항상 확정된다 — 스냅샷이 없으면 나중에
  어댑터를 읽어 상태를 해석할 때, 그때의 그래프와 지금의 그래프가 다르다는 사실을 알 방법이 없다.

### v2 상태 파일 예시

```json
{
  "schemaVersion": 2,
  "runId": "run-1",
  "revision": 1,
  "pipeline": {
    "statePath": ".review-kit-state.json",
    "stages": [
      { "id": "work-start", "skill": "work-start", "type": "auto", "group": "준비", "dependsOn": [] },
      { "id": "requirements", "skill": "requirement-fanout", "type": "gate", "group": "설계",
        "dependsOn": ["work-start"], "activation": "optional", "skipCondition": "단일 이해관계자" },
      { "id": "spec", "skill": "spec", "type": "gate", "group": "설계", "dependsOn": ["work-start", "requirements"] }
    ]
  },
  "nodes": {
    "work-start":   { "state": "done", "completedAt": "2026-08-07" },
    "requirements": { "state": "skipped", "reason": "단일 이해관계자" },
    "spec":         { "state": "gate_wait", "bypassedDeps": ["requirements"] }
  },
  "history": [
    { "id": "work-start",   "state": "done",      "at": "2026-08-07" },
    { "id": "requirements", "state": "skipped",   "at": null },
    { "id": "spec",         "state": "gate_wait", "at": null }
  ]
}
```

`nodes`가 현재 상태의 SSOT이고 `history`는 append-only 이력이다. v1이 마지막 `gate_wait`
항목을 `done`으로 덮어썼던 예외 규칙은 v2에 없다 — 현재 상태는 `nodes`가 들고 있으므로
이력을 고칠 이유가 없다.

`node scripts/gen-status.js {statePath}`는 입력이 v2면 그래프 뷰(그룹 묶음 + 의존 관계 +
진행률)를, v1이면 기존 선형 뷰를 낸다.

---

## 요구사항 원장 (`requirementsLedger`, 기본 off)

`enabled: true`일 때만 `requirement-fanout` Step 4(상충 Gate) 완료 직후, 결정된 항목마다
`requirementsLedger.path`(기본 `.review-kit-requirements.jsonl`)에 한 줄씩 append:

```json
{"id":"R-{n}","topic":"...","decided_at":"<호스트 시계>","resolution":"A|B|혼합","from_personas":["planner","user"],"conflict":true}
```

- append-only — 기존 줄 수정 금지(과거 결정을 지우면 "왜 이렇게 안 했나"를 나중에 재구성할 수
  없다).
- 충돌 없이 자동 반영된 항목(요구사항 대부분)은 원장에 안 남긴다 — 원장은 **사람이 결정한
  지점만의 이력**이다. 전체 요구사항 목록은 `{paths.specFile}`이 이미 갖고 있다.
- 의도적으로 좁은 원장이다 — "fanout이 사람에게 넘긴 결정"만 남긴다. 새 주제 감지 시점부터 전체
  이력을 쌓는 광범위한 원장이 필요하면, 호스트가 여기 스키마를 자기 프로젝트 사정에 맞게 확장한다.
