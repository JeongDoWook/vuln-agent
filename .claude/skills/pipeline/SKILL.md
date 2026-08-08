---
name: pipeline
description: Use when the user wants to run the review-kit chain end to end instead of invoking each stage skill manually, or wants to resume after a gate. Drives whichever chain the adapter declares — verification-only (requirement-fanout → design-review → code-review) or the full lifecycle (work-start → spec → implement → self-qa → code-review → submit → finish) — reading `.review-kit.json`'s `pipeline.stages` and stopping only at declared gates and external waits.
---

# pipeline — 스테이지 체인 드라이버

> 이 스킬은 어떤 스테이지 스킬도 **대체하지 않는다** — 어댑터가 정의한 순서대로 이어 부르고,
> 게이트에서만 멈추는 오케스트레이터다. 각 스테이지의 실제 절차(관점 수, 병합 규칙, 점수식,
> 프로바이더 호출)는 여전히 해당 스킬의 SKILL.md가 SSOT다.
> 알고리즘 상세: `kit/workflow/pipeline-algorithm.md` — Codex 등 단일 세션 CLI는 이 스킬 대신
> `AGENTS.md`의 "스테이지 진행" 절을 그대로 따르면 동일한 결과를 낸다(도구만 다르고
> 알고리즘은 하나).

---

## Step 1 — 어댑터에서 스테이지 목록 읽기

```bash
cat .review-kit.json | grep -A 40 '"pipeline"'
ls .pipeline.json                      # 있으면 라이프사이클 스킬을 쓸 수 있는 설치다
```

`pipeline.stages`가 있으면 **그것이 SSOT**다. 없으면 설치 범위에 따라 두 프리셋 중 하나를 쓴다
(상세와 각 타입의 근거: `pipeline-algorithm.md` "스테이지 체인 두 프리셋"):

| 설치 범위 | 기본 체인 |
|---|---|
| `.pipeline.json` **없음** (검증 전용) | `requirements`(optional, gate) → `design`(gate) → `code-review`(gate) |
| `.pipeline.json` **있음** (라이프사이클) | `work-start`(auto) → `requirements`(optional, gate) → `spec`(gate) → `implement`(auto) → `self-qa`(gate) → `sync`(auto) → `code-review`(gate, cutlineGate) → `submit`(gate) → `merge`(external, **wait**) → `finish`(auto) |

**주의 — `design-review`를 라이프사이클 체인에 스테이지로 넣지 마라.** `spec` 스킬이 내부에서
호출한다. 스테이지로도 두면 3관점 분석이 두 번 돈다. `release`·`dev-env`도 이 체인에 없다
(전자는 이슈가 아니라 릴리스 주기, 후자는 스테이지가 아닌 유틸).

`.pipeline.json`이 있는 설치라면 첫 스테이지 진입 전에 한 번 확인한다 — 프로바이더가
깨져 있으면 `work-start`부터 실패한다:

```bash
node scripts/px.js doctor
```

`pipeline.statePath`(기본 `.review-kit-state.json`)를 읽어 현재 위치(`state.current`)를 확인한다.
파일이 없으면 `{current: 0, history: []}`로 새로 시작.

---

## Step 2 — 스테이지 순회

`state.current`부터 스테이지를 하나씩 처리한다. 각 스테이지 진입 시 한 문장으로 알린다
("→ {stage.id} 진입"). 상세 분기 규칙은 `pipeline-algorithm.md` "실행 루프" 절 그대로:

| stage.type | 동작 |
|---|---|
| `external` (`wait` 없음/false) | 실행하지 않는다. "→ {stage.id}는 호스트 프로젝트 스테이지 — review-kit 미실행. 완료 후 계속 진행하세요." 한 줄 안내 → `external_skipped` 기록 + `state.current` 증가 + Write → 다음 스테이지로 즉시 진행(재입력 불필요) |
| `external` (`wait: true`) | 실행할 것이 없다. `stage.note`로 **무엇을 기다리는지** 알린 뒤 `{id, status:"external_wait"}` append + 즉시 Write, **여기서 정지.** 사용자가 완료를 알리면 그 항목을 `{id, status:"external_done", at}`으로 갱신하고 `state.current` 증가 + Write |
| `gate` (optional=true 이고 skipCondition 충족) | 한 줄 안내 → `{id, status:"skipped", reason}` append + `state.current` 증가 + Write → 다음 스테이지로 즉시 진행 |
| `gate` (실행 대상) | 해당 `stage.skill`을 Skill tool로 호출(예: `Skill({skill:"spec"})`) → 완료 후 `state.history`에 `{id, status:"gate_wait"}`을 append하고 즉시 Write, **여기서 정지**, 사용자 승인/결정 대기. 승인을 받은 뒤에만 그 항목을 `{id, status:"done", gate_approved_at}`으로 갱신하고 `state.current`를 증가시킨다 — 승인 전 다음 스테이지로 넘어가지 않는다 |
| `auto` | 해당 스킬 호출 → `state.current` 증가 + `{id, status:"done", at}` append → 완료되면 사용자 재입력 없이 바로 다음 스테이지로 진행 |

**정지하는 두 타입(`gate`·`external wait`)만 Write를 두 번 한다** — 정지 **전**(`*_wait`)과
사용자 응답 **후**(`done`/`external_done`). 대기 중 세션이 끊겨도 재개한 세션이 "실행은 됐지만
아직 승인/완료 신호를 못 받음"을 상태 파일만으로 구분할 수 있게 하기 위해서다
(`state.current`를 먼저 올려버리면 재개 시 미승인 게이트를 완료로 착각하고 건너뛴다).
나머지 타입은 정지가 없으므로 한 번만 Write하되, **`state.current`는 반드시 함께 올린다** —
빠뜨리면 재개한 세션이 같은 스테이지를 무한히 다시 가리킨다.

`auto` 스테이지가 실패하면(예: `implement` 중 빌드 실패, `sync` 중 충돌) **다음 스테이지로
넘어가지 않는다.** `state.current`를 올리지 말고 그 자리에 멈춰 사용자에게 보고한다 —
`auto`는 "성공하면 안 멈춘다"는 뜻이지 "실패해도 지나간다"는 뜻이 아니다. 프로바이더 계약의
`exit 2`(계약/게이트 위반)도 같다.

`code-review` 스테이지에서 `cutlineGate: true`이면, 점수 등급이 CAUTION/BLOCKED일 때 게이트
통과 자체를 보류하고 사용자에게 수정/감수/재시도 여부를 먼저 묻는다 — PASS일 때만 다음
스테이지로 넘어가는 걸 사용자가 즉시 승인할 수 있다.

---

## Step 2b — 그래프 체인일 때 (`dependsOn`이 하나라도 있으면)

어댑터의 `pipeline.stages` 중 **한 노드라도 `dependsOn`을 선언했으면** 위의 `state.current` 순회
대신 그래프 루프를 쓴다. 판정은 이 한 줄뿐이다 — 섞어 해석하지 않는 이유는
`pipeline-algorithm.md` 「그래프 실행 모델 (v2)」 §노드에 있다.

루프는 `state.current` 대신 **지금 돌릴 수 있는 노드 목록**으로 돈다:

```bash
node -e "
const g = require('./scripts/lib/pipeline/graph');
const fs = require('fs');
const adapter = JSON.parse(fs.readFileSync('.review-kit.json','utf8'));
const graph = g.normalize(adapter.pipeline);
const cycles = g.detectCycles(graph);
if (cycles.length) { console.error('사이클: ' + cycles.join(' · ')); process.exit(2); }
const statePath = adapter.pipeline.statePath || '.review-kit-state.json';
const state = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath,'utf8')) : g.createState(graph);
console.log(JSON.stringify({ ready: g.readyNodes(graph, state).map(n => n.id), summary: g.summarize(graph, state) }));
"
```

- **사이클이 있으면 아무것도 실행하지 않고 멈춘다.** 실행 중에 고칠 수 있는 상태가 아니라
  어댑터 정의의 오류다.
- `ready`가 **둘 이상이면 그 노드들은 서로 독립**이다. `auto` 노드끼리는 동시에 착수해도 되고,
  `gate`가 섞여 있으면 gate는 각자 자기 승인을 기다린다 — 한 gate의 대기가 다른 가지를 멈추지 않는다.
- 각 노드의 처리(`auto`/`gate`/`external`의 정지 규칙)는 **Step 2 표와 동일하다.** 달라지는 것은
  "다음이 무엇인가"를 정하는 방식뿐이다.
- 노드 하나를 처리한 뒤 상태를 `advance(state, nodeId, result)`로 갱신하고 파일에 쓴다.
  `advance`는 입력 상태를 변형하지 않고 새 상태를 돌려준다 — 반환값을 써야 한다.
- **optional 노드를 skip한 자리에서 멈추지 않는다.** 그 노드에만 의존하던 하위는 차단되지 않고
  `ready`가 되며, 입력이 덜 찼다는 사실은 `bypassedDeps`에 남는다. 이 전파를 사람이 흉내내지
  말고 `propagateBypass`가 준 결과를 그대로 쓴다.
- **required 노드가 `failed`면 그 하위는 blocked다.** `blockedNodes(graph, state)`가 목록을 주며,
  이건 저장하는 상태가 아니라 파생값이다 — 실패를 고쳐 다시 돌리면 저절로 풀린다.

정지 조건은 v1과 같다: `ready`가 비었는데 정착하지 않은 노드가 남아 있으면 **무엇이 막고 있는지**
(대기 중인 gate·external, 또는 failed된 required)를 보고하고 멈춘다.

---

## Step 3 — 재개(resume)

이미 이 스킬을 돌리다가 게이트에서 멈춘 상태로 세션이 끊겼다면, 다시 `/pipeline`을 호출했을 때
`state.current`가 가리키는 스테이지부터 이어간다 — 이전에 `done`으로 기록된 스테이지는 다시
실행하지 않는다(멱등). 마지막 history 항목이 `gate_wait`이면 그 스테이지는 **이미 실행 완료,
승인만 미수신** 상태다 — `stage.skill`을 재실행하지 말고 곧바로 승인 요청만 다시 보여준다.
`external_wait`이면 애초에 실행할 것이 없으므로 **무엇을 기다리는지만** 다시 보여준다.

라이프사이클 체인은 재개 지점이 세션 밖에도 있다 — 작업공간이 이미 있는데 `work-start`부터
다시 도는 일이 없도록, 상태 파일이 없더라도 `node scripts/px.js ws resolve`로 현재 디렉터리가
이미 어느 작업공간인지 먼저 확인한다. 이미 있으면 사용자에게 어느 스테이지부터 이어갈지 묻고
`state.current`를 그 지점으로 맞춘 뒤 시작한다.

---

## Step 4 — 상태 시각화(선택)

```bash
node scripts/gen-status.js {pipeline.statePath}
```

`.review-kit-state.json`을 자기완결적 HTML로 렌더링(SSOT: `scripts/assets/report.css`). 매
스테이지마다 자동으로 열지 않는다 — 사용자가 요청하거나 게이트 시점에만 안내.

---

## 어댑터가 채워야 하는 값

| 키 | 의미 | 기본값 |
|---|---|---|
| `pipeline.stages` | `[{id, skill, type, optional?, skipCondition?, cutlineGate?, wait?, note?}, ...]` | 설치 범위에 따른 프리셋 (Step 1 표) |
| `pipeline.statePath` | 상태 파일 경로 | `.review-kit-state.json` |

`wait`는 `type: external`에서만 의미가 있다(기본 `false`).

## Reference

- `kit/workflow/pipeline-algorithm.md` — 스테이지 타입 의미, 두 프리셋과 각 타입의 근거, 실행 루프, 상태 파일 스키마, 요구사항 원장 스키마
- `kit/contract/provider-contract.md` — 라이프사이클 스테이지가 외부로 나가는 유일한 문 (`px`)
- `kit/workflow/guardrails.md` — 역할 분리·사전확인·종결조건 + §5 스테이지별 검증 강도 하한
- `kit/skills/*/SKILL.md` — 각 스테이지 실제 절차
