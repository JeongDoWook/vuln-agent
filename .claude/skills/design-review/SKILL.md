---
name: design-review
description: Use before implementation starts, once a spec/requirements draft exists. Runs a 3-perspective design analysis (Pragmatist / Regression Analyst / QA) — optionally a Devil's-Advocate team debate — surfaces failure modes before they become code, then gates on user approval.
---

# design-review — 설계 확정 전 3관점 분석 + Gate

> **전제**: 설계 단계는 모든 버그를 잡을 수 없다. 목표는 완벽함이 아니라, 구현 후 발견하면 비싼 실수를
> **구현 전에 값싸게** 표면화하는 것.
> **읽기 전용 원칙**: 이 스킬이 dispatch하는 에이전트는 프로덕션 코드를 고치지 않는다. 설계 단계에서
> 코드를 고치는 검증자는 검증자가 아니라 두 번째 저자다.

이 스킬은 어댑터(`.review-kit.json`)의 `paths.specFile` / `paths.planFile` / `paths.codeContextFile`을
읽어 아래 절차를 수행한다. 어댑터가 없으면 프로젝트 루트의 스펙/요구사항 문서를 사용자에게 물어 확정한다.

---

## Step 1 — 입력 확인

```bash
cat {paths.specFile} 2>/dev/null | head -20   # 없으면 요구사항 원문(이슈/티켓)을 직접 Read
```

- Spec 초안이 있으면 그대로 분석 대상으로 삼는다.
- 없으면 요구사항 원문을 근거로 이 스킬 안에서 초안을 새로 쓴다(Step 3 참고).

---

## Step 2 — 경로 선택: 단일 패스 vs 팀 토론

작은 변경(파일 3개 이하, 신규 API/DB 변경 없음)은 **단일 패스**로 충분하다. 아래 조건 중 하나라도
해당하면 **팀 토론**(Devil's Advocate 발산)을 권장한다:

- 되돌리기 어려운 인프라 선택(이벤트 소싱, SSE/WebSocket, 분산 락, 동기↔비동기 전환, 서비스 간 트랜잭션 경계)
- 변경 파일 10개 이상 또는 새 아키텍처 도입
- 기존 계약(API/DB 스키마)을 깨는 변경

### 단일 패스 (기본)

한 번의 구조화된 프롬프트로 3관점을 동시에 얻는다:

```
Requirements:
{spec 핵심 내용}

Code context:
{code_path 전체 내용 또는 관련 파일 요약}

Analyze concisely from the 3 perspectives below (2–4 bullets per perspective):

**Pragmatist** — Fastest and safest implementation direction
**Regression Analyst** — Risk of regression in existing code
**QA** — Cases that must be verified (core scenarios + boundary values)

Immediately after analysis, fill in and write the spec draft.
```

### 팀 토론 — `design-devil-advocate` / `design-regression-analyst` / `design-runtime-trap`

3개 에이전트를 **단일 메시지에서 동시에 background dispatch**한다(P2P 흐름):

```
[Round 1 — 동시]
  design-devil-advocate   ──findings──▶  design-regression-analyst
  design-runtime-trap     (독립 분석 시작)

[Round 2 — P2P]
  design-regression-analyst  ──rebuttal────▶  design-devil-advocate
  design-regression-analyst  ──risks────────▶  design-runtime-trap

[Round 3 — 호출자 수집]
  design-devil-advocate      ──final──▶  caller
  design-regression-analyst  ──final──▶  caller
  design-runtime-trap        ──final──▶  caller
```

세 에이전트 모두 완료(`"DONE: *"` 수신) 후 각 sentinel 사이 YAML을 파싱한다. `status: open`으로 남은
항목은 Gate 요약에 "미합의 쟁점"으로 별도 노출한다.

> 에이전트 spawn 실패 또는 타임아웃(~5분) 시 **조용히 단일 패스로 폴백**한다 — 이 단계가 회귀를
> 만들면 안 된다.

---

## Step 3 — 분석 결과를 스펙에 반영

분석에서 나온 `spec_updates`(field/action/value)를 스펙 문서에 반영한다. 없으면 스펙 초안을 그대로 확정한다.

---

## Step 4 — Plan 수립

- 구현 순서와 단계별 체크리스트를 작성한다
- TDD 적용 대상을 명시한다
- 예상 공수와 리스크 항목을 기록한다

`{paths.planFile}`에 저장한다.

---

## Step 5 — 보고 + Gate

분석 결과(3관점 + 미합의 쟁점 + 리스크)를 사람이 읽을 수 있는 요약(HTML 또는 텍스트)으로 만들어
승인을 요청한다:

```
분석 완료 — {핵심 리스크 1~2줄}
[미합의 쟁점: N건 — 있을 때만 노출]

검토 후 승인하면 구현을 시작합니다.
```

**사용자 승인 전에는 구현 단계로 자동 진행하지 않는다.**

---

## 어댑터가 채워야 하는 값

| 키 | 의미 |
|---|---|
| `paths.specFile` / `paths.planFile` / `paths.codeContextFile` | 산출물 경로 템플릿 |
| `runtimeTrapTaxonomy` | `design-runtime-trap`이 스캔할 함정 패턴 (스택별로 교체) |

## Reference

- `kit/workflow/design-review-algorithm.md` — 팀 토론 P2P 프로토콜 상세
- `kit/workflow/guardrails.md` — 결함 클래스를 구현 전에 한 번에 설계하는 원칙(위 팀 토론 트리거 조건의 근거)
- `.claude/agents/design-devil-advocate.md` / `design-regression-analyst.md` / `design-runtime-trap.md`
