---
name: self-qa
description: Use after implementation is done and before code-review — the implementer verifies their own work against the acceptance criteria (static checks → AC verification → scoped tests → QA artifact), then stops at a gate.
---

# self-qa — 구현자 자기 검증

> **code-review를 대체하지 않는다.** 여기서 하는 건 *구현자가 자기 작업을 AC 기준으로 점검*하는
> 일이다. 적대적 5관점 리뷰는 그 다음 단계(`code-review`)가 담당한다. 두 단계를 합치면
> 저자 = 검증자가 되어 `kit/workflow/guardrails.md` §1이 깨진다.

---

## Step 1 — 진입 확인

```bash
node scripts/px.js ws resolve --json      # slug · repos · branch · stage
node scripts/px.js ws stage {slug} QA
git log @{u}..HEAD --oneline              # 구현 커밋이 원격에 반영됐는지
```

- `ws resolve`가 실패하면(작업 공간 밖) 위치를 안내하고 중단한다.
- upstream이 없으면 "구현 단계의 1차 push가 끝났는지" 사용자에게 확인받고 진행한다.
- AC의 출처는 `{paths.specFile}`(구현 단계가 만든 스펙)이다. 없으면 사용자에게 AC 목록을 받는다.

---

## Step 2 — 정적 검증 (테스트 실행 전)

```bash
node scripts/px.js run lint  --json
node scripts/px.js run build --json
```

- `exit 3`(스택에 해당 명령 정의 없음) → 그 항목만 `skip`으로 기록하고 계속한다.
- `exit 1`(실패) → **여기서 고친다.** 정적 오류를 남긴 채 AC 검증으로 넘어가지 않는다.
- 고친 내용은 요약 한 줄씩 모아 뒤의 `static_check.errors_fixed`에 넣는다.

---

## Step 3~4 — 실행 경로 분기

Workflow tool 을 쓸 수 있으면 `kit/workflows/test-matrix.js` 로 검증 매트릭스를 먼저 설계한다 —
카테고리별 케이스 설계와 **AC 미커버 판정을 스크립트가 직접** 수행한다(에이전트의 "다 덮었습니다"를
믿지 않는다). `acIds` 에 스펙의 AC id 목록을 넘겨야 그 판정이 동작한다. 반환값의 `uncoveredAc` 가
비어 있지 않으면 **다음 단계를 권하지 않는다.** 케이스 실행과 수정은 여전히 아래 절차가 한다.

없으면 아래 산문 절차를 그대로 수행한다 — 결과는 같고 강제가 없을 뿐이다.

---

## Step 3 — AC 검증

스펙의 `acceptance_criteria` 항목마다 **코드 근거**(파일:라인)를 붙여 pass/fail을 판정한다.
"구현했으니 통과"는 근거가 아니다 — 해당 AC를 만족시키는 코드 경로를 실제로 지목해야 한다.

fail 항목은 원인을 적고 즉시 수정한다. 수정 후 Step 2를 다시 돌린다.
검증 중 발견한 경계 조건은 `edge_cases`에 모은다(AC에 없던 것이라도 기록한다).

> `{codingGuard.acEvidenceRequired}`가 true인 어댑터에서는 근거 없는 pass를 fail로 취급한다.

---

## Step 4 — 스코프 한정 테스트

AC 검증이 끝난 뒤 **한 번만** 돌린다. 변경 모듈에 한정하되, 공유 라이브러리·공통 설정이
변경분에 포함됐으면 전체를 돌린다.

```bash
node scripts/px.js run test --filter {tests.scopeFilter} --json   # 스코프 한정
node scripts/px.js run test --json                                # 공유 코드 변경 시
```

`exitCode != 0`이면 실패 테스트를 고치고 재실행한다. **테스트 실패 상태로 이 스킬을 끝내지 않는다** —
`submit`이 이 결과를 진입 게이트로 읽는다.

---

## Step 5 — QA 산출물

결과를 `{paths.qaOutDir}/qa.json`으로 조립한다(Write 도구).

```json
{
  "title": "{ISSUE_REF} QA Result",
  "date": "{YYYY-MM-DD HH:MM}",
  "repo": "{repo}", "branch": "{branch}", "sha": "{short_sha}",
  "static_check": {
    "typecheck": "pass|fail|skip",
    "lint": "pass|fail|skip",
    "test": "pass|fail|skip",
    "errors_fixed": ["..."]
  },
  "review": { "score": null, "grade": null, "report_path": null },
  "ac": {
    "pass": 0, "total": 0,
    "failures": [ { "id": "AC-N", "desc": "...", "note": "실패 원인" } ]
  },
  "edge_cases": ["..."],
  "commit": { "hash": "...", "message": "..." }
}
```

`review` 블록은 아직 비워 둔다 — `code-review`가 채운다. 자기 점검 결과를 리뷰 점수로 위장하지 않는다.

```bash
node scripts/gen-qa.js {paths.qaOutDir}/qa.json   # (선택) 생성기가 있을 때만
```

`scripts/gen-qa.js`가 없는 설치본에서는 **HTML 렌더를 생략하고 `qa.json`만 남긴다** — 이 스킬은
JSON을 SSOT로 삼으며, HTML은 사람이 읽기 위한 부가 산출물이다.

---

## Step 6 — 게이트 정지

```
✅ self-qa 완료
   정적: typecheck {r} / lint {r} / test {r}
   AC  : {pass}/{total}  (실패 {n}건)
   엣지: {n}건 기록
   산출: {paths.qaOutDir}/qa.json

다음: /code-review — 5관점 적대적 리뷰. 여기서 멈춥니다.
```

AC 실패가 1건이라도 남아 있으면 **다음 단계를 권하지 않고** 실패 목록과 함께 정지한다.

---

## 어댑터가 채워야 하는 값

| 키 | 의미 |
|---|---|
| `paths.specFile` | AC 원본(구현 단계 산출 스펙) 경로 |
| `paths.qaOutDir` | `qa.json` / QA HTML 저장 경로 |
| `tests.scopeFilter` | `run test --filter`에 넘길 스코프 표현식 (없으면 전체 실행) |
| `codingGuard.acEvidenceRequired` | AC pass에 코드 근거를 강제할지 |

## Reference

- `kit/contract/provider-contract.md` §2.4 `ws` · §2.6 `run` — 여기서 쓰는 유일한 외부 접점
- `kit/workflow/guardrails.md` §1(역할 분리) · §2(부수효과 명령 전 상태 확인)
- `kit/skills/code-review/SKILL.md` — 이 스킬 다음 단계
- `scripts/gen-qa.js` — QA 결과 HTML 생성기 (선택)
