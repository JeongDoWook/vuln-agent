# code-review — Algorithm Detail

> `kit/skills/code-review/SKILL.md`의 Step 3~5를 구현하는 상세 알고리즘. `{...}` 표기는
> `.review-kit.json` 어댑터 값이다.

---

## Critic 판정 기준

```
auto_fix   — ALL 충족:
  solution_code 존재하고 완전함 / 단일 파일 변경만으로 완결 /
  로직 변경 없음(naming, null guard, annotation, constant, comment) / 아키텍처·도메인 판단 불필요

human_review — ANY 해당:
  solution_code 없거나 불완전 / 멀티 파일 변경 필요 / 로직 의미 변경 수반 / 설계·도메인 지식 필요

dropped — ALL 충족 (강화된 기준):
  해당 파일·라인을 직접 Read해 반증 근거를 확인한 경우만 허용
  "이미 방어됨" 또는 "패턴이 실제로 존재하지 않음"을 코드 증거로 명시
  단순 "해당 없어 보임" 판단만으로는 dropped 불가 → human_review로 처리
```

---

## Phase 1 — Critical Loop (human_review Critical만)

`{criticalLoop.maxIterations}`회까지:

```
iteration = 0
while Critical > 0:
  iteration += 1
  fix all Critical items at once (executor agent, priority order regardless of perspective)
  after_each: [run project test command] → commit "fix: {title} (review-it{N})"

  # Critical이 있었던 관점만 선별 재호출 (전체 diff 재전송 안 함, 수정 파일만)
  re-invoke relevant perspective agents only

  # decision_memo 필터 (Phase 2 참고) — 기존 항목은 재확인 없이 자동 적용
  new_items = re-review 결과 중 decision_memo에 없는 것
  new_items > 0 → HTML 갱신 → 사용자 결정 대기
  new_items = 0 → 자동 적용만

  if iteration >= {criticalLoop.maxIterations} and Critical > 0:
    센티넬 파일 생성(`{reviewOutDir}/.review-critical-unresolved`)
    ⛔ 중단 — 잔여 Critical 목록 출력, 수동 개입 대기
```

Critical = 0 달성 시 센티넬 제거 → Phase 2.

**Team 경로**(선택, `{criticalLoop.agentTeamsEnvFlag}=1`인 환경): fixer/reviewer 2 워커가 상주하며
task 단위로 핑퐁 — 매 iteration마다 새로 spawn하는 대신 맥락을 보존해 "같은 실수 반복"을 줄인다.
팀 도구 실패 시 현재까지의 수정/커밋 내역을 보존한 채 spawn-each-iteration 경로로 폴백.

---

## Phase 2 — Warning 처리

### 심각도 평가

| 기준 | High | Medium | Low |
|---|---|---|---|
| 런타임 영향 | 실제 실패 유발 가능 | 특정 케이스에서 오동작 | 동작에 영향 없음 |
| 영향 범위 | 다중 모듈/공개 API | 단일 모듈 | 지역 변수/내부 함수 |
| 향후 수정 난이도 | 스키마/인터페이스 변경 필요 | 리팩터링 필요 | 단순 개선 |

### decision_memo — 결정 영속화

```
decision_memo: Map<fingerprint, { decision, comment, impact }>
  fingerprint = "{loc}|{title}"
  decision    = "do" | "defer" | "skip" | "accept"
```

재리뷰 결과 중 `fingerprint`가 이미 memo에 있으면 재확인 없이 자동 적용(감점 계산에 반영).
없으면 새 항목 — HTML에 추가해 사용자 결정을 받는다.

### 처리 흐름

```
for each warning_item:
  impact = auto_assess(warning_item)
  Low    → 자동 accept (사유 자동 생성: "영향 범위 국소적, 런타임 영향 없음, 추후 개선 예정")
  Medium → 사용자 선택: [Fix] [PR 코멘트로 등록] [Accept + 사유]
  High   → Fix 권장. 거부 시 사유 필수 → accept 처리 + 감사 로그 기록
```

**Accept은 의도적 결정이지 묵인이 아니다.** 근거 없는 accept는 허용하지 않는다.

---

## Phase 3 — 점수 계산

시작 점수: **100** (Critical = 0일 때만 계산 가능).

```
REPO_TYPE 판정: {tracks.detect}  (예: basename(repoRoot)에 'fe' 포함 → FE, 'be' 포함 → BE)
```

감점표는 어댑터 `tracks.{TRACK}.deductions`에서 가져온다. BE 트랙처럼 관점별 가중치
(`weightSecurityRegression`)가 있으면 Security/Regression Warning에 곱해 적용한다.

```
score = 100 - Σ(deductions)
grade = score >= tracks.{TRACK}.cutlinePass    → PASS
      : score >= tracks.{TRACK}.cutlineCaution → CAUTION
      : else                                    → BLOCKED
```

### 계산은 반드시 스크립트로 검산한다 (필수)

`report.json`의 `warning_results[]`를 채운 뒤 **점수를 손으로 적지 말고** 아래를 실행한다:

```bash
node scripts/gen-score.js {reviewOutDir}/report.json --write
```

어댑터의 감점표를 직접 곱해 `score`/`grade`/`cutline`/`deductions`를 채워 넣는다. 이미 점수가
적혀 있는 상태에서 `--write` 없이 실행하면 **검산 모드**로 동작하고, 적힌 값과 계산값이 다르면
`exit 2`로 실패한다 — 파이프라인에서 게이트로 쓸 수 있는 유일한 기계적 신호다.

이 단계를 건너뛰면 감점표가 아무리 세밀해도 곱셈을 LLM이 하게 되어 **같은 리뷰를 두 번 돌렸을 때
다른 점수가 나온다.** 등급이 컷라인 근처일수록 그 차이가 통과/차단을 가른다.

감점표 키 해석 규칙(스크립트와 동일):

```
1) warning{Impact}{SecReg|Quality}   예: warningHighSecReg   — 관점을 나눈 표(BE 트랙 형태)
2) warning{Impact}                    예: warningHigh         — 뭉뚱그린 표(FE 트랙 형태)
   Impact = High|Medium|Low, SecReg = perspective ∈ {Security, Regression}
   result 키는 fix / mr_comment(=mrComment) / accept
   weightSecurityRegression 은 SecReg 전용 행이 없을 때만 곱한다(있으면 이중 적용)
```

### 자동 재시도 (컷라인 미달, 최대 `{scoreRetry.maxIterations}`회)

```
while score < cutlinePass:
  fixable High/Medium Warning → executor fix
  Warning이 남은 관점만 선별 재호출
  decision_memo 필터 적용 → 신규 항목만 HTML
  재계산

  if 시도 횟수 초과:
    score_unresolved 기록 + 부분 진행 상태 저장(`{reviewOutDir}/.review-score-unresolved`)
    ⛔ 중단 — 상위 감점 항목 안내, 수동 개선 후 재실행 요청
```

---

## 산출물 스키마

### review.json (Step 2 산출)

```json
{
  "title": "...", "date": "...", "context": "{branch} | {commit}",
  "items": [
    { "id": "1", "severity": "critical|warning", "perspective": "Quality|Security|Regression|CodeAudit|RuntimeTrap",
      "impact": "High|Medium|Low", "title": "...", "subtitle": "...", "file": "...", "line": 0,
      "problem": "...", "current_code": "...", "solution": "...", "solution_code": "...", "auto_fixable": false }
  ]
}
```

### report.json (완료 시 산출)

```json
{
  "title": "...", "date": "...", "context": "...", "repo_type": "{TRACK}",
  "score": 0, "grade": "PASS|CAUTION|BLOCKED", "cutline": 0,
  "score_adjusted": null, "adjustment_note": null,
  "summary": { "critical_fixed": 0, "critical_open": 0, "warning_fixed": 0, "warning_mr": 0, "warning_accepted": 0, "info": 0, "iterations": 0 },
  "deductions": [ { "perspective": "...", "result": "fix|mr_comment|accept", "count": 0, "points": 0 } ],
  "critical_history": [ { "iteration": 0, "perspective": "...", "loc": "file:line", "summary": "..." } ],
  "warning_results": [ { "result": "fix|mr_comment|accept", "perspective": "...", "loc": "file:line", "title": "...", "impact": "High|Medium|Low", "reason": "...", "plan": "..." } ],
  "fix_commits": [ { "hash": "...", "message": "..." } ]
}
```

`scripts/gen-review.js` / `scripts/gen-report.js`로 각각 HTML 렌더.

> **`score`·`grade`·`cutline`·`deductions`는 손으로 적지 않는다.** 위 스키마를 보고 값을 채우는
> 순간 점수가 LLM 계산이 되어 재현성이 깨진다. `node scripts/gen-score.js <report.json> --write`가
> 어댑터 감점표를 곱해 채우고, `--write` 없이 부르면 이미 적힌 값을 검산해 어긋나면 `exit 2`다.
> `summary.critical_open > 0`이어도 `exit 2` — Critical이 열려 있으면 점수 자체가 무효다.

**선택 필드**

- `score_adjusted` / `adjustment_note` — 리뷰 전에 이미 합의된 항목(사전합의 accepted-risk)을 감점에서
  제외한 조정 점수. 쓰지 않으면 둘 다 `null`로 두면 되고, 그때 리포트는 `score`를 그대로 표시한다.
  값을 넣으면 리포트에 `{score}점 → {score_adjusted}점`과 사유가 함께 노출된다.
  **`gen-score.js`는 `score`만 계산한다** — 조정은 사람이 근거를 적어 넣는 자리라 자동화하지 않는다.
- `summary.critical_open` — 잔여 Critical 수. `0`이 아니면 점수 자체가 무효이며,
  `gen-score.js`가 경고를 출력한다(Phase 3은 Critical = 0일 때만 유효하다).
