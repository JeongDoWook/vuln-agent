---
name: wt-spec
description: Use when the user types "/wt-spec". 활성 worktree 에서 설계 단계(Step 2~3)를 수행한다 — spec 확정, 3관점 분석(pragmatist·regression·qa), (Normal/Complex 시)해결옵션 발산, Plan 수립, analysis.html 리포트, 🔴 Gate 1. vuln-agent 전용.
---

# wt-spec — 설계 단계 (Step 2~3)

활성 worktree 에서 spec 을 확정하고, **3관점 분석**으로 함정을 선제 표면화한 뒤, Plan 을 세우고
분석 리포트(analysis.html)를 열어 **Gate 1** 승인을 받는다.

> claude-pipeline 의 FE/BE lead 분리는 vuln-agent(단일 레포)에선 하나의 도메인 관점으로 통합.

---

## 진입 즉시

```bash
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
ACTIVE=$(cat "$MAIN/wt/.active" 2>/dev/null)
WT_DIR="$MAIN/wt/$ACTIVE"; SLUG="${ACTIVE#*-}"; PIPE="$WT_DIR/.pipe/$SLUG"
[ -f "$PIPE/spec.yaml" ] || { echo "❌ spec.yaml 없음 — /wt-setup 먼저"; exit 1; }
COMPLEXITY=$(grep -m1 '^complexity:' "$PIPE/spec.yaml" | awk '{print $2}' | tr -d '"')
echo "complexity: $COMPLEXITY / worktree: $WT_DIR"
[ "$COMPLEXITY" = "trivial" ] && echo "⚡ Nano — wt-spec 생략 대상. /wt-impl 로 바로 가세요."
```

---

## Step 2-0: spec.yaml 확정 + affected_files 채우기

`$PIPE/spec.yaml` 을 Read. `affected_files` 가 비어 있으면 worktree 코드(`$WT_DIR/server`, `agent`, `matcher-ai`, `db`, `config`)를 직접 읽어 관련 파일·함수·PDO 쿼리를 특정해 채운다.

---

## Step 2-A0: 해결 옵션 발산 (Normal·Complex 한정) — 수렴 전 1회

> **목적**: 곧장 "어떻게 구현"으로 수렴하기 전에 방향 2~3개를 **단기 vs 장기**로 펼쳐 사용자가 선택하게 한다.
> **Simple/Trivial 이면 이 단계 전체 skip.**

```
Agent(
  subagent_type: "oh-my-claudecode:architect",   # 없으면 Explore
  model: "opus",
  description: "해결 옵션 발산",
  prompt: """
cwd: {WT_DIR}
spec: .pipe/{slug}/spec.yaml
이 변경을 구현하는 서로 다른 방향 2~3개를 도출하라(최소패치 ~ 정석구조화 ~ 확장대비).
각 옵션을 단기 vs 장기로 강제 평가해 YAML 반환:

options:
  - id: A
    name: 방향 이름
    approach: 한 줄 구현 방향
    horizon: short|balanced|long
    cost_now: low|medium|high
    cost_to_change_later: low|medium|high
    forecloses: 이 선택이 막는 것 (없으면 생략)
    reversibility: easy|medium|hard
    recommend_when: 이 옵션이 맞는 조건
recommendation: 기본 추천 id + 한 줄 이유
"""
)
```

결과를 사용자에게 제시(**Gate 0.5**): "방향을 선택해주세요 — id 또는 혼합/수정". 선택된 방향을 spec.yaml 에 *확정 구현 방향*으로 주입. conversation.jsonl 에 `{"event":"solution_direction_chosen","content":"<id> — <한 줄>"}`.
실패 시 조용히 skip 후 Step 2-A 진행.

---

## Step 2-A: 3관점 분석 (pragmatist · regression · qa)

> 설계 단계는 모든 버그를 못 잡는다 — Devil's Advocate + Runtime Trap 으로 런타임 함정을 선제 표면화.

모델 라우팅: `simple→haiku`, `normal→sonnet`, `complex→opus`.

```
Agent(
  subagent_type: "Explore",   또는 general-purpose
  model: "{라우팅}",
  description: "spec 3관점 분석",
  prompt: """
cwd: {WT_DIR}
spec: .pipe/{slug}/spec.yaml
affected_files 의 실제 코드를 Read 한 뒤 3관점 분석. 결과 YAML 반환:

pragmatist:                       # Devil's Advocate — "문제없음" 금지
  direction: 이 구현 방향이 실패할 가능성이 높은 주된 이유 한 줄 (필수)
  simplify:
    - 설계의 잠재 결함/숨은 복잡도 (파일·근거 포함, 최소 2개)
regression:
  risks:
    - affected: 영향받는 기존 기능/파일 (커넥터·웹·CLI·DB)
      severity: low|medium|high
      note: 한 줄
qa:
  runtime_traps:                  # vuln-agent(PHP) 함정 패턴
    - type: SQLi|PDO-unprepared|XSS-unescaped|header-injection|path-traversal|secret-leak|N+1-query|missing-tx|encoding-cp949|null-deref|type-juggling|기타
      location: 파일 또는 패턴
      note: 한 줄
  ac_gaps:
    - AC-N: 검증 불가/보완 필요 (없으면 생략)
  edge_cases:
    - 경계값/예외 케이스 (2개 이내)
spec_updates:
  - field: spec.yaml 변경 필드
    action: add|modify|remove
    value: 변경 내용 한 줄
"""
)
```

> **Complex 이면(옵션)** 3개 named 에이전트(devil-advocate ↔ regression ↔ runtime-trap)로 P2P 상호반박 후 합의 — 토큰 비용 큼, 명시 요청 시만.

`spec_updates` 를 spec.yaml 에 반영. 비어 있으면 그대로 확정.

---

## Step 3: Plan 수립 → plan.yaml

`$PIPE/plan.yaml` 작성 (Write):

```yaml
title: "{이슈 제목}"
steps:
  - id: S1
    desc: 구현 단계 한 줄
    files: [server/xxx.php]
    test: 이 단계 검증 방법 (php -l / 스모크 / 수동)
    risk: low|medium|high
    tdd: false            # PHP — 스모크 기반. 핵심 로직은 true 로 표시
risks:
  - 3관점 분석에서 나온 주요 리스크 요약
```

---

## Step 3-5: analysis.html 리포트 생성 — Gate 1 직전 필수

> **원칙(claude-pipeline Rule 5·3)**: 사람에게 보이는 종합 결과는 HTML, 생성 후 즉시 open.
> vuln-agent 엔 gen 스크립트가 없으므로 **자체 완결형 HTML 을 Write 로 직접 생성**한다.

`$PIPE/analysis.html` 에 아래 구조의 self-contained HTML 을 Write:

- 헤더: 제목 / slug / branch / complexity / 날짜
- **실패 시나리오** (pragmatist.direction) + **설계 결함** (simplify 목록)
- **회귀 위험** 표 (affected / severity 배지 / note)
- **런타임 함정** 목록 (type / location / note) + AC 갭 + 엣지케이스
- **Spec 변경** 표 (field / action / value) — 없으면 "변경 없음"
- **요구사항 & AC** (spec.yaml)
- **Plan** 단계 (risk 배지, tdd 태그)

인라인 CSS(다크/라이트 무관, 카드+배지), 외부 리소스 금지. 생성 후:

```bash
start "" "$PIPE/analysis.html"   # Windows. (mac: open / linux: xdg-open)
```

conversation.jsonl: `{"event":"analysis_html_reported","content":"analysis.html 생성·open — Gate 1"}`

---

## 🔴 Gate 1

```
분석 리포트를 열었습니다: .pipe/{slug}/analysis.html
(3관점 분석 · Spec · Plan)

[핵심 1~2줄 — 주요 리스크 또는 미합의 쟁점]

검토 후 승인하면 /wt-impl 로 구현을 시작합니다.
```

사용자 승인 전 /wt-impl 자동 진행 금지. 승인 시:
`{"ts":"{nowISO9}","event":"spec_plan_approved","by":"user"}`

## Non-Goals
- 구현/커밋 (wt-impl)
- 테스트 실행 (wt-qa)
