---
name: wt-qa
description: Use when the user types "/wt-qa" or "Self QA". 활성 worktree 에서 검증 단계(Step 7)를 수행한다 — 정적검사 + 3관점 코드리뷰(Quality·Security·Regression) + 점수화 + AC검증 + 스모크 + 커밋 → 🔴 Gate 2. vuln-agent 전용.
---

# wt-qa — 검증 단계 (Step 7) · Self QA

활성 worktree 브랜치의 변경을 정적검사 → 3관점 리뷰 → AC검증 → 스모크 순으로 검증하고 커밋한 뒤 **Gate 2**.

---

## 진입 즉시

```bash
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
ACTIVE=$(cat "$MAIN/wt/.active" 2>/dev/null)
WT_DIR="$MAIN/wt/$ACTIVE"; SLUG="${ACTIVE#*-}"; PIPE="$WT_DIR/.pipe/$SLUG"
BRANCH=$(git -C "$WT_DIR" rev-parse --abbrev-ref HEAD)
HEAD_SHA=$(git -C "$WT_DIR" rev-parse --short HEAD)
COMPLEXITY=$(grep -m1 '^complexity:' "$PIPE/spec.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo normal)
echo "branch: $BRANCH @ $HEAD_SHA / complexity: $COMPLEXITY"
git -C "$WT_DIR" diff --stat origin/main...HEAD
```

conversation.jsonl: `{"event":"qa_start","content":"branch:{BRANCH}, head:{HEAD_SHA}"}`

> **Nano(trivial)**: 3관점 리뷰 생략 → `php -l` + 단일 빠른 리뷰만 → 커밋 → Gate 2.

---

## Step 7-1: 정적검사 (테스트 실행은 뒤에서 1회)

```bash
CH=$(git -C "$WT_DIR" diff --name-only origin/main...HEAD)
echo "$CH" | grep '\.php$' | while read f; do php -l "$WT_DIR/$f" >/dev/null && echo "✓ $f" || echo "✗ $f"; done
echo "$CH" | grep '\.sh$'  | while read f; do bash -n "$WT_DIR/$f" && echo "✓ $f" || echo "✗ $f"; done
echo "$CH" | grep -q 'compose.*\.yml' && (cd "$WT_DIR" && docker compose -f compose.yml config >/dev/null 2>&1 && echo "✓ compose" || echo "✗ compose")
```

오류는 즉시 수정. conversation.jsonl: `{"event":"qa_static_check","content":"php:{pass|fail}, sh:{pass|skip}, errors:[...], fixed:[...]"}`

---

## Step 7-1.5 / 7-1.6: 클린코드 · 아키텍처 체크리스트 (AI 셀프)

변경 코드에 대해 vuln-agent CLAUDE.md 원칙으로 자문:
- YAGNI(지금 필요?) / KISS(더 단순?) / DRY(기존 헬퍼로 되나 — `vg_h/vg_pdo/vg_secret/vg_upsert_*`?) / SOLID(한 책임? 기존 커넥터 수정 없이 확장?)
- 비밀값 하드코딩 없나 / PDO prepared 만 썼나 / 출력 이스케이프 했나

위반은 즉시 수정하거나 리뷰 항목으로 넘긴다.

---

## Step 7-2: 3관점 병렬 코드리뷰 (Quality · Security · Regression)

> **재사용 판정**: 직전 리뷰 리포트의 커밋과 현재 HEAD 가 같고 트리가 clean 이면 재사용.

**단일 메시지에서 3개 에이전트 동시 dispatch.** diff = `git diff origin/main...HEAD` + 변경 파일 전체.

```
Agent(subagent_type="oh-my-claudecode:quality-reviewer", model="opus", name="quality")
  프롬프트: Quality 관점. cwd={WT_DIR}. 가독성/SOLID/DRY중복/복잡도/유지보수성.
    각 항목 YAML: {sev: critical|warning, imp: High|Med|Low, title, loc: path:line, problem, fix, patch, auto: true|false}
    + info: N (정보성 건수)

Agent(subagent_type="oh-my-claudecode:security-reviewer", model="opus", name="security")
  프롬프트: Security 관점(OWASP + PHP). cwd={WT_DIR}. 취약점 수집기 프로젝트이므로 보안 가중.
    점검: SQLi(문자열결합 쿼리·비-prepared), XSS(미이스케이프 echo), 인증/인가 우회,
          비밀값·PII 노출(로그 포함), 입력검증 누락, path traversal, SSRF(커넥터 fetch),
          역직렬화, 헤더/CRLF 인젝션, 의존성 취약점.
    각 항목 YAML: 위와 동일 스키마 (problem 에 OWASP 분류 포함)

Agent(subagent_type="oh-my-claudecode:code-reviewer", model="opus", name="regression")
  프롬프트: Regression 관점. cwd={WT_DIR}. diff + 변경파일 + db/*.sql 마이그레이션 + 테스트.
    점검: DB 스키마 영향(누락 마이그레이션·롤백불가·인덱스), 커넥터 계약(run(PDO,$conn) LSP),
          웹↔CLI 인터페이스 호환, 변경 로직의 테스트 커버리지, 기존 스모크 깨질 위험, 부작용(공유상태·캐시).
    각 항목 YAML: 위와 동일 스키마
```

3개 완료 후 항목 병합 → CRITICAL / WARNING 분류. 집계표 출력:

```
┌──────────────┬──────────┬─────────┬──────┐
│ 관점         │ Critical │ Warning │ Info │
│ Quality      │    N     │    N    │  N   │
│ Security     │    N     │    N    │  N   │
│ Regression   │    N     │    N    │  N   │
│ Total        │    N     │    N    │  N   │
└──────────────┴──────────┴─────────┴──────┘
```

병합 항목을 `$PIPE/review.json` 에 저장 (필드: id, severity, perspective, impact, title, file, line, problem, current_code, solution, solution_code, auto_fixable).

---

## Step 7-2-C: Critic 검증 (적대적) + 라우팅

리뷰 항목이 진짜인지 critic 에이전트로 교차검증(허위양성 제거):

```
Agent(subagent_type="oh-my-claudecode:critic", model="opus", description="review verdict")
  프롬프트: review.json 각 항목을 코드로 검증. 각 항목 verdict:
    - auto_fix: 명백·단일파일·안전 → 자동수정 대상
    - human_review: 판단 필요 or Critical → 사용자 확인
    - reject: 허위양성/근거부족 → 제외
```

- `auto_fix` → 파일별 executor 로 수정 → 커밋
- `human_review` Critical → **Step 7-3 Critical 루프**
- `human_review` Warning → 사용자 decision(do/defer/skip)
- `reject` → 집계 제외

---

## Step 7-3: Critical 루프 + Warning 처리 + 점수

### Critical 루프 (최대 5회)
`human_review` Critical 이 0 이 될 때까지: 수정 → 해당 관점만 재리뷰. 5회 초과 시 중단·보고.

### Warning 처리 (decision 기반)
- `do` → 즉시 수정
- `defer` → 미수정, 점수 감점 대상으로 집계
- `skip` → 집계 제외

### 점수 계산 (vuln-agent — 보안 가중 단일 컷오프)
```
base = 100
- Critical 1건당 -15  (Critical > 0 이면 무조건 BLOCKED)
- Warning High   -7
- Warning Medium -4
- Warning Low    -2
컷오프: 85점 (보안 수집기 특성상 FE/BE 통합보다 높게)
등급: score≥85 & Critical=0 → PASS / Critical=0 & score<85 → CAUTION / Critical>0 → BLOCKED
```
**점수 미달 시 자동 재시도(최대 5회)**: 수정 가능한 High/Medium Warning → 수정 → 재리뷰 → 재계산. 5회 후에도 미달이면 `score_unresolved` 기록·중단.

---

## Step 7-4: AC 검증

spec.yaml 의 각 `acceptance_criteria` 를 코드/동작으로 확인.
conversation.jsonl: `{"event":"qa_ac_verify","content":"ac_total:N, pass:N, fail:N, items:[{id, result, note}]"}`

---

## Step 7-5: 스코프 스모크 테스트 (리뷰+AC 완료 후 최초 1회)

> 스택이 떠 있어야 함. 변경이 웹/API 에 닿으면 실행, DB/문서만이면 skip.

```bash
# 스택 기동 여부 확인
curl -sf http://localhost:8080/ >/dev/null 2>&1 && bash "$WT_DIR/tests/smoke.sh" || \
  echo "⚠️ 스택 미기동 — ./compose_runner.sh dev up -d 후 스모크 필요 (또는 변경이 런타임 무관이면 skip 사유 기록)"
```

conversation.jsonl: `{"event":"qa_complete","content":"review_score:N, grade:{PASS|CAUTION|BLOCKED}, ac_pass:N/N, smoke:{pass|skip}, commit:{SHA}"}`

---

## Step 7-6: 검증 커밋 + qa 리포트 HTML

```bash
git -C "$WT_DIR" add -A
git -C "$WT_DIR" commit -m "qa: 검증 반영 ({score}점 {grade}, AC {pass}/{total})" 2>/dev/null || echo "변경 없음"
```

`$PIPE/qa-{timestamp}.html` 자체 완결형 HTML 생성(정적검사·점수·등급·AC·엣지케이스·타임라인) 후 `start "" "$PIPE/qa-*.html"`.

---

## 🔴 Gate 2

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ 검증 완료 — {score}점 / {PASS|CAUTION|BLOCKED}
  정적검사 : php -l pass
  3관점    : Critical {N} / Warning {N}
  AC       : {pass}/{total}
  스모크   : {pass|skip}

리포트: .pipe/{slug}/qa-*.html
PR 을 만들려면 → /wt-push
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

BLOCKED(Critical>0)이면 push 금지 안내. push/PR 은 사용자가 `/wt-push` 로 개시.

## Non-Goals
- push/PR (wt-push)
- main 직접 커밋
