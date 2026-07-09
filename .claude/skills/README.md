# wt 파이프라인 (vuln-agent)

`claude-pipeline`(withVTM 2.0 · GitLab · 멀티레포 · cmux 멀티세션)의 작업 파이프라인을
vuln-agent 환경(**단일 PHP 레포 · GitHub · git worktree · 같은 세션**)에 맞게 이식한 스킬 모음.

핵심 치환: claude-pipeline 의 **GitLab 이슈 생성** → vuln-agent 의 **git worktree + 브랜치 생성**.

---

## 전체 흐름

```
/wt          요구분석 · 난이도판정(L0~L3) · (Full 시)코드분석 → 🔵 요구사항 확정 Gate
   ↓ /wt-setup
             git worktree add + 브랜치 생성 + spec.yaml·conversation.jsonl  ← GitLab 이슈 대체
   ↓ (같은 세션에서 계속)
/wt-spec     3관점 분석(pragmatist·regression·qa) · (Normal↑)옵션 발산 · Plan · analysis.html
   ↓ 🔴 Gate 1
/wt-impl     구현 + 정적검사(php -l) + 커밋
   ↓ (자동 전환)
/wt-qa       정적검사 + 3관점 리뷰(Quality·Security·Regression) + 점수화 + critic + AC검증 + 스모크
   ↓ 🔴 Gate 2
/wt-push     push + GitHub PR 생성(gh)  ← GitLab MR 대체
   ↓ 🔴 Gate 3 (PR merge 는 사용자가 GitHub 에서 직접)
/wt-done     merge 후 worktree 제거 + 브랜치 정리
```

**게이트 원칙**: 각 🔴 게이트에서 사용자 응답 없이 다음 단계 자동 진행 금지. PR merge·main 병합은 항상 수동.

## 경로 규약

| 항목 | 위치 |
|---|---|
| worktree | `wt/{MMDD}-{slug}/` (main 저장소에서 `.gitignore` 처리) |
| 브랜치 | `{type}/{slug}` (feature/fix/refactor/chore) |
| 파이프라인 산출물 | `wt/{MMDD}-{slug}/.pipe/{slug}/` (그 worktree `.git/info/exclude` 로 커밋 제외) |
| 활성 worktree 포인터 | `wt/.active` |
| 완료 후 보존 | `wt/.archive/{MMDD}-{slug}/` (spec·리뷰·QA 리포트 감사추적) |

- 같은 세션 원칙: 모든 스킬은 `git rev-parse --git-common-dir` 로 main 을 찾고 `git -C "$WT_DIR"` 로 worktree 를 조작한다(Bash cwd 가 매 호출 리셋되므로).

## 안전장치

- `.claude/hooks/block-main-push.sh` (PreToolUse:Bash) — **main 직접 commit/push 차단**. 항상 worktree 브랜치 경유.
- `.gitattributes` — `*.sh/*.php eol=lf` (Windows CRLF 오염 방지, 기존 완비).
- 검증 게이트 — `php -l`(문법) + `bash -n`(쉘) + `tests/smoke.sh`(회귀) 통과해야 커밋/PR.

---

## claude-pipeline 감사 — 채택 / 각색 / 제외 결정

claude-pipeline 전 영역(docs/rules·검증·자동화·분석설계)을 감사해 vuln-agent 규모(YAGNI/KISS)에 맞게 취사선택한 결과.

### ✅ 채택 (이 스킬/훅에 반영됨)

| 패턴 | 출처 | 반영 위치 |
|---|---|---|
| 난이도 L0~L3 → Nano/Fast/Full 트랙 라우팅 + CLEAR/UNCLEAR 명확도 | wt/SKILL.md | `wt` |
| 3관점 분석(pragmatist=Devil's Advocate / regression / qa 런타임함정) | wt-spec-analyze.js | `wt-spec`, `wt-qa` |
| 해결옵션 발산(단기 vs 장기: cost_now/cost_to_change_later/reversibility/forecloses) | wt-spec Step 2-A0 | `wt-spec` (YAGNI 판단 구조화) |
| complexity → 모델 라우팅(simple=haiku/normal=sonnet/complex=opus) | ai-model-routing | `wt-spec` |
| 3관점 병렬 코드리뷰 + 점수화 + 자동 재시도(최대 5회) | step-review.md | `wt-qa` |
| Critical=0 강제 루프 + critic 적대적 검증(auto_fix/human_review/dropped, "dropped엔 코드증거 필수") | wt-review / critic | `wt-qa` |
| auto_fixable 기준(단일파일+로직불변+완전한 patch만 자동적용) | wt-review-auto | `wt-qa` |
| analysis.html 종합 리포트(사람=HTML) — 단, gen 스크립트 없이 인라인 생성 | rules.yaml Rule5/Rule3 | `wt-spec` |
| worktree 는 항상 origin/main 기준 생성 + 해시 검증 | workspace.yaml | `wt-setup` |
| **main 직접 push/commit 차단 훅** | block-main-deploy.sh | `.claude/hooks/block-main-push.sh` |
| PR 승인 게이트("진행/OK" 전 생성 금지) + description 자동초안 템플릿 | mr/SKILL.md | `wt-push` |
| 검증 없이 PR/병합 금지 · `--no-verify` 우회 금지 · 시크릿 커밋 금지 | prohibitions.yaml | 게이트 규율 |

### 🔧 각색 (개념만, PHP 규모로 축소)

- **런타임 함정 카탈로그** Java/Spring(N+1·Lombok·LazyInit·TX경계) → PHP/PDO(SQLi·PDO-unprepared·XSS·header-injection·path-traversal·secret-leak·N+1·missing-tx·encoding-cp949·type-juggling)로 재작성 → `wt-spec`·`wt-qa`.
- **점수 컷오프** FE 80 / BE 85 이원화 → vuln-agent 단일 컷오프 **85(보안 수집기라 Security 가중)**. Critical>0 → BLOCKED.
- **FE/BE lead 분리** → 단일 레포이므로 regression 관점에 흡수(별도 vg-lead 는 L2↑에서 선택).

### ❌ 제외 (YAGNI / 인프라 불일치)

- cmux/tmux 멀티세션, `mx.js` CLI 계층, GitLab API(`gitlab.js`) → GitHub `gh`·같은 세션으로 대체.
- Node `gen-review.js`/`gen-qa.js`/`gen-report.js` 렌더러 파이프라인 → 인라인 HTML(npm 없음).
- 브라우저 do/defer/skip 클릭 UX, decision-review.html → 채팅 텍스트 결정(1인·같은 세션).
- Path A 에고 P2P 토론 팀, wt-impl phase형 레이어 병렬 → 규모 과설계.
- spec.yaml/plan.yaml 풀 스키마·`pre_accepted_tradeoffs`·task.md 단계의존 → `memory/` + 경량 spec 으로 대체.
- k6 perf 스크립트, requirements.jsonl ledger, repos.yaml SSOT 파생 → 해당 데이터 없음.

### 💡 향후 선택 도입 후보 (지금은 보류)

- git `pre-push` 훅(로컬 즉시 차단, Claude 훅과 이중화)
- 커밋 타입별 그룹핑 알림(Discord/Slack — OMC `configure-notifications` 위임)
- SemVer 자동 계산(Conventional Commits → major/minor/patch) + CHANGELOG 삽입
- last_reviewed_commit 캐시(동일 커밋 재리뷰 스킵), decision_memo(재질문 방지)

> 상세 감사 원본 4종은 세션 스크래치패드(`audit-1~4.md`)에 보존. 핵심 통찰: claude-pipeline 의 가치는
> `Workflow` 인프라가 아니라 그 위 패턴 — **stateless fan-out + JSON 스키마 강제 + silent-null 방어 + 배치 critic 적대검증**.
> vuln-agent 규모에선 `Agent` 병렬 호출 + 프롬프트 내 스키마 명시로 동형 재현(KISS).
