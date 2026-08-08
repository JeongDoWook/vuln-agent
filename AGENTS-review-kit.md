# spec-review-kit — Codex / 단일세션 CLI 진입점

이 파일은 **실행 규칙만** 담는다. 각 스테이지가 *무엇을 어떻게* 하는지는 도구 무관한 알고리즘 문서가
SSOT이며, Claude Code 쪽 `kit/skills/*/SKILL.md`도 같은 문서를 가리킨다 — **절차를 여기서 다시
서술하지 않는다**(재서술하면 두 진입점이 조용히 어긋난다).

| 스테이지 | 절차 SSOT | 역할 브리핑 |
|---|---|---|
| requirement-fanout (선택) | `kit/workflow/requirement-fanout-algorithm.md` | `.claude/agents/persona-fanout.md` · `requirement-synthesizer.md` |
| design-review | `kit/workflow/design-review-algorithm.md` | `.claude/agents/design-{devil-advocate,regression-analyst,runtime-trap}.md` |
| code-review | `kit/workflow/code-review-algorithm.md` | `.claude/agents/{quality,security,regression}-reviewer.md` · `code-auditor.md` · `runtime-trap-hunter.md` · `review-critic.md` |
| 라이프사이클 9종 (work-start · work-sync · spec · implement · self-qa · submit · finish · release · dev-env) | `.claude/skills/<이름>/SKILL.md` — 설치 위치다(킷 저장소 안에서는 `kit/skills/`). 도구 무관 절차라 Codex도 그대로 수행한다(frontmatter만 무시) | — |
| pipeline (스테이지 체인) | `kit/workflow/pipeline-algorithm.md` | — |
| milestone (여러 작업을 넘나드는 층) | `kit/workflow/milestone-algorithm.md` → `node scripts/ms.js` (기본 dry-run) | — |
| 외부 시스템 접점 (트래커·PR·작업공간·알림·릴리스) | `kit/contract/provider-contract.md` → `node scripts/px.js` | — |
| 전 스테이지 공통 | `kit/workflow/guardrails.md` | — |

역할 브리핑(`.claude/agents/*.md` — 설치 위치다. 킷 저장소 안에서는 `kit/agents/`)은 상단 YAML
frontmatter(`name:`/`tools:`/`model:`)가 Claude Code 서브에이전트 등록 메타데이터이니 **무시하고
`---` 아래 본문만** 그 관점의 지시로 사용한다.

> `.claude/` 밑에 두는 이유는 Claude Code 가 서브에이전트를 **거기서만 찾기** 때문이다
> (`Agent(subagent_type="persona-fanout")`). Codex 쪽에는 아무 차이가 없다 — 경로만 그쪽으로 맞추고
> 본문을 그대로 읽는다. 두 벌로 복사하지 않는다.

값(`{paths.*}` · `{git.diffBase}` · `{tracks.*}` · `{runtimeTrapTaxonomy}` 등)은 전부 저장소 루트의
`.review-kit.json` 어댑터에서 온다. `example-adapter/.review-kit.json` 참고.

---

## 핵심 원칙 — 도구가 달라도 변하지 않는 것

**저자 ≠ 검증자.** 병렬 서브에이전트가 없어도 검증(critic) 패스는 방금 고친 사람의 추론을 이어받지
않고 **코드에서 다시 증거를 확인**해야 한다.

순차 실행은 병렬보다 이 원칙이 깨지기 쉽다 — 같은 세션에서 이어 쓰면 직전 결론에 관성적으로 동조하게
된다. 그래서 모든 후속 패스는:

- **앞 패스의 결론을 근거 없이 수긍하지 않는다** — 인용된 `file:line`을 직접 다시 읽고 판정한다.
- 결론 직전에 "**이 판단이 틀렸다면 무엇 때문일까**"를 한 번 자문한 뒤 확정한다.
- 매 패스를 "이 코드/설계는 반드시 실패한다"는 전제에서 **새로 시작**한다 — 이전 패스가 이미 지적한
  항목에 안주하지 않는다.

---

## 실행 전략 — 위에서부터 가능한 것 하나만 쓴다

### 1. 외부 터미널 워커 (TermKeep · Windows Terminal · PowerShell이 있으면 우선)

메인 세션이 지시 전체를 `<저장소>/.initial-prompt`에 UTF-8로 기록한 뒤:

```bash
node scripts/spawn-worker.js <저장소> <저장소>/.initial-prompt <label> [codex|claude]
```

5번째 인자로 새 터미널에서 띄울 CLI를 고른다(생략 시 `codex`). **이 스크립트는 도구 전용이 아니다** —
Claude Code 메인 세션도 같은 방식으로 `claude` 워커를 띄운다. 지시문 본문은 인자·IPC로 보내지 않고
워커가 `.initial-prompt`를 직접 읽는다(긴 한글 프롬프트가 터미널 인용부호에서 깨지는 것을 회피).
파일에 비밀값을 넣지 말고, 작업 완료 후 정리한다.

### 2. Codex 하위 에이전트 스레드

`.codex/agents/*.toml`의 역할에 위임한다. 별도 OS 터미널이 아니라 현재 세션에 연결된 독립
스레드이며 CLI에서는 `/agent`로 상태·결과를 확인한다. 메인 세션은 요구사항·결정·게이트를 맡는다.

### 3. 단일 세션 순차 fallback

하위 에이전트를 못 쓰는 환경. 각 관점을 **독립 패스로 순서대로** 실행하되, 위 「핵심 원칙」의
3개 항목을 매 패스에 명시적으로 적용한다.

### 공통 규칙

- 읽기/분석 역할은 가능한 경우 병렬 실행하고, 결과가 모인 뒤 별도 critic이 인용된 `file:line`을 다시 읽는다.
- 여러 에이전트가 같은 파일을 동시에 수정하지 않는다. 리뷰 에이전트는 **read-only**이며 auto-fix는
  메인 세션이 적용한다(`.codex/agents/*.toml`의 `sandbox_mode`가 이걸 강제한다 —
  `requirement-synthesizer`만 `workspace-write`).

---

## 스테이지 진행

`.review-kit.json`의 `pipeline.stages`를 읽어 순서대로 처리한다. 없으면 설치 범위에 따라
프리셋 A(검증 전용) 또는 프리셋 B(라이프사이클 전 주기)로 떨어진다 —
두 프리셋의 내용과 각 스테이지 타입의 근거는 `kit/workflow/pipeline-algorithm.md`
「스테이지 체인 두 프리셋」절이 SSOT다. 분기 규칙·상태 파일 스키마·재개 방식은 같은 문서의
「실행 루프」절 **그대로** — Skill tool이 없으므로 `stage.skill` 호출 자리에 위 표의 해당
알고리즘 문서를 직접 수행하는 것으로 대체한다.

요약하면: `external`은 안내만 하고 통과하되 **`wait: true`면 정지하고 외부 완료 신호를 기다린다**,
`gate`는 수행 후 `gate_wait` 기록 → **정지·승인 대기** → 승인 후 `done`으로 갱신, `auto`는
성공 시 무정지 진행(**실패하면 그 자리에 멈춘다**). 정지하지 않는 모든 분기도 `state.current`를
반드시 함께 올린다. `code-review`가 `cutlineGate: true`인데 등급이 CAUTION/BLOCKED면 다음 단계
진행 여부를 먼저 묻는다.

라이프사이클 스테이지(`work-start`·`spec`·`implement`·`self-qa`·`work-sync`·`submit`·`finish`)는
GitLab/GitHub/터미널을 직접 만지지 않고 **프로바이더 계약**(`kit/contract/provider-contract.md`,
`node scripts/px.js`)으로만 나간다. 체인 시작 전에 `node scripts/px.js doctor`를 한 번 돌린다.
`design-review`는 `spec` 안에서 불리므로 별도 스테이지로 두지 않는다.

체인이 **선형이 아니라 그래프**일 수도 있다. 어댑터의 `pipeline.stages` 중 한 노드라도
`dependsOn`을 선언했으면 `state.current` 순회 대신 그래프 루프를 쓴다 — 규칙은
`kit/workflow/pipeline-algorithm.md` 「그래프 실행 모델 (v2)」가 SSOT이고, 판정·전파는
`scripts/lib/pipeline/graph.js`의 순수 함수(`normalize` · `detectCycles` · `readyNodes` ·
`advance` · `propagateBypass` · `blockedNodes`)를 **직접 호출해서** 얻는다. 사람이 흉내내지 않는다:
optional 노드를 껐을 때 하위가 막히는지 통과하는지는 그 전파 규칙에 걸려 있고, 손으로 판정하면
반드시 어긋난다. `readyNodes`가 둘 이상을 돌려주면 그 노드들은 서로 독립이므로 동시에 진행해도 된다.

산출물 렌더링:

```bash
node scripts/gen-review.js {reviewOutDir}/review.json    # 결정 HTML
node scripts/gen-report.js {reviewOutDir}/report.json    # 최종 리포트
node scripts/gen-score.js {reviewOutDir}/report.json     # 점수·등급 기계 계산(검산)
node scripts/gen-status.js {pipeline.statePath}          # 스테이지 진행 현황 (v1 선형 / v2 그래프 자동 판별)
node scripts/gen-milestone.js {milestone.statePath}      # 마일스톤 Wave·슬롯 현황
```

마일스톤 층을 쓴다면 `node scripts/ms.js <서브커맨드>` 를 쓴다 — `--apply` 가 없으면 **항상
dry-run** 이고, 출력은 `px` 와 같은 JSON 봉투·같은 종료 코드(0/1/2/**3=미지원**)다. 이 층도
외부 시스템에는 `px` 로만 나간다.

---

## 환경 규칙 (실행 도구 무관 — 이 저장소 산출물이 한글이라 특히 중요)

**한글을 출력하는 Python 스크립트는 첫 줄에 `sys.stdout.reconfigure(encoding='utf-8')`을 넣는다.**
없으면 Windows에서 stdout이 cp949로 나가, 이 결과를 읽는 쪽(하니스·다음 패스·리포트 렌더러)이
UTF-8로 기대할 때 깨진다. 콘솔 코드페이지(`chcp 65001`)를 맞춰도 해결되지 않는다 — 코드페이지와
Python stdout 인코딩은 별개라, 파일을 올바르게 읽어도 출력 시 다시 cp949로 인코딩된다. 문제는
**출력 경로**이지 입력 파일이 아니다.

이 저장소 기본 스크립트는 전부 Node라 해당 없다 — 이식하는 프로젝트가 review/report 파이프라인에
**Python 스크립트를 추가**할 때만 적용되는 규칙이다.

---

## 설치

설치 목록의 SSOT는 `kit/manifest.json` 하나다. 손으로 `cp` 목록을 관리하지 않는다.

```bash
node scripts/install-kit.js --list                            # 그룹·프로파일
node scripts/install-kit.js <저장소> --profile review --dry-run
node scripts/install-kit.js <저장소> --profile full            # 라이프사이클·계약까지
```

Codex 진입점(`codex` 그룹 — 이 파일과 `.codex/*`)은 **모든 프로파일에 포함**된다. Claude Code
진입점도 같이 깔린다 — 두 진입점이 같은 `.claude/agents`·`kit/workflow`·`kit/contract`를 공유하므로
중복 비용이 거의 없고, 도구를 바꿔 쓸 때 재설치가 필요 없다.

이 파일은 `AGENTS-review-kit.md`라는 이름으로 들어간다. 호스트에 기존 `AGENTS.md`가 있으면
덮어쓰지 말고 상단에 참조 한 줄만 추가한다.

설치 후:

```bash
node scripts/px.js doctor              # contract 그룹을 깔았으면 가장 먼저. 통과 전에는 라이프사이클 스킬을 신뢰할 수 없다
node scripts/kit-manifest.js check     # 이후 언제든 — 킷 대비 드리프트면 exit 2
```
