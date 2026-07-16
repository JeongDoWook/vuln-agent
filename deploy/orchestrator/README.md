# orchestrator — 마일스톤 세션 + 병렬 워커 세션

한 세션(**마일스톤/메인**)이 계획만 들고, 실제 작업은 **독립 claude 세션**을 창마다
띄워서 시킨다. Windows PowerShell 전용 — tmux/cmux 불필요.

마무리 방식은 두 가지다:

- **옵션 A: 워커별 개별 PR (기본)** — 워커가 각자 커밋→push→PR 까지 끝낸다. 서로 관련
  없는 독립 작업을 여러 개 병렬로 돌릴 때 쓴다(리뷰도 워커별로 따로 받는다).
- **옵션 B: 마일스톤 통합 PR** — 워커는 커밋→push 까지만 하고(`-Finish push`), 메인이
  `merge-milestone.ps1` 로 그 브랜치들을 로컬에서 순서대로 병합해 PR 1개로 묶어 낸다.
  파일이 겹치거나 서로 연관된 하위작업을 모아 리뷰 부담을 줄이고 싶을 때 쓴다.

```powershell
# 옵션 B 예시
.\deploy\orchestrator\spawn-worker.ps1 -Task sub-a -Finish push -Prompt "..."
.\deploy\orchestrator\spawn-worker.ps1 -Task sub-b -Finish push -Prompt "..."
.\deploy\orchestrator\merge-milestone.ps1 -Milestone my-feature -Task sub-a,sub-b
```

> 영감: `claude-pipeline` 의 `scripts/lib/multiplexer.js`(cmux/tmux/**powershell** 추상화).
> 거기선 cmux 로 워크스페이스/탭을 관리하지만, 여기선 그 `powershell` 경로 하나만 떼어
> vuln-agent 의 `deploy/wt.sh` 워크트리 위에 얹었다. 워커 = 워크트리 = 브랜치 = PR.

## 왜 이렇게 하나 (메모리)

서브에이전트는 요약이 메인 컨텍스트에 계속 쌓여 결국 `/compact` 가 필요하다.
독립 세션은 **각자 컨텍스트 창**을 갖고 끝나면 죽으므로, 무거운 작업 컨텍스트가
메인에 안 쌓인다. 메인은 계획서 + 결과 파일 몇 줄만 들고 가볍게 유지된다.
조율은 화면 공유(tmux)가 아니라 **파일**로 한다:

```
메인(마일스톤) 세션
 ├─ .omc/plans/<milestone>.md        ← 계획서(단일 진실, milestone.template.md 참고)
 ├─ spawn-worker.ps1 -Task a ...      ← 워커 탭 1 (wt/a, feat/a)
 ├─ spawn-worker.ps1 -Task b ...      ← 워커 탭 2 (wt/b, feat/b)
 ├─ watch-workers.ps1                 ← 전원 끝날 때까지 대기 후 취합(메인이 이어받음)
 └─ PR 병합 후  stop-worker.ps1 -Task a
```

## 메인 세션 절차 (CLAUDE.md 요약의 전문)

1. **조사·계획**: 관련 코드를 읽고 어느 파일·무슨 변경·어떻게 검증할지 정한다. 한두 줄로
   알린 뒤 진행(막지 않음 — 규모가 크거나 되돌리기 어려우면 먼저 확인).
2. **스폰**: 하위작업마다 워커를 띄운다.
   - **작업량·독립성에 맞춰 워커 수를 늘린다** — 하나로 뭉쳐 맡기지 않는다. 서로 다른
     파일이면 무조건 나눈다. **같은 파일이라도** 건드리는 줄 범위가 겹치지 않으면 나눈다 —
     각 워커는 자기 워크트리(=자기 사본)에서 origin/main 을 기점으로 작업하므로 비겹침
     구간을 여러 워커가 동시에 고쳐도 각자 PR 은 문제없다(병합 순서만 뒤에 신경 쓰면 됨).
   - "버그 4개 고쳐줘" 류는 워커 1개에 욱여넣지 말고 워커 4개로 쪼갠다 — 무관한 하위작업을
     한 프롬프트에 모으면 프롬프트도 길어지고 하나가 막히면 전체가 막힌다.
   - 하위작업 1개 → `spawn-worker.ps1 -Task <슬러그> -Prompt "..."` 로 바로.
     **2개 이상** → 스킬 `orchestrator-plan`(지시문을 `.omc/tasks/<슬러그>.md` 로 먼저 작성,
     번호가 아니라 내용을 아는 슬러그로) → `orchestrator-spawn`(`spawn-batch.ps1` 로 일괄 스폰).
     인라인 `-Prompt "..."` 로 PowerShell 안에서 긴 지시문을 직접 조립하지 않는 이유는
     아래 "프롬프트 전달 안전성" 참고.
   - 기본 `-Permissions ask`(워커가 탭에서 사용자 승인). 믿고 맡길 작업만 `-Permissions skip`.
3. **워커**: 자기 워크트리에서 구현 → 검증(php -l·smoke) → 커밋 → push → PR.
4. **대기·리뷰**: `watch-workers.ps1` 로 전원 완료까지 대기 → 취합 보고 전에 스킬
   `orchestrator-review` 로 각 워커 브랜치 diff 를 자동 리뷰(quality+security) →
   결과를 이 창에 보고. **PR 링크는 정보 제공용이지 병합 신호가 아니다** — 병합 여부는
   메인이 모든 워커를 취합한 뒤 사용자에게 확인받고 결정한다.
   - 사용자가 워커 탭에서 곧장 병합하면, 메인이 뒤이어 같은 브랜치에 후속 커밋을 얹다가
     이미 닫힌 PR 과 연결이 끊기는 경합이 생긴다(실제로 겪음: PR #170/#171 분리 원인).
     그래서 **같은 브랜치에 후속 커밋을 얹기 전엔 먼저 `gh pr view <브랜치> --json state`
     로 이미 병합됐는지 확인한다.** 이미 병합됐으면 별도 후속 PR 로 새로 낸다.
5. **정리**: PR 병합 뒤 `reap-merged.ps1` 로 워크트리 자동 정리(gh 인증 필요).

**왜 메인이 직접 구현하지 않나**: 편집·시행착오 컨텍스트가 메인에 쌓이면 `/compact` 가 필요해진다.
무거운 건 전부 워커 탭에 남기고, 메인은 계획 + 취합 몇 줄만 들고 가볍게 유지한다.

## 프롬프트 전달 안전성

지시문을 `claude` 실행 CLI 인자로 직접 넘기면(과거 방식) 프롬프트에 큰따옴표나 마크다운
백틱이 섞였을 때 Windows 커맨드라인 재인용 중 그 지점에서 잘리는 사고가 두 번 있었다
(`ui-toolbar-actions`: 큰따옴표, `ui-infotip`: 백틱). `spawn-worker.ps1` 은 이제 지시문을
`.initial-prompt` 파일로만 전달하고, `claude` 에는 "그 파일을 읽고 시작해라"라는 짧고
특수문자 없는 트리거 문장만 인자로 준다 — 프롬프트 내용 자체엔 어떤 특수문자가 있어도 안전하다.

다만 이건 **spawn-worker.ps1 내부**(파일 → claude) 구간의 방어다. **메인이 PowerShell 한
호출 안에서 긴 지시문을 인라인 `-Prompt "..."` 로 조립하는 것** 자체는 별개 위험이라
(오타·명령줄 길이 제한) 하위작업이 2개 이상이면 `orchestrator-plan` 스킬로 지시문을 먼저
파일(`.omc/tasks/<슬러그>.md`)로 써 두고 `-PromptFile` 로 스폰한다.

## 스킬 (.claude/skills)

세 스킬이 "명령 작성 → 구현 실행 → 리뷰" 단계를 분리한다(claude-pipeline 의
`wt-spec`/`wt-impl`/`wt-review` 패턴에서 아이디어만 가져와 이 저장소 규모로 최소화 —
GitLab 이슈 연동·Gate 승인·spec/qa/push/done 나머지 단계는 과설계라 가져오지 않았다):

| 스킬 | 단계 | 하는 일 |
|---|---|---|
| `orchestrator-plan` | 명령(정적) | 작업을 하위작업으로 쪼개 `.omc/tasks/<슬러그>.md` 지시문만 쓴다. 워커 스폰 없음 |
| `orchestrator-spawn` | 구현(동적) | 그 파일들로 `spawn-batch.ps1` 을 실행해 워커를 일괄 스폰 |
| `orchestrator-review` | 리뷰 | 워커 완료(PR 생성) 후, 병합 확인 전에 브랜치 diff 를 quality/security 로 자동 리뷰 |

하위작업이 1개뿐이면 `orchestrator-plan`/`spawn` 없이 `spawn-worker.ps1` 을 바로 써도 된다 —
배치 처리는 하위작업이 여러 개일 때 반복 호출·슬러그 매칭 실수를 없애는 게 목적이다.

## 파일

| 스크립트 | 역할 |
|---|---|
| `spawn-worker.ps1` | 워커 1개 스폰 — 워크트리 생성 + `.initial-prompt` 주입 + claude 창 실행 |
| `spawn-batch.ps1` | 워커 **여러 개** 스폰 — `.omc/tasks/*.md` 파일마다 `spawn-worker.ps1 -PromptFile` 자동 호출, 성공분은 `.omc/tasks/archive/` 로 이동 |
| `status.ps1` | 워커 감독 — 결과 파일·git·PR 상태 한눈에 (`-Watch` 주기 갱신) |
| `watch-workers.ps1` | **자동 이어받기** — 전원이 끝날 때까지 대기했다가 취합 리포트 후 종료 |
| `merge-milestone.ps1` | **마일스톤 통합 PR(옵션 B)** — 전원 완료를 기다렸다가 워커 브랜치들을 로컬 병합해 PR 1개로 낸다 |
| `stop-worker.ps1` | 워커 정리 — 워크트리 제거 + 매니페스트 삭제 |
| `reap-merged.ps1` | **병합 자동정리** — PR 이 main 에 병합된 워커를 감지해 stop-worker 실행(gh 필요) |
| `worker-stop-hook.ps1` | **완료 자동기록** — 워커 세션이 idle 될 때 git 상태로 결과 파일을 갱신(spawn 이 주입) |
| `milestone.template.md` | 계획서 템플릿 |

런타임 산출물(메인 트리 `.omc/` 에 고정, git 추적 밖):
- `.omc/logs/<task>.log` — 헤드리스 워커 출력
- `.omc/results/<task>.md` — 워커가 남기는 진행/결과 (`대기중`→`진행중`→`완료`/`차단`)
- `.omc/orchestrator/<task>.json` — 워커 매니페스트(status.ps1 이 읽음)

## 쓰는 법

```powershell
cd C:\APM\Apache24\htdocs\vuln-agent

# 1) 워커 하나 — 보이는 창(대화형, 직접 지켜봄)
.\deploy\orchestrator\spawn-worker.ps1 -Task cve-badge `
    -Prompt "server/public/findings.php 에 CVE 심각도 배지 추가. app.css 클래스 사용."

# 2) 여러 개 병렬 — 계획서 항목마다 한 줄씩
.\deploy\orchestrator\spawn-worker.ps1 -Task feed-kisa -PromptFile .omc\tasks\kisa.md
.\deploy\orchestrator\spawn-worker.ps1 -Task feed-epss -PromptFile .omc\tasks\epss.md

# 3) 분리된 새 창으로 (탭 말고 별도 창)
.\deploy\orchestrator\spawn-worker.ps1 -Task feed-nvd -Prompt "..." -Launch window

# 4) 헤드리스(창 없이 로그로만) — 대량 팬아웃·읽기 작업에
.\deploy\orchestrator\spawn-worker.ps1 -Task audit-sql -Prompt "..." -Launch headless

# 5) 감독 (한눈에 보기)
.\deploy\orchestrator\status.ps1            # 전체 현황 한 번
.\deploy\orchestrator\status.ps1 -Watch     # 5초마다 갱신
.\deploy\orchestrator\status.ps1 -Task cve-badge   # 특정 워커 결과 전문

# 6) 자동 이어받기 — 전원 끝날 때까지 대기 후 취합 (메인이 여기서 이어받음)
.\deploy\orchestrator\watch-workers.ps1              # 전체 대기
.\deploy\orchestrator\watch-workers.ps1 -Task a,b    # a,b 만 대기

# 7) PR 병합 후 정리 — 수동 한 개
.\deploy\orchestrator\stop-worker.ps1 -Task cve-badge

# 7') 또는 병합 자동정리 — main 병합된 워커를 감지해 알아서 정리 (gh 인증 필요)
.\deploy\orchestrator\reap-merged.ps1            # 한 번 훑기
.\deploy\orchestrator\reap-merged.ps1 -DryRun    # 정리 대상만 표시
.\deploy\orchestrator\reap-merged.ps1 -Watch     # 5분마다 반복 감시
```

## 파라미터 (spawn-worker.ps1)

| 파라미터 | 기본 | 설명 |
|---|---|---|
| `-Task` | (필수) | 슬러그. 브랜치·워크트리·로그·결과 파일 이름 기준 |
| `-Prompt` / `-PromptFile` | — | 워커 지시문(둘 중 하나 필수) |
| `-Prefix` | `feat` | 브랜치 접두사 (feat/fix/chore) |
| `-Base` | `origin/main` | 워크트리 기점 |
| `-Permissions` | `skip` | `skip`=자율(--dangerously-skip-permissions), `ask`=매번 확인 |
| `-Launch` | `tab` | `tab`=현재 WT 창에 새 탭 · `window`=분리된 새 창 · `headless`=창 없이 로그로만 |
| `-DryRun` | off | 워크트리·지시문·매니페스트만 만들고 claude 실행은 생략(미리보기) |
| `-Finish` | `pr` | `pr`=워커가 스스로 커밋·push·PR(옵션 A) · `push`=커밋·push 까지만(옵션 B, `merge-milestone.ps1` 과 짝) |

## 자동 이어받기 & 최적화

claude-pipeline 은 cmux `read-screen` 으로 **다른 세션 화면을 훔쳐봐** 완료를 감지한다
("완료"/"✅"/idle 마커 폴링). 순수 PowerShell 은 화면을 못 읽으므로, 워커가
`.omc/results/<task>.md` 첫 줄에 남기는 상태 라벨을 폴링한다 — 화면 스크래핑보다 확실한 신호.

`watch-workers.ps1` 이 그 폴링을 담당한다: 감시 대상 전원이 종료 상태(`완료`|`차단`)가 되면
취합 리포트를 찍고 종료 → 메인 세션이 그 출력을 받아 사용자에게 답한다(= 이어받는 지점).

**핵심 최적화**: 이 대기 루프는 claude 가 아니라 **순수 셸**이다. 기다리는 동안 메인 세션의
컨텍스트(토큰)가 전혀 늘지 않는다 — 무거운 작업 컨텍스트는 각 워커 탭에만 쌓이고, 메인은
계획 + 취합 몇 줄만 들고 가볍게 유지된다. 이게 서브에이전트(요약이 메인에 계속 쌓임) 대비
이 구조의 이점이다. (부수 최적화: 결과 파일 mtime 이 바뀐 것만 다시 읽고, 상태가 바뀐
워커만 한 줄 출력한다.)

**결정론적 완료 신호 (`worker-stop-hook.ps1`)**: 워커(claude)가 "완료" 기록을 잊으면
watch-workers 가 영영 못 기다린다 — 실제로 겪은 취약점이다. 그래서 spawn 이 워커 워크트리의
`.claude/settings.local.json` 에 **Stop 훅**을 심는다. 워커 세션이 idle 될 때마다 훅이 git
상태로 결과 파일을 자동 갱신한다(모델의 협조 불요):
- HEAD 가 push 됨(+커밋) → `완료(자동)` · 커밋만/미커밋 → `진행중(자동)` · 변경 없음 → `대기중(자동)`
- 워커/메인이 **명시한** `완료`/`차단` 은 덮지 않는다(명시 신호 우선). 이게 claude-pipeline 의
  "thinking→idle" 감지에 대응하는 결정론적 버전이다.

## 워커 라이프사이클 — 언제 정리하나

워커는 **PR 생성 시점이 아니라 main 병합 시점**에 정리한다. PR 은 리뷰가 되돌아올 수 있어,
병합 전까지는 같은 브랜치·워크트리가 다시 필요하다(리뷰 코멘트 반영). 세션을 PR 생성에
닫으면 그 컨텍스트가 날아가 재스폰해야 한다. **진짜로 필요 없어지는 시점은 병합**이다.

```
스폰 → 작업 → 커밋 → push → PR ──(리뷰·수정 왕복)──▶ main 병합 ──▶ 정리(stop/reap)
                              └ 이 구간은 워크트리를 살려둔다 ┘
```

- 병합은 GitHub 에서 사람이 한다(시스템 밖). 로컬이 알려면 PR 상태를 폴링해야 하고 → `gh` 필요.
- `reap-merged.ps1` 이 그 폴링을 한다: 각 워커 브랜치의 PR 이 `MERGED` 면 stop-worker 로 정리.
  `-Watch` 로 5분마다 돌리면 **완전 자동**(병합하는 순간 다음 주기에 알아서 치워진다).
- `gh` 미인증이면 안내 후 아무것도 안 한다 — `gh auth login` 은 사용자가 직접(OAuth/토큰).

## 주의

- **각 워커 = 별도 세션 = 별도 토큰 과금.** 병렬로 많이 띄우면 비용도 병렬로 나간다.
- `-Permissions skip` 은 워커가 커밋/push 를 막힘 없이 하도록 하는 자율 모드다.
  민감한 작업은 `-Permissions ask` 로 띄우고 창에서 직접 승인한다.
- 워커는 `CLAUDE.md` 규칙을 그대로 따른다(main 직접 금지·검증 게이트·PR). 지시문
  프리앰블에 그 요구가 박혀 있다.
- 순수 PowerShell 창은 화면을 프로그램으로 훔쳐볼 수 없다 → 감독은 `status.ps1`(결과
  파일 기반)로 한다. 워커가 결과 파일을 잊어도 `worker-stop-hook.ps1` 이 git 상태로
  자동 기록하므로, "워커가 성실히 갱신" 에 의존하지 않는다.
- 워크트리·DB·스택 규칙은 최상위 `CLAUDE.md` 를 따른다. 스택은 `server·db·tests` 를
  건드리는 워커에서만 올린다.
