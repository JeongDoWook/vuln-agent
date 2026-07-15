# orchestrator — 마일스톤 세션 + 병렬 워커 세션

한 세션(**마일스톤/메인**)이 계획만 들고, 실제 작업은 **독립 claude 세션**을 창마다
띄워서 시킨다. Windows PowerShell 전용 — tmux/cmux 불필요.

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

## 파일

| 스크립트 | 역할 |
|---|---|
| `spawn-worker.ps1` | 워커 1개 스폰 — 워크트리 생성 + `.initial-prompt` 주입 + claude 창 실행 |
| `status.ps1` | 워커 감독 — 결과 파일·git·PR 상태 한눈에 (`-Watch` 주기 갱신) |
| `watch-workers.ps1` | **자동 이어받기** — 전원이 끝날 때까지 대기했다가 취합 리포트 후 종료 |
| `stop-worker.ps1` | 워커 정리 — 워크트리 제거 + 매니페스트 삭제 |
| `reap-merged.ps1` | **병합 자동정리** — PR 이 main 에 병합된 워커를 감지해 stop-worker 실행(gh 필요) |
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
  파일 기반)로 한다. 워커가 `.omc/results/<task>.md` 를 성실히 갱신하는 게 전제다.
- 워크트리·DB·스택 규칙은 최상위 `CLAUDE.md` 를 따른다. 스택은 `server·db·tests` 를
  건드리는 워커에서만 올린다.
