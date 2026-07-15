# 마일스톤: <제목>

> 메인(마일스톤) 세션이 이 파일을 채우고, 각 작업을 spawn-worker.ps1 로 팬아웃한다.
> 이 파일은 계획의 단일 진실. 워커는 자기 항목만 받아 독립 세션에서 처리한다.
> 실제 계획서는 .omc/plans/<milestone>.md 에 둔다(이 파일은 템플릿).

## 배경 / 목표
<무엇을, 왜. 완료 판정 기준(acceptance)까지.>

## 작업 분해 (워커 단위)

각 작업은 **독립적으로** 끝날 수 있어야 한다(파일 충돌 최소화 — 워크트리로 격리되지만
같은 파일을 여러 워커가 만지면 PR 병합에서 충돌한다). 작업당 워커 1개 = 브랜치 1개 = PR 1개.

| # | Task 슬러그 | 지시문 요지 | 주요 파일 | 의존 |
|---|---|---|---|---|
| 1 | `<slug-a>` | <한 줄> | server/... | 없음 |
| 2 | `<slug-b>` | <한 줄> | server/... | 없음 |
| 3 | `<slug-c>` | <한 줄> | ... | 1,2 완료 후 |

## 스폰 명령

```powershell
# 의존 없는 것 먼저 병렬로
.\deploy\orchestrator\spawn-worker.ps1 -Task <slug-a> -PromptFile .omc\tasks\<slug-a>.md
.\deploy\orchestrator\spawn-worker.ps1 -Task <slug-b> -PromptFile .omc\tasks\<slug-b>.md

# 감독
.\deploy\orchestrator\status.ps1 -Watch

# 1·2 PR 병합 후 3 스폰
.\deploy\orchestrator\spawn-worker.ps1 -Task <slug-c> -PromptFile .omc\tasks\<slug-c>.md
```

## 워커 지시문 (.omc/tasks/<slug>.md)

각 워커에 넘길 상세 지시. spawn-worker 가 여기에 오케스트레이터 프리앰블(브랜치·검증
게이트·PR·결과 파일 규칙)을 자동으로 덧붙이므로, 여기엔 **작업 내용만** 적으면 된다.

예 (.omc/tasks/slug-a.md):
```
server/public/findings.php 의 CVE 목록에 심각도 배지를 추가한다.
- 색은 app.css 의 기존 .badge-* 클래스를 쓴다(PHP 인라인 style 금지).
- critical/high/medium/low 4단계.
- 스크린샷 없이도 판단되게, 렌더 결과를 결과 파일에 요약.
```
