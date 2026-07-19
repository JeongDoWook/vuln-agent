---
name: orchestrator-spawn
description: .omc/tasks/*.md 에 준비된 지시문 파일들로 워커를 실제로 스폰한다("구현 실행" 단계). orchestrator-plan 이 만들어 둔 파일을 소비한다. 단일 하위작업이면 spawn-worker.ps1 을 직접 써도 된다.
---

# orchestrator-spawn — 구현(워커 실행) 단계

`orchestrator-plan` 이 `.omc/tasks/*.md` 에 써 둔 지시문 파일들을 실제 워커로 띄운다.
이 스킬은 **지시문을 만들지 않는다** — 이미 있는 파일만 소비한다. 지시문이 아직 없으면
먼저 `orchestrator-plan` 으로 돌아간다(또는 하위작업이 1개뿐이면 그냥
`spawn-worker.ps1 -Task <슬러그> -Prompt "..."` 인라인으로 바로 스폰).

## 절차

1. **대상 확인**:
   ```powershell
   Get-ChildItem .omc\tasks\*.md
   ```
   비어 있으면 `orchestrator-plan` 부터 실행하라고 사용자에게 알리고 멈춘다.

2. **스폰**:
   ```powershell
   .\deploy\orchestrator\spawn-batch.ps1
   ```
   기본값은 `-Permissions ask -Launch auto -Finish pr -Prefix feat -Base origin/main` — 워커가
   사용자 승인을 받고, 완료 시 스스로 PR 까지 낸다. 필요하면 오버라이드:
   - 믿고 맡길 작업만 `-Permissions skip`
   - 창 없이 로그로만 돌리려면 `-Launch headless`
   - 여러 워커를 로컬 병합해 PR 1개로 묶을 계획이면 `-Finish push`(이후 `merge-milestone.ps1`)

   **`-Launch` 는 그냥 생략해라(기본값 `auto` 를 쓴다).** `auto` 가 지금 세션이 termkeep
   안에서 도는지 부모 프로세스 체인으로 감지해 termkeep 이면 termkeep 새 세션으로, 아니면
   현재 터미널에 맞춰 띄운다(`deploy/orchestrator/README.md` "호스트 터미널 자동 감지" 절).
   `-Launch tab`/`window` 을 손으로 넘기면 이 감지를 건너뛰어 termkeep 안에서 돌아도 무조건
   Windows Terminal 새 탭으로 튄다 — 실제로 이 문서에 "기본값" 이라고 잘못 적혀 있던 예시를
   그대로 따라 했다가 termkeep 세션 대신 별도 창 탭 3개가 뜬 사고가 있었다(2026-07-19).
   사용자가 명시적으로 "새 창으로/탭으로/헤드리스로 띄워줘" 라고 하지 않는 한 `-Launch` 인자
   자체를 아예 쓰지 않는다.

   스폰에 성공한 파일은 자동으로 `.omc/tasks/archive/` 로 옮겨진다(재실행 시 중복 스폰 방지).

3. **대기·취합**:
   ```powershell
   .\deploy\orchestrator\watch-workers.ps1
   ```
   전원 완료(`완료`|`차단`) 상태가 될 때까지 대기 후 취합 리포트를 낸다. 메인 세션 컨텍스트는
   이 대기 동안 늘어나지 않는다(순수 셸 폴링).

4. **보고**: 워커별 결과(완료/차단, PR 링크 유무)를 사용자에게 취합해 알린다. PR 링크는
   정보 제공용일 뿐 병합 신호가 아니다 — 병합 여부는 사용자 확인 후 결정한다(CLAUDE.md).

## 단일 하위작업일 때

`.omc/tasks/` 파일이 1개뿐이거나 애초에 쪼갤 필요가 없었다면, `spawn-batch.ps1` 대신
`spawn-worker.ps1` 을 직접 한 번 불러도 무방하다 — 이 스킬의 배치(batch) 기능은 하위작업이
여러 개일 때 반복 호출·슬러그 매칭 실수를 없애는 게 목적이라, 1개짜리에는 오버헤드다.

## 참고

- `deploy/orchestrator/README.md` — 전체 오케스트레이터 사용법(개별 스폰, 감독, 정리 등)
- `deploy/orchestrator/spawn-batch.ps1` — 이 스킬이 부르는 실제 스크립트
