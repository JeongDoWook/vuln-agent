---
name: orchestrator-review
description: 워커가 완료(PR 생성)를 보고한 뒤, 병합 여부를 사용자에게 확인받기 전에 각 워커 브랜치 diff 를 자동으로 코드리뷰한다(quality+security). watch-workers.ps1 로 전원 완료를 확인한 직후 이어서 쓴다.
---

# orchestrator-review — 워커 완료 후 자동 리뷰

## 언제 쓰나

`watch-workers.ps1`(또는 `status.ps1`)로 워커가 "완료"(PR 생성됨)를 보고한 직후, 사용자에게
"PR #N 병합할까요?" 라고 묻기 **전에** 이 스킬로 diff 를 한 번 리뷰한다. 하위작업이 1개뿐이어도
동일하게 적용 — 이 스킬은 워커 개수와 무관하게 "완료 보고된 각 브랜치"마다 돈다.

## 절차

1. **대상 확보**: `.omc/orchestrator/*.json` 매니페스트에서 `finish=pr` 이고 대응하는
   `.omc/results/<task>.md` 가 "완료"로 시작하는 task 들의 `branch` 필드를 모은다(또는
   사용자가 특정 PR 번호·브랜치를 직접 지목한 경우 그것만).

2. **브랜치마다 diff 확보** (워커 워크트리에 직접 들어가지 않는다 — 워커 세션을 방해하지 않기
   위해 fetch+diff 로 본다):
   ```bash
   git fetch origin <branch>
   git diff origin/main...origin/<branch>
   ```

3. **리뷰 에이전트 배정** (변경 규모에 맞춰, 과설계 금지):
   - php/css/sql 등 로직·화면 변경이 있으면 `quality-reviewer` + `security-reviewer` 를
     병렬로(각 sonnet).
   - 문서(`.md`)나 오케스트레이터 스크립트(`.ps1`)만 바뀐 브랜치는 `quality-reviewer` 하나면
     충분하다.
   - 리뷰 프롬프트에 이 저장소 `CLAUDE.md` 원칙(YAGNI/KISS/DRY/SOLID, `app.css` 소유 원칙,
     인라인 `style` 금지, 검증 게이트 요구사항)과 이 프로젝트 특유의 함정(예: 프롬프트를
     PowerShell/CLI 인자로 직접 넘기면 특수문자에 잘리는 문제 — 이미 겪음)을 상기시킨다.

4. **결과 취합**:
   - 발견사항 없음 → "리뷰 통과" 한 줄로 넘어간다.
   - **차단급**(보안 결함, 정합성 버그, CLAUDE.md 가드레일 위반) 발견 → 병합 확인 전에
     사용자에게 먼저 알린다. 워커 탭이 살아 있으면 그 탭에 후속 커밋을 요청하고, 이미
     종료됐으면 `spawn-worker.ps1`(같은 브랜치, 기존 워크트리 재사용)로 후속 수정을
     맡긴다 — 새 브랜치를 만들지 않는다.
   - 사소한(스타일·소규모 리팩터) 발견 → 병합 여부 확인 메시지에 "리뷰 메모"로 같이
     붙여 보고만 하고, 병합 자체를 막지는 않는다(최종 판단은 사용자).

5. **보고**: 리뷰 결과를 포함해 최종 취합 보고를 한다(PR 링크 + 리뷰 요약). 병합 여부는
   항상 사용자 확인 후 결정한다 — 이 스킬은 그 판단을 대신하지 않는다(CLAUDE.md
   "PR 링크는 메인이 취합해서 보고한다" 원칙 그대로).

## 하지 않는 것

- 코드를 직접 고치지 않는다(리뷰만). 고칠 게 있으면 워커(또는 후속 워커)에게 맡긴다.
- 매번 무거운 멀티에이전트 리뷰를 돌리지 않는다 — 이 저장소는 1인 유지보수라
  quality+security 표준 리뷰면 충분하다(YAGNI). 사용자가 "ultrareview"를 명시로 요청할
  때만 `/code-review ultra`.

## 참고

- 기존 `/code-review` 스킬과 겹치는 리뷰 로직은 그걸 그대로 재사용한다(중복 구현 금지 — DRY).
  이 스킬이 더하는 건 "**언제**(워커 완료 직후, 병합 확인 전) **누구를 대상으로**(완료
  보고된 워커 브랜치들) 자동으로 부를지"뿐이다.
- `.claude/skills/orchestrator-plan`(명령 단계) → `.claude/skills/orchestrator-spawn`
  (구현 단계) → 이 스킬(리뷰 단계) → 사용자 병합 확인, 순서로 이어진다.
