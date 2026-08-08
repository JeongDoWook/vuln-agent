---
name: implement
description: Use after the spec/design gate is approved and before any review stage. Executes the plan inside the verified workspace — decomposes work into parallel units where the plan allows, keeps changes on the working branch, runs lint/build (not the full test suite), and commits per unit.
---

# implement — Plan 실행 (구현 + 커밋)

> `px` = `node scripts/px.js`. 종료코드 `2`는 정지 후 보고, `3`은 수동 처리 요청 후 계속.
> 스택 명령을 직접 쓰지 않는다 — `px run lint` / `px run build` / `px env up` 만 부른다.
> 무엇이 실행되는지는 `.pipeline.json`의 `stacks`가 정한다.

---

## Step 1 — 전제 확인

```bash
node scripts/px.js ws resolve --cwd . --json
node scripts/px.js ws verify {slug} --json      # exit 2 → 정지
cat {paths.specFile} {paths.planFile} 2>/dev/null
```

- `ws verify`가 `exit 2`면 작업 디렉터리가 origin 기준에서 벗어난 것이다 — **여기서 멈춘다.**
  이 상태로 만든 커밋은 이후 diff·리뷰·PR 대상이 전부 어긋난다.
- `{paths.planFile}`이 없고 스펙에 "Nano" 표시도 없으면 설계 게이트를 통과하지 않은 것이다 →
  `spec`을 먼저 돌리라고 안내하고 멈춘다.
- Nano(스펙에 명시)면 Plan 없이 진행한다 — 파일 찾기 → 수정 → 커밋만 수행하고 TDD·분해를 생략한다.

```bash
node scripts/px.js ws stage {slug} IMPL
```

---

## Step 2 — 작업 브랜치 확인

`ws create`가 이미 `origin/{base}` 기준으로 작업 브랜치를 만들어 뒀다. 브랜치가 없거나 다른
브랜치에 있으면 새로 만들지 말고 먼저 원인을 확인한다(작업 공간을 잘못 찾았을 가능성이 크다).
의도적으로 갈래를 추가해야 할 때만:

```bash
node scripts/px.js branch new {name} --base {base} --repo {repo}
```

base가 그사이 움직였다면 `work-sync`를 먼저 돌린다 — 오래된 base 위에서 구현하면 구현이 끝난
뒤에 충돌을 해결하게 된다.

---

## Step 3 — 개발 환경 기동 (필요할 때만)

```bash
node scripts/px.js env up --repo {repo}     # exit 3 → 정의 없음, skip
```

의존성 설치·로컬 서버가 필요한 변경에서만 부른다. `exit 3`이면 프로젝트가 그런 정의를 두지
않은 것이므로 **조용히 건너뛰고 진행**한다.

---

## Step 4 — Plan 순서대로 구현

Workflow tool 을 쓸 수 있고 **분해할 작업이 실제로 여럿이면** `kit/workflows/impl-phases.js` 로
이 단계를 돌린다 — 페이즈 경계(A→B→C) 순차 실행, **대상 파일이 겹치는 작업의 자동 직렬화**,
에이전트의 전체 테스트 실행 금지, 페이즈 끝 검사 1회가 코드로 강제된다. 분해가 애매하면 부르지
않는다 — **순차 구현이 기본값이다.** 없으면 아래 산문 절차를 그대로 수행한다(결과는 같고 강제가
없을 뿐이다).

`{paths.planFile}`의 단계를 순서대로 수행한다. 단계마다:

1. 그 단계가 **TDD 대상**이면 실패하는 테스트를 먼저 쓴다.
2. 구현한다. 스펙의 **확정 구현 방향**을 벗어나는 판단이 필요해지면 임의로 바꾸지 말고 멈춰서
   사용자에게 확인한다 — 방향은 설계 게이트에서 합의된 값이다.
3. 스펙의 **미합의 쟁점**에 해당하는 코드에 닿으면, 어떻게 처리했는지 커밋 메시지에 남긴다.

### 병렬 분해 (다중 도메인·레이어일 때만)

Plan의 단계들이 **파일 단위로 겹치지 않을 때만** 분해한다. 같은 파일을 두 작업자가 만지면
분해 이득보다 충돌 비용이 크다.

```
Phase A  도메인별 하위 레이어(서비스·저장소)  — 동시
Phase B  Phase A에 의존하는 상위 레이어(진입점·컨트롤러) — 동시
Phase C  시나리오 단위 통합                    — 마지막
```

각 작업자는 자기 파일 범위 안에서 **테스트 작성 → 구현 → 커밋**까지 끝낸다. 분해가 애매하면
분해하지 않는다 — 순차 구현이 기본값이다.

---

## Step 5 — 검사

```bash
node scripts/px.js run lint  --repo {repo}
node scripts/px.js run build --repo {repo}
```

- **전체 테스트 스위트는 여기서 돌리지 않는다.** 검증 스테이지(self-qa)에서 스코프를 한정해
  한 번만 실행한다 — 같은 테스트를 두 스테이지에서 돌리면 시간만 두 배로 들고, 실패를 누가
  책임지는지도 흐려진다.
- 단, **TDD로 방금 쓴 테스트**는 해당 대상만 좁혀 실행한다: `px run test --filter {대상}`.
- `run` 동사가 `exit 3`(정의 없음)이면 그 검사만 건너뛰고, **무엇을 건너뛰었는지 보고에 남긴다.**

---

## Step 6 — 커밋 + 보고

작업 단위별로 커밋한다(한 커밋 = 한 단계). 커밋 메시지에 작업 단위 ref를 포함한다.
**push·PR 생성은 이 스킬의 일이 아니다.**

```bash
node scripts/px.js notify send --event impl_done --text "{slug} — 구현 완료"
```

```
✅ implement 완료
   단계      : {완료 N} / {전체 N}
   변경 파일 : {N}개
   검사      : lint {통과|skip} · build {통과|skip}
   미해결    : {미합의 쟁점 처리 내역 또는 남은 항목}
   다음      : 검증 스테이지(self-qa) → code-review
```

Plan 단계를 전부 끝내지 못했으면 **완료로 보고하지 않는다** — 남은 단계와 이유를 명시한다.

---

## 어댑터가 채워야 하는 값

| 키 | 파일 | 의미 |
|---|---|---|
| `paths.specFile` / `paths.planFile` | `.review-kit.json` | 구현 입력(확정 방향·AC·단계·TDD 대상) |
| `stacks.{stack}.{lint,build,test,dev}` | `.pipeline.json` | `px run` / `px env`가 실제로 실행할 명령 |
| `repos[].stack` | `.pipeline.json` | repo별 스택 선택 |

## Reference

- `kit/contract/provider-contract.md` §2.4 `ws` · §2.6 `run` — `ws verify`의 `exit 2`, `run`의 `exit 3` 의미
- `kit/skills/spec/SKILL.md` — 확정 구현 방향·Plan을 만드는 앞 단계
- `kit/skills/code-review/SKILL.md` — 구현 이후 리뷰 스테이지
- `kit/workflow/guardrails.md` §2 · §4 — 실행 전 상태 확인 · 결함 클래스는 한 경로가 아니라 전 경로를 고친다
