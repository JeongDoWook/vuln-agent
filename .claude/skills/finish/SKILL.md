---
name: finish
description: Use after the PR has been merged — verifies merge state, gets explicit user confirmation, closes the issue, then removes the workspace. Never deletes review/QA artifacts.
---

# finish — 이슈 종료 → 작업공간 정리

> 🚨 **정리는 되돌릴 수 없다.** 이 스킬의 모든 파괴적 동작은 (a) 병합 확인, (b) 사용자 명시 승인
> 두 관문을 통과한 뒤에만 실행된다. 순서를 바꾸거나 하나를 생략하지 않는다.

---

## Step 1 — 진입 게이트 (read-only)

```bash
node scripts/px.js ws resolve --json                       # slug · issue · repos · branch
node scripts/px.js pr get --source "{branch}" --json       # state 확인
node scripts/px.js ws verify {slug} --json                 # 미푸시 커밋·불일치 검사
```

| 조건 | 처리 |
|---|---|
| `pr.state == "merged"` | 진행 |
| `pr.state == "open"` / `"closed"` | **중단** — "PR이 아직 병합되지 않았습니다. 병합 후 다시 실행하세요." |
| `pr get`이 `exit 3` (PR 미지원 트래커) | 사용자에게 "병합이 끝났는지" 직접 확인받고 진행 |
| `ws verify`가 `exit 2` | **중단** — 커밋 안 된 변경·push 안 된 커밋이 있다. 목록을 보고한다 |

멀티레포 작업 공간이면 **레포마다** 위 판정을 반복한다. 하나라도 미병합이면 전체를 중단한다
(레포 단위로 부분 정리하려면 사용자가 명시적으로 그 레포를 지정해야 한다).

---

## Step 2 — 🔴 사용자 확인 (자동 진행 금지)

Step 1이 전부 통과하면 아래 블록을 **그대로 보여주고 명시적 승인**을 받는다.
승인 전에는 `issue close`도 `ws close`도 실행하지 않는다.

```
아래를 정리합니다. 진행할까요?

  작업공간 : {ws.slug}   ({ws.root})
  이슈     : #{ws.issue} → closed
  대상 레포 : {repo}({branch}) …

  [삭제]  {repo.dir}                      ← 작업 클론/워크트리
  [보존]  {paths.reviewOutDir} · {paths.qaOutDir} · 스펙/설계/리뷰 산출물 전부
```

> **slug는 `ws resolve`가 반환한 값을 그대로 쓴다.** 스스로 추측하거나 축약하지 않는다 —
> 부분문자열 매칭으로 엉뚱한 작업 공간을 지운 사고가 실제로 있었다. 계약은 정확 매칭만 허용하며,
> 못 찾으면 `exit 1`로 멈춘다.

---

## Step 3 — 이슈 종료

```bash
node scripts/px.js issue close {ws.issue} --yes --json
```

- 멱등이다. 이미 closed면 성공으로 처리한다.
- `exit 2`(`--yes` 없이 호출)는 이 스킬의 버그다 — 플래그를 확인하고 재실행한다.
- `exit 1`(네트워크·권한)이면 **여기서 멈춘다.** 이슈가 열린 채로 작업 공간만 지우면
  추적 단서가 사라진다. 정리는 이슈 종료 다음이다.

---

## Step 4 — 작업공간 정리

```bash
node scripts/px.js ws close {ws.slug} --yes --json          # 전체
node scripts/px.js ws close {ws.slug} --yes --repo {repo}   # 특정 레포만
```

반환된 `removed[]`를 그대로 보고한다. 직접 `rm -rf`·`git worktree remove`를 실행하지 않는다 —
경로 안전 가드는 계약 구현 안에 있고, 스킬이 우회하면 그 가드가 무의미해진다.

### 산출물은 지우지 않는다

스펙·설계 리뷰·`review.json`/`report.json`·`qa.json`과 렌더된 HTML은 **감사 기록**이다.
`ws close`가 소스 클론을 지운 뒤에도 이 파일들은 남아야 한다. 어댑터의
`paths.*OutDir`가 작업 클론 **내부**를 가리키고 있으면, 정리 전에 `{paths.archiveDir}`로
옮긴 뒤 진행하고 그 사실을 보고한다.

---

## Step 5 — 마무리

```bash
node scripts/px.js notify send --event work_done --text "{issue} 완료 — {pr.url}"
node scripts/px.js tab done {ws.slug}
```

둘 다 **실패해도 진행한다.** 알림은 부수 효과고, 터미널 탭 정리는 프로바이더가 `none`이면
`{"skipped":true}`로 조용히 지나간다.

```
✅ finish 완료
   이슈 #{issue} closed  ·  PR #{pr.ref} merged
   삭제 : {removed[]}
   보존 : {산출물 경로}
```

---

## 어댑터가 채워야 하는 값

| 키 | 의미 |
|---|---|
| `paths.reviewOutDir` / `paths.qaOutDir` | 보존 대상 산출물 경로 |
| `paths.archiveDir` | 산출물이 작업 클론 내부에 있을 때 옮길 위치 |
| `notify.doneEvent` | 완료 알림 이벤트 이름 (미등록이면 자동 skip) |

## Reference

- `kit/contract/provider-contract.md` §2.1 `issue` · §2.4 `ws` — 파괴적 동사의 `--yes` 규칙
- `kit/workflow/guardrails.md` §2 — 부수효과 명령 실행 전 상태 확인
- `kit/skills/submit/SKILL.md` — 이 스킬의 선행 단계
