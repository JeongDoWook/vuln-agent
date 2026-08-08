---
name: work-sync
description: Use when the base branch has moved and the working branch needs to catch up — before starting implementation, before review, and always before opening a PR. Resolves each repo's real base branch through the provider contract, merges it into the working branch, and stops on conflict or drift instead of pushing.
---

# work-sync — 작업 브랜치를 base 최신 상태로 맞춘다

> `px` = `node scripts/px.js`. 종료코드 `2`는 **정지 후 보고**, `3`은 **수동 처리 요청 후 계속**.

> 🚨 **base가 무엇인지 추측하지 않는다.** 작업 브랜치는 `origin/{base}` 시점에서 `--no-track`으로
> 생성되므로 upstream이 남아 있지 않고, base는 repo마다 다를 수 있다(한쪽은 개발 브랜치,
> 다른 쪽은 마일스톤 브랜치). base 판정은 반드시 `branch resolve-target`에 맡긴다 —
> **한 브랜치를 병합해놓고 다른 브랜치로 PR을 여는 사고**가 여기서 갈린다.

---

## Step 1 — 대상 확인

```bash
node scripts/px.js ws resolve --cwd . --json
```

현재 디렉터리가 속한 작업 공간의 `repos[]`가 대상이다. `ws resolve`가 실패하면 작업 공간 밖이므로
slug를 사용자에게 확인한 뒤 `ws list`로 대상을 특정한다. 아래 Step 2~4는 **repo마다 개별 반복**한다.

---

## Step 2 — base 브랜치 판정

```bash
node scripts/px.js branch resolve-target --repo {repo} --json
# → { "target": "...", "reason": "repos[].base | open PR target | merge-base 추론" }
```

- `reason`이 설정값(`repos[].base`)이 아닌 **추론**이면, 판정 결과와 근거를 사용자에게 한 줄로
  노출한다 — 조용히 병합하지 않는다.
- 사용자가 base를 명시했으면 그 값을 우선한다(`--target {branch}`).

---

## Step 3 — 동기화

```bash
node scripts/px.js branch sync --repo {repo} --target {target} --json
# → { "target": "...", "merged": true, "conflicts": [] }
```

`branch sync`가 보장하는 순서(구현 세부는 프로바이더 몫, 스킬은 결과만 읽는다):
원격 fetch(prune 포함) → base 존재 확인 → 이미 포함돼 있으면 skip → **merge** → merge-base 재검증.

- **rebase는 쓰지 않는다.** 작업 브랜치는 이미 공유·푸시됐을 수 있고, 이력을 다시 쓰면 리뷰에서
  본 diff와 PR의 diff가 달라진다.
- **push하지 않는다.** 이 스킬은 로컬 병합까지만이다.

---

## Step 4 — 충돌 처리

`conflicts`가 비어있지 않으면 **그 repo에서 멈춘다.** 충돌 파일 목록을 그대로 보여주고 해결을
요청한다. 자동 해결·`--theirs`류 일괄 선택·되돌리기를 시도하지 않는다 — 어느 쪽이 맞는지는
요구사항을 아는 사람만 판단할 수 있다.

```
❌ {repo} 병합 충돌 — {N}개 파일
   • {path}
   해결 후 다시 /work-sync 를 호출하면 나머지 repo부터 이어갑니다.
```

다른 repo는 계속 처리한다 — 한 repo의 충돌이 나머지 repo의 동기화를 막을 이유는 없다.

---

## Step 5 — 드리프트 확인 (PR 직전 필수)

```bash
node scripts/px.js branch drift-check --repo {repo} --target {target} --json
```

`exit 2`(드리프트)면 **push·PR 생성으로 진행하지 않는다.** Step 2로 돌아가 다시 동기화하고,
재차 드리프트가 나면 base 판정이 잘못됐을 가능성을 먼저 의심해 사용자에게 확인한다.

---

## Step 6 — 보고

```
✅ work-sync 완료
   {repo}  base={target} ({reason})  {merged|이미 최신}
   {repo}  ❌ 충돌 {N}건 — 수동 해결 필요
```

충돌이 하나라도 있으면 **완료로 보고하지 않는다.** 어떤 repo가 남았는지 명시한다.

---

## 어댑터가 채워야 하는 값

| 키 | 파일 | 의미 |
|---|---|---|
| `repos[].base` | `.pipeline.json` | repo별 기본 base 브랜치 (판정 1순위 근거) |
| `providers.workspace` | `.pipeline.json` | clone / worktree — 동기화 대상 디렉터리 구조 결정 |

## Reference

- `kit/contract/provider-contract.md` §2.3 `branch` — `resolve-target` / `sync` / `drift-check` 계약과 `exit 2` 규칙
- `kit/workflow/guardrails.md` §2 — 실패한 명령을 맹목적으로 재시도하지 않는다
