---
name: release
description: Use to cut or refresh a release branch and its PR, and after that PR is merged, to tag the release. Every irreversible step requires explicit user confirmation; merging is always left to a human.
---

# release — 릴리스 브랜치·PR 준비 → (사람이 병합) → 태깅

> **되돌리기 어려운 동작만 모여 있는 스킬이다.** 버전 확정·push·PR 생성·태깅은 전부 **사용자 확인
> 없이 진행하지 않는다.** PR **자동 병합은 어떤 경우에도 하지 않는다** — 병합은 사람이 UI에서 한다.
>
> `Step 1~5 (릴리스 브랜치 + PR)` → **[사람: 병합]** → `Step 6 (태그)`

레포가 여럿이면 **레포마다 독립 처리**한다. 한 레포가 충돌로 막혀도 다른 레포는 계속 진행한다.

---

## Step 1 — 사전 확인
```bash
node scripts/px.js doctor                # 실패하면 중단
node scripts/px.js ws resolve --json     # 작업 공간 안이면 중단 — 레포 루트 세션 전용
```

토큰·설정이 불완전한 상태로 릴리스를 만들면 절반만 반영된 상태가 남는다.

---

## Step 2 — 상태 탐지 (레포별)

```bash
node scripts/px.js pr list --state open --target {release.target} --json
```

- source가 `{release.branchPattern}` 형태인 열린 PR이 **있으면 → 갱신 경로**
- 없으면 → **신규 경로**
- 둘 이상이면 어느 것인지 사용자에게 확인받고 진행한다.

현재 버전은 `release tags --limit 1`의 최신 태그에서 읽고, 없으면(`exit 3` 포함)
`{release.versionFile}`의 `{release.versionKey}`로 폴백한다(둘 다 없으면 `0.0.0`). 두 값이 어긋나면
**높은 쪽을 기준으로 삼고 보고한다** — 배포된 태그보다 낮은 버전을 새로 다는 사고를 막는다.

---

## Step 3 — 버전 확정 (신규 경로 · 사용자 확인 필수)

`{release.target}`에 아직 안 들어간 커밋의 제목 prefix를 집계해 bump를 **추천**한다.

| 근거 | 추천 |
|---|---|
| `BREAKING CHANGE` 또는 `!` suffix 포함 | major |
| `feat` 1건 이상 | minor |
| `fix`/`refactor`/`chore`만 | patch |

추천값과 근거(feat N건 · fix N건)를 함께 제시하고 **사용자에게 확정을 받는다.** 직접 입력받은 값은
SemVer(`x.y.z`)여야 하고 현재 버전보다 **커야 한다** — 아니면 사유를 설명하고 재입력을 받는다.
레포가 여럿이어도 질문은 **1회만** 한다. 갱신 경로 레포는 기존 릴리스 브랜치의 버전을 그대로 쓴다.

---

## Step 4 — 브랜치 준비

```bash
# 신규 — 릴리스 브랜치 생성
node scripts/px.js branch new {release.branchPattern} --base {release.source} --repo {repo} --json
# 갱신 — 기존 릴리스 브랜치를 체크아웃한 뒤 source를 병합
node scripts/px.js branch sync --target {release.source} --repo {repo} --json
```

`conflicts`가 비어 있지 않으면 **그 레포만** 중단한다 — 충돌 파일 목록을 보고하고 작업 사본은
보존한 뒤 다음 레포로 넘어간다. 이미 최신이면 push·PR 갱신을 건너뛰고 `이미 최신`으로 보고한다.

### 버전 bump + 변경 이력

1. `{release.versionFile}`의 버전을 확정 버전으로 수정 → 커밋 (`chore: bump version → {VERSION}`)
2. `{release.changelogFile}`이 **있을 때만** 상단에 `## [{VERSION}] — {YYYY-MM-DD}` 블록을 추가하고,
   그 아래 `### 신규 기능` / `### 버그 수정` / `### 리팩토링`으로 커밋을 분류한다. 항목이 없는
   분류는 섹션째 생략한다. 파일이 없으면 건너뛴다 — 문서를 새로 만들지 않는다.

커밋 후 `git push origin "{release.branch}:{release.branch}"` (명시 refspec).

---

## Step 5 — PR 생성 또는 갱신

**신규 경로** — 본문 초안을 사용자에게 보여주고 승인받은 뒤 생성한다.

```bash
node scripts/px.js pr create \
  --source "{release.branch}" --target "{release.target}" \
  --title "release: {VERSION}" --body "{승인받은 본문}" \
  --labels release --json
```

**갱신 경로** — `pr get`으로 현재 본문을 읽어, 기존 항목은 **보존**한 채 새 커밋만 해당 분류
섹션에 덧붙인 **전체 본문**을 넘긴다(계약은 append를 제공하지 않는다). 합친 본문도 승인을 받는다.

```bash
node scripts/px.js pr get {ref} --json                        # 현재 본문
node scripts/px.js pr update {ref} --body "{합친 본문}" --json
node scripts/px.js notify send --event released --text "release {VERSION} PR 준비" --url "{pr.url}"
```

여기서 **정지**한다. 병합은 사용자가 한다.

---

## Step 6 — 태깅 (병합 완료 후 · 별도 실행)

병합 여부를 먼저 확인한다 — `pr list --state open --target {release.target}`에 해당 릴리스 PR이
남아 있으면 그 레포는 **태깅을 건너뛰고** "병합 후 다시 실행" 안내만 한다.

```bash
node scripts/px.js release tags --repo {repo} --limit 5 --json          # 기존 태그 이름 규칙 확인
node scripts/px.js release tag {release.tagPattern} \
  --ref {release.target} --message "release: {VERSION}" --repo {repo} --json
node scripts/px.js release publish {release.tagPattern} \
  --name "{release.releaseNamePattern}" --body "{릴리스 노트}" --repo {repo} --json
```

- **태그 이름은 `release tags` 결과의 `v` prefix 규칙에 맞춘다.** 계약은 이름을 정규화하지
  않으므로, 여기서 어긋나면 규칙이 갈린 채 그대로 남는다.
- 릴리스 본문은 `{release.changelogFile}`의 `## [{VERSION}]` 블록. 없으면 PR 본문을 쓴다.
- 같은 이름이 이미 있으면 기존 객체가 돌아온다 — 성공으로 처리하고 `이미 존재`로 보고한다.
- `release tag`가 **`exit 2`** — 같은 이름 태그가 **다른 ref**를 가리킨다. **여기서 멈춘다.**
  태그를 옮기지 말고, 어긋난 ref 두 개를 사용자에게 보고한다.
- `exit 3` — 태그 개념이 없는 프로바이더다. 태그명·ref·본문을 출력하고 수동 처리를 안내한다.
- `release publish`는 태그가 **먼저 있어야** 한다. 순서를 바꾸지 않는다.

---

## 최종 보고

레포별 1행: `{repo} | 신규/갱신 | {x.y.z} | push ✅/⚠️충돌/— | PR #{ref} 생성/갱신/— | 태그 ✅/이미 존재/수동`.
충돌 레포는 보존된 작업 사본 경로와 충돌 파일 목록을 함께 안내한다.

## 어댑터가 채워야 하는 값

| 키 | 의미 |
|---|---|
| `release.source` / `release.target` | 릴리스를 따는 브랜치 / 병합 대상 (예: `develop` → `main`) |
| `release.branchPattern` | 릴리스 브랜치 이름 형식 (예: `release/{version}`) |
| `release.tagPattern` | 태그 이름 형식 — `v` prefix 유무를 기존 태그와 맞춘다 |
| `release.releaseNamePattern` | 릴리스 표시 이름 (태그명과 다를 수 있다, 예: 태그 `1.5.0` / 이름 `v1.5.0`) |
| `release.versionFile` / `release.versionKey` | 버전이 적힌 파일과 키 |
| `release.changelogFile` | 변경 이력 파일 (없으면 이력 갱신 skip) |

## Reference

- `kit/contract/provider-contract.md` §2.2 `pr` · §2.3 `branch` · §2.5 `notify` · §2.8 `doctor` · §2.9 `release`
- `kit/workflow/guardrails.md` §2(부수효과 전 상태 확인) · §3(사람의 최종 승인은 대체하지 않는다)
- `kit/skills/finish/SKILL.md` — 개별 작업 종료(릴리스와 별개 흐름)
