# 프로바이더 계약 — 스킬과 외부 시스템 사이의 유일한 경계

> **이 문서가 SSOT다.** 라이프사이클 스킬(`kit/skills/*`)은 GitLab·GitHub·Slack·터미널을
> **직접 만지지 않는다.** 아래 동사만 호출하고, 그 동사를 무엇이 수행하는지는
> `.pipeline.json`이 정한다. 트래커를 GitLab에서 GitHub으로 바꿔도 **스킬 본문은 한 줄도 바뀌지 않는다.**

```
kit/skills/*          "px issue get 123"           ← 스킬은 이 문장만 안다
       │
       ▼
scripts/px.js         계약 진입점 · 인자 파싱 · 종료코드
       │
       ▼
scripts/lib/provider/index.js    .pipeline.json 을 읽어 구현을 고른다
       │
       ├─ tracker/    gitlab.js · github.js · local.js
       ├─ notify/     slack.js · none.js
       ├─ workspace/  clone.js · worktree.js
       └─ mux/        cmux.js · tmux.js · none.js
```

---

## 1. 호출 규약

```bash
node scripts/px.js <group> <verb> [args...] [--flag value] [--json]
```

- **stdout** — 기계 판독용 **JSON 한 덩어리만**. 그 외 아무것도 쓰지 않는다.
- **stderr** — 사람이 읽을 진행/경고 메시지. 스킬은 이걸 파싱하지 않는다.
- **종료 코드**
  | 코드 | 의미 |
  |---|---|
  | `0` | 성공 |
  | `1` | 사용법·설정·네트워크 오류 (재시도 가능) |
  | `2` | **계약/게이트 위반** — 진행하면 안 되는 상태(예: 대상 브랜치 드리프트, 미승인 게이트). 스킬은 이걸 받으면 **멈추고 사용자에게 보고한다** |
  | `3` | 이 프로바이더가 해당 동사를 지원하지 않음 (예: `local` 트래커의 `pr merge`) — 스킬은 대체 경로로 폴백하거나 사용자에게 수동 처리를 요청한다 |

- 모든 동사는 **멱등**해야 한다. 이미 만들어진 것을 다시 만들라고 하면 성공으로 처리하고
  기존 객체를 반환한다(에러 아님). 워커가 중복 실행돼도 안전해야 하기 때문이다.
- **파괴적 동사**(`ws close`, `pr merge`, `issue close`)는 `--yes` 없이는 실행하지 않고
  `exit 2`와 함께 무엇을 지울지 출력한다.
- **멱등성이 `--yes`보다 먼저다.** 대상이 **이미 그 상태**면(닫힌 이슈를 `issue close`,
  병합된 MR을 `pr merge`) `--yes` 없이도 `exit 0` + 기존 객체를 반환한다. 여기서 `exit 2`를
  주면 재실행하는 워커가 매번 막히는데, 정작 지울 것은 남아 있지 않다. `--yes`는
  **상태를 실제로 바꿀 때만** 요구한다.

### 공통 응답 봉투

```json
{ "ok": true,  "verb": "issue.get", "provider": "gitlab", "data": { ... } }
{ "ok": false, "verb": "issue.get", "provider": "gitlab", "error": { "code": "not_found", "message": "..." } }
```

- `error.message` 는 사람이 읽을 한 줄이다. **스킬은 이걸 파싱하지 않는다** — 분기는 `error.code` 로만 한다.
- `error.data` 는 선택 필드로, **구조화된 부가 정보**를 담는다. 파괴적 동사가 `--yes` 없이
  거부될 때 "무엇을 바꾸려 했는지"가 여기 들어간다. 사람이 읽을 문장에만 담으면
  스킬이 확인 프롬프트를 만들 수 없다.

```json
{ "ok": false, "verb": "issue.close", "provider": "gitlab",
  "error": { "code": "confirmation_required",
             "message": "issue.close 는 파괴적 동사다 — --yes 없이는 실행하지 않는다.",
             "data": { "ref": "123", "title": "...", "url": "https://...", "willBecome": "closed" } } }
```

- `provider` 는 **실패했을 때도 채운다.** 어떤 프로바이더가 그 동사를 거부했는지가
  폴백 경로를 고르는 근거이기 때문이다(예: `exit 3` 을 준 게 `local` 인지 `github` 인지).

---

## 2. 동사 목록

### 2.1 `issue` — 작업 단위

| 동사 | 인자 | data 반환 |
|---|---|---|
| `issue get <ref>` | — | `Issue` |
| `issue create` | `--title` `--body` `[--labels a,b]` `[--assignee]` `[--milestone]` | `Issue` |
| `issue update <ref>` | `[--title]` `[--body]` `[--add-labels]` `[--remove-labels]` `[--assignee]` `[--milestone]` | `Issue` |
| `issue close <ref>` | `--yes` | `Issue` |
| `issue list` | `[--state open\|closed\|all]` `[--labels]` `[--milestone]` `[--limit]` | `Issue[]` |

```jsonc
// Issue
{ "ref": "123",              // 프로바이더 내 식별자(문자열). GitLab=iid, GitHub=number, local=파일명
  "title": "...", "body": "...",
  "state": "open|closed",
  "labels": ["..."], "assignee": "..." , "milestone": "..." ,
  "url": "https://...",      // 없으면 null
  "repo": "be" }             // 멀티레포일 때 어느 레포의 이슈인지
```

### 2.2 `pr` — 병합 요청 (GitLab MR · GitHub PR 통일 명칭)

| 동사 | 인자 | data |
|---|---|---|
| `pr create` | `--source` `--target` `--title` `--body` `[--draft]` `[--assignee]` `[--labels]` | `PR` |
| `pr get <ref>` | 또는 `--source <branch>` | `PR` |
| `pr update <ref>` | `[--title]` `[--body]` `[--target]` `[--draft]` `[--add-labels]` `[--remove-labels]` | `PR` |
| `pr list` | `[--state]` `[--target]` | `PR[]` |
| `pr merge <ref>` | `--yes` `[--strategy merge\|squash\|rebase]` | `PR` |

> `pr update`는 **주어진 필드만** 바꾼다. `--body`를 생략하면 본문은 손대지 않는다. 본문을 부분
> 갱신하려면 호출자가 `pr get`으로 현재 본문을 읽어 합친 뒤 전체를 넘긴다 — 계약은 append를
> 제공하지 않는다(마크다운 섹션 구조를 프로바이더가 해석하면 안 되기 때문).

- **`--strategy`는 프로바이더마다 지원 범위가 다르다.** 지원하지 않는 전략을 받으면 흉내내지
  말고 `exit 3`으로 답한다. 스킬은 그걸 받아 다른 전략으로 재시도하거나 수동 병합을 요청한다.
  실측 — GitHub은 `merge|squash|rebase` 셋 다 요청 단위로 받지만, **GitLab의 rebase-merge는
  프로젝트 설정(`merge_method`)이지 요청 파라미터가 아니다.** GitLab에서 `--strategy rebase`는
  `exit 3`이 정답이고, 이걸 "rebase 후 merge" 두 번 호출로 대신하면 계약이 약속한 원자성이 깨진다.
  전략을 생략하면 프로바이더/프로젝트의 기본 병합 방식을 따른다.
- **`--draft`는 상태이지 반드시 별도 필드는 아니다.** 프로바이더가 draft 파라미터를 제공하지
  않으면 그 프로바이더의 관례로 표현한다 — GitLab MR create API에는 draft 인자가 없고
  제목의 `Draft: ` 접두사가 곧 draft 상태다. 어느 쪽이든 반환하는 `PR.draft`는 **불리언으로
  정규화**한다(`iid`→`ref`와 같은 이유). 스킬은 제목 문자열로 draft를 판별하면 안 된다.

```jsonc
// PR
{ "ref": "45", "title": "...", "state": "open|merged|closed",
  "source": "feature/issue-123-x", "target": "develop",
  "url": "https://...", "draft": false, "repo": "be" }
```

### 2.3 `branch` — 브랜치·동기화

| 동사 | 인자 | data |
|---|---|---|
| `branch resolve-target` | `[--repo]` | `{ "target": "develop", "reason": "repos[].base" }` |
| `branch new <name>` | `--base <ref>` `[--repo]` | `{ "name": "...", "base": "...", "head": "<sha>" }` |
| `branch sync` | `[--repo]` `[--target]` | `{ "target": "...", "merged": true, "conflicts": [] }` — origin/target fetch + merge |
| `branch drift-check` | `[--repo]` `[--target]` | `{ "drifted": false, "ahead": 0, "behind": 0 }` — **드리프트면 `exit 2`** |

> `branch drift-check`가 `exit 2`면 **push·PR 생성으로 진행하지 않는다.** 호스트의
> `mx.js wt-push validate`가 하던 역할이다.

### 2.4 `ws` — 작업 공간 (병렬 세션 격리의 핵심)

| 동사 | 인자 | data |
|---|---|---|
| `ws create <slug>` | `--issue <ref>` `[--repo r1,r2]` | `Workspace` |
| `ws verify <slug>` | — | `{ "ok": true, "checks": [ { "name":"head-matches-origin", "ok":true } ] }` — **불일치면 `exit 2`** |
| `ws stage <slug> <STAGE>` | — | `Workspace` (STAGE: `SPEC\|IMPL\|QA\|REVIEW\|PR\|DONE`) |
| `ws resolve` | `[--cwd]` | `Workspace` — 현재 디렉터리가 속한 작업 공간 |
| `ws list` | — | `Workspace[]` |
| `ws close <slug>` | `--yes` `[--repo]` | `{ "removed": ["..."] }` |

```jsonc
// Workspace
{ "slug": "0807-asset-tag", "issue": "123",
  "root": "wt/0807-asset-tag",
  "mode": "clone|worktree",
  "stage": "IMPL",
  "repos": [ { "id":"be", "dir":"wt/0807-asset-tag/be-123",
               "branch":"feature/issue-123-asset-tag", "base":"develop" } ] }
```

**`ws create`가 반드시 보장하는 것** — 이게 병렬 세션이 안 겹치는 근거다:

1. 각 레포 작업 디렉터리는 **`origin/{base}` 시점에서 생성**한다. 로컬 브랜치 기준 금지.
2. 생성 직후 `HEAD == origin/{base}`를 검증한다. 다르면 `exit 2`.
3. `mode: "clone"` — 레포마다 독립 `.git`. 한 세션의 파괴적 git 명령이 다른 세션에 닿지 않는다. **기본값.**
4. `mode: "worktree"` — `.git` 오브젝트 저장소를 공유해 디스크·시간을 아낀다. 작업 파일과
   브랜치는 여전히 완전 격리되지만(같은 브랜치의 이중 체크아웃은 git이 막는다),
   `gc`·`reset --hard`·reflog 조작은 **다른 워크트리에 영향을 준다.** 단일레포 + 대용량
   저장소에서만 선택한다.

### 2.5 `notify` — 알림

| 동사 | 인자 | data |
|---|---|---|
| `notify send` | `--event <name>` `--text <t>` `[--url]` `[--level info\|warn\|error]` | `{ "sent": true, "channel": "..." }` |

- `.pipeline.json`의 `notify.events`에 없는 이벤트는 **조용히 skip하고 `ok:true, sent:false`** 를 반환한다.
- 프로바이더가 `none`이면 항상 `sent:false`. **스킬은 알림 실패로 멈추지 않는다** — 알림은 부수 효과다.

### 2.6 `run` — 스택별 명령

| 동사 | 인자 | data |
|---|---|---|
| `run test` | `[--repo]` `[--filter]` | `{ "command":"...", "exitCode":0, "durationMs":0 }` |
| `run build` | `[--repo]` | 〃 |
| `run lint` | `[--repo]` | 〃 |
| `env up` / `env down` | `[--repo]` | `{ "started": ["be","fe"], "urls": {...} }` |

명령 문자열은 `.pipeline.json`의 `stacks.{stack}.{verb}`에서 온다. 정의가 없으면 `exit 3`.

### 2.7 `tab` — 터미널 멀티플렉서 (선택)

| 동사 | 인자 |
|---|---|
| `tab open <label>` | `[--cwd]` `[--cmd]` |
| `tab done <label>` / `tab kill <label>` | — |

프로바이더가 `none`이면 전부 `exit 0` + `{"skipped":true}`. **스킬은 이걸로 흐름을 바꾸지 않는다.**

### 2.8 `doctor` — 설정 진단

```bash
node scripts/px.js doctor
```

프로바이더별로 설정·토큰·연결을 점검하고 표를 출력한다.
**설치 직후 가장 먼저 돌리는 명령이며, 어떤 스킬도 이게 통과하기 전에는 신뢰할 수 없다.**

점검 결과는 세 가지다. 종료 코드는 **`fail`이 하나라도 있으면 `exit 1`**, 아니면 `exit 0`이다.

| 상태 | 뜻 | exit 반영 |
|---|---|---|
| `ok` | 설정·토큰·연결 확인됨 | — |
| `fail` | 고쳐야 동작한다 (토큰 없음, 연결 거부, 필수 설정 누락) | **`exit 1`** |
| `missing` | `providers.*`가 고른 구현 모듈이 아직 없다 | 없음 |

`missing`을 실패로 치지 않는 이유 — 이 계약은 tracker·workspace·notify·mux·run으로 나뉘어
**따로 구현·설치**된다. tracker만 붙인 프로젝트에서 `run` 구현이 없다고 `exit 1`을 주면
doctor는 영원히 빨간불이고, 그러면 아무도 안 보게 된다. 없는 구현의 동사를 실제로 부르면
그때 `exit 3`이 나오므로 신호는 잃지 않는다.

### 2.9 `release` — 태그·릴리스

| 동사 | 인자 | data |
|---|---|---|
| `release tags` | `[--repo]` `[--limit]` `[--pattern]` | `Tag[]` — 버전 내림차순 |
| `release tag <name>` | `--ref <branch\|sha>` `[--message]` `[--repo]` | `Tag` |
| `release publish <tag>` | `--name` `--body` `[--repo]` | `Release` |
| `release get <tag>` | `[--repo]` | `Release` |

```jsonc
// Tag
{ "name": "1.5.0", "ref": "main", "sha": "abc1234",
  "message": "release: 1.5.0",       // annotation. lightweight면 null
  "createdAt": "2026-08-07T00:00:00Z", "repo": "be" }

// Release
{ "tag": "1.5.0", "name": "v1.5.0", "body": "...",
  "url": "https://...", "repo": "be" }
```

- **태그 이름을 정규화하지 않는다.** `v` prefix 유무는 프로젝트 규칙이므로 받은 문자열을 그대로
  쓴다. `release tags`도 **원본 이름을 그대로** 돌려주고, `pattern`으로 거르기만 한다 —
  SemVer 정렬을 위해 내부적으로 `v`를 떼는 건 프로바이더 사정이고, `name`에 반영하면 안 된다.
- **멱등이되 덮어쓰지 않는다.** 같은 이름의 태그·릴리스가 이미 있으면 **기존 객체를 반환하고
  `ok:true`** 로 끝낸다. 다른 `ref`를 가리키고 있어도 **이동시키지 않는다** — 이미 배포된 태그를
  옮기면 그 태그를 받아간 모든 곳이 조용히 어긋난다. ref 불일치는 `exit 2`로 보고한다.
- 태그 생성과 릴리스 발행은 **별개 동사**다. 태그만 필요한 프로젝트가 있고, 릴리스 노트 본문은
  태그 annotation과 수명이 다르기 때문이다. `release publish`는 대상 태그가 **이미 있어야** 한다.
- 태그·릴리스 개념이 없는 프로바이더(`local` 등)는 전부 `exit 3`.

---

## 3. `.pipeline.json` — 프로바이더 선택과 프로젝트 사실

`.review-kit.json`(리뷰 방법론 어댑터)과 **별개 파일**이다. 리뷰만 쓰는 프로젝트는
`.pipeline.json` 없이도 동작하고, 라이프사이클 스킬을 쓸 때만 필요하다.

```jsonc
{
  "providers": {
    "tracker":   "gitlab",     // gitlab | github | local
    "notify":    "none",       // slack | none
    "workspace": "clone",      // clone | worktree
    "mux":       "none"        // cmux | tmux | none
  },

  "tracker": {
    "gitlab": { "host": "https://gitlab.example.com", "tokenEnv": "GITLAB_TOKEN" },
    "github": { "host": "https://api.github.com", "owner": "org", "tokenEnv": "GITHUB_TOKEN",
                "tokenCommand": "gh auth token" },   // 선택 — 아래 "토큰 출처" 참고
    "local":  { "dir": ".pipeline/issues" }
  },

  "notify": {
    "slack": { "webhookEnv": "SLACK_WEBHOOK_URL",
               "events": ["pr_created", "review_blocked", "released"] }
  },

  "workspace": {
    "root": "wt",
    "dirPattern": "{MMDD}-{slug}",
    "repoDirPattern": "{repo}-{issue}",
    "branchPattern": "feature/issue-{issue}-{slug}"
  },

  "repos": [
    { "id": "be", "project": "org/app-be", "remote": "git@...:org/app-be.git",
      "base": "develop", "stack": "java-gradle" }
  ],

  "stacks": {
    "java-gradle": { "test": "./gradlew test", "build": "./gradlew build", "dev": "./gradlew bootRun" },
    "node-vite":   { "test": "npm test", "build": "npm run build", "dev": "npm run dev",
                     "install": "npm ci" }
  }
}
```

**비밀값은 이 파일에 넣지 않는다.** `.pipeline.json`은 커밋 대상이고, 토큰은 아니기 때문이다.

### 토큰 출처 — 어댑터가 선언한 두 가지뿐

| 키 | 의미 | 우선순위 |
|---|---|---|
| `<x>Env` | 토큰이 든 **환경변수 이름** | 1 — 값이 있으면 이걸 쓴다 |
| `<x>Command` | 토큰을 stdout으로 뱉는 **명령** (예: `gh auth token`) | 2 — 환경변수가 비었을 때만 |

`tokenCommand`를 둔 이유는, 토큰이 이미 다른 도구의 자격증명 저장소(`gh` keyring, 사내 vault CLI)에
있는 프로젝트가 흔하기 때문이다. 그걸 환경변수로 **한 벌 더 복사해 두라고 요구하면** 토큰 사본이
셸 설정·CI 변수로 흩어지고, 만료·회수 때 어디를 지워야 하는지 아무도 모르게 된다.

반대로 "`gh`가 깔려 있으면 알아서 쓴다"는 **암묵 폴백은 하지 않는다.** 그러면 어떤 자격증명으로
외부에 나갔는지가 설정 어디에도 안 남는다. 어댑터가 명시로 적었을 때만 실행한다.

- 환경변수가 먼저인 이유: CI나 일회성 실행이 어댑터 기본값을 이길 수 있어야 한다.
- 명령은 **셸을 거치지 않는다**(공백으로 쪼개 그대로 실행). 셸을 거치면 어댑터 한 줄이 임의 셸 구문이 된다.
- stdout은 로그·에러 메시지 어디에도 싣지 않는다 — 그게 토큰 본문이다.
- `px doctor`는 값이 아니라 **출처**를 표시한다(`환경변수 GITHUB_TOKEN 에서 읽음` / `명령 'gh auth token' 에서 읽음`).
- 해석은 `scripts/lib/provider/index.js`의 `resolveSecret` **한 곳**에서만 한다. `release/*`도 같은
  함수를 부른다 — 예전엔 거기서 `process.env`를 직접 읽어서, 출처가 늘 때마다 그쪽만 조용히 뒤처졌다.

---

## 4. 구현자가 지켜야 하는 것

- **의존성 0.** Node 내장 모듈만 쓴다(`https`·`child_process`·`fs`·`path`). 이 저장소 전체 규칙이다.
- **프로바이더 모듈은 서로를 모른다.** `tracker/github.js`가 `tracker/gitlab.js`를 참조하면 안 된다.
  공통 로직은 `lib/provider/http.js` 같은 중립 모듈로 뺀다.
- **미지원 동사는 던지지 말고 `exit 3`** 으로 표현한다. 예: `local` 트래커에는 `pr merge`가 없다.
- 응답 `data`의 필드 이름은 위 스키마를 따른다. GitLab의 `iid`, GitHub의 `number`를
  **각자 `ref`로 정규화**하는 것이 프로바이더의 책임이다 — 스킬이 프로바이더별 필드를 알면 계약이 깨진다.

### 4.1 모듈 인터페이스 (필수)

프로바이더 모듈은 **동사 맵을 export** 한다. 최상위에 함수를 펴놓기만 하면 진입점이 찾지 못한다.

```js
module.exports = {
  id: 'gitlab',
  verbs: {
    'issue.get':    (ctx, positional, flags) => Promise<data>,
    'issue.create': (ctx, positional, flags) => Promise<data>,
  },
  doctor: (ctx) => Promise<Array<{ name, status, detail }>>,   // 선택
};
```

- 키는 **`<group>.<verb>` 문자열 그대로**다(`ws.create`, `branch.drift-check`).
- `ctx` = `{ config, repoRoot, log }`. `log`는 stderr 출력용 — stdout에 쓰면 봉투가 깨진다.
- `doctor`가 없어도 된다. 있으면 `px doctor`가 결과에 합친다.

### 4.2 에러 규약 (필수)

**프로바이더 모듈은 진입점을 import 하지 않는다** — 서로를, 그리고 `px.js`를 몰라야 하기 때문이다.
그래서 예외는 **평범한 `Error`에 아래 필드를 얹어** 던진다. 진입점이 그걸 그대로 흡수한다.

```js
const e = new Error('--yes 가 없어 삭제하지 않았습니다');
e.code = 'confirmation_required';   // 봉투의 error.code — 스킬은 이걸로만 분기한다
e.exitCode = 2;                     // 계약 §1의 종료 코드
e.data = { wouldRemove: [...] };    // 봉투의 error.data — 구조화된 부가 정보
throw e;
```

| 필드 | 없으면 |
|---|---|
| `code` | `"internal"` 로 떨어진다 — **스킬이 분기할 수 없게 되므로 반드시 채운다** |
| `exitCode` | `1`로 떨어진다. 거부(2)·미지원(3)은 **반드시 명시**한다 |
| `data` | 생략 가능. 단 파괴적 동사의 거부에는 "무엇을 바꾸려 했는지"를 넣는다 |

> **이 절이 없어서 실제로 결함이 났다(2026-08-07).** 진입점은 자체 에러 클래스를 만들고
> 워크스페이스 모듈은 `e.exitCode`를 얹는 방식을 택했는데, 진입점이 자기 클래스가 아닌 에러의
> `code`/`exitCode`/`data`를 버리고 전부 `internal`+`exit 1`로 뭉갰다. 그 결과
> **`ws close`가 `--yes` 없이도 `exit 0`으로 통과**했고, 지울 목록도 사라졌다.
> 계약이 응답 봉투만 정하고 **모듈이 그 봉투를 어떻게 채우는지**를 안 정하면 이런 구멍이 생긴다.

## Reference

- `scripts/px.js` — 계약 진입점
- `scripts/lib/provider/index.js` — 설정 → 구현 해석
- `example-adapter/.pipeline.json` — 채워진 예시
- `kit/workflow/guardrails.md` §2 — 부수효과 명령 실행 전 상태 확인(파괴적 동사 `--yes` 규칙의 근거)
