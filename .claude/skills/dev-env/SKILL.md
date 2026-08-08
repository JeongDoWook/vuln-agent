---
name: dev-env
description: Use to start or stop the local dev environment for the current workspace (dev servers, ports, logs). Thin wrapper over the provider contract — the skill only dispatches and reports.
---

# dev-env — 개발환경 기동/종료

포트 할당·의존 레포 준비·프로세스 관리 같은 **실제 로직은 계약 구현이 전담**한다. 이 스킬은
호출과 결과 보고만 한다 — 여기에 분기 로직을 넣기 시작하면 스택마다 스킬이 갈라진다.

---

## Step 1 — 위치 확인

```bash
node scripts/px.js ws resolve --json     # slug · repos · root
```

작업 공간 밖이면 위치를 안내하고 중단한다. 다른 작업 공간을 대상으로 하려면 사용자가 slug를
명시해야 하고, 그때는 `--repo`/`--cwd`로 대상을 지정해 호출한다.

---

## Step 2 — 기동 또는 종료

| 의도 | 명령 |
|---|---|
| 시작 ("개발환경 실행", "dev 띄워") | `node scripts/px.js env up --json` |
| 종료 ("개발 서버 내려", "stop") | `node scripts/px.js env down --json` |
| 특정 레포만 | 위 명령에 `--repo {id}` |

```bash
node scripts/px.js env up --json
```

반환:

```json
{ "started": ["be", "fe"], "urls": { "be": "http://localhost:8080", "fe": "http://localhost:5173" } }
```

- `exit 3` — 해당 스택에 `dev` 명령 정의가 없다. **추측해서 `npm run dev` 같은 걸 실행하지 않는다.**
  `.pipeline.json`의 `stacks.{stack}.dev`를 채우도록 안내하고 중단한다.
- `exit 1` — 포트 충돌·의존성 미설치 등. 원인을 보고하고, 같은 명령을 맹목적으로 재시도하지 않는다.
  이미 떠 있는 프로세스가 원인이면 `env down` 후 1회 재시도한다.

### 전용 탭에 띄우기 (선택)

장시간 붙잡는 프로세스라 멀티플렉서가 있으면 별도 탭으로 분리한다.

```bash
node scripts/px.js tab open dev-{slug} --cwd "{ws.root}"
```

프로바이더가 `none`이면 `{"skipped":true}`로 조용히 지나간다. **이 결과로 흐름을 바꾸지 않는다** —
탭이 없으면 현재 세션에서 그대로 띄운다.

---

## Step 3 — 보고

계약이 돌려준 URL·상태를 **그대로** 전달한다. 포트를 스킬이 추측해서 적지 않는다.

```
✅ dev-env 시작
   {repo}: {url}
   종료  : node scripts/px.js env down
```

종료 시:

```
✅ dev-env 종료 — {stopped[]}
```

---

## Non-Goals

- 테스트 실행 (→ `self-qa` Step 4의 `run test`)
- 빌드·배포 (→ `run build` · `release`)
- 개발 서버 로그를 근거로 한 디버깅 — 이 스킬은 기동/종료까지다

---

## 어댑터가 채워야 하는 값

| 키 | 의미 |
|---|---|
| `stacks.{stack}.dev` | 개발 서버 실행 명령 (`.pipeline.json`) — 없으면 `env up`이 `exit 3` |
| `stacks.{stack}.install` | 의존성 설치 명령 (구현이 필요할 때 선행 실행) |
| `providers.mux` | 전용 탭 사용 여부 (`none`이면 탭 단계 자동 skip) |

## Reference

- `kit/contract/provider-contract.md` §2.6 `run`/`env` · §2.7 `tab` · §3 `.pipeline.json`
- `kit/workflow/guardrails.md` §2 — 실패 시 맹목적 재시도 금지
