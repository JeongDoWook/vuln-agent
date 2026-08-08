---
name: work-start
description: Use at the very beginning of a task — a loose one-line request, a ticket reference, or a workspace whose local clone is missing. Classifies the change size, secures the work unit through the provider contract, provisions an isolated workspace verified against origin, and hands off to requirement-fanout / spec / implement.
---

# work-start — 작업 단위 확보 + 격리된 작업 공간 생성

> 이 문서에서 `px` 는 `node scripts/px.js` 의 줄임말이다. 스킬은 트래커·git 호스팅을 직접 만지지
> 않고 **계약 동사만** 호출한다(`kit/contract/provider-contract.md`).
> 공통 종료코드 처리: `2` = 계약/게이트 위반 → **즉시 멈추고 사용자에게 보고**,
> `3` = 프로바이더 미지원 → **사용자에게 수동 처리를 요청하고 그 결과를 입력받아 계속 진행**한다.
> 트래커가 `local`이거나 아예 없어도 이 스킬은 끝까지 동작해야 한다.

---

## Step 1 — 사전 점검

```bash
node scripts/px.js doctor
node scripts/px.js ws resolve --cwd . --json    # 이미 작업 공간 안이면 Workspace 반환
```

- `ws resolve`가 성공하면 **이미 작업 공간 안**이다 → 신규 생성 대신 Step 6(복구)으로 간다.
- `doctor` 실패는 치명적이다 — 어떤 동사도 신뢰할 수 없으므로 원인을 보고하고 멈춘다.

---

## Step 2 — 입력 파싱

| 항목 | 추출 규칙 |
|---|---|
| 기존 작업 단위 참조 | 입력에 `#N` / `이슈 N` / `{ref}` 형태가 있으면 신규 생성 없이 `issue get` |
| 대상 repo | 어댑터 `repos[]` 중 명시된 것, 없으면 요구사항 내용으로 판별하고 애매하면 확인 |
| 제목 | 50자 이내 한 줄 |
| 상세 | 나머지 전체를 원문 그대로 보존 |
| slug | 제목에서 영문 소문자 + 하이픈 3~5 단어 |

---

## Step 3 — 난이도·명확도 판정 (경로 결정)

| 레벨 | 기준 | 경로 |
|---|---|---|
| **L0 Trivial** | 로직 변경 없음(문구·상수·스타일값 치환) | **Nano** — spec 생략, 바로 `implement` |
| **L1 Simple** | 1~3 파일, 로직 소폭, 아키텍처 영향 없음 | **Fast** — `spec` 경량 |
| **L2 Normal** | 다수 파일, 로직 변경, 테스트 필요 | **Fast** — `spec` 정규 |
| **L3 Complex** | 아키텍처·도메인 변경, 크로스 모듈 | **Full** |

명확도가 아래 중 하나라도 해당하면 **L3(Full)로 격상**한다: "어디에 있는지/찾아서/분석해서"가
포함됨 · 이해관계자가 여럿이거나 요구가 한 줄 티켓 수준 · 영향 repo 자체가 불명확.

- **Full** → 작업 공간 생성까지만 하고 `requirement-fanout` 스킬로 넘긴다. 이 스킬 안에서
  요구사항을 발산하지 않는다.
- **Nano/Fast** → 그대로 Step 4로 진행한다.

판정 결과를 한 줄로 사용자에게 알린다(어느 경로로 가는지 숨기지 않는다).

---

## Step 4 — 작업 단위 확보

```bash
# 기존 참조가 있으면
node scripts/px.js issue get {ref} --json
# 없으면
node scripts/px.js issue create --title "{제목}" --body "{상세}" --json
```

- `exit 3`(트래커 없음/미지원) → 사용자에게 "작업 단위 식별자를 알려달라"고 요청하고, 받은 값을
  `{ref}`로 삼아 **계속 진행**한다. 트래커 부재는 중단 사유가 아니다.
- 멀티레포면 repo마다 반복하고 `{ref}` 목록을 유지한다.

---

## Step 5 — 작업 공간 생성 + HEAD 검증

```bash
node scripts/px.js ws create {slug} --issue {ref} --repo {r1,r2} --json
node scripts/px.js ws verify {slug} --json
```

`ws create`는 각 repo 작업 디렉터리를 **`origin/{base}` 시점에서** 만들고, 만든 직후
`HEAD == origin/{base}`를 검증한다. `ws verify`가 `exit 2`면 **거기서 멈춘다** — 로컬 브랜치
잔재 위에서 작업이 시작되면 이후 diff·리뷰·PR 대상이 전부 어긋난다.

동사는 멱등이다 — 같은 slug로 다시 불러도 실패가 아니라 기존 작업 공간을 반환한다.

---

## Step 6 — 기존 작업 공간 복구 (PC 이전·클론 유실)

`ws resolve`가 이미 성공했거나, 사용자가 "작업 공간 복구"를 요청한 경우:

```bash
node scripts/px.js ws list --json
node scripts/px.js ws verify {slug} --json     # 항목마다
```

`verify` 실패 항목만 모아 사용자에게 제시하고(선택 없이 전부 재생성하지 않는다), 선택된 항목에
대해 `ws create {slug} --issue {ref}`를 다시 실행한다(멱등이므로 안전). 복구 대상이 없으면
"모든 작업 공간이 정상"이라고 한 줄로 보고하고 끝낸다.

---

## Step 7 — 스펙 초안 자리 잡기 + 스테이지 기록

`{paths.specFile}`에 최소 초안을 쓴다 — 제목·작업단위 ref·경로(Nano/Fast/Full)·요구사항 원문·
완료 조건 1건. **여기서 설계를 하지 않는다.** 초안은 `spec` 스킬의 입력일 뿐이다.

```bash
node scripts/px.js ws stage {slug} SPEC
```

Nano 경로면 초안에 "Nano — spec 생략"을 남기고 `ws stage {slug} IMPL`로 바로 넘긴다.

---

## Step 8 — 완료 보고

```bash
node scripts/px.js tab open {slug} --cwd {workspace.root}   # mux 없으면 skip 됨
node scripts/px.js notify send --event work_started --text "{slug} — {제목}"
```

`tab`·`notify`는 부수 효과다 — 실패하거나 skip돼도 **흐름을 바꾸지 않는다.**

```
✅ work-start 완료 ({Nano|Fast|Full})
   작업 단위 : {ref}
   작업 공간 : {workspace.root}  (HEAD == origin/{base} 검증됨)
   다음      : {Full → /requirement-fanout · Fast → /spec · Nano → /implement}
```

---

## 어댑터가 채워야 하는 값

| 키 | 파일 | 의미 |
|---|---|---|
| `repos[]` (`id`/`base`/`stack`) | `.pipeline.json` | 대상 레포와 각 레포의 base 브랜치 |
| `workspace.dirPattern` / `branchPattern` | `.pipeline.json` | 작업 공간·브랜치 이름 규칙 |
| `providers.tracker` / `providers.workspace` | `.pipeline.json` | 작업 단위·격리 방식(clone 권장) |
| `paths.specFile` | `.review-kit.json` | Step 7 초안 저장 위치 |

## Reference

- `kit/contract/provider-contract.md` §2.1 `issue` · §2.4 `ws` — 이 스킬이 쓰는 동사와 `ws create` 보장 사항
- `kit/skills/requirement-fanout/SKILL.md` — Full 경로에서 이어받는 스킬
- `kit/workflow/guardrails.md` §2 — 부수효과 명령 실행 전 상태 확인
