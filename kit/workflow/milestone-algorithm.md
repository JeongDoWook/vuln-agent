# milestone — Algorithm Detail

> `kit/skills/milestone/SKILL.md`(Claude Code)와 단일 세션 CLI(Codex 등) 양쪽이 공유하는
> **다중 작업 오케스트레이션 규칙**. 도구 전용 기능에 의존하지 않는 순수 서술 —
> 이 문서 자체는 어느 쪽에서 읽어도 같다.
> 구현: `scripts/ms.js` · `scripts/lib/milestone/*.js` · `scripts/gen-milestone.js`

---

## 왜 이 층이 필요한가

`pipeline`은 **이슈 하나의 주기**만 안다 — work-start → spec → implement → … → finish.
현실의 마일스톤은 수십 건이 서로를 기다리며, 한 기계에서 동시에 돌릴 수 있는 작업 수에는
상한이 있다. "지금 무엇을 착수해도 되는가"를 사람이 매번 머리로 계산하면, 계산이 틀린 것을
아무도 모른 채 오래된 base 위에 병렬 작업이 쌓이고 통합 시점에 충돌이 한꺼번에 터진다.

**트래커에 결합되지 않는 이유는 하나뿐이다.** 이 층은 외부 시스템을 직접 만지지 않고
`kit/contract/provider-contract.md`의 동사만 부른다 —
`issue list --state --labels --milestone --limit` · `pr get --source` · `ws create/verify/stage/list` ·
`branch drift-check` · `notify send`. GitLab을 GitHub으로 바꿔도 이 문서와 구현은 한 줄도 바뀌지 않는다.

**마일스톤 층은 직접 구현하지 않는다.** 하는 일은 배분·관측·검토뿐이고, 코드 변경은 전부
각 작업공간에서 도는 `pipeline` 한 주기가 한다.

---

## 용어

| 용어 | 뜻 |
|---|---|
| **마일스톤** | 이 오케스트레이션의 단위. 항목 집합 + Wave 구성 + 진행 상태 = state 파일 하나 |
| **항목(item)** | 한 번의 `pipeline` 주기로 처리되는 작업 단위. 트래커 이슈 1건이 보통이지만, 사람이 여러 저장소의 이슈를 한 항목으로 합칠 수 있다 |
| **ref** | 항목 참조 식별자. **`<repo>:<id>` 형식만 정본**이다(`be:908`) |
| **Wave** | 위상 레벨이 같은 항목들의 묶음. 같은 Wave 안의 항목끼리는 서로를 기다리지 않는다. Wave 번호 = 위상 레벨 |
| **슬롯** | 동시 진행 상한. **저장소 작업 디렉터리(= 세션) 단위**로 센다 — 두 저장소를 걸친 항목 하나는 2슬롯이다 |
| **의존(`dependsOn`)** | 선행 항목의 key 목록. 전부 `done`이어야 착수한다. 사람이 확정해 state에 적는다 |

### 왜 ref 는 저장소 한정 형식만 받는가

다중 저장소에서는 이슈 번호대가 겹친다(FE 884-889 / BE 902-908처럼 둘 다 800~900대).
저장소를 생략한 숫자(`908`)로 한쪽만 빼려는 조작이 **양쪽 저장소의 908을 동시에** 건드린다.
그래서 `<repo>:<id>` 하나만 정본이고, **형식 위반은 조용히 무시하지 않고 즉시 에러**다.
실측된 오탈자(`"be:"` · `"be:abc"` · `":908"` · `"fe:908:x"`)는 전부 "매치 안 됨"으로 조용히
통과해 스코핑을 fail-open 시켰다 — 빼려던 항목이 계획에 남아 그대로 착수됐다.
스코핑에서 "빼려던 게 안 빠짐"은 "필요없는 게 빠짐"보다 훨씬 위험하다.

### 상태

```
queued → ready → specced → dispatched → impl → qa_ok → pr_open → merged → done
                                    ↘  (어디서든)  blocked  ↗ (blockedFrom 으로만 복귀)
```

`ACTIVE_STATUSES`(슬롯을 점유하는 상태) = `dispatched · impl · qa_ok · pr_open · merged · blocked`.

- **`merged`가 포함되는 이유** — 병합돼도 정리(`finish`) 전까지 작업공간과 세션이 살아 있다.
- **`blocked`가 포함되는 이유** — 멈춘 항목도 작업공간은 그대로다. 빼두면 2슬롯짜리 항목이
  blocked로 멈추는 즉시 슬롯 2개가 조용히 풀려, **실제로는 꽉 찬 용량 위로** 새 작업이 얹힌다.
- 단 "슬롯을 점유한다"와 "자동으로 다시 관측한다"는 **별개 결정**이다. blocked는 슬롯은
  점유하되 관측 대상에서는 완전히 빠진다(자동 복귀 없음 — 아래 `watch` 참고).

---

## 서브커맨드

```bash
node scripts/ms.js status                  # 현재 Wave·슬롯·blocked 요약
node scripts/ms.js plan     [--apply] [--force]
node scripts/ms.js dispatch [--apply]
node scripts/ms.js watch    [--apply]
node scripts/ms.js advance  [--apply]
node scripts/ms.js report   [--apply] [--out <file.html>]
```

**`--apply` 없는 기본은 항상 dry-run이다** — 아무것도 쓰지 않고 무엇을 할지만 보여준다.
출력 규약과 종료 코드는 `px.js`와 같다(stdout = JSON 봉투 한 덩어리, stderr = 사람이 읽을 글,
exit `0` 성공 / `1` 설정·state 오류 / `2` 게이트 위반 / `3` 미지원).

---

## `plan` — 항목 수집 → 우선순위 → Wave 제안 → 사람 승인 → `--apply`

1. **selector 형식을 먼저 검증한다** — 네트워크를 타기 전에. `excludeRefs`의 오탈자가
   "매치 안 됨"으로 조용히 통과하면 스코핑이 fail-open 한다.
2. `px issue list --state … --labels … --milestone … --limit …` 로 항목을 수집한다.
   반환된 `Issue.repo`가 어느 저장소인지를 정한다(단일 저장소 설치면 `selector.repos[0]`).
3. **분류** — 포함 조건(`titlePrefix`/`titleContains`, 없으면 전부 포함)과
   명시적 배제(`excludeRefs`/`titleExclude`)를 가른다.
   **배제 판정이 상태 필터보다 먼저다** — 상태 필터를 먼저 적용하면 닫힌 이슈가 배제 판정을
   타지 못해 "명시적 제외"가 아니라 "오펀"으로 분류되고, 폐기한 이슈가 백로그에서 영영 안 사라진다.
4. **병합**(아래 규칙 전부 적용) → **위상정렬 → Wave 산출** → **표를 사람에게 제시하고 승인**.
5. 승인 후에만 `--apply`.

### 병합 규칙 — 이 절이 이 층에서 가장 값진 부분이다

전부 실제로 사고가 났던 지점이다. 구현: `scripts/lib/milestone/plan-merge.js`.

**(a) 이번 수집에서 사라진 항목은 삭제하지 않고 오펀으로 보존하고 경고한다.**
버리면 `status`·`workspace`·`branches`·`prs`가 통째로 증발한다. 항목이 `done`에 도달하는
바로 그 순간(이슈를 닫는 순간)이 수집에서 사라지는 순간이라 가장 위험하다.
경고를 무시하지 말고 **왜 안 보이는지**(정상 종료 vs selector 실수로 이탈) 확인한다.
부수 효과로, 살아있는 항목이 그 오펀을 `dependsOn`으로 참조 중이었다면 "존재하지 않는
선행 참조"로 Wave 산출 자체가 실패했을 상황도 막아준다.

**(b) 사람이 명시적으로 뺀 항목(`excludeRefs`/`titleExclude`)은 실제로 제거한다.**
오펀과 혼동하지 않는다 — **닫힌/이탈한 이슈**(사람 의도 아님)는 살아남고,
**의도적으로 뺀 이슈**는 죽는다. 이 구분이 없으면 오펀 보존이 사람의 의도를 매번 되살려
스코핑 도구가 첫 `--apply` 이후 조용히 무력화된다.

**(c) 단 `queued`가 아닌(이미 착수된) 항목은 배제 매치여도 삭제를 거부하고 경고한다.**
그 항목의 `workspace`/`branches`/`prs`가 유일한 기록이라 조용히 지우면 복구할 수 없다.
확인 후 정말 지워야 하면 `--force`를 준다. `queued`(아직 아무 작업도 안 한 순수 백로그)는
`--force` 없이도 즉시 제거된다.

**(d) 항목 참조는 저장소 한정 형식이 정본이고, 형식 위반은 즉시 에러다.** (위 "용어" 참고)

**(e) 여러 항목이 같은 ref 를 동시에 보유하면 결정적 규칙으로 소유자를 정하고 경고한다.**
- `self-claim`(항목이 자기 key와 같은 ref 보유 — 트리비얼하게 모두 성립)보다
  `foreign-claim`(다른 key의 항목이 그 ref 보유 = 사람이 손으로 합친 결과)이 **항상 이긴다.**
  후자가 더 신뢰할 수 있는 신호고, 전자는 병합 전 상태의 화석일 뿐이다.
- 둘 다 foreign이면 정상 병합이 아니라 손 편집 실수다 → **key 오름차순**으로 먼저 오는 쪽을
  소유자로 확정하고 나머지에서 그 ref만 제거한다(항목 전체는 지우지 않는다).
  그러지 않으면 같은 ref를 둘이 중복으로 세어 **슬롯 합계가 부풀려진다.**
- 판정은 prevItems를 key 오름차순으로 정렬한 뒤 수행한다 — **입력 배열의 우연한 순서에
  결과가 좌우되면 안 된다.**
- 흡수돼 items에서 빠진 key는 조용히 지우지도, 중복인 채로 남기지도 않고 `absorbed`로
  소리 내어 보고한다. 그 key가 자기만의 status/workspace/prs를 갖고 있었을 수 있고, 그 값이
  소유 항목 쪽에 옮겨졌는지는 알 도리가 없기 때문이다.

**(f) 제외 패턴은 단순 부분문자열이 아니라 토큰 경계 매치다.**
`"v3"`는 `"컴플라이언스 v3 데모"`·`"(docs/v3)"`에 매치하지만 `"rev3"`·`"v30"`에는 매치하지
않는다. 패턴 자신의 끝이 영숫자가 아니면(`"[문서]"`) 그쪽 경계 검사는 하지 않는다.
대소문자는 무시한다. 이 매치는 단순 필터링이 아니라 **실제 삭제**까지 하므로, 오탐이
곧 데이터 유실이다.

**소유권 분리** — 재계획이 무엇을 덮어쓰고 무엇을 보존하는지:

| 소유자 | 필드 | 재계획 시 |
|---|---|---|
| 트래커 | `title` · `priority` · `refHints` | 덮어쓴다 |
| 사람 | `dependsOn` · `status` · `slug` · `workspace` · `branches` · `prs` · `specVerified` · `gate` · `blockedFrom` · `notes` · `waves[].approvedAt` | 그대로 이어간다 |
| 기계(관측) | `lastObservedAt` · `lastObservedReason` · `evidenceMissCount` | 그대로 이어간다 |

`evidenceMissCount`가 재계획마다 0으로 리셋되면 임계 직전까지 쌓인 미스가 매번 지워져
`blocked` 승격이 **영원히 안 걸린다.** `waves[].approvedAt`은 Wave의 항목 구성(집합, 순서
무관)이 같을 때만 이어진다 — 구성이 바뀌면 승인 당시 검토 대상과 달라진 것이므로 리셋한다.

### 우선순위 정렬키

1. 위상 레벨 오름차순 (선행 없는 것 먼저) — 이 레벨이 곧 Wave 번호
2. 우선순위 라벨 순위 — **어댑터의 `priorityLabels` 순서**. `P0`/`P1`을 하드코딩하지 않는다
3. 다운스트림 차수 내림차순 (많이 물린 linchpin 먼저)
4. 최소 id 오름차순 — 동률 시 결정성 확보

4번이 없으면 같은 입력이 실행할 때마다 다른 Wave를 내고, 사람의 Wave 승인이 무의미해진다.

---

## `dispatch` — 빈 슬롯 × 우선순위 × 의존 충족 → 착수

게이트 순서가 곧 정책이다. **드리프트 → 부하 → slug → 의존 → 슬롯.**

1. **slug 게이트** — `slug`는 트래커가 주지 않는다. 사람이 착수 직전 state에 채운다.
   유효한 slug = 영숫자·하이픈·언더스코어, 시작/끝은 영숫자.
   거부되는 것: `null`/`''`은 물론 **리터럴 문자열 `"null"`/`"undefined"`**(JSON을 손으로
   고치다 남기는 실측된 실수 — falsy 검사를 통과해버린다), 앞뒤 공백, 경로 구분자(`/`, `..`),
   셸 메타문자. slug는 작업공간 디렉터리명과 브랜치명 양쪽에 그대로 쓰이기 때문이다.
   **절대 손으로 slug를 추측해 명령을 채워 넣지 않는다** — state를 고치고 다시 실행한다.
2. **드리프트 게이트** — `px branch drift-check`. 초과하면 슬롯 계산보다 **먼저** 후보 전원을
   보류한다. 오래된 base 위에서 병렬 착수하면 통합 시점에 충돌이 한꺼번에 터진다.
   `exit 3`(프로바이더가 드리프트 개념을 모름)이면 게이트를 끈다. 그 외의 실패는
   **실측하지 못한 것**이지 "드리프트 없음"이 아니므로 fail-open 하지 않고 멈춘다.
3. **의존 판정** — `dependsOn`이 전부 `done`이 아닌 항목은 슬롯이 남아도 착수하지 않는다.
4. **슬롯** — `slotsUsed(ACTIVE 항목의 refs 수 합계)`. 2슬롯짜리 항목은 잔여 1슬롯에 들어가지 않는다.
5. 통과한 항목마다 `px ws create <slug> --issue <id> --repo …` → `ws verify` → `ws stage SPEC`,
   그리고 그 작업공간에서 **`pipeline` 한 주기**를 착수시킨다. 마일스톤 층은 직접 구현하지 않는다.
6. `--apply`는 **부분 성공을 반드시 기록한다.** 일부가 실패해도 성공분은 state에 남기고,
   그 뒤에 실패를 알린다(재실행이 이미 만든 작업공간을 다시 만들지 않게 하기 위해서다).
   `workspace`에는 예측한 경로가 아니라 **`ws create`가 실제로 돌려준 값**을 적는다.

---

## `watch` — 진행 감지 → Gate 도달 시 사람 검토 → 승인/반려

1. 활성 항목(단 `blocked` 제외)마다 관측한다 — `px ws list`로 작업공간 스테이지를,
   `px pr get --source <branch>`로 저장소별 PR 상태를.
   브랜치명은 `item.branches`가 정본이고, 없으면 어댑터의 `branchPattern`으로 추정한다.
2. 전이를 계산한다(아래 규칙). **`--apply` 없이는 아무것도 쓰지 않는다.**
3. Gate에 도달한 항목은 사람이 검토하고 승인/반려한다 — 승인은 그 작업공간에 지시로 보낸다.
   반려면 state는 그대로 두고 구체적 수정 지시만 보낸다.

### `done` 승격은 "완전하고 전부 merged인 PR 근거"를 요구한다

작업공간이 `DONE` 스테이지에 도달했다는 사실은 **병합됐다는 뜻이 아니다.** 순서를 잘못 밟으면
아티팩트는 done인데 PR은 아직 열려 있거나 아예 못 찾은 상태가 실재한다.

| 관측 | 판정 |
|---|---|
| 모든 저장소의 PR을 찾았고 **전부 merged** | `done` |
| 전부 찾았는데 하나라도 merged가 아님 | `pr_open` (모순 반박) |
| **근거 자체가 불충분**(일부 저장소의 PR을 못 찾음) | 증거미스 — 즉시 done이 **아니다** |
| 확인할 저장소가 없음(refs 비정상) | `unknown` — blocked가 아니다. "사람이 확인할 구체적 대상"이 없는데 blocked를 쓰면 오해를 부른다 |

"반박 없음"과 "근거 완비"를 혼동하면 안 된다. 두 저장소 항목에서 한쪽만 merged이고 나머지
PR을 못 찾은 경우를 "반박 없음 → done"으로 처리하면 **병합되지도 않은 항목이 슬롯을 풀어준다.**

### 증거미스는 연속 카운터로 센다

트래커 replica lag·일시적 API 오류 한 번으로도 "근거 불충분"이 재현된다. 매번 사람을 부르면
노이즈가 커서 아무도 안 본다. 항목별 **연속** 미스가 `watch.evidenceMissLimit`(기본 3, 없거나
0/음수/비숫자면 기본값)회에 도달해야 실제 `blocked`가 된다. 그 전까지는 "미스 N/임계회 — 보류"
로그만 남는다. 근거가 완비된 라운드가 한 번이라도 오면 카운터는 **즉시 0으로 리셋**된다.

**조회 실패(에러)와 그냥 못 찾음(빈 결과)은 같게 취급한다.** 둘 다 "이번 라운드에 이 저장소의
근거를 못 얻었다"는 같은 뜻인데, 예전엔 전자가 조용한 무한 재시도, 후자가 즉시 blocked로
갈려 비대칭이었다. 사유 문구만 구분한다.

### 그 밖의 관측 규칙

- **다단계 전이** — 한 라운드에 여러 Gate를 건너뛴 관측(`dispatched` 상태인데 `qa_ok` 아티팩트가
  잡힘)은 순서대로 여러 단계에 걸쳐 적용한다. `pipeline`이 자동 연쇄되므로 흔한 일이다.
- **역행 거부** — 관측값이 현재 상태보다 뒤에 있으면 강제하지 않고 거부로 보고한다.
  잘못된 아티팩트 잔존이나 state 수기 편집 오류일 수 있다.
- **관측 불가 ≠ blocked** — slug가 무효해 브랜치명을 정할 수 없거나 스테이지를 아예 못 읽은
  라운드는 그 항목을 통째로 건너뛴다. **blocked로 밀어붙이지 않는다** — 그건 데이터 문제지
  증거 문제가 아니고, blocked 사유("브랜치 컨벤션 확인")가 실제 원인과 어긋나 사람을 헷갈리게 한다.
- **거부 목록은 한 번에 출력한다** — 관측 단계의 거부와 적용 도중 생긴 거부를 전부 확정한 뒤에.
- **적용 0건이면 state 파일을 쓰지 않는다** — 내용은 그대로인데 mtime만 새로 찍히면
  "state 갱신 없음" 메시지와 실제 파일 상태가 어긋난다.
- **`blocked`는 자동 복귀하지 않는다** — 매 라운드 눈에 띄게 보고는 하지만 관측·전이 계산
  대상에서 완전히 제외한다. 복귀는 사람이 원인을 해결하고 `blockedFrom`으로 직접 되돌릴 때만.
- **기계 관측은 `notes`를 절대 건드리지 않는다** — `notes`는 사람 소유다. 관측 사유는
  `lastObservedReason`/`lastObservedAt`에만 남긴다. 다단계 전이가 일상이라 관측 사유를 notes에
  밀어넣으면 한 번의 `watch --apply`가 사람의 메모를 스텝 수만큼 덮어쓴다.

---

## `advance` — 완료 감지 → 슬롯 회수 → 다음 항목 착수

1. `watch`와 같은 관측·전이를 수행한다.
2. `done`으로 간 항목이 반납한 슬롯을 계산한다(2저장소 항목은 2슬롯).
3. 빈 슬롯만큼 다음 후보를 제시한다 — 착수는 `dispatch --apply`가 한다(한 명령이 관측과
   착수를 동시에 하면 무엇 때문에 멈췄는지가 흐려진다).
4. Wave의 모든 항목이 `done`이면 통합 시점을 알린다. **통합 절차 자체는 호스트 프로젝트의
   것이다** — 이 층은 통합 MR/PR을 만들지 않는다(§Non-Goals).

무인 루프로 돌린다면 `advance`를 주기 실행하고, Gate 도달·`blocked`·거부가 나오면 사람이 본다.

---

## `report` / `status`

- `status` — 항목 수, 상태별 집계, 슬롯 점유, Wave 진행, `blocked` 목록.
- `report` — 진행 표. `--apply`면 `scripts/gen-milestone.js`로 자기완결적 HTML을 만든다
  (Wave 표 · 슬롯 점유 · 의존 그래프 · 경고 목록). 스타일 SSOT는 `scripts/assets/report.css`.

---

## state 손편집 방어

이 문서는 여러 지점에서 "state를 직접 고쳐라"라고 안내한다(`dependsOn` 확정, `slug` 확정,
`blocked` 복귀). 즉 손상된 state는 드문 사고가 아니라 **예상 가능한 입력**이다.

- **로드 시점에 한 번에 검증한다.** 각 항목의 `key`(ref 형식) · `refs`(비어있지 않은 객체) ·
  `status`(허용 목록) · `dependsOn`(ref 형식) · `evidenceMissCount`(유한한 숫자)를 먼저 본다.
  문제가 있으면 나중에 다른 함수 안에서 원시 `TypeError`나 조용한 오답(`Math.min()` →
  `Infinity` → 그 항목이 티 안 나게 정렬 맨 뒤로 밀림)으로 죽는 대신, **어느 항목의 어느
  필드인지 이름을 대며 즉시 실패**한다. 문제를 가장 진단하기 쉬운 시점이 로드하는 그 순간이다.
- 슬롯 계산(`slotsOf`)과 정렬(`minId`)에도 같은 방어를 남겨둔다(벨트+서스펜더) — 손으로 만든
  항목으로 직접 호출되는 경로가 있기 때문이다.
- **쓰기 직전 `{name}.json.bak`으로 백업한다.** 원본이 있을 때만(최초 생성 시엔 백업 없음),
  **한 단계 깊이뿐이다** — 연속 `--apply`는 직전 `.bak`을 덮어쓴다. 복구용 아카이브가 아니라
  "바로 직전 한 번" 스냅샷이다. 여러 시점을 보존하려면 따로 복사해 둔다.

---

## 어댑터 설정 — `.review-kit.json` 의 `milestone` 절

**하드코딩된 트래커·저장소·라벨 이름은 구현 어디에도 없다.** 전부 여기서 온다.

```jsonc
{
  "milestone": {
    "name": "v2",                                  // 마일스톤 이름(state 최초 생성 시)
    "statePath": ".review-kit-milestone.json",     // 기본값
    "base": "develop",                             // 통합 대상 브랜치(생략 시 프로바이더 기본값)
    "branchPattern": "feature/issue-{id}-{slug}",  // branches 가 비었을 때의 추정 규칙
    "priorityLabels": ["P0", "P1"],                // 순서가 곧 우선순위. 여기 없는 값은 맨 뒤

    "selector": {
      "repos": ["be", "fe"],       // 이 저장소의 항목만 본다(비우면 전부)
      "state": "open",
      "milestone": "v2",           // 트래커의 마일스톤 이름/id — 없으면 생략
      "labels": [],
      "limit": 100,
      "excludeRefs": ["be:908"],   // 반드시 "<repo>:<id>". 형식 위반은 즉시 에러
      "titleExclude": ["v3", "[문서]"],   // 토큰 경계·대소문자 무시
      "titleContains": null,       // 마일스톤 객체를 안 쓰는 트래커용 보조 수단
      "titlePrefix": null
    },

    "concurrency": { "maxSlots": 4, "loadavgLimit": 12 },   // loadavgLimit 0/null 이면 부하 게이트 끔
    "drift":       { "maxCommits": 30, "maxFiles": 60 },
    "watch":       { "evidenceMissLimit": 3 }
  }
}
```

설정은 `.review-kit.json`에, **런타임 상태는 state 파일에** 둔다 — state는 "지금 무엇이 어디까지
갔는가"만 담는다. state 스키마 정본: `scripts/schema/milestone-state.schema.json`.

---

## Non-Goals

- **PR 자동 병합** — 사람이 고정으로 승인한다.
- **통합 MR/PR 생성** — Wave 완료를 알리기만 한다. 통합 절차는 호스트 프로젝트 소유다.
- **직접 구현** — 코드 변경은 전부 각 작업공간의 `pipeline`이 한다.
- **`pipeline` 수정** — 이 층은 기존 스킬을 호출만 한다.
- **마일스톤 밖 항목 처리.**

## Reference

- `kit/contract/provider-contract.md` — 외부로 나가는 유일한 문
- `kit/workflow/pipeline-algorithm.md` — 이 층이 착수시키는 이슈 1건 주기
- `kit/workflow/guardrails.md` — 사전확인·파괴적 동사 규칙
- `scripts/ms.js` · `scripts/lib/milestone/*` · `scripts/gen-milestone.js` · `scripts/schema/milestone-state.schema.json`
