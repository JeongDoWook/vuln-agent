---
name: wt
description: Use when the user types "/wt" with or without arguments. 인자 없이 "/wt" → 커맨드 선택 메뉴. "/wt 제목 - 설명" → 전체 파이프라인(요구분석 → 난이도판정 → Gate1) 즉시 시작. vuln-agent 단일 레포 · git worktree · 같은 세션 전용.
---

# wt Skill — 작업 허브 (vuln-agent)

`/wt` 는 vuln-agent 작업을 **git worktree + 브랜치**로 격리해 시작하는 파이프라인 진입점이다.
claude-pipeline 의 GitLab 이슈 생성 자리를 **브랜치 생성**으로 대체했다.

> **환경 전제 (claude-pipeline 과 다름)**
> - 단일 PHP 레포(이 저장소). FE/BE/TC 분리 없음.
> - `git worktree add` 로 폴더+브랜치 동시 생성 (GitLab 이슈 없음).
> - **같은 세션**에서 `/wt-spec → /wt-impl → /wt-qa → /wt-push` 순차 진행 (cmux/별도세션 없음).
> - 원격은 GitHub. MR 대신 `gh` PR.

---

## 경로 상수 (모든 wt 스킬 공통)

```bash
# main 저장소 루트 (worktree 안에서 실행해도 항상 main 을 가리킴)
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
# 활성 worktree (wt-setup 이 기록)
ACTIVE=$(cat "$MAIN/wt/.active" 2>/dev/null)   # 예: 0709-cve-detail-filter
WT_DIR="$MAIN/wt/$ACTIVE"                       # worktree 루트
SLUG="${ACTIVE#*-}"                             # MMDD- 접두 제거
PIPE="$WT_DIR/.pipe/$SLUG"                      # 파이프라인 산출물 (브랜치에 커밋 안 됨)
```

> worktree 안의 `.pipe/` 는 `wt-setup` 이 그 worktree 의 `.git/info/exclude` 에 등록해 **브랜치 오염 없음**.

---

## 진입 분기

### `/wt` 단독 호출 → AskUserQuestion 단일 질문

인자 없이 `/wt` 만 입력하면 **AskUserQuestion 툴**로 선택지를 1회 표시한다.

**질문**: "단계를 선택하거나, 새 작업은 Other에 요구사항을 입력하세요."
- header: `wt 커맨드`

```
옵션 A: 설계          — /wt-spec (Spec + 3관점 분석 + Plan)
옵션 B: 구현 + 테스트 — /wt-impl
옵션 C: 검증(QA)      — /wt-qa (정적검사 + 3관점 리뷰 + AC검증)
옵션 D: PR 생성       — /wt-push
Other (자유 입력):     새 작업 요구사항 직접 입력
                       예) 필터 추가 - 심각도·상태 2종
```

- A/B/C/D → 해당 스킬 즉시 진행 (활성 worktree 대상)
- Other → 입력 텍스트를 요구사항으로 Phase 1 시작

### `/wt {인자}` 호출 → 즉시 실행

```
/wt CVE 상세 필터 추가 - 심각도·상태 필터 2종
/wt kisa 커넥터 매핑 버그 수정 - 날짜 파싱 오류
/wt 지금까지 요구사항으로 진행해줘   ← 대화 맥락 캡처
```

- `-` 앞 → 이슈 제목 핵심 (50자 이내)
- `-` 뒤 → 요구사항 상세 (없어도 동작)
- "지금까지"/"위 내용으로" → 대화 맥락에서 추출 후 확인

---

## 🚨 사전 체크

```bash
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
basename "$MAIN"                       # vuln-agent 확인
git -C "$MAIN" status --short | head   # main 이 clean 인지 (dirty 면 안내 후 계속 여부 확인)
```

vuln-agent 루트가 아니면 안내 후 중단.

---

## Phase 1 — 파싱 & 난이도 판정 & (필요 시) 분석

### 1-1. 파싱

| 항목 | 추출 규칙 |
|---|---|
| 이슈 제목 | `-` 앞 텍스트에서 핵심 추출, 50자 이내 |
| 요구사항 상세 | `-` 뒤 텍스트 전체 보존 |
| 이슈 타입 | `feature` / `fix` / `refactor` / `chore` 분류 |
| slug | 제목에서 영문 소문자 + 하이픈 3~5 단어 (예: `cve-detail-filter`) |

> 브랜치명은 `{type}/{slug}` (예: `feature/cve-detail-filter`). worktree 는 `wt/{MMDD}-{slug}`.

### 1-1-A. 난이도 판정 — 파싱 직후 즉시

| 레벨 | 이름 | 기준 | vuln-agent 예시 |
|------|------|------|------|
| **L0** | Trivial | 로직 변경 없음. 텍스트·상수·스타일값 치환 | UI 문구, 라벨, CSS 값, 에러 메시지 |
| **L1** | Simple | 1~3 파일, 로직 소폭, 구조 영향 없음 | 컬럼 추가, 단순 조건, 쿼리 파라미터 |
| **L2** | Normal | 다수 파일, 로직 변경, 검증 필요 | 신규 커넥터, 웹 기능, 버그 수정 |
| **L3** | Complex | 스키마·도메인 변경, 크로스 모듈 | DB 스키마 변경, 매칭 로직 재설계 |

> **경로**: L0 → Nano Track / L1~L2 → Fast Track / L3 → Full 분석

### 1-1-B. 명확도 판정

**CLEAR** (Fast/Nano 진행) — 아래 중 1개 이상:
- 파일명·함수명·테이블·API 경로 명시
- 버그 재현 경로 명시 (에러메시지 / 엔드포인트 / 재현 스텝)
- 변경 범위 단순(1~3), 대화에서 이미 특정

**UNCLEAR → Full 분석 (L3 격상)** — 아래 중 1개라도:
- "어디에 있는지", "찾아서", "분석해서" 포함
- 영향 범위 불명확한 신규 기능
- 여러 모듈(커넥터/웹/CLI/DB)에 걸치는지 불명확

---

### ⚡ Nano Track (L0) — 분석·상세 QA 생략

```
⚡ Nano Track: 텍스트·상수·스타일 수준. wt-spec·3관점분석·상세리뷰 생략.
```

곧바로 `/wt-setup` 를 호출하되 **complexity=trivial** 신호를 넘긴다. 이후 `/wt-impl` 에서 파일 찾기·수정·커밋만, `/wt-qa` 에서 `php -l` + 1-에이전트 빠른 리뷰만.

### 🚀 Fast Track (L1·L2 CLEAR) — 분석 없이 바로 worktree

```
⚡ Fast Track: 요구사항이 명확합니다. 분석 없이 바로 worktree 를 생성합니다.
```

곧바로 `/wt-setup` 호출. spec.yaml 은 최소 초안(complexity=simple|normal)으로 시작하고, 코드 분석은 `/wt-spec` 에서 수행.

### 🔍 Full 분석 (UNCLEAR / L3)

worktree 생성 **전에** main 저장소(`$MAIN`)를 직접 읽어 관련 파일을 탐색한다.
(단일 레포 — temp clone 불필요, 코드가 이미 여기 있음.)

```
Agent(
  subagent_type: "Explore",   또는 general-purpose
  description: "SA — 요구사항 관련 코드 탐색",
  prompt: """
cwd: {MAIN}
req: {요구사항 상세}
hint: {이슈 제목}

server/(웹·API), agent/(수집 CLI), matcher-ai/, db/, config/ 에서
요구사항과 관련된 파일·함수·PDO 쿼리·라우트·커넥터를 탐색하라.
결과를 아래 YAML 로 반환하라 (설명 텍스트 금지):

relevant: yes|no
files:
  - path: server/relative/path.php
    symbol: 함수 또는 라우트
    change: 필요한 변경 한 줄
scope: 전체 변경 범위 한 줄
"""
)
```

반환 결과 + 구현 가설 2~3개를 사용자에게 제시하고 **확인/수정/추가 논의**를 받는다.
요구사항이 명확해질 때까지 반복한다.

---

## 🔵 Phase 1 Gate — 요구사항 확정

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 요구사항 분석 완료

  이슈 제목 : {이슈 제목}
  타입/slug : {type} / {slug}
  브랜치    : {type}/{slug}
  요구사항  : {확정 요구사항 요약}
  예상 파일 : {주요 변경 파일 목록}
  난이도    : {L0|L1|L2|L3} ({Nano|Fast|Full})

추가 논의가 필요하면 자유롭게 질문하세요.
작업 환경(worktree + 브랜치)을 만들려면:

  👉 /wt-setup
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

`/wt-setup` 입력 전까지 Phase 2 로 넘어가지 않는다. 이 상태에서 자유롭게 추가 논의 가능.

---

## 전체 파이프라인 & Gate 정의

```
/wt          Phase 1: 파싱·난이도·(Full 시)분석 → 🔵 요구사항 확정 Gate
   ↓ /wt-setup
Phase 2: git worktree add + 브랜치 생성 + spec.yaml·conversation.jsonl 기록
   ↓ (같은 세션에서 계속)
/wt-spec     Step 2~3: 3관점 분석 + Plan + analysis.html
   ↓ 🔴 Gate 1 — "분석 리포트 검토 후 /wt-impl 로 구현 시작"
/wt-impl     Step 3~6: 구현 + 정적검사(php -l) + 커밋
   ↓ (자동 전환)
/wt-qa       Step 7: 정적검사 + 3관점 리뷰(Quality·Security·Regression) + AC검증 + 커밋
   ↓ 🔴 Gate 2 — "검증 완료. /wt-push 입력 대기"
/wt-push     Step 8: push + gh PR 생성
   ↓ 🔴 Gate 3 — "PR description 초안. 수정 후 '진행'/'생성'/'OK'"
   ↓ (PR merge 는 사용자가 GitHub 에서 직접)
/wt-done     Step 9: 병합 후 worktree 제거 + 브랜치 정리
```

- 각 Gate: 사용자 응답 없이 다음 단계 자동 진행 금지.
- PR merge 는 항상 사용자 수동.

---

## Non-Goals

- 기존 브랜치 재진입 (`/wt` 는 신규 작업 전용)
- PR 자동 merge
- main 직접 커밋 (항상 worktree 브랜치 경유)
