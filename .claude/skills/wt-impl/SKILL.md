---
name: wt-impl
description: Use when the user types "/wt-impl". 활성 worktree 브랜치에서 구현 + 정적검사(php -l) + 커밋을 수행한다(Step 3~6). 완료 후 /wt-qa 로 자동 전환. vuln-agent 전용.
---

# wt-impl — 구현 + 정적검사 (Step 3~6)

활성 worktree 브랜치에서 Plan(또는 spec)에 따라 구현하고, 정적검사 후 커밋한다.

> **테스트 실행 금지**: wt-impl 전 구간에서 `tests/smoke.sh` 등 런타임 테스트 실행 금지.
> `php -l`(문법)·`bash -n`(쉘)·설정 검증만. 스모크 테스트는 wt-qa 에서 리뷰+AC 완료 후 1회.

---

## 진입 즉시

```bash
MAIN=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
ACTIVE=$(cat "$MAIN/wt/.active" 2>/dev/null)
WT_DIR="$MAIN/wt/$ACTIVE"; SLUG="${ACTIVE#*-}"; PIPE="$WT_DIR/.pipe/$SLUG"
[ -d "$WT_DIR" ] || { echo "❌ 활성 worktree 없음 — /wt-setup 먼저"; exit 1; }

BRANCH=$(git -C "$WT_DIR" rev-parse --abbrev-ref HEAD)
COMPLEXITY=$(grep -m1 '^complexity:' "$PIPE/spec.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo normal)
echo "worktree: $WT_DIR / branch: $BRANCH / complexity: $COMPLEXITY"

# Gate 1 전제 확인: trivial 이 아니면 plan.yaml(= wt-spec 산출) 필요
if [ "$COMPLEXITY" != "trivial" ] && [ ! -f "$PIPE/plan.yaml" ]; then
  echo "⚠️  plan.yaml 없음 — /wt-spec(Gate 1) 미통과. 먼저 /wt-spec 권장 (강행하려면 계속)."
fi
[ "$COMPLEXITY" = "trivial" ] && echo "⚡ Nano Track — TDD·Plan 생략, 파일 찾기·수정·커밋만"
```

---

## Flow

```
[Main] Step 3: 사전 확인 (spec.yaml AC · plan.yaml 단계)
    ↓
[Main] Step 4: 활성 worktree 브랜치에서 작업 (git -C "$WT_DIR")
    ↓
[Main] Step 5: 구현
    ├─ L0/L1 (1~3 파일) → 직접 순차 구현
    └─ L2/L3 (다중 모듈) → 모듈별 병렬 executor 분해
         [Phase A: 동시] 커넥터/서비스/DB 레이어
         [Phase B]      웹·API·라우트 레이어 (A 의존 시)
         [Phase C]      통합 지점
    ↓
[Main] Step 6: 정적검사 (php -l / bash -n / 설정 검증) → 통과할 때까지 수정
    ↓
[Main] Step 6.5: 커밋 (한글 메시지, "돌아가는 상태")
    ↓
→ /wt-qa 자동 진입 안내
```

- 실제 소스 편집(.php 등)은 **executor** 에게 위임하거나 직접 수행. vuln-agent CLAUDE.md 의 YAGNI/KISS/DRY/SOLID 를 준수.
- L2/L3 병렬 분해 시, 파일 소유가 겹치면 순차로. 겹치지 않을 때만 병렬 executor.

---

## Step 5 — 구현 지침 (vuln-agent 규약)

- **비밀값**: 코드/커밋 금지 → Docker Secrets(`secrets/*.txt`). `vg_secret()` 헬퍼 사용.
- **DRY 헬퍼 재사용**: `vg_h()`, `vg_pdo()`, `vg_header/footer()`, `vg_upsert_*()`. 새 반복 로직은 3회째에 추출.
- **커넥터 추가**: `VgFeedConnector` 구현 + `vg_feed_make()` 한 줄 등록 (기존 커넥터 수정 금지 — OCP).
- **SQL**: PDO prepared statement 만. 문자열 결합 쿼리 금지 (SQLi).
- **한글**: 주석·커밋·UI 한글.

---

## Step 6 — 정적검사 (테스트 실행 금지)

```bash
# 변경된 PHP 파일 문법 검사
git -C "$WT_DIR" diff --name-only "$BRANCH" origin/main 2>/dev/null | grep '\.php$' | while read f; do
  php -l "$WT_DIR/$f" || echo "❌ 문법오류: $f"
done
# 변경된 쉘 스크립트
git -C "$WT_DIR" diff --name-only "$BRANCH" origin/main 2>/dev/null | grep '\.sh$' | while read f; do
  bash -n "$WT_DIR/$f" || echo "❌ 쉘문법오류: $f"
done
# compose 변경 시 설정 검증
git -C "$WT_DIR" diff --name-only "$BRANCH" origin/main 2>/dev/null | grep -q 'compose.*\.yml' && \
  (cd "$WT_DIR" && docker compose -f compose.yml config >/dev/null 2>&1 && echo "✅ compose config OK" || echo "⚠️ compose config 확인 필요")
```

오류가 있으면 전부 수정 후 재검사. 통과할 때까지 반복.

---

## Step 6.5 — 커밋

```bash
git -C "$WT_DIR" add -A
git -C "$WT_DIR" commit -m "{type}: {한글 요약}

{상세 — 무엇을·왜}

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

conversation.jsonl 기록:
```jsonl
{"ts":"{nowISO9}","step":"6","actor":"agent","event":"impl_committed","content":"{커밋 요약} — {변경 파일 N개}, php -l pass"}
```

---

## 완료 → wt-qa 자동 전환

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ 구현 완료 (커밋 {SHORT_SHA})
  변경 : {파일 목록}
  정적검사 : php -l pass / bash -n pass

이어서 검증(QA)을 진행합니다 → /wt-qa
  (정적검사 + 3관점 리뷰 + AC검증 + 스모크 테스트)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

사용자 개입 없이 `/wt-qa` 로 이어서 진행한다고 안내 후 계속. (Nano Track 은 wt-qa 경량 경로.)

## Non-Goals
- 런타임 테스트 실행 (wt-qa 담당)
- main 직접 커밋
- push/PR (wt-push 담당)
