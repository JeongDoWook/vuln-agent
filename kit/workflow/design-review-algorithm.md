# design-review — Team Debate Protocol Detail

> `kit/skills/design-review/SKILL.md` Step 2 "팀 토론" 경로의 P2P 메시지 프로토콜.

---

## 왜 토론인가 (단순 병렬 3관점이 아니라)

세 관점을 그냥 병렬로 물으면 서로의 주장을 반박할 기회가 없다 — Devil's Advocate가 낸 실패
시나리오를 Regression Analyst가 "그 정도는 아니다"라고 판단해도 그 판단이 기록에 남지 않는다.
**명시적으로 충돌·합의시켜서** 열린 채로 남은 쟁점만 사람에게 넘긴다.

---

## 에이전트 3개, 단일 메시지에서 동시 dispatch (background)

```
design-devil-advocate:
  [Round 1] spec_path + code_path Read → 실패 이유 최소 2개(파일명·근거 포함)
  완료 후: SendMessage(to: design-regression-analyst, "findings: {...}")
           design-regression-analyst의 rebuttal 수신 대기
  [Round 2] rebuttal 수신 시 각 항목 accept("합의")/reject("open") 판정
  완료 후: SendMessage(to: caller, "DONE: da-final\n{sentinel YAML}")

design-regression-analyst:
  [Round 1] spec_path + code_path Read. design-devil-advocate의 findings 수신 대기
  [Round 2] findings 수신 시 affected/severity 판정, 동의=채택/미동의="open"
            추가 회귀 위험(API/DB/외부 인터페이스) 스스로 지적
  완료 후: SendMessage(to: design-devil-advocate, "rebuttal: {...}")
           SendMessage(to: design-runtime-trap, "risks: {...}")
           SendMessage(to: caller, "DONE: regression-final\n{sentinel YAML}")

design-runtime-trap:
  [Round 1] spec_path + code_path Read. runtimeTrapTaxonomy 패턴 탐지 시작(독립).
            design-regression-analyst의 risks 수신 대기
  [Round 2] risks 수신 시 DA+regression 결과와 교차 검증, 미합의 항목 최종 "open" 태그
  완료 후: SendMessage(to: caller, "DONE: runtime-trap\n{sentinel YAML}")
```

## 흐름도

```
[Round 1 — 동시]
  devil-advocate      ──findings──▶  regression-analyst
  runtime-trap         (독립 분석 시작)

[Round 2 — P2P]
  regression-analyst  ──rebuttal────▶  devil-advocate
  regression-analyst  ──risks────────▶  runtime-trap

[Round 3 — caller 수집]
  devil-advocate       ──DONE: da-final──────▶  caller
  regression-analyst   ──DONE: regression-final▶  caller
  runtime-trap          ──DONE: runtime-trap───▶  caller
```

## 수집 (caller)

3개 `"DONE: *"` 모두 수신 후:

- 각 sentinel 사이 YAML 파싱
- `status: open`인 항목 → Gate 요약에 "미합의 쟁점"으로 별도 노출
- 합의 항목은 `note: "(devil-advocate↔regression-analyst 합의)"` 표기

**폴백**: spawn 실패 또는 `~5분` 내 미수신 → 조용히 단일 패스(SKILL.md Step 2 기본 경로)로 전환.

---

## 토큰 비용 주의

독립 컨텍스트 3개를 쓰므로 단일 패스보다 비용이 높다. SKILL.md Step 2의 트리거 조건(되돌리기
어려운 인프라 선택 / 변경 파일 10개+ / 계약 파괴 변경)에 해당하는 **크고 위험한 변경에서만** 쓴다.
