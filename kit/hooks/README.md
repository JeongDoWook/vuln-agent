# kit/hooks — 어댑터가 선언한 금지 규칙을 기계로 강제하는 층

`kit/workflow/guardrails.md` 의 항목 대부분은 **판단**이 필요해서 문장으로만 존재할 수밖에 없다.
그중 **명령 문자열만 보고 판정 가능한 것**은 훅으로 내려 실행 전에 `exit 2` 로 막는다 — 프롬프트가
지시를 놓쳐도 통과하지 않게 하는 것이 목적이다.

| 훅 | 시점 | 막는 것 |
|---|---|---|
| `guard-bash.js` | PreToolUse:Bash | 보호 브랜치 직접 push · force push · 어댑터가 지정한 금지 패턴 |

## 규칙은 어댑터에 있다

훅 파일에는 브랜치 이름도 금지 명령도 없다. 전부 저장소 루트 `.review-kit.json` 의 `guards` 절에서 온다.

```jsonc
"guards": {
  "protectedBranches": ["main", "master", "develop"],  // 이 이름으로 나가는 git push 를 막는다
  "blockForcePush": true,                              // 대상 브랜치와 무관하게 force push 차단
  "blockedCommands": [
    { "pattern": "rm\\s+-rf\\s+/(\\s|$)", "reason": "루트 삭제" }
  ]
}
```

`guards` 절이 없으면 **아무것도 막지 않는다.** 훅을 깔았다는 사실만으로 프로젝트가 모르는 규칙이
생기지 않아야 하기 때문이다 — 규칙은 어댑터가 명시적으로 켠다.

## 설치 (Claude Code)

```bash
cp -r spec-review-kit/kit/hooks <저장소>/kit/hooks/
```

`<저장소>/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "node \"$CLAUDE_PROJECT_DIR/kit/hooks/guard-bash.js\"" }
        ]
      }
    ]
  }
}
```

**Node 로 부른다.** 원본이 된 실전 훅은 bash + `python3` 조합이었는데, Windows 개발기에서
`python3` 가 없으면 명령 추출이 조용히 빈 문자열이 되어 **가드 전체가 무력화**됐다. 이 킷의
스크립트는 전부 node 내장만 쓰므로 node 로 통일한다.

## 이 훅이 못 막는 것

- **Codex·다른 CLI**: PreToolUse 훅에 해당하는 지점이 없다. 그 환경에서 이 규칙의 유일한 방어는
  `kit/workflow/guardrails.md` 와 `AGENTS.md` 의 문장이다 — 훅이 있다고 규칙을 문서에서 지우면 안 된다.
- **다른 경로로 나가는 같은 동작**: `px release`·MCP·에디터 GUI 는 Bash 를 거치지 않는다.
  파괴적 동작의 확인은 여전히 스킬 본문과 프로바이더 구현 안에 있어야 한다.
- **판단이 필요한 규칙**: "결함 클래스 단위로 고쳤는가", "검증 패스를 저자보다 약하게 돌리지
  않았는가" — 문자열로 판정할 수 없다. 이건 계속 문서 몫이다.

fail-open이다. 훅 자신의 파싱 실패나 설정 깨짐으로 사용자의 작업을 막지 않고, 그 사실을 stderr 에
남긴 뒤 통과시킨다. 조용히 무력화되는 것이 가장 나쁜 실패라서, 무력화될 때는 반드시 티를 낸다.
