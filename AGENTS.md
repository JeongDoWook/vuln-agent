# AGENTS.md

이 저장소를 다루는 모든 에이전트(Claude Code, Codex CLI 등)에 공통으로 적용되는 지침이다.
Claude Code 전용 지침은 CLAUDE.md 에 있고, 그 파일 상단에서 이 파일을 `@AGENTS.md` 로 불러온다.
Codex 는 파일명 규약으로 이 파일을 자동 로드한다 — 그래서 **양쪽이 같은 내용을 본다.**

설계 게이트·코드리뷰·라이프사이클 방법론(spec-review-kit)은 `AGENTS-review-kit.md` 가 진입점이다.
이 파일과 역할이 갈린다: 여기는 **이 저장소의 사실**(codelore 조회 규약 등), 저기는 **이식된 방법론의
실행 규칙**이다. 킷은 자기 진입점을 `AGENTS-review-kit.md` 로 따로 두고 이 파일을 덮어쓰지 않는다.

<!-- codelore:start -->
## codelore MCP — 파일 수정 전 히스토리 조회

이 저장소(`vuln-agent`)는 codelore 에 등록돼 있다. codelore 는 git 히스토리에서
"코드에 안 적힌 맥락"(왜 이렇게 됐는지, 무엇이 되돌려졌는지, 어떤 제약이 있는지)을 뽑아
MCP 로 조회하게 해주는 도구다. Claude Code·Codex CLI 양쪽 모두에 codelore MCP 서버가
등록돼 있다 — 이 디렉터리를 여는 어느 쪽 에이전트든 아래 도구를 바로 부를 수 있다.

**파일을 수정하기 전에 codelore MCP 의 `context_for_change` 를 수정 예정 경로들과 작업
의도로 호출한다.** `project` 는 항상 `"vuln-agent"` 로 지정한다 — codelore DB 에 저장소가 여러 개
등록돼 있어서 project 없이는 다른 저장소를 조회할 수 있다.

예: `context_for_change(paths=["경로"], intent="작업 의도", project="vuln-agent")`

기본 토큰 예산은 1200이며, 부족할 때만 `why(path, project)`, `constraints(path, project)`,
`history(path, project)` 로 상세를 펼친다. 경로를 모를 때는 `search(query, project="vuln-agent")`.

**주의**
- 기본 신뢰도 문턱은 0.8이다. diff 만 보고 추론한 노트(Tier 1b)는 신뢰도 상한이 0.6이라
  기본 조회에 안 나온다 — 필요하면 `minConfidence` 를 0.5~0.6으로 낮춰서 명시적으로 부른다.
- 응답에 붙는 인용/커밋 해시가 근거다. 미심쩍으면 `git show` 로 직접 대조한다.
- "기록 없음"과 "제약 없음"은 다르다 — 안 나왔다고 제약이 없다는 뜻이 아니다.
- MCP 연결이 안 보이면: Claude Code 는 `claude mcp get codelore`, Codex 는
  `codex mcp get codelore` 로 확인한다. codelore 웹 UI 의 "에이전트 연동" 버튼을
  다시 누르면 둘 다 재등록된다.
<!-- codelore:end -->
