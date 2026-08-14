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

**경로는 저장소 기준 상대 경로로 준다.** `server/public/assets.php` 이지
`assets.php` 가 아니다. 파일명만 주면 한 건도 안 걸리는데, 실측으로 미탐의 35%가
이것이었다. 못 알아본 경로는 응답이 "저장소에서 못 찾은 경로" 로 알려주고 비슷한
경로를 제안하니, 그 줄이 보이면 제안된 경로로 다시 묻는다.

**작업 중 알아낸 것은 `record` 로 되돌려 적는다.** 코드를 읽다 알아낸 제약이나
고쳐 보고서야 안 이유처럼, git 히스토리에 안 남는데 다음 사람이 알아야 하는 것을
남긴다 — 안 적으면 세션이 끝날 때 같이 사라진다. 커밋 메시지로 남길 수 있는 것은
커밋에 적는다. `why`·`context` 는 바로 조회에 나가고, `constraint`·`correction`
은 사람이 웹 UI 에서 확인해야 나간다.

예: `record(kind="why", path="경로", content="알아낸 것", project="vuln-agent")`

**주의**
- 응답의 `[kind 신뢰도]` 뒤에 `추론` 이 붙은 것은 커밋 본문이 아니라 diff 를 보고
  세운 것이라 인용이 없다. 방향을 잡는 데는 쓰되 사실로 삼기 전에 코드로 대조한다.
- 근거 줄의 `f15efe52` 는 커밋이라 `git show` 로 대조한다. `github_issue#11` 처럼
  종류가 붙은 것은 커밋이 아니라 이슈·PR 번호다.
- `에이전트기록` 은 다른 에이전트가 `record` 로 남긴 것이다. 사람이 확인한 것이
  아니므로 인용 있는 기록과 같은 무게로 읽지 않는다.
- 문턱은 kind 마다 다르다. `why`·`context` 는 0.6까지 기본으로 나오지만
  `constraint`·`correction` 은 0.8 이상만 나온다. "문턱에 걸림"이 보이면
  `minConfidence` 를 0.6으로 낮춰 한 번 더 묻는다.
- "기록 없음"과 "제약 없음"은 다르다 — 안 나왔다고 제약이 없다는 뜻이 아니다.
- MCP 연결이 안 보이면: Claude Code 는 `claude mcp get codelore`, Codex 는
  `codex mcp get codelore` 로 확인한다. codelore 웹 UI 의 "에이전트 연동" 버튼을
  다시 누르면 둘 다 재등록된다.
<!-- codelore:end -->
