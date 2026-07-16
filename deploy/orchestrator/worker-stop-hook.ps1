<#
  worker-stop-hook.ps1 — 워커 세션의 Claude Code Stop 훅.

  워커(claude)가 응답을 마치고 idle 될 때마다 실행된다. git 상태로 결과 파일을
  결정론적으로 갱신한다 → 워커가 "완료" 기록을 잊어도 메인(watch-workers/status/reap)이
  정확히 감지한다. claude-pipeline 의 "thinking→idle" 감지에 대응하는 결정론적 버전.

  판정(cwd = 워크트리 기준, 네트워크 없이 로컬 ref 만):
    - HEAD 가 origin/<branch> 로 push 됨(+커밋 있음)  → 완료(자동)
    - 커밋은 있는데 미push                            → 진행중(자동): 미push
    - 커밋 없이 편집만(미커밋 변경)                    → 진행중(자동): 미커밋
    - 변경 없음                                        → 대기중(자동)
  워커/메인이 이미 "완료"/"차단"을 명시했으면 건드리지 않는다(명시 신호 우선).

  spawn-worker.ps1 이 워커 워크트리의 .claude/settings.local.json 에 Stop 훅으로 등록한다.
  결과 파일이 없는 워크트리(오케스트레이터 워커가 아님)에서는 아무것도 안 한다.

  **히스토리 기록**: 매 idle 전환마다 .omc/history.jsonl 에 한 줄씩 append 한다(task/branch/
  status/시각). "에이전트가 기록하는 척 하다가 안 하는" 문제(claude-pipeline 의
  conversation.jsonl 이 실제로 겪는 문제 — 에이전트가 Write 로 스스로 남겨야 해서 자주
  빠뜨림)를 피하려고, 이 로그는 에이전트 협조 없이 **훅이 매번 강제로** 쓴다. report.ps1 이
  이 파일을 읽어 task 별 최초~마지막 idle 시각 차이(체류 시간)를 계산해 "어디서 오래
  걸렸는지" 보여준다.
#>
$ErrorActionPreference = 'SilentlyContinue'
try {
  $gitCommon = (& git rev-parse --git-common-dir 2>$null)
  if (-not $gitCommon) { exit 0 }
  $mainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
  $task = Split-Path (Resolve-Path .).Path -Leaf
  $branch = (& git rev-parse --abbrev-ref HEAD 2>$null)
  $resultPath = Join-Path $mainRoot ".omc\results\$task.md"

  # 오케스트레이터 워커가 아니면(결과 파일 없음) 조용히 빠진다.
  if (-not (Test-Path $resultPath)) { exit 0 }

  $ahead = [int](& git rev-list --count "origin/main..HEAD" 2>$null)
  $head = (& git rev-parse HEAD 2>$null)
  $remoteRef = (& git rev-parse --verify --quiet "refs/remotes/origin/$branch" 2>$null)
  $pushed = ($remoteRef -and $head -and $remoteRef.Trim() -eq $head.Trim())
  $dirty = [bool](& git status --porcelain --untracked-files=no 2>$null)

  $status =
  if ($pushed -and $ahead -gt 0) { '완료' }
  elseif ($ahead -gt 0) { '진행중' }
  elseif ($dirty) { '진행중' }
  else { '대기중' }

  # 히스토리는 명시 신호 유무와 무관하게 매번 남긴다 — task 별 idle 타임라인이 목적이라
  # "이미 완료로 굳었다" 도 하나의 데이터 포인트다(예: 완료 후 사용자가 후속 질문한 시각).
  $historyPath = Join-Path $mainRoot '.omc\history.jsonl'
  $entry = [ordered]@{
    ts     = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    task   = $task
    branch = $branch
    status = $status
    ahead  = $ahead
    dirty  = $dirty
  }
  Add-Content -Path $historyPath -Value ($entry | ConvertTo-Json -Compress) -Encoding UTF8

  # 명시 신호(완료/차단) 우선 — 결과 파일 텍스트는 이미 있으면 덮지 않는다.
  $first = (Get-Content $resultPath -TotalCount 1 -Encoding UTF8 2>$null)
  if ($first -match '^(완료|차단)') { exit 0 }

  $line =
  if ($status -eq '완료') { "완료(자동): +$ahead 커밋 push됨 · $branch" }
  elseif ($ahead -gt 0) { "진행중(자동): +$ahead 커밋, 미push · $branch" }
  elseif ($dirty) { "진행중(자동): 편집 중, 미커밋 · $branch" }
  else { "대기중(자동): 변경 없음 · $branch" }

  Set-Content -Path $resultPath -Value $line -Encoding UTF8
}
catch { }
exit 0
