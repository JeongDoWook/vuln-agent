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

  # 명시 신호(완료/차단) 우선 — 이미 있으면 덮지 않는다.
  $first = (Get-Content $resultPath -TotalCount 1 -Encoding UTF8 2>$null)
  if ($first -match '^(완료|차단)') { exit 0 }

  $ahead = [int](& git rev-list --count "origin/main..HEAD" 2>$null)
  $head = (& git rev-parse HEAD 2>$null)
  $remoteRef = (& git rev-parse --verify --quiet "refs/remotes/origin/$branch" 2>$null)
  $pushed = ($remoteRef -and $head -and $remoteRef.Trim() -eq $head.Trim())
  $dirty = [bool](& git status --porcelain --untracked-files=no 2>$null)

  $line =
  if ($pushed -and $ahead -gt 0) { "완료(자동): +$ahead 커밋 push됨 · $branch" }
  elseif ($ahead -gt 0) { "진행중(자동): +$ahead 커밋, 미push · $branch" }
  elseif ($dirty) { "진행중(자동): 편집 중, 미커밋 · $branch" }
  else { "대기중(자동): 변경 없음 · $branch" }

  # 상태가 실제로 바뀔 때만 히스토리에 남긴다(매 idle tick 마다가 아니라 전환 시점만).
  if ($line -ne $first) {
    . (Join-Path $PSScriptRoot 'history-log.ps1')
    Add-OrchestratorHistory -MainRoot $mainRoot -Task $task -Event 'status' -Detail $line
  }

  # 첫 줄(상태 라벨)만 갈아끼우고 2행 이후 본문은 그대로 남긴다.
  # 라벨이 첫 줄이어야 하는 건 계약이다 — status.ps1·watch-workers.ps1·merge-milestone.ps1 이
  # Get-Content -TotalCount 1 로 첫 줄만 읽어 상태를 판정한다.
  # 예전엔 Set-Content 로 파일 전체를 $line 하나로 대체해서, 워커가 남긴 검증 증거가
  # idle 될 때마다 통째로 사라졌다(첫 줄이 '진행중' 이면 위 가드에도 안 걸린다).
  # 본문이 없는 1줄 파일이면 아래는 예전 동작과 동일하다.
  $body = @(Get-Content -Path $resultPath -Encoding UTF8 2>$null | Select-Object -Skip 1)
  Set-Content -Path $resultPath -Value (@($line) + $body) -Encoding UTF8
}
catch { }
exit 0
