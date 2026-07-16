<#
.SYNOPSIS
  오케스트레이터 이벤트 히스토리 기록 헬퍼 — dot-source 해서 Add-OrchestratorHistory 만 쓴다.

.DESCRIPTION
  "어디가 오래 걸렸는지" 를 나중에 되짚어보려면 사람(에이전트)이 기억해서 남기는 걸로는
  부족하다 — 까먹거나 생략하면 그 구간은 영영 안 남는다. 그래서 기록은 스크립트 3곳
  (spawn-worker.ps1 스폰 시점 · worker-stop-hook.ps1 상태 전환 시점 · reap-merged.ps1 정리
  시점)에서 **자동으로** 호출한다 — 워커·메인이 신경 안 써도 남는다.

  `.omc/logs/history.jsonl` 에 한 줄씩 append(JSON Lines). 실패해도 호출자를 절대 막지
  않는다(SilentlyContinue) — 히스토리 기록 실패가 실제 작업을 방해하면 안 된다.

.EXAMPLE
  . "$PSScriptRoot\history-log.ps1"
  Add-OrchestratorHistory -MainRoot $MainRoot -Task 'cve-badge' -Event 'spawn' -Detail 'feat/cve-badge'
#>
function Add-OrchestratorHistory {
  param(
    [Parameter(Mandatory)][string]$MainRoot,
    [Parameter(Mandatory)][string]$Task,
    [Parameter(Mandatory)][string]$Event,
    [string]$Detail = ''
  )
  try {
    $dir = Join-Path $MainRoot '.omc/logs'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $entry = [ordered]@{ ts = (Get-Date).ToString('o'); task = $Task; event = $Event; detail = $Detail }
    ($entry | ConvertTo-Json -Compress) | Add-Content -Path (Join-Path $dir 'history.jsonl') -Encoding utf8
  }
  catch { }
}
