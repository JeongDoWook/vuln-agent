<#
.SYNOPSIS
  .omc/history.jsonl 을 읽어 task 별 idle 타임라인 요약 — 어디서 오래 걸렸는지 본다.

.DESCRIPTION
  worker-stop-hook.ps1 이 워커 세션이 idle 될 때마다(에이전트 협조 없이, 훅이 강제로)
  남긴 기록을 task 별로 묶어, 최초~마지막 기록 사이 경과 시간(체류 시간)과 idle 전환
  횟수를 보여준다. 체류 시간이 긴 task 가 "오래 걸린" 작업이다.

  이건 claude-pipeline 의 work-report.py 처럼 Claude Code 원본 세션 transcript
  (~/.claude/projects/...) 까지 파싱하는 정밀 분석은 아니다 — 이 저장소 규모엔
  idle-간격 기반 요약이면 충분하다(YAGNI). 더 정밀한 분석이 실제로 필요해지면
  그때 transcript 파싱을 추가한다.

.EXAMPLE
  .\report.ps1                 # 전체 task 요약(체류 시간 내림차순)
  .\report.ps1 -Task cve-badge # 특정 task 의 idle 이벤트 전문
#>
param(
  [string]$Task,
  [switch]$Json
)

$ErrorActionPreference = 'Stop'

$gitCommon = (& git -C $PSScriptRoot rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw '스크립트가 git 저장소 안에 있지 않습니다.' }
if (-not [System.IO.Path]::IsPathRooted($gitCommon)) { $gitCommon = Join-Path $PSScriptRoot $gitCommon }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
$historyPath = Join-Path $MainRoot '.omc\history.jsonl'

if (-not (Test-Path $historyPath)) {
  Write-Host "히스토리 없음: $historyPath" -ForegroundColor Yellow
  Write-Host "워커가 아직 한 번도 idle 되지 않았습니다(worker-stop-hook.ps1 이 기록 대상)." -ForegroundColor DarkGray
  exit 0
}

$entries = Get-Content $historyPath | Where-Object { $_.Trim() -ne '' } | ForEach-Object {
  try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $_ }

if ($Task) {
  $filtered = $entries | Where-Object { $_.task -eq $Task } | Sort-Object { [datetime]$_.ts }
  if (-not $filtered) { Write-Host "task 없음: $Task" -ForegroundColor Yellow; exit 0 }
  if ($Json) { $filtered | ConvertTo-Json -Depth 5; exit 0 }
  $filtered | ForEach-Object {
    Write-Host "$($_.ts)  $($_.status)  ahead=$($_.ahead) dirty=$($_.dirty)" -ForegroundColor DarkGray
  }
  exit 0
}

$byTask = $entries | Group-Object task | ForEach-Object {
  $sorted = $_.Group | Sort-Object { [datetime]$_.ts }
  $first = [datetime]$sorted[0].ts
  $last = [datetime]$sorted[-1].ts
  [pscustomobject]@{
    Task        = $_.Name
    Branch      = $sorted[-1].branch
    LastStatus  = $sorted[-1].status
    IdleCount   = $sorted.Count
    First       = $first.ToString('MM-dd HH:mm')
    Last        = $last.ToString('MM-dd HH:mm')
    ElapsedMin  = [math]::Round((New-TimeSpan -Start $first -End $last).TotalMinutes, 1)
  }
} | Sort-Object ElapsedMin -Descending

if ($Json) { $byTask | ConvertTo-Json -Depth 5; exit 0 }

Write-Host "== 오케스트레이터 히스토리 — 체류 시간 내림차순 ==" -ForegroundColor Cyan
$byTask | Format-Table Task, Branch, LastStatus, IdleCount, First, Last, ElapsedMin -AutoSize
