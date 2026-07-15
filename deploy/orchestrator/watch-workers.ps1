<#
.SYNOPSIS
  워커 자동 이어받기 — 결과 파일을 폴링해 전원이 끝날 때까지 대기했다가 취합 리포트.

.DESCRIPTION
  claude-pipeline 은 cmux `read-screen` 으로 다른 세션 화면을 훔쳐봐 완료를 감지한다.
  순수 PowerShell 은 화면을 못 읽으므로, 워커가 `.omc/results/<task>.md` 첫 줄에 남기는
  상태 라벨(대기중/진행중/완료/차단)을 폴링한다. 감시 대상 전원이 종료 상태(완료|차단)가
  되면 취합 리포트를 찍고 exit 0 → 메인 세션이 그 출력을 받아 사용자에게 답한다.

  최적화:
    - 이 대기 루프는 claude 가 아니라 **순수 셸**이다. 기다리는 동안 메인 세션의 컨텍스트
      (토큰)가 전혀 늘지 않는다 — 무거운 작업 컨텍스트는 각 워커 탭에만 쌓인다. 이게 핵심.
    - 결과 파일의 mtime 이 바뀐 것만 다시 읽는다(변화 없으면 캐시된 라벨 사용).
    - 상태가 바뀐 워커만 한 줄 출력한다(폴링 스팸 방지).

.EXAMPLE
  .\watch-workers.ps1                  # 모든 워커가 끝날 때까지 대기 후 취합
  .\watch-workers.ps1 -Task a,b        # a,b 만 대기
  .\watch-workers.ps1 -TimeoutMin 30 -IntervalSec 10
#>
[CmdletBinding()]
param(
  # 감시할 워커 슬러그(생략 시 현재 스폰된 전체)
  [string[]]$Task,
  [int]$IntervalSec = 5,
  [int]$TimeoutMin = 60
)

$ErrorActionPreference = 'Stop'

$gitCommon = (& git rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw 'git 저장소가 아닙니다.' }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
$manifestDir = Join-Path $MainRoot '.omc\orchestrator'
# gh 는 방금 설치 시 기존 셸 PATH 에 없을 수 있다 → 설치 경로도 직접 찾는다.
function Resolve-Gh {
  $c = Get-Command gh -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $p = Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe'
  if (Test-Path $p) { return $p }
  return $null
}
$Gh = Resolve-Gh
$hasGh = [bool]$Gh

function Get-Manifests {
  if (-not (Test-Path $manifestDir)) { return @() }
  Get-ChildItem $manifestDir -Filter '*.json' | ForEach-Object {
    try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch { $null }
  } | Where-Object { $_ }
}
function Get-FirstLine($path) {
  if (-not (Test-Path $path)) { return '' }
  $l = Get-Content $path -TotalCount 1 -ErrorAction SilentlyContinue
  if ($l) { return $l.Trim() } else { return '' }
}
function Test-Terminal($line) { return ($line -match '^(완료|차단)') }
function Label-Color($line) {
  if ($line -match '^완료') { 'Green' } elseif ($line -match '^차단') { 'Red' }
  elseif ($line -match '^진행중') { 'Yellow' } else { 'Gray' }
}

# 감시 대상은 시작 시점에 고정한다(나중에 스폰된 워커는 이 대기에 안 낀다).
$initial = Get-Manifests
if ($Task) { $initial = $initial | Where-Object { $Task -contains $_.task } }
if (-not $initial) {
  Write-Host '감시할 워커 없음 (.omc/orchestrator/ 비어있음)' -ForegroundColor DarkGray
  exit 0
}
$watchTasks = @($initial.task)

Write-Host "=== 워커 자동 이어받기: $($watchTasks -join ', ') ===" -ForegroundColor Cyan
Write-Host "폴링 ${IntervalSec}s · 타임아웃 ${TimeoutMin}m · (대기 중 메인 컨텍스트 안 늘어남)" -ForegroundColor DarkGray

$lastLine = @{}    # task -> 마지막으로 본 첫 줄
$lastMtime = @{}   # task -> 마지막으로 읽은 결과 파일 mtime(ticks)
$deadline = (Get-Date).AddMinutes($TimeoutMin)

while ($true) {
  $mans = Get-Manifests | Where-Object { $watchTasks -contains $_.task }
  $doneCount = 0
  foreach ($m in $mans) {
    $line = $lastLine[$m.task]   # 기본값: 캐시
    $mt = if (Test-Path $m.result) { (Get-Item $m.result).LastWriteTimeUtc.Ticks } else { 0 }
    if ($lastMtime[$m.task] -ne $mt) {
      $lastMtime[$m.task] = $mt
      $line = Get-FirstLine $m.result
      if ($line -ne $lastLine[$m.task]) {
        Write-Host ("[{0}] {1,-18} {2}" -f (Get-Date -Format 'HH:mm:ss'), $m.task, $line) -ForegroundColor (Label-Color $line)
        $lastLine[$m.task] = $line
      }
    }
    if (Test-Terminal $line) { $doneCount++ }
  }

  if ($mans.Count -gt 0 -and $doneCount -eq $mans.Count) {
    Write-Host "`n=== 전원 종료 — 취합 ===" -ForegroundColor Cyan
    foreach ($m in $mans) {
      $line = Get-FirstLine $m.result
      $git = ''
      if (Test-Path $m.worktree) {
        $ahead = (& git -C $m.worktree rev-list --count "origin/main..$($m.branch)" 2>$null)
        $pushed = (& git -C $m.worktree ls-remote --heads origin $m.branch 2>$null)
        $git = "+$ahead 커밋 · " + $(if ($pushed) { 'push됨' } else { '미push' })
      }
      $pr = ''
      if ($hasGh) {
        try {
          $p = (& $Gh pr list --head $m.branch --json 'number,url' 2>$null | ConvertFrom-Json)
          if ($p) { $pr = "PR #$($p[0].number)" }
        } catch { }
      }
      Write-Host ("• {0} ({1})  {2} {3}" -f $m.task, $m.branch, $git, $pr) -ForegroundColor White
      Write-Host ("    {0}" -f $line) -ForegroundColor (Label-Color $line)
    }
    Write-Host ''
    exit 0
  }

  if ((Get-Date) -gt $deadline) {
    Write-Host "`n⚠ 타임아웃 ${TimeoutMin}m — 아직 종료 안 된 워커:" -ForegroundColor Yellow
    foreach ($m in $mans) {
      $line = Get-FirstLine $m.result
      if (-not (Test-Terminal $line)) { Write-Host "  $($m.task): $line" -ForegroundColor Yellow }
    }
    exit 2
  }

  Start-Sleep -Seconds $IntervalSec
}
