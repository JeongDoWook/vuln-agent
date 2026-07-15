<#
.SYNOPSIS
  워커 감독 — 스폰된 워커들의 결과 파일·git 상태·PR 을 한눈에.

.DESCRIPTION
  순수 PowerShell 창은 cmux 처럼 화면을 훔쳐볼 수 없다(read-screen 불가).
  그래서 워커는 파일로 상태를 남기고, 여기서 그 파일들을 모아 본다:
    - .omc/results/<task>.md  (워커가 남기는 진행/결과 — 대기중·진행중·완료·차단)
    - 워크트리 git 상태        (커밋 수·push 여부)
    - PR 상태                  (gh 있으면 조회)

.EXAMPLE
  .\status.ps1
  .\status.ps1 -Task cve-badge      # 특정 워커만, 결과 파일 전문 출력
  .\status.ps1 -Watch               # 5초마다 갱신
#>
[CmdletBinding()]
param(
  # 특정 워커만 상세히
  [string]$Task,
  # 주기적 갱신
  [switch]$Watch,
  [int]$IntervalSec = 5
)

$ErrorActionPreference = 'Stop'

$gitCommon = (& git rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw 'git 저장소가 아닙니다.' }
# git-common-dir 은 메인 트리에서 상대경로(.git)를 줄 수 있다 → 절대경로로 먼저 변환.
$gitCommonAbs = (Resolve-Path $gitCommon).Path
$MainRoot = Split-Path $gitCommonAbs -Parent
$manifestDir = Join-Path $MainRoot '.omc\orchestrator'

$hasGh = [bool](Get-Command gh -ErrorAction SilentlyContinue)

function Get-Workers {
  if (-not (Test-Path $manifestDir)) { return @() }
  Get-ChildItem $manifestDir -Filter '*.json' | ForEach-Object {
    try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch { $null }
  } | Where-Object { $_ }
}

# 결과 파일 첫 줄에서 상태 라벨 추출 (대기중/진행중/완료/차단)
function Get-ResultLine($path) {
  if (-not (Test-Path $path)) { return '(결과 파일 없음)' }
  $line = (Get-Content $path -TotalCount 1 -ErrorAction SilentlyContinue)
  if (-not $line) { return '(빈 결과 파일)' }
  return $line.Trim()
}

# 워크트리 git 상태: 브랜치가 origin 대비 몇 커밋 앞섰나 + push 됐나
function Get-GitState($wt, $branch) {
  if (-not (Test-Path $wt)) { return 'worktree 없음' }
  $ahead = (& git -C $wt rev-list --count "origin/main..$branch" 2>$null)
  $pushed = (& git -C $wt ls-remote --heads origin $branch 2>$null)
  $dirty = (& git -C $wt status --porcelain --untracked-files=no 2>$null)
  $parts = @()
  if ($ahead) { $parts += "+$ahead 커밋" }
  $parts += if ($pushed) { 'push됨' } else { '미push' }
  if ($dirty) { $parts += '미커밋변경' }
  return ($parts -join ' · ')
}

function Get-PrState($branch) {
  if (-not $hasGh) { return '' }
  $pr = (& gh pr list --head $branch --json number, state, url 2>$null | ConvertFrom-Json)
  if ($pr) { return "PR #$($pr[0].number) $($pr[0].state)" }
  return ''
}

function Show-Status {
  $workers = Get-Workers
  if (-not $workers) {
    Write-Host '스폰된 워커 없음 (.omc/orchestrator/ 비어있음)' -ForegroundColor DarkGray
    return
  }

  if ($Task) {
    $w = $workers | Where-Object { $_.task -eq $Task }
    if (-not $w) { Write-Host "워커 없음: $Task" -ForegroundColor Red; return }
    Write-Host "=== 워커: $($w.task) ($($w.branch)) ===" -ForegroundColor Cyan
    Write-Host "git : $(Get-GitState $w.worktree $w.branch)  $(Get-PrState $w.branch)"
    Write-Host "mode: $($w.mode)  pid: $($w.pid)  시작: $($w.startedAt)"
    Write-Host "--- 결과 파일 ($($w.result)) ---" -ForegroundColor DarkGray
    if (Test-Path $w.result) { Get-Content $w.result } else { Write-Host '(없음)' }
    return
  }

  Write-Host "=== 워커 현황 ($(Get-Date -Format 'HH:mm:ss')) ===" -ForegroundColor Cyan
  foreach ($w in $workers) {
    $status = Get-ResultLine $w.result
    $git = Get-GitState $w.worktree $w.branch
    $pr = Get-PrState $w.branch
    # 상태 라벨별 색
    $color = switch -Regex ($status) {
      '^완료'   { 'Green' }
      '^차단'   { 'Red' }
      '^진행중' { 'Yellow' }
      default   { 'Gray' }
    }
    Write-Host ("{0,-16} " -f $w.task) -ForegroundColor White -NoNewline
    Write-Host ("{0,-10} " -f $git) -ForegroundColor DarkGray -NoNewline
    if ($pr) { Write-Host ("{0} " -f $pr) -ForegroundColor DarkCyan -NoNewline }
    Write-Host $status -ForegroundColor $color
  }
  Write-Host ''
  Write-Host '상세: .\status.ps1 -Task <이름>   전문: Get-Content .omc/results/<이름>.md' -ForegroundColor DarkGray
}

if ($Watch) {
  while ($true) {
    Clear-Host
    Show-Status
    Start-Sleep -Seconds $IntervalSec
  }
}
else {
  Show-Status
}
