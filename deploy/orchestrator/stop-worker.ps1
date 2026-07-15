<#
.SYNOPSIS
  워커 정리 — 워크트리 제거(wt.sh rm) + 매니페스트 삭제.

.DESCRIPTION
  PR 이 병합된 뒤 호출한다. wt.sh rm 이 워크트리를 지우고, 병합된 브랜치면
  로컬·원격 브랜치까지 정리한다(미병합이면 브랜치는 남긴다 — wt.sh 의 안전판).
  결과 파일(.omc/results/<task>.md)·로그는 기본 보존한다(-Purge 로 함께 삭제).

.EXAMPLE
  .\stop-worker.ps1 -Task cve-badge
  .\stop-worker.ps1 -Task cve-badge -Purge     # 결과·로그까지 삭제
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Task,
  [switch]$Purge
)

$ErrorActionPreference = 'Stop'

$gitCommon = (& git rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw 'git 저장소가 아닙니다.' }
# git-common-dir 은 메인 트리에서 상대경로(.git)를 줄 수 있다 → 절대경로로 먼저 변환.
$gitCommonAbs = (Resolve-Path $gitCommon).Path
$MainRoot = Split-Path $gitCommonAbs -Parent
$MainRootFwd = $MainRoot -replace '\\', '/'
$omcDir = Join-Path $MainRoot '.omc'

# PowerShell 의 'bash' 는 WSL bash 로 잡혀 C:/ 경로를 못 여는 수가 있다 → git-bash 명시.
function Resolve-GitBash {
  $cands = @()
  $gitCmd = Get-Command git -ErrorAction SilentlyContinue
  if ($gitCmd) { $cands += Join-Path (Split-Path (Split-Path $gitCmd.Source)) 'bin\bash.exe' }
  $cands += (Join-Path $env:ProgramFiles 'Git\bin\bash.exe')
  if (${env:ProgramFiles(x86)}) { $cands += (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe') }
  foreach ($c in $cands) { if ($c -and (Test-Path $c)) { return $c } }
  return 'bash'
}
$GitBash = Resolve-GitBash

# 워크트리 제거 (있을 때만)
$wtDir = Join-Path $MainRoot "wt\$Task"
if (Test-Path $wtDir) {
  Write-Host "== 워크트리 제거: wt/$Task ==" -ForegroundColor Cyan
  & $GitBash "$MainRootFwd/deploy/wt.sh" rm $Task
  if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠ wt.sh rm 실패 (exit $LASTEXITCODE) — 미커밋 변경이 있으면 먼저 커밋/되돌리세요." -ForegroundColor Yellow
    return
  }
}
else {
  Write-Host "→ 워크트리 이미 없음: wt/$Task" -ForegroundColor Yellow
}

# 매니페스트 삭제
$manifestPath = Join-Path $omcDir "orchestrator\$Task.json"
if (Test-Path $manifestPath) { Remove-Item $manifestPath; Write-Host "✓ 매니페스트 삭제" -ForegroundColor Green }

if ($Purge) {
  foreach ($p in @("results\$Task.md", "logs\$Task.log")) {
    $full = Join-Path $omcDir $p
    if (Test-Path $full) { Remove-Item $full; Write-Host "✓ 삭제: .omc/$($p -replace '\\','/')" -ForegroundColor Green }
  }
}

Write-Host "완료: $Task 정리됨" -ForegroundColor Green
