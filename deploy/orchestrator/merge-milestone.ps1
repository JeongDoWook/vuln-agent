<#
.SYNOPSIS
  마일스톤 통합 PR — 여러 워커 브랜치가 끝나길 기다렸다가 로컬 병합해 PR 1개로 묶는다.

.DESCRIPTION
  watch-workers.ps1 과 같은 폴링 패턴(결과 파일 .omc/results/<task>.md 첫 줄 상태 라벨,
  mtime 캐시, @() 배열 고정)을 재사용하되, 전원 종료 후 "리포트만 찍고 끝" 이 아니라
  실제로 병합 작업을 수행한다:

    1) 지정된 -Task 워커들의 매니페스트를 읽는다.
    2) 전원이 완료(^완료) 상태가 될 때까지 기다린다(차단이 하나라도 있으면 중단).
    3) milestone/<Milestone> 워크트리를 새로 만든다(origin/main 기점, 이미 있으면 재사용).
    4) 그 워크트리 안에서 각 워커 브랜치를 순서대로 `git merge --no-ff` 한다.
    5) 전부 병합되면 push 하고 gh pr create 로 PR 1개만 만든다.

  -Finish push 로 스폰한 워커(스스로 PR 을 만들지 않고 push 까지만 한 워커)를 모아
  하나의 마일스톤 PR 로 내는 용도. spawn-worker.ps1 의 옵션 B 파트너 스크립트.

.EXAMPLE
  .\merge-milestone.ps1 -Milestone my-feature -Task sub-a,sub-b

.EXAMPLE
  .\merge-milestone.ps1 -Milestone my-feature -Task sub-a,sub-b -TimeoutMin 30
#>
[CmdletBinding()]
param(
  # 마일스톤 슬러그 — wt/<Milestone>, 브랜치 milestone/<Milestone>, PR 제목에 쓰인다.
  [Parameter(Mandatory)][string]$Milestone,

  # 병합할 워커 슬러그들 (.omc/orchestrator/<task>.json 이 있어야 한다)
  [Parameter(Mandatory)][string[]]$Task,

  [string]$Base = 'origin/main',
  [int]$IntervalSec = 5,
  [int]$TimeoutMin = 60
)

$ErrorActionPreference = 'Stop'

# 저장소는 cwd 가 아니라 스크립트 위치 기준으로 찾는다 — 어느 폴더에서 실행해도 동작.
$gitCommon = (& git -C $PSScriptRoot rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw '스크립트가 git 저장소 안에 있지 않습니다.' }
if (-not [System.IO.Path]::IsPathRooted($gitCommon)) { $gitCommon = Join-Path $PSScriptRoot $gitCommon }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
$MainRootFwd = $MainRoot -replace '\\', '/'
$manifestDir = Join-Path $MainRoot '.omc\orchestrator'
$resultDir = Join-Path $MainRoot '.omc\results'

# ── git-bash 탐색 (wt.sh 호출용, spawn-worker.ps1 과 동일 패턴) ───────────────
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

# gh 는 cwd 의 git 저장소로 repo 를 추론한다 → GH_REPO 로 고정(reap-merged.ps1 과 동일 패턴).
$originUrl = (& git -C $MainRoot remote get-url origin 2>$null)
if ($originUrl -match 'github\.com[:/](.+?)(?:\.git)?/?\s*$') { $env:GH_REPO = $matches[1] }

function Resolve-Gh {
  $c = Get-Command gh -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $p = Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe'
  if (Test-Path $p) { return $p }
  if (${env:ProgramFiles(x86)}) {
    $p2 = Join-Path ${env:ProgramFiles(x86)} 'GitHub CLI\gh.exe'
    if (Test-Path $p2) { return $p2 }
  }
  return $null
}
$Gh = Resolve-Gh
if (-not $Gh) { throw "gh(GitHub CLI) 없음. 설치: winget install --id GitHub.cli -e" }

# 네이티브 gh 호출 래퍼. PS5.1 은 EAP=Stop 에서 네이티브 stderr 를 터미네이팅 에러로
# 취급해 크래시한다 → EAP 를 잠시 낮춰 stderr 를 삼키고 exit code 만 본다.
function Invoke-Gh([string[]]$GhArgs) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $out = & $Gh @GhArgs 2>$null
  $code = $LASTEXITCODE
  $ErrorActionPreference = $prev
  return [pscustomobject]@{ Out = $out; Code = $code }
}

if ((Invoke-Gh @('auth', 'status')).Code -ne 0) {
  throw "gh 인증 안 됨. 먼저 실행: gh auth login"
}

# ── 매니페스트 로드 ────────────────────────────────────────────────────────────
function Get-Manifest($t) {
  $p = Join-Path $manifestDir "$t.json"
  if (-not (Test-Path $p)) { throw "워커 매니페스트 없음: $t (.omc/orchestrator/$t.json) — spawn-worker.ps1 로 먼저 스폰하세요." }
  return (Get-Content $p -Raw | ConvertFrom-Json)
}
# @(...) 필수: -Task 가 1개면 스칼라가 돼 .Count 가 null → 이후 반복·카운트가 깨진다.
$manifests = @($Task | ForEach-Object { Get-Manifest $_ })

function Get-FirstLine($path) {
  if (-not (Test-Path $path)) { return '' }
  # -Encoding UTF8 필수: 워커는 UTF-8 로 쓰는데 PS5.1 기본은 cp949 → 완료/차단 라벨이 깨진다.
  $l = Get-Content $path -TotalCount 1 -Encoding UTF8 -ErrorAction SilentlyContinue
  if ($l) { return $l.Trim() } else { return '' }
}
function Test-Done($line) { return ($line -match '^완료') }
function Test-Blocked($line) { return ($line -match '^차단') }
function Label-Color($line) {
  if ($line -match '^완료') { 'Green' } elseif ($line -match '^차단') { 'Red' }
  elseif ($line -match '^진행중') { 'Yellow' } else { 'Gray' }
}

Write-Host "=== 마일스톤 통합 대기: $Milestone ($($manifests.task -join ', ')) ===" -ForegroundColor Cyan
Write-Host "폴링 ${IntervalSec}s · 타임아웃 ${TimeoutMin}m" -ForegroundColor DarkGray

$lastLine = @{}
$lastMtime = @{}
$deadline = (Get-Date).AddMinutes($TimeoutMin)

while ($true) {
  $doneCount = 0
  $blocked = @()
  foreach ($m in $manifests) {
    $line = $lastLine[$m.task]
    $mt = if (Test-Path $m.result) { (Get-Item $m.result).LastWriteTimeUtc.Ticks } else { 0 }
    if ($lastMtime[$m.task] -ne $mt) {
      $lastMtime[$m.task] = $mt
      $line = Get-FirstLine $m.result
      if ($line -ne $lastLine[$m.task]) {
        Write-Host ("[{0}] {1,-18} {2}" -f (Get-Date -Format 'HH:mm:ss'), $m.task, $line) -ForegroundColor (Label-Color $line)
        $lastLine[$m.task] = $line
      }
    }
    if (Test-Done $line) { $doneCount++ }
    if (Test-Blocked $line) { $blocked += $m.task }
  }

  if ($blocked.Count -gt 0) {
    Write-Host "`n✗ 차단된 워커가 있어 병합을 진행하지 않습니다: $($blocked -join ', ')" -ForegroundColor Red
    Write-Host "  해당 워커를 먼저 해결한 뒤 다시 실행하세요." -ForegroundColor Yellow
    exit 2
  }

  if ($doneCount -eq $manifests.Count) {
    Write-Host "`n=== 전원 완료 — 병합 시작 ===" -ForegroundColor Cyan
    break
  }

  if ((Get-Date) -gt $deadline) {
    Write-Host "`n⚠ 타임아웃 ${TimeoutMin}m — 아직 완료 안 된 워커:" -ForegroundColor Yellow
    foreach ($m in $manifests) {
      $line = Get-FirstLine $m.result
      if (-not (Test-Done $line)) { Write-Host "  $($m.task): $line" -ForegroundColor Yellow }
    }
    exit 2
  }

  Start-Sleep -Seconds $IntervalSec
}

# ── 마일스톤 워크트리 생성 (이미 있으면 재사용) ────────────────────────────────
$milestoneBranch = "milestone/$Milestone"
$milestoneDir = Join-Path $MainRoot "wt\$Milestone"

if (Test-Path $milestoneDir) {
  Write-Host "→ 마일스톤 워크트리 이미 존재, 재사용: wt/$Milestone" -ForegroundColor Yellow
}
else {
  Write-Host "== 마일스톤 워크트리 생성: $milestoneBranch → wt/$Milestone ==" -ForegroundColor Cyan
  Push-Location $MainRoot
  try { & $GitBash "$MainRootFwd/deploy/wt.sh" add $milestoneBranch $Base } finally { Pop-Location }
  if ($LASTEXITCODE -ne 0) { throw "wt.sh add 실패 (exit $LASTEXITCODE)" }
}

# ── 워커 브랜치 순서대로 로컬 병합 ─────────────────────────────────────────────
# 같은 로컬 저장소의 워크트리 간이라 브랜치 참조를 그냥 볼 수 있다 — origin fetch 불필요.
# 이미 병합된 브랜치를 다시 merge 하면 git 이 "Already up to date" 로 무해하게 넘어가므로
# 충돌 해결 후 재실행해도 안전하다.
Push-Location $milestoneDir
try {
  foreach ($m in $manifests) {
    Write-Host "-- 병합: $($m.branch) --" -ForegroundColor Cyan
    & git merge --no-ff $m.branch -m "병합: $($m.branch)"
    if ($LASTEXITCODE -ne 0) {
      Write-Host "`n✗ 병합 충돌: $($m.branch)" -ForegroundColor Red
      Write-Host "  wt/$Milestone 에서 충돌을 수동으로 해결한 뒤 git add + git commit 으로" -ForegroundColor Yellow
      Write-Host "  마무리하고, 이 스크립트를 다시 실행하세요(이미 병합된 브랜치는 재실행 시" -ForegroundColor Yellow
      Write-Host "  'Already up to date' 로 무해하게 건너뜁니다)." -ForegroundColor Yellow
      Write-Host "    cd wt/$Milestone" -ForegroundColor DarkGray
      Write-Host "    # 충돌 해결 후" -ForegroundColor DarkGray
      Write-Host "    git add -A; git commit --no-edit" -ForegroundColor DarkGray
      exit 2
    }
  }

  # ── push + PR ─────────────────────────────────────────────────────────────
  Write-Host "-- push: $milestoneBranch --" -ForegroundColor Cyan
  & git push -u origin $milestoneBranch
  if ($LASTEXITCODE -ne 0) { throw "push 실패 (exit $LASTEXITCODE)" }

  $bodyLines = @("이 PR 은 다음 워커 브랜치를 마일스톤 `"$Milestone`" 으로 로컬 병합해 묶은 것입니다:", '')
  foreach ($m in $manifests) {
    $bodyLines += "- ``$($m.branch)`` ($($m.task))"
    $resultFileText = if (Test-Path $m.result) { Get-Content $m.result -Raw -Encoding UTF8 } else { '' }
    if ($resultFileText -match '(?m)^완료:.*$') {
      $bodyLines += "  $($matches[0])"
    }
  }
  $body = $bodyLines -join "`n"
  $bodyFile = Join-Path $milestoneDir '.milestone-pr-body.txt'
  [System.IO.File]::WriteAllText($bodyFile, $body, (New-Object System.Text.UTF8Encoding($false)))

  Write-Host "-- PR 생성 --" -ForegroundColor Cyan
  $prResult = Invoke-Gh @('pr', 'create', '--title', "마일스톤: $Milestone", '--body-file', $bodyFile, '--base', 'main', '--head', $milestoneBranch)
  Remove-Item $bodyFile -ErrorAction SilentlyContinue
  if ($prResult.Code -ne 0) { throw "gh pr create 실패 (exit $($prResult.Code))" }

  Write-Host "`n✓ PR: $($prResult.Out)" -ForegroundColor Green
}
finally {
  Pop-Location
}
