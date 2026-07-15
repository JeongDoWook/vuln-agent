<#
.SYNOPSIS
  병합된 워커 자동 정리 — PR 이 main 에 병합된 워커를 감지해 stop-worker 로 치운다.

.DESCRIPTION
  워커 매니페스트의 브랜치별로 gh 로 PR 상태를 조회한다. state == MERGED 인 워커는
  소임을 다한 것 → stop-worker.ps1 을 호출해 워크트리·매니페스트를 정리한다.
  OPEN/리뷰중/미생성 PR 은 건드리지 않는다(리뷰 수정 여지를 남긴다).

  왜 "PR 생성"이 아니라 "병합"이 트리거인가: PR 은 리뷰가 되돌아올 수 있어, 병합 전까지는
  같은 브랜치·워크트리가 다시 필요하다. 진짜로 필요 없어지는 시점은 main 병합이다.

  gh 인증 필요: `gh auth login`. 미인증이면 안내 후 종료(정리 안 함).

.EXAMPLE
  .\reap-merged.ps1                       # 한 번 훑어 병합된 워커 정리
  .\reap-merged.ps1 -DryRun               # 정리 대상만 표시(실제 정리 안 함)
  .\reap-merged.ps1 -Purge                # 결과·로그까지 삭제
  .\reap-merged.ps1 -Watch -IntervalMin 5 # 5분마다 반복 감시
#>
[CmdletBinding()]
param(
  # 병합 감지만 하고 stop-worker 는 호출하지 않음
  [switch]$DryRun,
  # stop-worker 에 -Purge 전달(결과·로그 파일까지 삭제)
  [switch]$Purge,
  # 주기적 반복
  [switch]$Watch,
  [int]$IntervalMin = 5
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$stopWorker = Join-Path $scriptDir 'stop-worker.ps1'

$gitCommon = (& git rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw 'git 저장소가 아닙니다.' }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
$manifestDir = Join-Path $MainRoot '.omc\orchestrator'

# ── gh 확인 ──────────────────────────────────────────────────────────────────
# gh 는 방금 설치 시 기존 셸 PATH 에 없을 수 있다 → 설치 경로도 직접 찾는다.
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
if (-not $Gh) {
  Write-Host "gh(GitHub CLI) 없음. 설치: winget install --id GitHub.cli -e" -ForegroundColor Red
  exit 1
}
# 네이티브 gh 호출 래퍼. PS5.1 은 EAP=Stop 에서 네이티브 stderr 를 터미네이팅 에러로
# 취급해 크래시한다(gh auth status 는 성공해도 stderr 에 쓴다). EAP 를 잠시 낮춰
# stderr 를 삼키고 exit code 만 본다.
function Invoke-Gh([string[]]$GhArgs) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $out = & $Gh @GhArgs 2>$null
  $code = $LASTEXITCODE
  $ErrorActionPreference = $prev
  return [pscustomobject]@{ Out = $out; Code = $code }
}

if ((Invoke-Gh @('auth', 'status')).Code -ne 0) {
  Write-Host "gh 인증 안 됨. 먼저 실행: gh auth login" -ForegroundColor Yellow
  Write-Host "  (브라우저 OAuth 또는 토큰 — 사용자가 직접 인증해야 합니다.)" -ForegroundColor DarkGray
  exit 1
}

function Get-Manifests {
  if (-not (Test-Path $manifestDir)) { return @() }
  Get-ChildItem $manifestDir -Filter '*.json' | ForEach-Object {
    try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch { $null }
  } | Where-Object { $_ }
}

# 브랜치의 PR 이 병합됐나 → $true/$false. PR 없거나 오류면 $false(건드리지 않음).
function Test-Merged($branch) {
  # --json 값은 콤마-연결 단일 문자열로 인용한다(PS 에서 number,mergedAt 은 배열 연산자).
  $r = Invoke-Gh @('pr', 'list', '--head', $branch, '--state', 'merged', '--json', 'number,mergedAt')
  if ($r.Code -ne 0 -or -not $r.Out) { return $false }
  # @(...) 필수: PR 이 1개면 스칼라가 돼 .Count 가 null → 병합 감지를 놓친다.
  $prs = @($r.Out | ConvertFrom-Json)
  return ($prs.Count -gt 0)
}

function Reap-Once {
  $mans = Get-Manifests
  if (-not $mans) { Write-Host '스폰된 워커 없음' -ForegroundColor DarkGray; return }
  $reaped = 0
  foreach ($m in $mans) {
    if (Test-Merged $m.branch) {
      if ($DryRun) {
        Write-Host "[DryRun] 병합됨 → 정리 대상: $($m.task) ($($m.branch))" -ForegroundColor Yellow
      }
      else {
        Write-Host "== 병합 감지 → 정리: $($m.task) ($($m.branch)) ==" -ForegroundColor Cyan
        if ($Purge) { & $stopWorker -Task $m.task -Purge } else { & $stopWorker -Task $m.task }
        $reaped++
      }
    }
    else {
      Write-Host "· 유지(미병합): $($m.task) ($($m.branch))" -ForegroundColor DarkGray
    }
  }
  if (-not $DryRun) { Write-Host "정리 $reaped 개." -ForegroundColor Green }
}

if ($Watch) {
  while ($true) {
    Write-Host "=== reap ($(Get-Date -Format 'HH:mm:ss')) ===" -ForegroundColor Cyan
    Reap-Once
    Write-Host "다음 감시까지 ${IntervalMin}m..." -ForegroundColor DarkGray
    Start-Sleep -Seconds ($IntervalMin * 60)
  }
}
else {
  Reap-Once
}
