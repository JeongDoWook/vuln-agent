<#
.SYNOPSIS
  .omc/tasks/*.md 에 미리 써 둔 지시문 파일들을 훑어, 파일 하나당 워커 하나씩 자동 스폰한다.

.DESCRIPTION
  "명령(지시문 작성) 단계"와 "구현(워커 실행) 단계"를 분리하는 흐름의 실행 쪽 절반이다.
  메인 세션은 하위작업을 쪼갠 뒤 Write 도구로 .omc/tasks/<슬러그>.md 파일들을 먼저 써 두고
  (CLAUDE.md "병렬 워커 오케스트레이터" 원칙 — 인라인 -Prompt 로 셸에서 긴 문자열을 직접
  조립하지 않는다), 그 다음 이 스크립트 한 번으로 전부 스폰한다. spawn-worker.ps1 을
  파일마다 손으로 반복 호출하다 슬러그를 잘못 짝짓거나 하나를 빼먹는 실수를 없앤다.

  스폰에 성공한 파일은 .omc/tasks/archive/ 로 옮긴다 — 재실행 시 이미 스폰한 작업을
  또 스폰하지 않는다(스폰 자체는 spawn-worker.ps1 이 기존 워크트리를 재사용하므로 멱등하지만,
  "무엇을 다음에 또 스폰할지" 목록이 지저분해지는 걸 막는다).

.EXAMPLE
  .\spawn-batch.ps1
  # .omc/tasks/*.md 전부를 기본값(Permissions ask, Launch auto, Finish pr)으로 스폰
  # Launch auto = spawn-worker.ps1 이 호스트 터미널을 감지해 같은 터미널로 띄운다

.EXAMPLE
  .\spawn-batch.ps1 -Permissions skip -Launch headless
#>
param(
  # 대상 파일 glob (기본: 모든 대기 중 하위작업)
  [string]$Glob = '.omc/tasks/*.md',

  # 아래 4개는 spawn-worker.ps1 로 그대로 전달된다
  [ValidateSet('feat', 'fix', 'chore')][string]$Prefix = 'feat',
  [string]$Base = 'origin/main',
  [ValidateSet('skip', 'ask')][string]$Permissions = 'ask',
  # 값 집합·기본값은 spawn-worker.ps1 의 -Launch 와 일치시킨다(배치만 다르면 감지가 안 붙는다)
  [ValidateSet('auto', 'termkeep', 'tab', 'window', 'headless')][string]$Launch = 'auto',
  [ValidateSet('pr', 'push')][string]$Finish = 'pr',

  # 미리보기만 — 스폰·아카이브 생략
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ── 메인 트리 루트 (spawn-worker.ps1 과 동일 규칙) ────────────────────────────
# PS 5.1 은 네이티브 exe 의 stderr 를 ErrorRecord 로 승격하고, EAP=Stop 이면 그게 종료 오류가 된다
#   — `2>$null` 리다이렉트가 바로 그 승격의 방아쇠다(실측). 저장소 밖에서 실행하면 git 이
#   'fatal: not a git repository' 를 stderr 로 쓰므로, 아래 friendly throw 대신 NativeCommandError
#   로 죽는다. 네이티브 호출 구간에만 EAP 를 낮추고 finally 로 원복한다(native-call.ps1 의
#   Invoke-Native, merge-milestone.ps1/reap-merged.ps1 의 Invoke-Gh 와 같은 대응). 이 파일엔
#   네이티브 호출이 이 하나뿐이라 헬퍼를 dot-source 하지 않고 인라인으로 둔다.
$prev = $ErrorActionPreference
try { $ErrorActionPreference = 'SilentlyContinue'; $gitCommon = (& git -C $PSScriptRoot rev-parse --git-common-dir 2>$null) }
finally { $ErrorActionPreference = $prev }
if (-not $gitCommon) { throw '스크립트가 git 저장소 안에 있지 않습니다.' }
if (-not [System.IO.Path]::IsPathRooted($gitCommon)) { $gitCommon = Join-Path $PSScriptRoot $gitCommon }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent

$tasksGlob = if ([System.IO.Path]::IsPathRooted($Glob)) { $Glob } else { Join-Path $MainRoot $Glob }
$files = Get-ChildItem -Path $tasksGlob -File -ErrorAction SilentlyContinue | Sort-Object Name

if (-not $files) {
  Write-Host "대상 없음: $tasksGlob 에 파일이 없습니다." -ForegroundColor Yellow
  Write-Host "먼저 하위작업마다 .omc/tasks/<슬러그>.md 로 지시문을 써 두세요(Write 도구)." -ForegroundColor DarkGray
  exit 0
}

Write-Host "== spawn-batch: $($files.Count)개 하위작업 발견 ==" -ForegroundColor Cyan
$files | ForEach-Object { Write-Host "  · $($_.Name)" -ForegroundColor DarkGray }

if ($DryRun) {
  Write-Host "[DryRun] 스폰 생략." -ForegroundColor DarkGray
  exit 0
}

$spawnWorker = Join-Path $PSScriptRoot 'spawn-worker.ps1'
$archiveDir = Join-Path $MainRoot '.omc/tasks/archive'
if (-not (Test-Path $archiveDir)) { New-Item -ItemType Directory -Force -Path $archiveDir | Out-Null }

$results = @()
foreach ($f in $files) {
  $slug = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
  Write-Host ""
  Write-Host "-- 스폰: $slug (from $($f.Name)) --" -ForegroundColor Cyan
  try {
    & $spawnWorker -Task $slug -PromptFile $f.FullName -Prefix $Prefix -Base $Base `
      -Permissions $Permissions -Launch $Launch -Finish $Finish
    Move-Item -Path $f.FullName -Destination (Join-Path $archiveDir $f.Name) -Force
    $results += [pscustomobject]@{ Slug = $slug; Status = 'spawned' }
  }
  catch {
    Write-Host "  ✗ 스폰 실패: $($_.Exception.Message)" -ForegroundColor Red
    $results += [pscustomobject]@{ Slug = $slug; Status = "실패: $($_.Exception.Message)" }
  }
}

Write-Host ""
Write-Host "== spawn-batch 완료 ==" -ForegroundColor Cyan
$results | Format-Table -AutoSize
