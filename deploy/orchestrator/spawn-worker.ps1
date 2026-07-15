<#
.SYNOPSIS
  워커 1개 스폰 — 새 워크트리 + 보이는 PowerShell 창에서 독립 claude 세션을 띄운다.

.DESCRIPTION
  claude-pipeline 의 multiplexer.js launchWinTerminal(powershell) 을 vuln-agent 의
  wt.sh 워크트리 위에 얹은 것. tmux/cmux 없이 Windows PowerShell 만으로 동작한다.

  흐름:
    1) deploy/wt.sh add <prefix>/<task>  → wt/<task> 워크트리 생성(origin/main 기점)
    2) 워커 지시문을 wt/<task>/.initial-prompt 로 주입(오케스트레이터 프리앰블 포함)
    3) -Launch tab(현재 WT 창 새 탭·기본) / window(분리 창) / headless(창 없이 로그)로 claude 실행
    4) <MainRoot>/.omc/orchestrator/<task>.json 에 워커 매니페스트 기록(status.ps1 이 읽음)

  워커는 자기 워크트리에서 구현→커밋→push→PR 까지 하고,
  진행/결과 요약을 <MainRoot>/.omc/results/<task>.md 에 남긴다(메인이 파일로 감독).

.EXAMPLE
  .\spawn-worker.ps1 -Task cve-badge -Prompt "findings.php 에 CVE 심각도 배지 추가"

.EXAMPLE
  .\spawn-worker.ps1 -Task matcher-fix -PromptFile .omc/tasks/matcher.md -Launch headless
#>
[CmdletBinding(DefaultParameterSetName = 'Inline')]
param(
  # 작업 슬러그. 브랜치·워크트리·로그·결과 파일 이름의 기준. 예: cve-badge
  [Parameter(Mandatory)][string]$Task,

  # 인라인 지시문(문자열)
  [Parameter(ParameterSetName = 'Inline')][string]$Prompt,

  # 또는 지시문을 담은 파일 경로
  [Parameter(ParameterSetName = 'File')][string]$PromptFile,

  # 브랜치 접두사 (feat/fix/chore)
  [ValidateSet('feat', 'fix', 'chore')][string]$Prefix = 'feat',

  # 워크트리 기점
  [string]$Base = 'origin/main',

  # 권한 모드: skip = --dangerously-skip-permissions(자율 워커 기본), ask = 매번 확인
  [ValidateSet('skip', 'ask')][string]$Permissions = 'skip',

  # 워커를 어디에 띄울지:
  #   tab     = 현재 Windows Terminal 창에 새 탭(기본)
  #   window  = 분리된 새 PowerShell 창
  #   headless= 창 없이 claude -p, 출력은 로그 파일로만
  [ValidateSet('tab', 'window', 'headless')][string]$Launch = 'tab',

  # 워크트리·지시문·매니페스트만 만들고 claude 실행은 생략(미리보기·테스트용)
  [switch]$DryRun,

  # 마무리 방식: pr(기본) = 워커가 스스로 커밋·push·PR 까지. push = 커밋·push 까지만 하고
  # PR 은 만들지 않는다 — 메인 세션이 merge-milestone.ps1 로 여러 워커 브랜치를 로컬 병합해
  # PR 1개로 묶어 낸다(마일스톤 통합 PR 모드).
  [ValidateSet('pr', 'push')][string]$Finish = 'pr'
)

$ErrorActionPreference = 'Stop'

# ── 메인 트리 루트 (wt.sh 와 동일 규칙: git-common-dir 의 부모) ───────────────
# 저장소는 cwd 가 아니라 스크립트 위치 기준으로 찾는다 — 어느 폴더에서 실행해도 동작.
$gitCommon = (& git -C $PSScriptRoot rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw '스크립트가 git 저장소 안에 있지 않습니다.' }
if (-not [System.IO.Path]::IsPathRooted($gitCommon)) { $gitCommon = Join-Path $PSScriptRoot $gitCommon }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
$MainRootFwd = $MainRoot -replace '\\', '/'

# ── git-bash 탐색 ────────────────────────────────────────────────────────────
# PowerShell 의 'bash' 는 WSL bash(C:\Windows\System32\bash.exe)로 잡혀 C:/ 경로를
# 못 여는 수가 있다("No such file"). Git for Windows 의 bash 를 명시적으로 우선한다.
function Resolve-GitBash {
  $cands = @()
  $gitCmd = Get-Command git -ErrorAction SilentlyContinue
  if ($gitCmd) {
    # C:\Program Files\Git\cmd\git.exe → C:\Program Files\Git\bin\bash.exe
    $cands += Join-Path (Split-Path (Split-Path $gitCmd.Source)) 'bin\bash.exe'
  }
  $cands += (Join-Path $env:ProgramFiles 'Git\bin\bash.exe')
  if (${env:ProgramFiles(x86)}) { $cands += (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe') }
  foreach ($c in $cands) { if ($c -and (Test-Path $c)) { return $c } }
  return 'bash'   # 최후 fallback
}
$GitBash = Resolve-GitBash

# ── Windows Terminal 탐색 (-Launch tab 용) ───────────────────────────────────
# wt.exe 는 앱 실행 별칭이라 PATH/Get-Command 로 안 잡히는 수가 있다 → 경로로 직접 찾는다.
function Resolve-Wt {
  $p = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wt.exe'
  if (Test-Path $p) { return $p }
  $g = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.WindowsTerminal*\wt.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($g) { return $g.FullName }
  $c = Get-Command wt.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  return $null
}

# ── 지시문 확보 ──────────────────────────────────────────────────────────────
if ($PromptFile) {
  if (-not (Test-Path $PromptFile)) { throw "PromptFile 없음: $PromptFile" }
  $taskText = Get-Content $PromptFile -Raw
}
elseif ($Prompt) {
  $taskText = $Prompt
}
else {
  throw '-Prompt 또는 -PromptFile 중 하나는 필요합니다.'
}

$branch = "$Prefix/$Task"
$wtDir = Join-Path $MainRoot "wt\$Task"

# ── .omc 런타임 디렉터리 (메인 트리 고정 — 모든 워커가 여기로 결과를 모은다) ──
$omcDir = Join-Path $MainRoot '.omc'
$logDir = Join-Path $omcDir 'logs'
$resultDir = Join-Path $omcDir 'results'
$manifestDir = Join-Path $omcDir 'orchestrator'
foreach ($d in @($logDir, $resultDir, $manifestDir)) {
  if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}
$logPath = Join-Path $logDir "$Task.log"
$resultPath = Join-Path $resultDir "$Task.md"
$manifestPath = Join-Path $manifestDir "$Task.json"

# ── 워크트리 생성 (wt.sh 위임 — 이미 있으면 그대로 사용) ─────────────────────
if (Test-Path $wtDir) {
  Write-Host "→ 워크트리 이미 존재, 재사용: wt/$Task" -ForegroundColor Yellow
}
else {
  Write-Host "== 워크트리 생성: $branch → wt/$Task ==" -ForegroundColor Cyan
  # wt.sh(bash) 도 cwd 에서 git 저장소를 찾는다 → 메인 트리에서 실행해야 한다.
  Push-Location $MainRoot
  try { & $GitBash "$MainRootFwd/deploy/wt.sh" add $branch $Base } finally { Pop-Location }
  if ($LASTEXITCODE -ne 0) { throw "wt.sh add 실패 (exit $LASTEXITCODE)" }
}

# ── 워커 지시문 = 사용자 작업 + 오케스트레이터 프리앰블 ───────────────────────
$resultPathFwd = $resultPath -replace '\\', '/'
$finishBlock = if ($Finish -eq 'push') {
@"
- 완료 시: 커밋 → push 까지만 한다. **PR 은 만들지 않는다** — 이 브랜치는 메인 세션이
  마일스톤 브랜치로 로컬 병합한 뒤 PR 하나로 묶어서 낸다.
- 진행/결과 요약을 아래 파일에 한국어로 남긴다(메인 세션이 이 파일로 너를 감독한다):
    $resultPathFwd
  · 시작할 때 한 줄: '진행중: <무엇을 하는 중>'
  · 끝나면: '완료: <한 일 요약>' 다음 줄에 'push 완료, 브랜치: $branch'
  · 막히면: '차단: <이유>' 로 남기고 멈춘다.
"@
} else {
@"
- 완료 시: 커밋 → push → PR 생성까지 한다.
- 진행/결과 요약을 아래 파일에 한국어로 남긴다(메인 세션이 이 파일로 너를 감독한다):
    $resultPathFwd
  · 시작할 때 한 줄: '진행중: <무엇을 하는 중>'
  · 끝나면: '완료: <한 일 요약>' + PR 링크
  · 막히면: '차단: <이유>' 로 남기고 멈춘다.
- **PR 링크는 이 탭에 보여도 정보 제공용이다.** 사용자에게 "이제 병합하세요" 처럼 행동을 유도하지
  않는다 — 병합 진행 여부는 메인(오케스트레이터) 세션이 모든 워커를 취합한 뒤 사용자에게 확인받고
  결정한다. 이 탭에서 곧장 병합되면, 메인이 뒤이어 같은 브랜치에 후속 커밋을 얹다가 경합할 수 있다.
"@
}
$preamble = @"
$taskText

---
[오케스트레이터 지침 — 이 워커 세션 규칙]
- 너는 vuln-agent 워크트리 wt/$Task/ 에서 도는 독립 워커다. 브랜치: $branch.
- 저장소 규칙은 CLAUDE.md 를 따른다. main 직접 커밋/push 금지 — 이 브랜치에서만.
- 코드를 건드렸으면 검증 게이트 통과: php -l / bash -n / (server·db·tests 변경 시) tests/smoke.sh.
$finishBlock
"@
Set-Content -Path (Join-Path $wtDir '.initial-prompt') -Value $preamble -Encoding utf8

# ── 결과 파일 초기화 (status.ps1 이 즉시 잡도록) ──────────────────────────────
Set-Content -Path $resultPath -Value "대기중: 워커 스폰됨 ($branch)" -Encoding utf8

# ── Stop 훅 등록 (결정론적 완료 자동기록) ────────────────────────────────────
# 워커 세션이 idle 될 때마다 worker-stop-hook.ps1 이 git 상태로 결과 파일을 갱신한다 →
# 워커가 "완료" 기록을 잊어도 메인(watch-workers)이 감지한다. settings.local.json 은
# gitignore(전역 **/.claude/settings.local.json)라 워커가 커밋할 위험이 없다.
# 이미 있으면(재스폰) 덮지 않는다.
$claudeDir = Join-Path $wtDir '.claude'
$settingsPath = Join-Path $claudeDir 'settings.local.json'
if (-not (Test-Path $settingsPath)) {
  if (-not (Test-Path $claudeDir)) { New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null }
  $hookScript = Join-Path $PSScriptRoot 'worker-stop-hook.ps1'
  $hookCmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$hookScript`""
  $settings = @{ hooks = @{ Stop = @(@{ hooks = @(@{ type = 'command'; command = $hookCmd }) }) } }
  $settings | ConvertTo-Json -Depth 8 | Set-Content -Path $settingsPath -Encoding utf8
}

# ── claude 실행 ──────────────────────────────────────────────────────────────
# 실행 명령을 워커별 .launch.ps1 파일에 담는다. -Command 인라인 대신 -File 을 쓰면
# wt 의 ';' 파싱·따옴표 이스케이프 지옥을 피할 수 있다.
$permFlag = if ($Permissions -eq 'skip') { '--dangerously-skip-permissions' } else { '' }
$wtDirEsc = $wtDir -replace "'", "''"
$launchPs1 = Join-Path $wtDir '.launch.ps1'

if ($Launch -eq 'headless') {
  $launchBody = @"
Set-Location -LiteralPath '$wtDirEsc'
`$p = Get-Content '.initial-prompt' -Raw
claude $permFlag -p `$p *> '$($logPath -replace "'", "''")'
"@
}
else {
  $launchBody = @"
Set-Location -LiteralPath '$wtDirEsc'
`$env:TERM = 'xterm-256color'
Write-Host '=== 워커: $Task ($branch) ===' -ForegroundColor Cyan
Write-Host '결과 파일: $resultPathFwd' -ForegroundColor DarkGray
Write-Host ''
`$p = Get-Content '.initial-prompt' -Raw
claude $permFlag `$p
"@
}

$proc = $null
if ($DryRun) {
  # 미리보기: 워크트리·지시문·매니페스트는 만들되 claude 는 띄우지 않는다.
  Write-Host "✓ [DryRun] 워크트리·지시문 준비됨: wt/$Task ($branch)" -ForegroundColor Green
  Write-Host "  claude 실행은 생략. 실제 스폰은 -DryRun 없이 다시 실행." -ForegroundColor DarkGray
}
else {
  Set-Content -Path $launchPs1 -Value $launchBody -Encoding utf8   # PS 5.1 utf8 = BOM(한글 배너)
  $eff = $Launch
  if ($Launch -eq 'tab') {
    $wt = Resolve-Wt
    if (-not $wt) {
      Write-Host "⚠ Windows Terminal(wt.exe) 없음 → 분리된 새 창으로 대체." -ForegroundColor Yellow
      $eff = 'window'
    }
    else {
      # -w 0 = 가장 최근 사용한 WT 창에 새 탭. 없으면 새 창을 연다.
      & $wt -w 0 new-tab --title $Task -d $wtDir powershell.exe -NoExit -NoProfile -File $launchPs1
      Write-Host "✓ 새 탭 열림: $Task (현재 Windows Terminal 창)  브랜치: $branch" -ForegroundColor Green
    }
  }
  if ($eff -eq 'window') {
    $proc = Start-Process powershell -PassThru -ArgumentList '-NoExit', '-NoProfile', '-File', $launchPs1
    Write-Host "✓ 워커 창 열림: $Task (PID $($proc.Id))  브랜치: $branch" -ForegroundColor Green
  }
  elseif ($eff -eq 'headless') {
    $proc = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile', '-File', $launchPs1
    Write-Host "✓ 헤드리스 워커 시작: $Task (PID $($proc.Id))  로그: .omc/logs/$Task.log" -ForegroundColor Green
  }
}

# ── 매니페스트 기록 (status.ps1 이 워커 목록을 여기서 읽는다) ─────────────────
$manifest = [ordered]@{
  task        = $Task
  branch      = $branch
  worktree    = $wtDir
  log         = $logPath
  result      = $resultPath
  mode        = $Launch
  permissions = $Permissions
  finish      = $Finish
  pid         = if ($proc) { $proc.Id } else { $null }
  startedAt   = (Get-Date).ToString('s')
}
$manifest | ConvertTo-Json | Set-Content -Path $manifestPath -Encoding utf8

Write-Host "  매니페스트: .omc/orchestrator/$Task.json" -ForegroundColor DarkGray
