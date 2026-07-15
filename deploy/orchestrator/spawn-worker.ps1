<#
.SYNOPSIS
  워커 1개 스폰 — 새 워크트리 + 보이는 PowerShell 창에서 독립 claude 세션을 띄운다.

.DESCRIPTION
  claude-pipeline 의 multiplexer.js launchWinTerminal(powershell) 을 vuln-agent 의
  wt.sh 워크트리 위에 얹은 것. tmux/cmux 없이 Windows PowerShell 만으로 동작한다.

  흐름:
    1) deploy/wt.sh add <prefix>/<task>  → wt/<task> 워크트리 생성(origin/main 기점)
    2) 워커 지시문을 wt/<task>/.initial-prompt 로 주입(오케스트레이터 프리앰블 포함)
    3) 보이는 PowerShell 창(-Visible, 기본) 또는 헤드리스(-Headless)로 claude 실행
    4) <MainRoot>/.omc/orchestrator/<task>.json 에 워커 매니페스트 기록(status.ps1 이 읽음)

  워커는 자기 워크트리에서 구현→커밋→push→PR 까지 하고,
  진행/결과 요약을 <MainRoot>/.omc/results/<task>.md 에 남긴다(메인이 파일로 감독).

.EXAMPLE
  .\spawn-worker.ps1 -Task cve-badge -Prompt "findings.php 에 CVE 심각도 배지 추가"

.EXAMPLE
  .\spawn-worker.ps1 -Task matcher-fix -PromptFile .omc/tasks/matcher.md -Headless
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

  # 창을 띄우지 않고 백그라운드에서 claude -p 로 실행, 출력은 로그 파일로만
  [switch]$Headless,

  # 워크트리·지시문·매니페스트만 만들고 claude 실행은 생략(미리보기·테스트용)
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ── 메인 트리 루트 (wt.sh 와 동일 규칙: git-common-dir 의 부모) ───────────────
$gitCommon = (& git rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw 'git 저장소가 아닙니다.' }
# git-common-dir 은 메인 트리에서 상대경로(.git)를 줄 수 있다 → 절대경로로 먼저 변환.
$gitCommonAbs = (Resolve-Path $gitCommon).Path
$MainRoot = Split-Path $gitCommonAbs -Parent
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
  & $GitBash "$MainRootFwd/deploy/wt.sh" add $branch $Base
  if ($LASTEXITCODE -ne 0) { throw "wt.sh add 실패 (exit $LASTEXITCODE)" }
}

# ── 워커 지시문 = 사용자 작업 + 오케스트레이터 프리앰블 ───────────────────────
$resultPathFwd = $resultPath -replace '\\', '/'
$preamble = @"
$taskText

---
[오케스트레이터 지침 — 이 워커 세션 규칙]
- 너는 vuln-agent 워크트리 wt/$Task/ 에서 도는 독립 워커다. 브랜치: $branch.
- 저장소 규칙은 CLAUDE.md 를 따른다. main 직접 커밋/push 금지 — 이 브랜치에서만.
- 코드를 건드렸으면 검증 게이트 통과: php -l / bash -n / (server·db·tests 변경 시) tests/smoke.sh.
- 완료 시: 커밋 → push → PR 생성까지 한다.
- 진행/결과 요약을 아래 파일에 한국어로 남긴다(메인 세션이 이 파일로 너를 감독한다):
    $resultPathFwd
  · 시작할 때 한 줄: '진행중: <무엇을 하는 중>'
  · 끝나면: '완료: <한 일 요약>' + PR 링크
  · 막히면: '차단: <이유>' 로 남기고 멈춘다.
"@
Set-Content -Path (Join-Path $wtDir '.initial-prompt') -Value $preamble -Encoding utf8

# ── 결과 파일 초기화 (status.ps1 이 즉시 잡도록) ──────────────────────────────
Set-Content -Path $resultPath -Value "대기중: 워커 스폰됨 ($branch)" -Encoding utf8

# ── claude 실행 명령 조립 ────────────────────────────────────────────────────
$permFlag = if ($Permissions -eq 'skip') { '--dangerously-skip-permissions' } else { '' }
$wtDirEsc = $wtDir -replace "'", "''"

if ($DryRun) {
  # 미리보기: 워크트리·지시문·매니페스트는 만들되 claude 는 띄우지 않는다.
  Write-Host "✓ [DryRun] 워크트리·지시문 준비됨: wt/$Task ($branch)" -ForegroundColor Green
  Write-Host "  claude 실행은 생략. 실제 스폰은 -DryRun 없이 다시 실행." -ForegroundColor DarkGray
  $proc = $null
}
elseif ($Headless) {
  # 헤드리스: 창 없이, claude -p(비대화형) 출력을 로그 파일로만.
  $psCmd = @"
Set-Location '$wtDirEsc'
`$p = Get-Content '.initial-prompt' -Raw
claude $permFlag -p `$p *> '$($logPath -replace "'", "''")'
"@
  $proc = Start-Process powershell -WindowStyle Hidden -PassThru `
    -ArgumentList '-NoProfile', '-Command', $psCmd
  Write-Host "✓ 헤드리스 워커 시작: $Task (PID $($proc.Id))  로그: .omc/logs/$Task.log" -ForegroundColor Green
}
else {
  # 보이는 창: 대화형 claude. 사용자가 직접 지켜보고 이어서 타이핑도 가능.
  $psCmd = @"
Set-Location '$wtDirEsc'
`$env:TERM = 'xterm-256color'
Write-Host '=== 워커: $Task ($branch) ===' -ForegroundColor Cyan
Write-Host '결과 파일: $resultPathFwd' -ForegroundColor DarkGray
Write-Host ''
`$p = Get-Content '.initial-prompt' -Raw
claude $permFlag `$p
"@
  $proc = Start-Process powershell -PassThru `
    -ArgumentList '-NoExit', '-NoProfile', '-Command', $psCmd
  Write-Host "✓ 워커 창 열림: $Task (PID $($proc.Id))  브랜치: $branch" -ForegroundColor Green
}

# ── 매니페스트 기록 (status.ps1 이 워커 목록을 여기서 읽는다) ─────────────────
$manifest = [ordered]@{
  task        = $Task
  branch      = $branch
  worktree    = $wtDir
  log         = $logPath
  result      = $resultPath
  mode        = if ($Headless) { 'headless' } else { 'visible' }
  permissions = $Permissions
  pid         = $proc.Id
  startedAt   = (Get-Date).ToString('s')
}
$manifest | ConvertTo-Json | Set-Content -Path $manifestPath -Encoding utf8

Write-Host "  매니페스트: .omc/orchestrator/$Task.json" -ForegroundColor DarkGray
