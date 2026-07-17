<#
.SYNOPSIS
  워커 1개 스폰 — 새 워크트리 + 보이는 PowerShell 창에서 독립 claude 세션을 띄운다.

.DESCRIPTION
  claude-pipeline 의 multiplexer.js launchWinTerminal(powershell) 을 vuln-agent 의
  wt.sh 워크트리 위에 얹은 것. tmux/cmux 없이 Windows PowerShell 만으로 동작한다.

  흐름:
    1) deploy/wt.sh add <prefix>/<task>  → wt/<task> 워크트리 생성(origin/main 기점)
    2) 워커 지시문을 wt/<task>/.initial-prompt 로 주입(오케스트레이터 프리앰블 포함)
    3) -Launch auto(호스트 터미널 감지·기본) / termkeep(새 termkeep 세션) / tab(현재 WT 창 새 탭)
       / window(분리 창) / headless(창 없이 로그)로 claude 실행
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
  #   auto    = 지금 이 세션이 도는 터미널을 감지해 같은 터미널로 스폰(기본, Resolve-HostTerminal)
  #   termkeep= termkeep 데몬에 새 세션(탭) 생성
  #   tab     = 현재 Windows Terminal 창에 새 탭
  #   window  = 분리된 새 PowerShell 창
  #   headless= 창 없이 claude -p, 출력은 로그 파일로만
  [ValidateSet('auto', 'termkeep', 'tab', 'window', 'headless')][string]$Launch = 'auto',

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

# ── 호스트 터미널 감지 (-Launch auto 용) ─────────────────────────────────────
# 사용자가 claude 를 띄운 터미널과 같은 종류로 워커를 스폰한다.
#   termkeep(사용자 자작 세션 매니저) 안 → termkeep 새 세션 · WT 안 → 새 탭 · 그 외 → 새 창
#
# 왜 env 검사와 부모 체인을 둘 다 보는가:
#   termkeep 이 PTY 에 TERMKEEP=1 을 심게 재빌드돼, 지금은 빠른 경로(env)가 실제로 맞는다
#   (실측 2026-07: termkeep 안에서 도는 claude 에서 $env:TERMKEEP 이 1). 다만 옛 데몬 바이너리로
#   띄운 세션엔 그 변수가 없으므로, 부모 프로세스 체인을 거슬러 termkeepd.exe/termkeep.exe 를
#   찾는 판정을 폴백으로 남겨 둔다.
#   실측된 체인: claude.exe → cmd.exe → node.exe → powershell.exe → termkeepd.exe → termkeep.exe
function Resolve-HostTerminal {
  if ($env:TERMKEEP -eq '1') { return 'termkeep' }   # 빠른 경로(재빌드된 termkeep)

  # 체인 탐색은 절대 throw 하지 않는다 — 감지 실패가 워커 스폰 자체를 막으면 안 된다.
  try {
    $seen = @{}
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue
    for ($d = 0; $d -lt 20 -and $p -and -not $seen.ContainsKey([int]$p.ProcessId); $d++) {
      $seen[[int]$p.ProcessId] = $true
      if ($p.Name -eq 'termkeepd.exe' -or $p.Name -eq 'termkeep.exe') { return 'termkeep' }

      $ppid = [int]$p.ParentProcessId
      if ($ppid -le 0) { break }
      $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$ppid" -ErrorAction SilentlyContinue
      if (-not $parent) { break }   # 부모가 이미 종료 → 체인 끝(분리된 창이 이 경우다)

      # Windows 는 PID 를 재사용한다. 부모가 죽은 뒤 그 PID 를 무관한 프로세스가 물고 있으면
      # 엉뚱한 체인으로 새어 오판한다 → 부모가 자식보다 늦게 태어났으면 재사용된 PID 로 보고 끊는다.
      if ($parent.CreationDate -gt $p.CreationDate) { break }
      $p = $parent
    }
  }
  catch { }   # CIM 조회 실패 → 아래 폴백

  if ($env:WT_SESSION) { return 'tab' }   # Windows Terminal 안
  return 'window'                          # 맨 PowerShell 콘솔 창
}

# ── 워커 termkeep 세션 이름 = S<중앙세션ID>/<슬러그> ─────────────────────────
# 사용자는 중앙 세션(창)을 여러 개 띄운다. 이름이 슬러그뿐이면 사이드바에 워커가 나란히 쌓여도
# 어느 창 소생인지 알 수 없다("무슨 일" 만 알고 "누구 밑" 은 모른다). 그래서 만든 세션의 ID 를
# 접두사로 박는다 — 짧고, 이름순 정렬 시 같은 창의 워커가 뭉친다.
# ASCII 만 쓴다(한글·이모지는 cp949 재해석으로 깨진 전례가 있다).
#
# ID 출처는 $env:TERMKEEP_SESSION_ID — 재빌드된 termkeep 이 PTY 에 심어 준다(실측 2026-07:
# 사이드바의 'Session N' 과 정확히 일치). 이 스크립트는 중앙 세션의 claude 가 실행하므로 그
# env 를 그대로 물려받는다 = 스폰하는 쪽이 자기가 몇 번 창인지 이미 안다.
#
# 옛 데몬으로 띄운 세션엔 이 변수가 없다(Resolve-HostTerminal 주석의 경고와 같은 사정).
# 그때는 접두사를 생략하고 슬러그만 쓴다 — 최악이라도 접두사 도입 전과 동일하다.
# 'S0/'·'unknown/' 같은 가짜 값은 지어내지 않는다: 이 저장소는 폴백이 조용히 틀린 값을 넣어
# 사고가 난 전례가 있다(PR #217). 생략할 땐 그 사실을 한 줄 출력해 보이게 한다.
function Resolve-WorkerSessionName {
  param([Parameter(Mandatory)][string]$TaskName)

  # 빈 값도 이 검사에서 같이 걸린다(값이 없든 쓸 수 없든 결과는 "접두사 생략" 하나).
  $sid = "$env:TERMKEEP_SESSION_ID".Trim()
  if ($sid -notmatch '^[A-Za-z0-9_-]+$') {
    Write-Host "→ TERMKEEP_SESSION_ID 없음/사용불가 → 소유 세션 접두사 생략, 이름: $TaskName" -ForegroundColor DarkGray
    return $TaskName
  }
  return "S$sid/$TaskName"
}

# ── termkeep 새 세션으로 워커 스폰 ───────────────────────────────────────────
# termkeep 데몬(termkeepd.exe)과 TCP 로 말한다: 127.0.0.1:<port>, 개행으로 끝나는 JSON 한 줄씩.
# 포트는 %APPDATA%\termkeep\daemon.json 에 있다(예: {"pid":10456,"port":51115}).
# 데몬은 SessionCreated 를 모든 구독 클라이언트에 브로드캐스트하고 GUI 가 그 이벤트로 탭을
# 띄우므로, 우리가 세션만 만들면 사용자 화면에 탭이 뜬다.
#
# 왜 CreateSession 의 cwd/command 대신 SendInput 인가:
#   termkeep 소스엔 cwd/command 필드가 있지만 미커밋·미빌드라 지금 도는 데몬엔 그 기능이 없다.
#   게다가 serde 는 모르는 필드를 에러 없이 조용히 무시하므로 응답만 보고는 신/구 데몬을 구분할
#   수 없다(성공한 척 빈 셸만 뜬다). CreateSession{name} + SendInput 은 양쪽에서 똑같이 동작하는
#   단일 경로라 분기가 필요 없다(KISS).
#
# 실패는 전부 $null 반환 → 호출부가 window 로 폴백한다. 감지·IPC 문제로 워커 스폰 자체가
# 실패하면 안 되므로 여기서 throw 하지 않는다.
function Start-TermkeepWorker {
  param(
    [Parameter(Mandatory)][string]$LaunchPs1,
    [Parameter(Mandatory)][string]$TaskName,
    [Parameter(Mandatory)][string]$WorkDir
  )

  $djPath = Join-Path $env:APPDATA 'termkeep\daemon.json'
  if (-not (Test-Path $djPath)) {
    Write-Host "⚠ termkeep daemon.json 없음($djPath) → 새 PowerShell 창으로 대체." -ForegroundColor Yellow
    return $null
  }
  try { $port = [int](Get-Content -Raw $djPath | ConvertFrom-Json).port } catch { $port = 0 }
  if (-not $port) {
    Write-Host "⚠ termkeep daemon.json 에서 포트를 못 읽음 → 새 PowerShell 창으로 대체." -ForegroundColor Yellow
    return $null
  }

  $client = $null
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $port)
    $stream = $client.GetStream()
    $stream.ReadTimeout = 1000     # 1초마다 깨어나 아래 마감시한을 검사한다(영영 매달리지 않게)
    $enc = New-Object System.Text.UTF8Encoding($false)
    $reader = New-Object System.IO.StreamReader($stream, $enc)
    $writer = New-Object System.IO.StreamWriter($stream, $enc)
    $writer.AutoFlush = $true

    # 데몬은 새 클라이언트를 paused 로 시작해서 Output 브로드캐스트를 안 보낸다. ListSessions 를
    # 한 번 보내야 paused 가 풀린다(데몬 소스 확인 + 실측). 아래에서 "프롬프트가 실제로 떴는지"를
    # PTY 출력으로 확인하려면 이게 먼저 필요하다.
    $writer.Write('{"type":"ListSessions"}' + "`n")

    # JSON 은 반드시 한 줄 — 개행이 프레임 구분자다. (name 필드는 #[serde(default)] 가 없어
    # 반드시 있어야 한다.)
    $createMsg = ([ordered]@{ type = 'CreateSession'; name = $TaskName } | ConvertTo-Json -Compress)
    $writer.Write($createMsg + "`n")

    # 응답 사이에 SessionList·다른 세션의 Output 이 섞여 오므로 SessionCreated 를 골라 읽는다.
    $sid = $null
    $deadline = (Get-Date).AddSeconds(10)
    while (-not $sid -and (Get-Date) -lt $deadline) {
      try { $line = $reader.ReadLine() } catch { continue }   # ReadTimeout → 마감시한 재검사
      if (-not $line) { continue }
      try { $m = $line | ConvertFrom-Json } catch { continue }
      if ($m.type -eq 'SessionCreated' -and $m.session_id) { $sid = [string]$m.session_id }
      elseif ($m.type -eq 'Error') {
        Write-Host "⚠ termkeep 세션 생성 실패($($m.message)) → 새 PowerShell 창으로 대체." -ForegroundColor Yellow
        return $null
      }
    }
    if (-not $sid) {
      Write-Host "⚠ termkeep 데몬이 SessionCreated 를 안 보냄 → 새 PowerShell 창으로 대체." -ForegroundColor Yellow
      return $null
    }

    # PTY 안 powershell 이 프롬프트를 내기 전에 밀어 넣은 키는 그대로 버려진다. 고정 대기는
    # 못 믿는다 — 700ms 로는 입력이 통째로 씹혔고, 실측상 프롬프트까지 약 2.4초 걸렸다.
    # 그래서 데몬이 브로드캐스트하는 PTY 출력에서 프롬프트('PS ...>')를 눈으로 확인한 뒤 넣는다.
    # 느린 PC 에서도 안전하고, 빨리 뜨면 그만큼 빨리 지나간다.
    $acc = ''
    $ready = $false
    $promptDeadline = (Get-Date).AddSeconds(20)
    while (-not $ready -and (Get-Date) -lt $promptDeadline) {
      try { $line = $reader.ReadLine() } catch { continue }
      if (-not $line) { continue }
      try { $m = $line | ConvertFrom-Json } catch { continue }
      if ($m.type -eq 'Output' -and $m.session_id -eq $sid -and $m.data) {
        try { $acc += [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($m.data)) } catch { }
        if ($acc -match 'PS [^\r\n]*>') { $ready = $true }
      }
    }
    if (-not $ready) {
      # 세션은 이미 떴으니 창 폴백 대신 그대로 시도한다(입력이 씹히면 사용자가 탭에서 직접 실행 가능).
      Write-Host "⚠ termkeep 프롬프트를 확인 못 했지만 입력을 시도한다(session $sid)." -ForegroundColor Yellow
    }

    $wtDirEsc = $WorkDir -replace "'", "''"
    $ps1Esc = $LaunchPs1 -replace "'", "''"
    $cmdText = "Set-Location -LiteralPath '$wtDirEsc'; powershell -NoProfile -ExecutionPolicy Bypass -File '$ps1Esc'" + "`r"

    # data 는 base64 로 인코딩된 바이트다(데몬이 디코드해 PTY 에 그대로 쓴다).
    # UTF-8 바이트로 인코딩해야 한다 — 경로에 한글이 들어간다(사용자 홈이 C:\Users\정도욱).
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cmdText))
    $inputMsg = ([ordered]@{ type = 'SendInput'; session_id = $sid; data = $b64 } | ConvertTo-Json -Compress)
    $writer.Write($inputMsg + "`n")   # 성공 시 무응답이라 읽지 않는다

    Write-Host "✓ termkeep 새 세션: $TaskName (session $sid)" -ForegroundColor Green
    return $sid
  }
  catch {
    Write-Host "⚠ termkeep 연결/전송 실패($($_.Exception.Message)) → 새 PowerShell 창으로 대체." -ForegroundColor Yellow
    return $null
  }
  finally {
    if ($client) { $client.Close() }
  }
}

# ── 지시문 확보 ──────────────────────────────────────────────────────────────
if ($PromptFile) {
  if (-not (Test-Path $PromptFile)) { throw "PromptFile 없음: $PromptFile" }
  # -Encoding UTF8 필수: PS5.1 Get-Content 기본은 ANSI(한국어 윈도 = cp949)라 BOM 없는
  # UTF-8 을 cp949 로 오독한다. 지시문은 claude 의 Write 도구가 쓴 BOM 없는 UTF-8 이다.
  # 그대로 두면 오독한 글자를 아래 Set-Content 가 UTF-8 로 다시 써서 이중으로 깨진다
  # (실제 사고: 워커가 '理쒖긽??README.md' 같은 지시문을 받아 복원해 읽고서야 작업했다).
  $taskText = Get-Content $PromptFile -Raw -Encoding UTF8
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
  스모크가 이 트리 전용 컨테이너 부재로 중단(exit 2)되면 **네 워크트리 스택은 스스로 올려도 된다**
  (./deploy/compose_runner.sh dev up -d). 이 트리 전용 web+scheduler 만 뜨고(db 는 안 뜬다)
  컨테이너명이 트리마다 고유해 다른 워커를 건드리지 않는다. 메인 트리 스택과 공용 DB 는 사람 몫이다.
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

# ── 스폰 모드 확정 ───────────────────────────────────────────────────────────
# -Launch auto 면 지금 이 세션이 도는 터미널을 보고 워커도 같은 터미널로 띄운다.
# 사용자가 모드를 명시했으면 감지 없이 그대로 존중한다(기존 동작 유지).
$LaunchMode = $Launch
if ($Launch -eq 'auto') {
  $LaunchMode = Resolve-HostTerminal
  $how = switch ($LaunchMode) {
    'termkeep' { 'termkeep 새 세션으로 스폰' }
    'tab' { 'Windows Terminal 새 탭으로 스폰' }
    default { '새 PowerShell 창으로 스폰' }
  }
  Write-Host "→ 호스트 터미널 감지: $LaunchMode → $how" -ForegroundColor Cyan
}

# ── claude 실행 ──────────────────────────────────────────────────────────────
# 실행 명령을 워커별 .launch.ps1 파일에 담는다. -Command 인라인 대신 -File 을 쓰면
# wt 의 ';' 파싱·따옴표 이스케이프 지옥을 피할 수 있다.
#
# 지시문(.initial-prompt)을 claude 의 CLI 인자로 그대로 넘기지 않는다 — 반드시 안 된다.
# claude 는 npm 셈(claude.cmd/.ps1)을 거쳐 실행되는데, 지시문에 큰따옴표(`"...")나
# 백틱(마크다운 인라인 코드 `` `foo` ``)이 하나라도 섞이면 Windows 커맨드라인 재인용
# 과정에서 인자가 그 지점에서 잘리거나 깨진다(실제로 두 번 겪음 — 백틱 케이스는 PowerShell
# 자체 이스케이프와 충돌, 큰따옴표 케이스는 셈의 재인용 중 조기 종료). 프롬프트 작성자가
# 특수문자를 피해서 우회할 문제가 아니라 구조적 결함이라 스크립트에서 근본 수정한다:
# 지시문은 오직 파일(.initial-prompt, Set-Content 로 안전하게 기록됨)로만 전달하고,
# claude 에는 그 파일을 읽으라는 짧고 안전한(따옴표·백틱·개행 없는) 트리거 문장만 넘긴다.
$permFlag = if ($Permissions -eq 'skip') { '--dangerously-skip-permissions' } else { '' }
$wtDirEsc = $wtDir -replace "'", "''"
$launchPs1 = Join-Path $wtDir '.launch.ps1'
$trigger = ".initial-prompt 파일을 Read 도구로 읽고, 그 내용을 지시사항 삼아 바로 작업을 시작해라."

if ($LaunchMode -eq 'headless') {
  $launchBody = @"
Set-Location -LiteralPath '$wtDirEsc'
claude $permFlag -p '$trigger' *> '$($logPath -replace "'", "''")'
"@
}
else {
  $launchBody = @"
Set-Location -LiteralPath '$wtDirEsc'
`$env:TERM = 'xterm-256color'
Write-Host '=== 워커: $Task ($branch) ===' -ForegroundColor Cyan
Write-Host '결과 파일: $resultPathFwd' -ForegroundColor DarkGray
Write-Host ''
claude $permFlag '$trigger'
"@
}

$proc = $null
$termkeepSessionId = $null
$eff = $LaunchMode   # 실제로 쓰인 모드(폴백되면 아래에서 바뀐다) — 매니페스트에 이 값을 남긴다
if ($DryRun) {
  # 미리보기: 워크트리·지시문·매니페스트는 만들되 claude 는 띄우지 않는다.
  Write-Host "✓ [DryRun] 워크트리·지시문 준비됨: wt/$Task ($branch)" -ForegroundColor Green
  Write-Host "  claude 실행은 생략. 실제 스폰은 -DryRun 없이 다시 실행." -ForegroundColor DarkGray
}
else {
  Set-Content -Path $launchPs1 -Value $launchBody -Encoding utf8   # PS 5.1 utf8 = BOM(한글 배너)
  if ($eff -eq 'termkeep') {
    # 세션 이름에만 소유 세션 태그를 붙인다 — 매니페스트의 task 등 다른 값은 슬러그 그대로다.
    $sessionName = Resolve-WorkerSessionName -TaskName $Task
    $termkeepSessionId = Start-TermkeepWorker -LaunchPs1 $launchPs1 -TaskName $sessionName -WorkDir $wtDir
    if ($termkeepSessionId) { Write-Host "  브랜치: $branch" -ForegroundColor Green }
    else { $eff = 'window' }   # daemon.json/연결/응답 문제 → 창으로 폴백
  }
  if ($eff -eq 'tab') {
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
# mode 에는 -Launch 인자(auto 일 수 있다)가 아니라 **실제로 쓰인 모드**를 남긴다.
# termkeep 모드면 pid 가 없으므로(창을 우리가 띄운 게 아니다) termkeepSessionId 로 세션을 가리킨다.
# status.ps1 이 mode/pid 를 그대로 읽으므로 기존 키는 유지한다.
$manifest = [ordered]@{
  task              = $Task
  branch            = $branch
  worktree          = $wtDir
  log               = $logPath
  result            = $resultPath
  mode              = $eff
  permissions       = $Permissions
  finish            = $Finish
  pid               = if ($proc) { $proc.Id } else { $null }
  termkeepSessionId = $termkeepSessionId
  startedAt         = (Get-Date).ToString('s')
}
$manifest | ConvertTo-Json | Set-Content -Path $manifestPath -Encoding utf8

. (Join-Path $PSScriptRoot 'history-log.ps1')
Add-OrchestratorHistory -MainRoot $MainRoot -Task $Task -Event 'spawn' -Detail "$branch ($eff/$Permissions)"

Write-Host "  매니페스트: .omc/orchestrator/$Task.json" -ForegroundColor DarkGray
