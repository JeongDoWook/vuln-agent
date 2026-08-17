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

# ── 네이티브 exe 호출 래퍼 (PS 5.1 stderr 승격 회피) ─────────────────────────
# 실측(2026-07-26): wt.sh 는 진행 상황(git worktree add 의 'Preparing worktree …')을 stderr 로
# 쓴다. PS 5.1 이 그걸 ErrorRecord 로 승격해, 워크트리는 정상 생성됐는데 스폰이 실패로 끝났다
# (spawn-batch 로 3개를 띄우면 3개 전부 '실패'로 찍혔다). 그래서 네이티브 호출은 이 래퍼를 거친다.
# 원리·주의사항은 native-call.ps1 의 주석에 있다(stop-worker.ps1 도 같은 파일을 쓴다).
. (Join-Path $PSScriptRoot 'native-call.ps1')

# ── 메인 트리 루트 (wt.sh 와 동일 규칙: git-common-dir 의 부모) ───────────────
# 저장소는 cwd 가 아니라 스크립트 위치 기준으로 찾는다 — 어느 폴더에서 실행해도 동작.
# 저장소 밖에서 실행하면 git 이 stderr 로 'fatal: not a git repository' 를 쓴다 → 위 승격 때문에
# 아래 friendly throw 대신 NativeCommandError 로 죽는다. 그래서 이 호출도 래퍼를 거친다.
$gitCommon = (Invoke-Native git @('-C', $PSScriptRoot, 'rev-parse', '--git-common-dir'))
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

# ── 안전한 토큰인지(영숫자·'-'·'_' 만) ───────────────────────────────────────
# 세션 이름의 세션 ID 와 트리거 문장의 작업 슬러그가 같은 판정을 쓴다. 이 화이트리스트를
# 통과하면 작은따옴표·백틱·개행·공백이 원천 배제되므로, 생성되는 런치 스크립트에서
# 작은따옴표 안에 그대로 끼워 넣어도 깨지지 않는다.
# 값을 고쳐서 통과시키지 않는다 — 못 미더우면 호출부가 그 값을 빼고 진행한다(가짜 값 금지).
function Test-SafeToken {
  param([string]$Value)
  return ($Value -match '^[A-Za-z0-9_-]+$')
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
  if (-not (Test-SafeToken $sid)) {
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
#   → 셸을 우리가 고를 수 없다는 뜻이기도 하다. 새 세션은 데몬 기본 셸로 뜨고 실측상 그게
#     cmd.exe 였다. 그래서 아래 프롬프트 감지와 주입 문장은 둘 다 셸 중립이어야 한다.
#
# 실패는 전부 $null 반환 → 호출부가 window 로 폴백한다. 감지·IPC 문제로 워커 스폰 자체가
# 실패하면 안 되므로 여기서 throw 하지 않는다.
function Start-TermkeepWorker {
  param(
    [Parameter(Mandatory)][string]$LaunchPs1,
    [Parameter(Mandatory)][string]$TaskName
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

    # ⚠ CreateSession 이 **먼저**고 ListSessions 는 그 뒤다. 순서를 바꾸면 아래 프롬프트 감지가
    # 통째로 죽는다 — 데몬은 ListSessions 를 받은 그 시점에 **존재하던** 세션에만 이 연결을
    # 구독시키므로, ListSessions 뒤에 만든 세션의 Output 은 이 연결로 영영 오지 않는다.
    # 실측(2026-07-27): ListSessions→CreateSession 순서로는 30초 동안 새 세션 Output 이 0건이고
    # (다른 세션 것만 2151줄 도착), 순서를 뒤집으니 0.16초 만에 첫 Output 이 왔다.
    #
    # JSON 은 반드시 한 줄 — 개행이 프레임 구분자다. (name 필드는 #[serde(default)] 가 없어
    # 반드시 있어야 한다.) CreateSession 의 직접 응답은 paused 상태에서도 온다(실측).
    $createMsg = ([ordered]@{ type = 'CreateSession'; name = $TaskName } | ConvertTo-Json -Compress)
    $writer.Write($createMsg + "`n")

    $sid = $null
    $centralTitle = $null
    $centralSid = "$env:TERMKEEP_SESSION_ID".Trim()
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

    # 사이드바 굵은 제목을 $TaskName 으로 락 건다(custom_name=true). CreateSession 의 name 만으로는
    # 안 된다 — SessionCreated 브로드캐스트엔 custom_name 필드가 없어 프론트가 세팅을 안 하고,
    # 이후 Claude 가 PTY 에 찍는 OSC 자동 타이틀에 곧 덮인다. RenameSession 은 프론트가 받으면
    # custom_name 을 true 로 명시 세팅하므로, 같은 이름으로 한 번 더 보내면 제목이 고정된다.
    #
    # $TaskName 이 비어 있으면 보내지 않는다 — 빈 문자열로 제목을 락 걸면 자동 타이틀조차
    # 못 들어오는 최악의 상태가 된다(이름 없음 < 자동 타이틀).
    #
    # 순서 레이스 없음(daemon/src/main.rs 확인, termkeep 저장소는 참고만·수정 안 함): 데몬은
    # 연결 하나당 요청을 순차 처리한다(main.rs:329-400 — read_line 후 process_request(msg).await
    # 완료까지 기다렸다가 다음 줄을 읽는다). CreateSession 은 state.create_session().await 이
    # 끝나고 SessionCreated 를 브로드캐스트한 다음에야 우리에게 응답한다(main.rs:407-419) — 즉
    # 우리가 그 응답(위 $sid)을 받은 시점엔 이미 세션이 서버 상태에 있고 다른 모든 클라이언트도
    # SessionCreated 를 먼저 받은 뒤다. 우리는 그 응답을 받은 뒤에만 RenameSession 을 보내므로
    # "세션이 아직 없어 조용히 무시" 되는 경로는 없다.
    #
    # 파이어앤포겟: 구버전 데몬이 이 메시지 타입을 몰라도(모르는 타입은 조용히 무시) 스폰 자체는
    # 막지 않는다 — 응답을 기다리지 않고 실패해도 조용히 한 줄만 남긴다. Flush 는 명시 호출한다
    # ($writer.AutoFlush 가 이미 true 라 사실상 즉시 나가지만, 뒤이은 20초짜리 Output 대기
    # 루프에 묻혀 안 나간 게 아님을 코드로도 분명히 한다).
    if (-not [string]::IsNullOrWhiteSpace($TaskName)) {
      try {
        $renameMsg = ([ordered]@{ type = 'RenameSession'; session_id = $sid; name = $TaskName } | ConvertTo-Json -Compress)
        $writer.Write($renameMsg + "`n")
        $writer.Flush()
      }
      catch {
        Write-Host "→ RenameSession 전송 실패(session $sid): $($_.Exception.Message) → 제목은 자동 타이틀에 덮일 수 있음." -ForegroundColor DarkGray
      }
    }

    # 데몬은 새 클라이언트를 paused 로 시작해서 Output 브로드캐스트를 안 보낸다. ListSessions 를
    # 한 번 보내야 paused 가 풀린다(데몬 소스 확인 + 실측: 이걸 안 보내면 Output 이 한 건도 안 온다).
    # 위에서 세션을 이미 만들어 뒀으므로 이 구독에 우리 새 세션도 포함된다.
    # 덤으로 오는 SessionList 에서 중앙 세션(자신)의 name 을 건진다 — 데몬 소스
    # (termkeep/shared/src/lib.rs) 확인: {type,sessions:[{id,name,alive,custom_name}]} 이고
    # rename_all 이 없어 필드명이 그대로다(id/name, camelCase 아님).
    $writer.Write('{"type":"ListSessions"}' + "`n")

    # PTY 안 셸이 프롬프트를 내기 전에 밀어 넣은 키는 그대로 버려진다. 고정 대기는 못 믿는다 —
    # 700ms 로는 입력이 통째로 씹혔고, 실측상 프롬프트까지 약 2.4초 걸렸다. 그래서 데몬이
    # 브로드캐스트하는 PTY 출력에서 프롬프트를 눈으로 확인한 뒤 넣는다.
    #
    # ⚠ 셸이 powershell 이라고 가정하지 않는다. 실측(2026-07-27) 새 세션은 **cmd.exe** 로 떴다.
    # 그래서 프롬프트 패턴이 둘이다:
    #   powershell → 'PS C:\...>'    ·    cmd → 'C:\Users\<사용자>>'
    # cmd 쪽에 줄머리 앵커('(?m)^')를 붙이면 안 된다 — 실제 바이트를 떠 보면 프롬프트 앞에
    # 커서이동 시퀀스가 붙어 같은 줄에 이어 온다:
    #   …(c) Microsoft Corporation. All rights reserved.<ESC>[4;1HC:\Users\<사용자>><ESC>[?25h
    # 앵커를 붙인 '(?m)^[A-Za-z]:\\[^\r\n]*>' 가 실패했던 이유가 이것이다. 대신 ESC 를 문자
    # 클래스에서 빼서(\x1b) 앞선 OSC 타이틀('<ESC>]0;C:\WINDOWS\system32\cmd.exe<BEL>')이
    # 뒤 문장까지 삼켜 오검출되는 일을 막는다.
    #
    # ⚠ 이 루프에서 **줄마다 ConvertFrom-Json 을 돌리면 안 된다.** unpause 직후 이 연결로는 다른
    # 세션들의 출력이 쏟아진다(실측: 20초에 1000~1500줄, 1.6MB). PS5.1 의 ConvertFrom-Json 은
    # 그 속도를 못 따라가고, 뒤처진 구독자는 메시지를 흘린다 — 같은 20초 동안 우리 세션 Output 이
    # **한 건도** 안 잡혔다(누적 버퍼 0바이트). 값싼 문자열 선필터로 바꾸자 우리 첫 Output 이
    # 도착 4번째 줄·0.03초에 잡혔다. 즉 위 정규식이 실패한 게 아니라 **볼 버퍼가 비어 있었다.**
    # 선필터는 데몬 직렬화 형식({"type":"Output","session_id":"17",...})에 기대지만, 어긋나도
    # 최악은 기존 동작(확인 못 하고 그냥 주입)이라 안전 방향으로 무너진다.
    # base64 data 안에는 '"' 가 못 들어가므로 needle 오검출도 없다.
    $needle = '"session_id":"' + $sid + '"'
    $acc = ''
    $ready = $false
    $promptDeadline = (Get-Date).AddSeconds(20)
    while (-not $ready -and (Get-Date) -lt $promptDeadline) {
      try { $line = $reader.ReadLine() } catch { continue }
      if (-not $line) { continue }
      if (-not ($line.Contains($needle) -or $line.Contains('"SessionList"'))) { continue }
      try { $m = $line | ConvertFrom-Json } catch { continue }
      if ($m.type -eq 'SessionList' -and $centralSid -and $m.sessions) {
        # 조회 실패는 부가 정보 손실일 뿐 — throw 하지 않는다(이 함수 전체가 실패해도
        # window 로 폴백하는 원칙과 동일하게, 여기선 title 만 $null 로 남기고 계속 진행).
        try {
          $match = $m.sessions | Where-Object { "$($_.id)".Trim() -eq $centralSid } | Select-Object -First 1
          if ($match) { $centralTitle = [string]$match.name }
        } catch { }
      }
      elseif ($m.type -eq 'Output' -and $m.session_id -eq $sid -and $m.data) {
        try { $acc += [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($m.data)) } catch { }
        if ($acc -match 'PS [^\r\n]*>' -or $acc -match '[A-Za-z]:\\[^\r\n\x1b]*>') { $ready = $true }
      }
    }
    if (-not $ready) {
      # 세션은 이미 떴으니 창 폴백 대신 그대로 시도한다(입력이 씹히면 사용자가 탭에서 직접 실행 가능).
      Write-Host "⚠ termkeep 프롬프트를 확인 못 했지만 입력을 시도한다(session $sid)." -ForegroundColor Yellow
    }

    # 주입 문장은 **셸 중립**이어야 한다 — 위에서 본 대로 세션 셸이 cmd.exe 일 수 있다.
    # cmd 는 'Set-Location' 도, 명령 구분자 ';' 도, 경로를 묶는 작은따옴표도 모른다(셋 다 동시에
    # 깨졌다). 그런데 .launch.ps1 은 자기 첫 줄에서 이미 `Set-Location -LiteralPath '<워크트리>'`
    # 를 하므로 여기서 cd 를 또 할 이유가 없다. 그걸 빼면 남는 한 문장은 cmd·PowerShell 양쪽에서
    # 문법이 같다.
    # 경로는 큰따옴표로 묶는다 — 두 셸 모두 인용부호로 받는다. Windows 경로엔 '"' 가 애초에 못
    # 들어가므로 이스케이프도 필요 없다(예전의 작은따옴표 '' 이스케이프가 사라진 이유가 이것이다).
    $cmdText = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$LaunchPs1`"" + "`r"

    # data 는 base64 로 인코딩된 바이트다(데몬이 디코드해 PTY 에 그대로 쓴다).
    # UTF-8 바이트로 인코딩해야 한다 — 경로에 한글이 들어간다(사용자 홈이 C:\Users\<사용자>).
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cmdText))
    $inputMsg = ([ordered]@{ type = 'SendInput'; session_id = $sid; data = $b64 } | ConvertTo-Json -Compress)
    $writer.Write($inputMsg + "`n")   # 성공 시 무응답이라 읽지 않는다

    Write-Host "✓ termkeep 새 세션: $TaskName (session $sid)" -ForegroundColor Green
    return [pscustomobject]@{ Sid = $sid; CentralTitle = $centralTitle }
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
  # 아카이브 이동(파일 맨 끝)에서 쓸 절대경로를 지금 확정한다 — 뒤쪽에 Push-Location 구간이 있어
  # 상대경로로 받은 값을 나중에 풀면 다른 디렉터리 기준으로 풀릴 수 있다.
  $PromptFileFull = (Resolve-Path -LiteralPath $PromptFile).Path
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
  # Invoke-Native 를 거치는 이유: wt.sh 가 진행 상황을 stderr 로 쓴다(native-call.ps1 주석 참고).
  # 종료코드 검사는 그대로 둔다 — 진짜 실패는 여전히 여기서 throw 된다.
  Push-Location $MainRoot
  try { Invoke-Native $GitBash @("$MainRootFwd/deploy/wt.sh", 'add', $branch, $Base) } finally { Pop-Location }
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
#
# 트리거 첫머리에는 작업 슬러그를 박는다. termkeep 사이드바의 워커 "제목" 은 termkeep 이 아니라
# claude 가 대화 내용(= 이 첫 문장)으로 자동 생성하는데, 트리거가 모든 워커에게 똑같았던 탓에
# 제목이 전부 'Read initial prompt …' 로 겹쳐 목록에서 구분이 안 됐다(부제는 #235 가 해결).
# 제목을 강제하는 API 는 없으므로 이건 유도일 뿐이다 — 슬러그가 제목에 실릴 가능성을 높인다.
#
# 슬러그를 '[foo] ' 같은 꼬리표로 붙이지 마라(실측 2026-07): claude 는 꼬리표를 제목에서 통째로
# 버려 '초기 프롬프트 파일 읽기 및 작업 시작' 이 됐다 — 슬러그가 사라져 고치기 전과 똑같아진다.
# 슬러그를 문장의 주어로 넣으니 제목이 'title-probe2 작업 시작' 으로 떴다. 그래서 꼬리표가 아니라
# 문장이다. 이 문장을 줄이거나 꼬리표로 되돌리려면 실제 스폰으로 제목을 다시 확인해라.
#
# 슬러그는 위 화이트리스트를 통과할 때만 넣는다: $Task 는 형식 검증이 없는 자유 문자열이라
# 작은따옴표가 섞이면 아래 `claude $permFlag '$trigger'` 가 그 자리에서 깨진다.
$triggerBody = '.initial-prompt 파일을 Read 도구로 읽고, 그 내용을 지시사항 삼아 바로 작업을 시작해라.'
if (Test-SafeToken $Task) {
  $trigger = "$Task 작업을 맡는다. $triggerBody"
}
else {
  Write-Host "→ 작업 슬러그에 쓸 수 없는 문자 → 트리거 접두사 생략(제목이 워커끼리 겹칠 수 있다): $Task" -ForegroundColor DarkGray
  $trigger = $triggerBody
}

# ── 워커 전사(transcript) 저장 ───────────────────────────────────────────────
# 부모(중앙) 세션의 환경에는 CLAUDE_CODE_CHILD_SESSION=1 이 들어 있다(실측 2026-07-26: 워커
# 안에서 `env | grep CLAUDE_CODE_CHILD_SESSION` → 1). spawn-worker.ps1 이 세우는 값이 아니라
# **상속된 것**이다. claude 는 그 마커를 보면 이 세션을 저장하지 않고 탭 하단에 경고를 띄운다:
#   "Transcript saving is off — inherited CLAUDE_CODE_CHILD_SESSION marker
#    · restart with CLAUDE_CODE_FORCE_SESSION_PERSISTENCE=1 to keep future transcripts"
# 그러면 워커가 무엇을 했는지 나중에 되짚을 기록도, --resume 도 남지 않는다.
#
# 변수 이름·값은 추측이 아니다 — 실행 중인 claude 2.1.220 바이너리에서 판정 로직을 직접 확인했다
# (경고 문구가 화면 폭에 잘려 이름이 불확실했으므로):
#   if (env.CLAUDE_CODE_FORCE_SESSION_PERSISTENCE) return false;   // false = 억제 안 함(저장한다)
#   if (!(env.CLAUDE_CODE_CHILD_SESSION && …)) return false;
# 같은 바이너리의 안내 문구도 "…FORCE_SESSION_PERSISTENCE=1 to keep future transcripts" 다.
#
# 상속 마커(CLAUDE_CODE_CHILD_SESSION)를 지우는 대신 이 변수를 세우는 이유: 그 마커는 전사 말고
# 다른 판정에도 쓰여(팀/서브에이전트 감지) 지웠을 때의 부작용 범위를 알 수 없다. 이 변수는 전사
# 억제 한 가지만 끈다 — 좁은 쪽을 고른다.
# NO_COLOR 를 지우는 것과 같은 자리·같은 이유다: 부모 환경의 오염이 워커로 새는 것을 런치 바디에서
# 끊는다(부모 세션은 재시작 전까지 못 고친다).
$transcriptEnv = @'
# 부모 세션에서 상속된 CLAUDE_CODE_CHILD_SESSION=1 때문에 claude 가 이 세션의 전사를 저장하지
#   않는다("Transcript saving is off"). claude 가 안내하는 해제 변수를 세워 워커도 기록을 남긴다.
$env:CLAUDE_CODE_FORCE_SESSION_PERSISTENCE = '1'
'@

if ($LaunchMode -eq 'headless') {
  $launchBody = @"
Set-Location -LiteralPath '$wtDirEsc'
$transcriptEnv
claude $permFlag -p '$trigger' *> '$($logPath -replace "'", "''")'
"@
}
else {
  $launchBody = @"
Set-Location -LiteralPath '$wtDirEsc'
`$env:TERM = 'xterm-256color'
# NO_COLOR 가 상속돼 있으면 워커 탭의 색이 통째로 깨진다(Write diff 가 빨강/초록 통짜 블록).
#   부모 환경이 오염돼 있어도 워커는 항상 정상이도록 여기서 지운다. 문서만으로는 못 막는다 —
#   ~/.claude/settings.json 의 env 에 한 번 들어가면 그 뒤 뜬 모든 워커가 상속받고,
#   settings.json 을 고쳐도 **이미 떠 있는 부모 세션**의 환경은 재시작 전까지 그대로다(실측 2026-07-26).
Remove-Item Env:NO_COLOR -ErrorAction SilentlyContinue
$transcriptEnv
Write-Host '=== 워커: $Task ($branch) ===' -ForegroundColor Cyan
Write-Host '결과 파일: $resultPathFwd' -ForegroundColor DarkGray
Write-Host ''
claude $permFlag '$trigger'
"@
}

$proc = $null
$termkeepSessionId = $null
$centralSessionTitle = $null   # termkeep 모드가 아니면 그대로 $null(매니페스트에 빈 값으로 남는다)
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
    $startResult = Start-TermkeepWorker -LaunchPs1 $launchPs1 -TaskName $sessionName
    $termkeepSessionId = if ($startResult) { $startResult.Sid } else { $null }
    $centralSessionTitle = if ($startResult) { $startResult.CentralTitle } else { $null }
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
      # wt.exe 도 경고를 stderr 로 낸다(예: 프로필 못 찾음) → 같은 승격 함정. 래퍼로 감싼다.
      # 종료코드 검사는 **새로 붙이지 않는다**: 원래 없던 게이트를 여기서 만들면, 탭은 떴는데
      # wt.exe 가 비영으로 끝나는 경우에 스폰이 새로 실패하기 시작한다(지금 고치는 것과 같은 종류의
      # 오탐). 승격만 막아 "탭은 떴는데 실패로 보고" 되는 것을 없애는 게 이 변경의 범위다.
      Invoke-Native $wt @('-w', '0', 'new-tab', '--title', $Task, '-d', $wtDir, 'powershell.exe', '-NoExit', '-NoProfile', '-File', $launchPs1)
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
  centralSessionTitle = $centralSessionTitle
  centralSessionId  = "$env:TERMKEEP_SESSION_ID".Trim()
  startedAt         = (Get-Date).ToString('s')
}
$manifest | ConvertTo-Json | Set-Content -Path $manifestPath -Encoding utf8

. (Join-Path $PSScriptRoot 'history-log.ps1')
Add-OrchestratorHistory -MainRoot $MainRoot -Task $Task -Event 'spawn' -Detail "$branch ($eff/$Permissions)"

Write-Host "  매니페스트: .omc/orchestrator/$Task.json" -ForegroundColor DarkGray

# ── 지시문 아카이브 (.omc/tasks/<슬러그>.md → .omc/tasks/archive/) ────────────
# 예전엔 spawn-batch.ps1 만 옮겼다. 그래서 배치를 안 쓰고 개별 스폰만 하면 이미 끝난 작업의
# 지시문이 .omc/tasks/ 에 계속 쌓였고(실제로 병합된 12개가 껍데기로 남았다), 나중에 누가
# spawn-batch.ps1 을 인자 없이 돌리면 그것들이 한꺼번에 재스폰될 뻔했다. 그래서 이동을
# spawn-worker 쪽으로 내리고 배치의 중복 로직은 걷어냈다(둘 다 옮기면 두 번째가 '원본 없음'
# 으로 실패해 배치가 통째로 실패로 뒤집힌다).
#
# 조건 셋을 모두 만족할 때만 옮긴다:
#   · -PromptFile 로 받았을 때만(인라인 -Prompt 는 옮길 파일이 없다)
#   · -DryRun 이 아닐 때만(미리보기가 파일을 옮기면 안 된다)
#   · 그 파일이 실제로 .omc/tasks/ 바로 아래에 있을 때만 — -PromptFile 은 아무 경로나 받으므로
#     저장소 밖 파일을 임의로 옮기지 않는다. (.omc/tasks/archive/ 안의 파일도 부모가 달라 제외된다.)
#
# 이동 실패는 스폰 실패로 취급하지 않는다 — 워커는 이미 떴는데 파일 이동이 안 됐다고 스크립트가
# 죽으면 그게 더 나쁘다. 경고만 남기고 넘어간다.
if ($PromptFileFull -and -not $DryRun) {
  try {
    $tasksDir = Join-Path $MainRoot '.omc\tasks'
    if (Test-Path $tasksDir) {
      $tasksDirFull = (Resolve-Path -LiteralPath $tasksDir).Path
      if ((Split-Path $PromptFileFull -Parent) -eq $tasksDirFull) {
        $archiveDir = Join-Path $tasksDirFull 'archive'
        if (-not (Test-Path $archiveDir)) { New-Item -ItemType Directory -Force -Path $archiveDir | Out-Null }
        $promptName = Split-Path $PromptFileFull -Leaf
        Move-Item -LiteralPath $PromptFileFull -Destination (Join-Path $archiveDir $promptName) -Force
        Write-Host "  지시문 아카이브: .omc/tasks/archive/$promptName" -ForegroundColor DarkGray
      }
    }
  }
  catch {
    Write-Host "⚠ 지시문 아카이브 실패(워커는 정상 스폰됨): $($_.Exception.Message)" -ForegroundColor Yellow
  }
}
