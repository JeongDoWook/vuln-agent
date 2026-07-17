<#
.SYNOPSIS
  워커 정리 — termkeep 세션 종료 + 워크트리 제거(wt.sh rm) + 매니페스트 삭제.

.DESCRIPTION
  PR 이 병합된 뒤 호출한다. 순서가 중요하다: **세션을 먼저 닫고 워크트리를 지운다.**
  세션이 살아 있으면 그 안의 claude 가 워크트리를 작업 디렉터리로 붙들고 있어
  `git worktree remove` 가 **등록을 해제한 뒤 폴더 삭제에서** 죽는다 → 등록은 없는데
  폴더는 남는 어중간한 상태가 된다(2026-07-17 에 두 번 겪었다).

  세션을 닫는 것만으로는 부족하다: 데몬이 PTY 를 닫아도 그 안에서 돌던 claude 는 살아남아
  워크트리를 계속 붙든다(실측). 그래서 세션을 닫은 뒤 그 워커가 남긴 프로세스 트리까지
  닫고, 폴더가 정말 풀렸는지 확인한 다음에야 지운다.

  세션을 못 닫으면 wt.sh rm 을 아예 부르지 않는다 — 반쯤 지우느니 안 지운다.

  wt.sh rm 이 워크트리를 지우고, 병합된 브랜치면 로컬·원격 브랜치까지 정리한다
  (미병합이면 브랜치는 남긴다 — wt.sh 의 안전판).
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

# 저장소는 cwd 가 아니라 스크립트 위치 기준으로 찾는다 — 어느 폴더에서 실행해도 동작.
$gitCommon = (& git -C $PSScriptRoot rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw '스크립트가 git 저장소 안에 있지 않습니다.' }
if (-not [System.IO.Path]::IsPathRooted($gitCommon)) { $gitCommon = Join-Path $PSScriptRoot $gitCommon }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
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

# ── termkeep 데몬에 한 요청 보내고 기대한 응답 한 줄 받기 ─────────────────────
# 규약은 spawn-worker.ps1 의 Start-TermkeepWorker 와 같다: %APPDATA%\termkeep\daemon.json 의
# 포트로 TCP, 개행으로 끝나는 JSON 한 줄씩. (IPC 코드가 두 파일에 생기지만 이 저장소 규약은
# 2회까지 허용·3회째에 추출이다. spawn 쪽은 세션 생성 + 프롬프트를 기다렸다가 SendInput 하는
# 전혀 다른 대화라, 지금 뽑으면 공통분모가 '소켓 열고 한 줄 쓴다' 뿐인 껍데기만 남는다.)
#
# **요청마다 새 연결**을 쓴다. 데몬은 ListSessions 를 받으면 응답(SessionList) 뒤로 모든 세션의
# 스크롤백을 쏟아붓는데, 다 안 읽으면 그 연결이 막혀 이후 요청이 처리되지 않는다(termkeep 의
# verify 스킬에 기록된 함정). 우리가 필요한 건 직접 응답 한 줄뿐이고 브로드캐스트 이벤트는
# 필요 없으므로, 한 줄만 읽고 연결을 닫으면 그 함정을 아예 피한다.
function Invoke-TermkeepMessage {
  param(
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][string]$Json,
    [Parameter(Mandatory)][string]$ExpectType,
    [int]$TimeoutSec = 10
  )
  $client = $null
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $Port)
    $stream = $client.GetStream()
    $stream.ReadTimeout = 1000     # 1초마다 깨어나 아래 마감시한을 검사한다(영영 매달리지 않게)
    $enc = New-Object System.Text.UTF8Encoding($false)
    $reader = New-Object System.IO.StreamReader($stream, $enc)
    $writer = New-Object System.IO.StreamWriter($stream, $enc)
    $writer.AutoFlush = $true
    $writer.Write($Json + "`n")

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
      try { $line = $reader.ReadLine() } catch { continue }   # ReadTimeout → 마감시한 재검사
      if (-not $line) { continue }
      try { $m = $line | ConvertFrom-Json } catch { continue }
      if ($m.type -eq $ExpectType -or $m.type -eq 'Error') { return $m }
    }
    return $null
  }
  catch { return $null }
  finally { if ($client) { $client.Close() } }
}

function Get-TermkeepPort {
  $djPath = Join-Path $env:APPDATA 'termkeep\daemon.json'
  if (-not (Test-Path $djPath)) { return 0 }
  try { return [int](Get-Content -Raw $djPath | ConvertFrom-Json).port } catch { return 0 }
}

function Get-TermkeepSession {
  param([Parameter(Mandatory)][int]$Port, [Parameter(Mandatory)][string]$SessionId)
  $m = Invoke-TermkeepMessage -Port $Port -Json '{"type":"ListSessions"}' -ExpectType 'SessionList'
  if (-not $m -or $m.type -ne 'SessionList') { return @{ ok = $false } }
  $s = @($m.sessions) | Where-Object { [string]$_.id -eq $SessionId } | Select-Object -First 1
  return @{ ok = $true; session = $s }
}

# ── 워커 termkeep 세션 닫기 ──────────────────────────────────────────────────
# ⚠ 매니페스트의 세션 ID 를 그대로 믿고 죽이면 안 된다. 사용자가 그 워커 탭을 이미 닫았고
#   termkeep 이 같은 번호를 **다른 새 세션에 재배정**했다면, 그 ID 로 DestroySession 을 보내는
#   순간 사용자의 멀쩡한 창이 죽는다. (spawn 쪽 Resolve-HostTerminal 이 재사용된 PID 를
#   같은 이유로 경계한다 — "부모가 자식보다 늦게 태어났으면 재사용된 PID 로 보고 끊는다".)
#   그래서 ListSessions 로 이름을 물어 **우리 워커 이름일 때만** 닫는다. #235 덕에 이름이
#   결정적이라 이 확인이 가능하다: S<중앙세션ID>/<슬러그>, 옛 데몬이면 접두사 없이 <슬러그>.
#   매니페스트엔 이름이 없고(스키마 고정) 어느 중앙 세션이 만들었는지도 없으므로, 접두사는
#   임의의 세션 ID 를 허용하되 슬러그는 정확히 일치해야 한다.
#
# 반환: $true = 진행해도 된다(닫았거나 애초에 없다) · $false = 중단(호출부가 wt.sh rm 을 건너뛴다)
function Stop-TermkeepWorkerSession {
  param([Parameter(Mandatory)][string]$SessionId, [Parameter(Mandatory)][string]$TaskName)

  $port = Get-TermkeepPort
  if (-not $port) {
    Write-Host "⚠ termkeep daemon.json 에서 포트를 못 읽음 — 세션 $SessionId 의 정체를 확인할 수 없다." -ForegroundColor Yellow
    return $false
  }

  $r = Get-TermkeepSession -Port $port -SessionId $SessionId
  if (-not $r.ok) {
    Write-Host "⚠ termkeep 데몬이 세션 목록에 응답하지 않음 — 세션 $SessionId 의 정체를 확인할 수 없다." -ForegroundColor Yellow
    return $false
  }
  if (-not $r.session) {
    Write-Host "→ termkeep 세션 $SessionId 이미 없음 — 닫을 것 없음." -ForegroundColor DarkGray
    return $true
  }

  $name = [string]$r.session.name
  $pattern = '^(S[A-Za-z0-9_-]+/)?' + [regex]::Escape($TaskName) + '$'
  if ($name -notmatch $pattern) {
    Write-Host "⚠ 세션 $SessionId 의 이름은 '$name' — 이 워커('$TaskName')가 아니다." -ForegroundColor Yellow
    Write-Host "  워커 탭이 이미 닫혀 번호가 남의 세션에 재배정된 것으로 보인다. 남의 세션은 닫지 않는다." -ForegroundColor Yellow
    return $false
  }

  $destroyMsg = ([ordered]@{ type = 'DestroySession'; session_id = $SessionId } | ConvertTo-Json -Compress)
  $d = Invoke-TermkeepMessage -Port $port -Json $destroyMsg -ExpectType 'SessionExited'
  if (-not $d -or $d.type -ne 'SessionExited') {
    $why = if ($d.type -eq 'Error') { $d.message } else { '응답 없음' }
    Write-Host "⚠ 세션 $SessionId 종료 실패($why)." -ForegroundColor Yellow
    return $false
  }

  # DestroySession 이 SessionExited 를 돌려준 뒤에도 목록에 잠깐 남는다(termkeep verify 스킬).
  # 정말 사라졌는지 다시 물어 확인한다 — 상한을 두고, 넘으면 중단한다.
  $deadline = (Get-Date).AddSeconds(5)
  while ((Get-Date) -lt $deadline) {
    $c = Get-TermkeepSession -Port $port -SessionId $SessionId
    if ($c.ok -and -not $c.session) {
      Write-Host "✓ termkeep 세션 닫힘: $name (session $SessionId)" -ForegroundColor Green
      return $true
    }
    Start-Sleep -Milliseconds 300
  }
  Write-Host "⚠ 세션 $SessionId 이 목록에서 사라지지 않음." -ForegroundColor Yellow
  return $false
}

# ── 워커가 남긴 프로세스 정리 ────────────────────────────────────────────────
# 세션을 닫아도 그 안에서 돌던 프로세스는 살아남는다. 실측(2026-07-17): DestroySession 이
# SessionExited 를 돌려준 뒤에도 .launch.ps1 을 물고 있던 powershell 과 그 자식 claude 가
# 그대로 떠서 워크트리를 작업 디렉터리로 계속 붙들었다 — 데몬이 PTY 를 닫으면 그 직계 셸은
# 죽지만 **손자까지 죽지는 않는다.** 그래서 세션만 닫고 지우려 들면 여전히 삭제가 실패한다.
#
# 대상을 PID 로 짐작하지 않는다(재사용된 PID 로 남을 죽이는 게 이 저장소의 단골 사고다).
# 우리가 만든 런처의 **경로가 커맨드라인에 그대로** 들어 있어(`-File <워크트리>\.launch.ps1`)
# 이 워크트리 것임이 자명하다 — 워크트리 경로는 트리마다 고유하므로 다른 워커와 겹칠 수 없고,
# 사용자가 손으로 연 셸은 애초에 이 경로를 커맨드라인에 갖지 않는다.
# claude 는 그 런처의 자식이라 자기 커맨드라인엔 경로가 없다 → 트리째(taskkill /T) 닫는다.
function Stop-WorkerProcessTree {
  param([Parameter(Mandatory)][string]$WorkDir)
  $launch = Join-Path $WorkDir '.launch.ps1'
  $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($launch) })
  foreach ($p in $procs) {
    Write-Host "  → 워커가 남긴 프로세스 종료: PID $($p.ProcessId) ($($p.Name)) + 자식" -ForegroundColor DarkGray
    & taskkill.exe /PID $p.ProcessId /T /F 2>&1 | Out-Null
  }
  return $procs.Count
}

# ── 워크트리가 정말 풀렸는지 확인 ────────────────────────────────────────────
# 세션을 닫아도 그 안의 프로세스가 워크트리를 놓기까지 잠깐 걸린다. 붙들고 있는 채로 지우면
# git worktree remove 가 등록을 해제한 **뒤** 폴더 삭제에서 죽어 어중간한 상태를 남긴다.
#
# 확인은 이름 바꾸기로 한다: 작업 디렉터리로 열린 핸들은 FILE_SHARE_DELETE 없이 열려 있어
# 삭제뿐 아니라 이름 바꾸기도 막는다 = 부작용 없이 삭제 가능 여부를 그대로 재현한다. 성공하면
# 곧바로 원래 이름으로 되돌린다(아무도 안 잡고 있음이 방금 증명됐으니 되돌리기는 실패하지 않는다).
# 한계: 잠긴 게 하위 폴더면(실측된 사고는 전부 워크트리 루트가 cwd 였다) 이 확인을 통과할 수
# 있다 — 그래도 통과 못 하는 경우를 거르는 것만으로 관측된 사고는 막는다.
function Wait-WorktreeUnlocked {
  param([Parameter(Mandatory)][string]$Dir, [int]$TimeoutSec = 15)
  $probe = "$Dir.__stopprobe"
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ($true) {
    try { [System.IO.Directory]::Move($Dir, $probe) }
    catch {
      if ((Get-Date) -ge $deadline) { return $false }
      Start-Sleep -Milliseconds 500
      continue
    }
    try { [System.IO.Directory]::Move($probe, $Dir) }
    catch { throw "워크트리 이름을 되돌리지 못했습니다: $probe → $Dir ($($_.Exception.Message))" }
    return $true
  }
}

$wtDir = Join-Path $MainRoot "wt\$Task"
$manifestPath = Join-Path $omcDir "orchestrator\$Task.json"

# ── 매니페스트를 **먼저** 읽는다 ─────────────────────────────────────────────
# 세션을 워크트리보다 먼저 닫아야 하므로, 삭제 뒤가 아니라 여기서 읽는다.
# (스키마는 spawn-worker.ps1 이 쓰고 status.ps1 이 읽는 그대로 — 여기선 읽기만 한다.)
$manifest = $null
if (Test-Path $manifestPath) {
  try { $manifest = Get-Content -Raw $manifestPath -Encoding UTF8 | ConvertFrom-Json }
  catch { Write-Host "⚠ 매니페스트를 읽지 못함($($_.Exception.Message)) — 세션 종료를 건너뛴다." -ForegroundColor Yellow }
}

# ── 1) 세션 종료 (termkeep 모드만) ───────────────────────────────────────────
# window/tab 모드는 창을 사용자가 닫는다 — 이번 범위 밖이라 건드리지 않는다(기존 동작 유지).
$sessionId = if ($manifest) { "$($manifest.termkeepSessionId)".Trim() } else { '' }
if ($manifest -and $manifest.mode -eq 'termkeep' -and $sessionId) {
  Write-Host "== termkeep 세션 종료: session $sessionId ==" -ForegroundColor Cyan
  if (-not (Stop-TermkeepWorkerSession -SessionId $sessionId -TaskName $Task)) {
    Write-Host ''
    Write-Host "중단: 세션을 닫지 못해 워크트리를 건드리지 않았다(wt.sh rm 미실행)." -ForegroundColor Red
    Write-Host "  지금 지우면 git 등록만 해제되고 폴더는 남는 어중간한 상태가 된다." -ForegroundColor DarkGray
    Write-Host "  → 워커 탭('$Task')을 직접 닫고 다시 실행하세요." -ForegroundColor Yellow
    Write-Host "  → 탭을 이미 닫았다면 매니페스트가 낡은 것이다: .omc/orchestrator/$Task.json 을 지우고 다시 실행." -ForegroundColor Yellow
    exit 1
  }
  # 세션이 우리 것으로 확인돼 닫혔다(또는 이미 없었다) → 그 세션이 남긴 프로세스도 우리 것이다.
  if (Test-Path $wtDir) { $null = Stop-WorkerProcessTree -WorkDir $wtDir }
}

# ── 2) 워크트리 제거 (있을 때만) ─────────────────────────────────────────────
if (Test-Path $wtDir) {
  if (-not (Wait-WorktreeUnlocked -Dir $wtDir)) {
    Write-Host ''
    Write-Host "중단: wt/$Task 를 아직 다른 프로세스가 붙들고 있다(wt.sh rm 미실행)." -ForegroundColor Red
    Write-Host "  → 그 폴더를 열어 둔 셸·편집기를 닫고 다시 실행하세요." -ForegroundColor Yellow
    exit 1
  }
  Write-Host "== 워크트리 제거: wt/$Task ==" -ForegroundColor Cyan
  # wt.sh(bash) 도 cwd 에서 git 저장소를 찾는다 → 메인 트리에서 실행해야 한다.
  Push-Location $MainRoot
  try { & $GitBash "$MainRootFwd/deploy/wt.sh" rm $Task } finally { Pop-Location }
  if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠ wt.sh rm 실패 (exit $LASTEXITCODE) — 미커밋 변경이 있으면 먼저 커밋/되돌리세요." -ForegroundColor Yellow
    return
  }
}
else {
  Write-Host "→ 워크트리 이미 없음: wt/$Task" -ForegroundColor Yellow
}

# ── 3) 매니페스트 삭제 ───────────────────────────────────────────────────────
if (Test-Path $manifestPath) { Remove-Item $manifestPath; Write-Host "✓ 매니페스트 삭제" -ForegroundColor Green }

if ($Purge) {
  foreach ($p in @("results\$Task.md", "logs\$Task.log")) {
    $full = Join-Path $omcDir $p
    if (Test-Path $full) { Remove-Item $full; Write-Host "✓ 삭제: .omc/$($p -replace '\\','/')" -ForegroundColor Green }
  }
}

Write-Host "완료: $Task 정리됨" -ForegroundColor Green
