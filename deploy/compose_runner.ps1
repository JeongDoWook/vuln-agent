# vuln-agent · Docker Compose Runner (PowerShell 래퍼)
#
# 실제 로직은 compose_runner.sh(bash) 에 있다 — 여기서는 git-bash 를 통해
# 같은 스크립트를 그대로 호출한다. 로직 중복 없음, sh 가 유일한 소스.
#
# 사용법 (compose_runner.sh 와 동일):
#   .\compose_runner.ps1 init
#   .\compose_runner.ps1 doctor
#   .\compose_runner.ps1 dev up -d
#   .\compose_runner.ps1 dev down
#   .\compose_runner.ps1 dev logs -f
#   .\compose_runner.ps1 prod up -d --build

$ErrorActionPreference = 'Stop'

# PATH 의 bash 가 WSL(system32\bash.exe)일 수 있어 git-bash 를 직접 찾는다.
# WSL bash 는 /c/... 를 윈도우 경로로 변환하지 않아(WSL 은 /mnt/c/ 사용) 스크립트를 못 찾는다.
$candidates = @(
    "$env:ProgramFiles\Git\bin\bash.exe",
    "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
    "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
)
$bashPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $bashPath) {
    Write-Error "git-bash(bash.exe)를 찾을 수 없습니다. Git for Windows 설치 확인."
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$shScript = (Join-Path $scriptDir 'compose_runner.sh') -replace '\\', '/'

& $bashPath $shScript @args
exit $LASTEXITCODE
