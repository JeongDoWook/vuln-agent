<#
.SYNOPSIS
  네이티브 exe 호출 래퍼 — dot-source 해서 Invoke-Native 만 쓴다. (PS 5.1 stderr 승격 회피)

.DESCRIPTION
  Windows PowerShell 5.1 은 네이티브 exe 가 stderr 에 쓴 줄을 ErrorRecord(NativeCommandError)로
  **승격**한다. 스크립트가 `$ErrorActionPreference='Stop'` 이면 그게 종료 오류가 되어,
  **종료코드가 0 이든 아니든** 그 자리에서 throw 된다 — "성공했는데 실패로 보고" 한다.
  실측 사고 2건:
    · 2026-07-26 spawn — wt.sh 가 진행 상황을 stderr 로 쓴다 → 워크트리는 만들어졌는데 스폰 실패.
    · 2026-07-27 stop  — 이미 없는 PID 에 taskkill → 'ERROR: The process "..." not found.' 한 줄에
      정리가 끝난 시점의 스크립트가 죽어, 워크트리 제거·브랜치 삭제가 통째로 안 돌았다.

  승격의 방아쇠는 **PowerShell 이 그 stderr 를 가로채는 상황**이다: `2>$null`·`2>&1` 리다이렉트가
  걸려 있거나 **호출자가 스트림을 합쳐 받을 때**(예: reap-merged.ps1 이 `& stop-worker.ps1` 을
  같은 프로세스에서 부르고, 그 reap 를 다시 합쳐 받는 경우). 그래서 `2>&1` 만 지우는 건 부족하다 —
  방아쇠 하나를 치울 뿐 근본(EAP 승격)은 그대로다.

  대응: 네이티브 호출 **구간에만** EAP 를 낮추고 `finally` 로 원복한다.

  · `2>&1` 로 덮지 마라 — stderr 가 stdout 에 섞여 출력을 읽는 쪽이 깨지고, 근본도 안 고쳐진다.
    출력을 감추고 싶으면 stdout 만 `| Out-Null` 한다.
  · **종료코드 검사(`$LASTEXITCODE`)는 호출부에 그대로 남긴다.** stderr 를 무시하는 것과
    종료코드를 무시하는 것은 다르다 — 진짜 실패는 여전히 걸러야 한다. `$LASTEXITCODE` 는 전역이라
    이 함수를 거쳐도 마지막 네이티브 프로세스의 값이 그대로 남는다.
  · 출력은 흘려보낸다(캡처하지 않는다) — wt.sh 의 진행 로그 등이 사용자에게 그대로 보여야 한다.
    캡처가 필요하면 호출부에서 받는다: `$out = Invoke-Native gh @('pr','list')`.

.EXAMPLE
  . "$PSScriptRoot\native-call.ps1"
  Invoke-Native $GitBash @("$MainRootFwd/deploy/wt.sh", 'rm', $Task)
  if ($LASTEXITCODE -ne 0) { ... }
#>
function Invoke-Native {
  param(
    [Parameter(Mandatory)][string]$FilePath,
    [string[]]$Arguments = @()
  )
  $prev = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'SilentlyContinue'
    & $FilePath @Arguments
  }
  finally { $ErrorActionPreference = $prev }
}
