<#
.SYNOPSIS
  .omc/logs/history.jsonl 를 읽어 작업별 스폰→완료→병합정리 소요시간을 보여준다.

.DESCRIPTION
  "어디가 오래 걸렸는지" 를 나중에 되짚어보는 용도. claude-pipeline 의 work-report.py
  (토큰·재작업·품질점수까지 마이닝하는 주간 HTML 대시보드)는 이 저장소 규모(1인 유지보수)엔
  과하다(YAGNI) — 여기선 스폰→완료→정리 세 시점의 경과시간만 표로 본다.

.EXAMPLE
  .\history-report.ps1
  .\history-report.ps1 -Task cve-badge   # 특정 작업만
#>
param(
  [string]$Task,
  [switch]$Raw   # 가공 없이 원본 이벤트 라인 그대로 출력
)

$ErrorActionPreference = 'Stop'

$gitCommon = (& git -C $PSScriptRoot rev-parse --git-common-dir 2>$null)
if (-not $gitCommon) { throw '스크립트가 git 저장소 안에 있지 않습니다.' }
if (-not [System.IO.Path]::IsPathRooted($gitCommon)) { $gitCommon = Join-Path $PSScriptRoot $gitCommon }
$MainRoot = Split-Path (Resolve-Path $gitCommon).Path -Parent
$histPath = Join-Path $MainRoot '.omc/logs/history.jsonl'

if (-not (Test-Path $histPath)) {
  Write-Host "히스토리 없음: $histPath" -ForegroundColor Yellow
  exit 0
}

$events = Get-Content $histPath -Encoding utf8 | ForEach-Object {
  try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $_ -and (-not $Task -or $_.task -eq $Task) }

if (-not $events) {
  Write-Host '기록된 이벤트 없음.' -ForegroundColor Yellow
  exit 0
}

if ($Raw) {
  $events | Sort-Object ts | ForEach-Object {
    Write-Host "$($_.ts)  [$($_.task)] $($_.event)  $($_.detail)"
  }
  exit 0
}

function Fmt-Span($from, $to) {
  if (-not $from -or -not $to) { return '—' }
  $span = ([datetime]$to) - ([datetime]$from)
  if ($span.TotalMinutes -lt 60) { return "{0:N0}분" -f $span.TotalMinutes }
  return "{0:N1}시간" -f $span.TotalHours
}

$rows = $events | Group-Object task | ForEach-Object {
  $g = $_.Group | Sort-Object ts
  $spawn = ($g | Where-Object event -eq 'spawn' | Select-Object -First 1).ts
  $done = ($g | Where-Object { $_.event -eq 'status' -and $_.detail -match '^완료' } |
    Select-Object -First 1).ts
  $merged = ($g | Where-Object event -eq 'merged_cleanup' | Select-Object -First 1).ts
  [pscustomobject]@{
    Task              = $_.Name
    스폰               = if ($spawn) { ([datetime]$spawn).ToString('MM-dd HH:mm') } else { '—' }
    '스폰→완료'       = Fmt-Span $spawn $done
    '완료→병합정리'   = Fmt-Span $done $merged
    상태               = if ($merged) { '정리됨' } elseif ($done) { '완료(미병합)' } else { '진행중' }
  }
}

$rows | Sort-Object 스폰 | Format-Table -AutoSize
