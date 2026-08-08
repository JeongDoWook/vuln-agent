'use strict';

// codex/claude를 실제 실행 커맨드로 바꾸는 곳 — 세 launcher 중 도구별 분기가
// 존재하는 유일한 파일이다. launcher들은 여기서 나온 cliCommand 문자열만 받고
// 그게 codex인지 claude인지 모른다.
const fs = require('fs');
const path = require('path');

// npm shim(claude.ps1/claude.cmd → npx)을 거치면 프롬프트 인자가 유실된다(실측 2026-07-27)
// — 워커는 항상 claude.exe를 직접 부른다.
function resolveClaudeExe() {
  if (process.platform !== 'win32') return 'claude';
  const npmExe = path.join(process.env.APPDATA || '', 'npm', 'node_modules',
    '@anthropic-ai', 'claude-code', 'bin', 'claude.exe');
  try { fs.lstatSync(npmExe); return npmExe; } catch (_) {}
  return 'claude';
}

// WindowsApps 별칭(wt.exe)은 AppExecLink 리파스포인트라서 existsSync는 항상 false를
// 준다 — lstat만 통과한다(실측).
function resolveWtAlias() {
  const alias = path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WindowsApps', 'wt.exe');
  try { fs.lstatSync(alias); return alias; } catch (_) { return null; }
}

// 5번째 인자로 고른 CLI(codex|claude)를 실제 실행 가능한 커맨드로 바꾼다. 도구
// 전용 분기는 여기 하나뿐 — launcher들은 cliCommand 문자열만 받고 codex/claude를 모른다.
function resolveCliCommand(tool) {
  return tool === 'claude' ? resolveClaudeExe() : 'codex';
}

module.exports = { resolveClaudeExe, resolveWtAlias, resolveCliCommand };
