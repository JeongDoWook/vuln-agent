'use strict';

// Strategy 2: 지금 세션이 Windows Terminal 안에서 돌고 있으면(WT_SESSION) 새 창
// 대신 같은 창에 탭 하나를 붙인다.
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { cleanEnv, HARNESS_ENV_KEYS } = require('./env');
const { resolveWtAlias } = require('./resolve-tool');

function isAvailable() {
  return process.platform === 'win32' && !!process.env.WT_SESSION && !!resolveWtAlias();
}

function launch({ cwd, cliCommand, label, trigger }) {
  const wtExe = resolveWtAlias();
  // wt는 커맨드라인의 `;`를 자기 subcommand 구분자로 먹어서 -Command 문자열을 그대로
  // 넘기면 세션이 조각난다(실측) — .ps1 런처로 세미콜론을 인자에서 없앤다.
  const psLines = [
    ...HARNESS_ENV_KEYS.map((k) => `Remove-Item Env:${k} -ErrorAction SilentlyContinue`),
    `Set-Location -LiteralPath '${cwd.replace(/'/g, "''")}'`,
    `& '${cliCommand.replace(/'/g, "''")}' '${trigger.replace(/'/g, "''")}'`,
  ];
  const launcher = path.join(cwd, '.spawn-worker-launch.ps1');
  // BOM 필수 — PowerShell 5.1은 BOM 없는 .ps1을 ANSI로 읽어 한글이 깨진다(실측).
  fs.writeFileSync(launcher, '﻿' + psLines.join('\r\n') + '\r\n', 'utf8');
  cp.spawn(wtExe, ['-w', '0', 'nt', '-d', cwd, '--title', label,
    'powershell.exe', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', launcher],
  { detached: true, stdio: 'ignore', env: cleanEnv() }).unref();
  return `Windows Terminal 탭 ${cliCommand} worker started: ${label}`;
}

module.exports = { isAvailable, launch };
