'use strict';

// Strategy 3: TermKeep도, Windows Terminal 탭도 안 되는 평범한 쉘 환경. 같은
// 파일 기반 계약(.initial-prompt)은 유지하되 새 창/프로세스만 그냥 띄운다.
// 항상 가능하므로 isAvailable()이 없다 — 앞 두 전략이 모두 실패했을 때의 최종 폴백.
const cp = require('child_process');
const { cleanEnv, powershellEnvClearCommand } = require('./env');

function launch({ cwd, cliCommand, promptFile }) {
  if (process.platform === 'win32') {
    const command = `${powershellEnvClearCommand()}; Set-Location -LiteralPath '${cwd.replace(/'/g, "''")}'; & '${cliCommand.replace(/'/g, "''")}'`;
    cp.spawn('powershell.exe', ['-NoLogo', '-NoExit', '-Command', command], {
      detached: true, stdio: 'ignore', env: cleanEnv(),
    }).unref();
    return `PowerShell ${cliCommand} worker started; prompt file: ${promptFile}`;
  }
  cp.spawn(cliCommand, [], { cwd, detached: true, stdio: 'ignore', env: cleanEnv() }).unref();
  return `${cliCommand} worker started; prompt file: ${promptFile}`;
}

module.exports = { launch };
