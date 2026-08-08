'use strict';

// Strategy 1: TermKeep 데몬에 소켓으로 접속해 새 세션을 만든다. 사용자가 보는
// 터미널 창은 이미 TermKeep이 들고 있으므로 새 OS 창을 띄우지 않는다.
const fs = require('fs');
const path = require('path');
const net = require('net');
const { powershellEnvClearCommand } = require('./env');

// 세션 생성 직후엔 쉘이 아직 입력을 못 받는다 — 쉘 기동과 프롬프트 트리거 전송을
// 각각 지연시켜 분리한다(실측).
const COMMAND_DELAY_MS = 2500;
const TRIGGER_DELAY_MS = 9000;
const STARTUP_TIMEOUT_MS = 30000;
// 트리거 전송 후 세션이 실제로 그걸 받아들일 시간을 준 뒤에야 소켓을 닫는다.
const SETTLE_DELAY_MS = 1000;

function daemonFilePath() {
  return path.join(process.env.APPDATA || '', 'termkeep', 'daemon.json');
}

function isAvailable() {
  return process.env.TERMKEEP === '1' && fs.existsSync(daemonFilePath());
}

function readPort() {
  try { return JSON.parse(fs.readFileSync(daemonFilePath(), 'utf8')).port || 0; } catch (_) { return 0; }
}

function sendInput(socket, sessionId, text) {
  const data = Buffer.from(text, 'utf8').toString('base64');
  socket.write(JSON.stringify({ type: 'SendInput', session_id: sessionId, data }) + '\n');
}

function sendLine(socket, sessionId, text) {
  sendInput(socket, sessionId, text);
  // TermKeep/Ink/PowerShell can treat text+CR in one PTY packet as pasted
  // content. Send Enter as a separate input event, like a human keystroke.
  setTimeout(() => sendInput(socket, sessionId, '\r'), 250);
}

function launch({ cwd, cliCommand, label, trigger }) {
  return new Promise((resolve, reject) => {
    const port = readPort();
    if (!port) return reject(new Error('TermKeep daemon.json has no port'));

    const socket = net.createConnection({ host: '127.0.0.1', port });
    let buffer = '';
    let sessionId = null;
    let commandSent = false;
    let triggerSent = false;

    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('TermKeep worker startup timed out'));
    }, STARTUP_TIMEOUT_MS);

    const fail = (message) => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error(message));
    };

    socket.on('error', (error) => fail(`TermKeep connection failed: ${error.message}`));
    socket.on('connect', () => {
      socket.write(JSON.stringify({ type: 'CreateSession', name: label }) + '\n');
      // Subscribe after creation. The daemon only streams Output for sessions
      // that existed when ListSessions was received.
      socket.write(JSON.stringify({ type: 'ListSessions' }) + '\n');
    });
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (!line.trim()) continue;
        let message;
        try { message = JSON.parse(line); } catch (_) { continue; }
        if (message.type === 'Error') return fail(`TermKeep daemon error: ${message.message}`);
        if (message.type === 'SessionCreated' && message.session_id && !sessionId) {
          sessionId = String(message.session_id);
          socket.write(JSON.stringify({ type: 'RenameSession', session_id: sessionId, name: label }) + '\n');
          // Keep shell startup separate from the prompt. The worker reads the file itself.
          setTimeout(() => {
            if (commandSent) return;
            commandSent = true;
            const command = `powershell -NoLogo -NoExit -Command "${powershellEnvClearCommand()}; Set-Location -LiteralPath '${cwd.replace(/'/g, "''")}'; & '${cliCommand.replace(/'/g, "''")}'"`;
            sendLine(socket, sessionId, command);
          }, COMMAND_DELAY_MS);
          setTimeout(() => {
            if (triggerSent) return;
            triggerSent = true;
            sendLine(socket, sessionId, trigger);
            setTimeout(() => {
              clearTimeout(timer);
              socket.destroy();
              resolve(`TermKeep ${cliCommand} worker started: session ${sessionId}`);
            }, SETTLE_DELAY_MS);
          }, TRIGGER_DELAY_MS);
        }
      }
    });
  });
}

module.exports = { isAvailable, launch };
