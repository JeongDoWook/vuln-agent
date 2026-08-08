'use strict';

// External worker launcher. The prompt never travels through the terminal IPC:
// the parent writes .initial-prompt, then the new session reads that file.
// Tool-agnostic: 5th arg picks which CLI the new terminal runs (codex | claude).
//
// 세 전략을 순서대로 시도하고, 딱 하나만 쓴다(섞어 쓰지 않음) — 각 전략은
// scripts/lib/worker/ 아래 독립 모듈이며 서로의 존재를 모른다:
//   1. TermKeep 세션   (lib/worker/termkeep-launcher.js)      — 새 OS 창 없음
//   2. Windows Terminal 탭 (lib/worker/windows-terminal-launcher.js)
//   3. 평범한 새 창/프로세스 (lib/worker/fallback-launcher.js) — 항상 가능
const fs = require('fs');
const path = require('path');

const termkeep = require('./lib/worker/termkeep-launcher');
const windowsTerminal = require('./lib/worker/windows-terminal-launcher');
const fallback = require('./lib/worker/fallback-launcher');
const { resolveCliCommand } = require('./lib/worker/resolve-tool');

const cwd = path.resolve(process.argv[2] || process.cwd());
const promptFile = path.resolve(process.argv[3] || path.join(cwd, '.initial-prompt'));
const tool = (process.argv[5] || 'codex').trim();
const label = process.argv[4] || `${tool}-worker-${Date.now()}`;

// 트리거는 **실제로 넘겨받은 프롬프트 파일**을 가리켜야 한다. 여기에 '.initial-prompt'를
// 하드코딩하면 워커를 여러 개 띄울 때 전부 같은 파일을 읽어 같은 일을 한다(2026-08-07 실측).
// cwd 기준 상대경로로 준다 — 워커의 작업 디렉터리가 cwd이고, 절대경로는 길고 인용부호에 취약하다.
const promptRel = path.relative(cwd, promptFile).split(path.sep).join('/') || path.basename(promptFile);
const trigger = `${promptRel} 파일을 읽고 그 내용을 지시사항으로 삼아 바로 작업을 시작해라.`;

if (!fs.existsSync(promptFile)) {
  console.error(`prompt file not found: ${promptFile}`);
  process.exit(2);
}

const cliCommand = resolveCliCommand(tool);
const ctx = { cwd, cliCommand, label, trigger, promptFile };

async function main() {
  // TermKeep이 가능하다고 판단되면 그 경로에 전념한다 — 실패해도 WT/폴백으로
  // 새지 않는다. 지금 창이 이미 TermKeep 소유라 다른 전략을 섞으면 두 개가
  // 동시에 뜬다.
  if (termkeep.isAvailable()) {
    try {
      console.log(await termkeep.launch(ctx));
    } catch (error) {
      console.error(error.message);
      process.exit(1);
    }
    return;
  }

  if (windowsTerminal.isAvailable()) {
    console.log(windowsTerminal.launch(ctx));
    return;
  }

  console.log(fallback.launch(ctx));
}

main();
