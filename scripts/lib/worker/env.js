'use strict';

// 세 launcher(termkeep/windows-terminal/fallback)가 공유하는 환경변수 정리 유틸.
// 도구별(codex/claude) 분기는 없다 — 워커 프로세스에 새겨진 하니스 흔적만 지운다.

// Claude Code 하니스가 자기 도구 프로세스에 심는 변수들. 그대로 상속되면 워커 탭이
// 색 없이(NO_COLOR) 뜨고 "Transcript saving is off"가 뜬다(2026-08-07 실측).
const HARNESS_ENV_KEYS = ['NO_COLOR', 'FORCE_COLOR', 'CLAUDECODE', 'CLAUDE_PID',
  'CLAUDE_CODE_CHILD_SESSION', 'CLAUDE_CODE_ENTRYPOINT',
  'CLAUDE_CODE_SESSION_ID', 'CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS'];

function cleanEnv() {
  const env = { ...process.env };
  HARNESS_ENV_KEYS.forEach((k) => delete env[k]);
  return env;
}

function powershellEnvClearCommand() {
  return HARNESS_ENV_KEYS.map((k) => `Remove-Item Env:${k} -ErrorAction SilentlyContinue`).join('; ');
}

module.exports = { HARNESS_ENV_KEYS, cleanEnv, powershellEnvClearCommand };
