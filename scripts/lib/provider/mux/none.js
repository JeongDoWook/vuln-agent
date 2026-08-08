'use strict';

// mux 프로바이더 — none (계약 §2.7)
//
// 멀티플렉서를 쓰지 않는 환경의 기본값. 모든 동사가 exit 0 + { skipped:true } 다.
// 스킬은 이 결과로 흐름을 바꾸지 않는다 — 그러라고 있는 프로바이더라서 어떤
// 인자를 줘도 던지지 않는다.

const flag = (args, ...names) => {
  if (!args || Array.isArray(args)) return undefined;
  for (const n of names) if (args[n] !== undefined) return args[n];
  return undefined;
};

const positionals = (args) => {
  if (!args) return [];
  if (Array.isArray(args)) return args.slice();
  for (const k of ['_', 'positional', 'positionals', 'args']) {
    if (Array.isArray(args[k])) return args[k].slice();
  }
  return [];
};

const labelOf = (args) => String(flag(args, 'label') || positionals(args)[0] || '') || null;

const skip = (verb) => async (args, ctx) => {
  const log = (ctx && ctx.log) || (() => {});
  const label = labelOf(args);
  log(`[mux] provider=none — tab ${verb} 생략${label ? ` (${label})` : ''}`);
  return { skipped: true, verb, label };
};

const open = skip('open');
const done = skip('done');
const kill = skip('kill');

// ── px.js 접속부 ─────────────────────────────────────────────

const adapt = (fn) => (ctx, args, flags) => fn(
  Object.assign({ _: Array.isArray(args) ? args : [] }, flags || {}),
  {
    config: (ctx && ctx.config) || {},
    repoRoot: (ctx && (ctx.repoRoot || ctx.rootDir)) || process.cwd(),
    log: (ctx && ctx.log) || ((m) => process.stderr.write(`${m}\n`)),
  }
);

const doctor = async () => [{ name: 'mux', ok: true, detail: 'provider=none — tab 동사는 전부 skip' }];

module.exports = {
  id: 'none',
  open,
  done,
  kill,
  verbs: { 'tab.open': adapt(open), 'tab.done': adapt(done), 'tab.kill': adapt(kill) },
  doctor,
};
