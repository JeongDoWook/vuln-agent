'use strict';

// notify 프로바이더 — none (계약 §2.5)
//
// 알림을 쓰지 않는 프로젝트의 기본값. 항상 성공하고 항상 sent:false 다.
// 조건 분기를 없애는 것이 존재 이유라서, 어떤 인자를 줘도 던지지 않는다.

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

const send = async (args, ctx) => {
  const log = (ctx && ctx.log) || (() => {});
  const event = String(flag(args, 'event') || positionals(args)[0] || '');
  log(`[notify] provider=none — 전송하지 않음${event ? ` (${event})` : ''}`);
  return { sent: false, skipped: true, event: event || null, channel: null };
};

// ── px.js 접속부 ─────────────────────────────────────────────

const adapt = (fn) => (ctx, args, flags) => fn(
  Object.assign({ _: Array.isArray(args) ? args : [] }, flags || {}),
  {
    config: (ctx && ctx.config) || {},
    repoRoot: (ctx && (ctx.repoRoot || ctx.rootDir)) || process.cwd(),
    log: (ctx && ctx.log) || ((m) => process.stderr.write(`${m}\n`)),
  }
);

const doctor = async () => [{ name: 'notify', ok: true, detail: 'provider=none — 알림을 보내지 않는다' }];

module.exports = { id: 'none', send, verbs: { 'notify.send': adapt(send) }, doctor };
