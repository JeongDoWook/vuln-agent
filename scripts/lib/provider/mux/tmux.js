'use strict';

// mux 프로바이더 — tmux (계약 §2.7)
//
// 터미널 멀티플렉서는 **선택 기능**이다. tmux 실행 파일이 없으면 죽지 않고
// exit 3(미지원)으로 떨어진다.
//
// label → 창 참조(session:index)는 레지스트리 파일에 적어 둔다. 창 이름으로도
// 타깃을 잡을 수 있지만, done 이 이름을 바꾸는 순간 그 경로가 끊긴다. 인덱스는
// 이름이 바뀌어도 유효하다.

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const DEFAULTS = Object.freeze({
  bin: 'tmux',
  session: 'pipeline',
  registry: '.pipeline/mux-tmux.json',
  donePrefix: 'done: ',
});

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

const fail = (code, message, exitCode) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  return e;
};

const cfgOf = (ctx) => Object.assign({}, DEFAULTS, ((ctx && ctx.config && ctx.config.mux) || {}).tmux || {});

const labelOf = (args) => {
  const label = String(flag(args, 'label') || positionals(args)[0] || '').trim();
  if (!label) throw fail('usage', '<label> 이 필요합니다', 1);
  return label;
};

const runBin = (bin, argv) => {
  const r = cp.spawnSync(bin, argv, { encoding: 'utf8' });
  if (r.error) {
    if (r.error.code === 'ENOENT') throw fail('unsupported', `'${bin}' 실행 파일을 찾을 수 없습니다 — mux 없이 진행하세요`, 3);
    throw fail('spawn_failed', `${bin} 실행 실패: ${r.error.message}`, 1);
  }
  return { ok: r.status === 0, status: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
};

const regPath = (ctx) => path.resolve(ctx.repoRoot, cfgOf(ctx).registry);

const regRead = (ctx) => {
  try { return JSON.parse(fs.readFileSync(regPath(ctx), 'utf8')); } catch (_) { return {}; }
};

const regWrite = (ctx, data) => {
  const p = regPath(ctx);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(data, null, 2) + '\n');
};

// ── open ─────────────────────────────────────────────────────

const open = async (args, ctx) => {
  const cfg = cfgOf(ctx);
  const log = (ctx && ctx.log) || (() => {});
  const label = labelOf(args);
  const cwd = path.resolve(ctx.repoRoot, String(flag(args, 'cwd') || ctx.repoRoot));
  const cmd = flag(args, 'cmd');

  const reg = regRead(ctx);
  if (reg[label] && reg[label].ref) {
    log(`[mux] '${label}' 는 이미 열려 있습니다 (${reg[label].ref})`);
    return { opened: false, label, ref: reg[label].ref, cwd: reg[label].cwd || cwd };
  }

  // 세션이 없으면 detached 로 만든다. has-session 의 비0 종료는 오류가 아니다.
  if (!runBin(cfg.bin, ['has-session', '-t', cfg.session]).ok) {
    const s = runBin(cfg.bin, ['new-session', '-d', '-s', cfg.session, '-c', cwd]);
    if (!s.ok) throw fail('open_failed', `tmux 세션 생성 실패: ${s.stderr}`, 1);
    log(`[mux] 세션 생성: ${cfg.session}`);
  }

  const w = runBin(cfg.bin, ['new-window', '-t', cfg.session, '-n', label, '-c', cwd, '-P', '-F', '#{window_index}']);
  if (!w.ok || !w.stdout) throw fail('open_failed', `tmux 창 생성 실패: ${w.stderr || w.stdout}`, 1);
  const ref = `${cfg.session}:${w.stdout}`;
  log(`[mux] 창 생성: ${label} (${ref})`);

  if (cmd) {
    runBin(cfg.bin, ['send-keys', '-t', ref, String(cmd), 'Enter']);
    log(`[mux] 명령 전달: ${ref}`);
  }

  reg[label] = { ref, cwd, session: cfg.session, openedAt: new Date().toISOString() };
  regWrite(ctx, reg);
  return { opened: true, label, ref, cwd };
};

// ── done ─────────────────────────────────────────────────────

const done = async (args, ctx) => {
  const cfg = cfgOf(ctx);
  const log = (ctx && ctx.log) || (() => {});
  const label = labelOf(args);
  const reg = regRead(ctx);
  const entry = reg[label];

  if (!entry || !entry.ref) {
    log(`[mux] '${label}' 기록이 없습니다 — skip`);
    return { label, done: false, skipped: true, reason: 'not_found' };
  }
  if (entry.done) return { label, done: true, ref: entry.ref };

  const name = `${cfg.donePrefix}${label}`;
  const r = runBin(cfg.bin, ['rename-window', '-t', entry.ref, name]);
  if (!r.ok) {
    log(`[mux] rename 실패 (${label}): ${r.stderr}`);
    return { label, done: false, ref: entry.ref, error: r.stderr };
  }

  reg[label] = Object.assign({}, entry, { done: true, name });
  regWrite(ctx, reg);
  log(`[mux] '${label}' → ${name}`);
  return { label, done: true, ref: entry.ref, name };
};

// ── kill ─────────────────────────────────────────────────────

const kill = async (args, ctx) => {
  const cfg = cfgOf(ctx);
  const log = (ctx && ctx.log) || (() => {});
  const label = labelOf(args);
  const reg = regRead(ctx);
  const entry = reg[label];

  if (!entry || !entry.ref) {
    log(`[mux] '${label}' 기록이 없습니다 — skip`);
    return { label, killed: false, skipped: true, reason: 'not_found' };
  }

  const r = runBin(cfg.bin, ['kill-window', '-t', entry.ref]);
  delete reg[label];
  regWrite(ctx, reg);
  if (!r.ok) {
    // 이미 사라진 창을 닫는 것도 성공으로 본다(멱등) — 기록만 정리하고 넘어간다.
    log(`[mux] kill 실패/이미 없음 (${label}): ${r.stderr}`);
    return { label, killed: false, ref: entry.ref, error: r.stderr };
  }
  log(`[mux] '${label}' 종료 (${entry.ref})`);
  return { label, killed: true, ref: entry.ref };
};

// ── doctor (계약 §2.8) ───────────────────────────────────────
// 실행 파일이 없다는 사실은 fail 이 아니다 — mux 는 선택 기능이다.

const doctor = async (ctx) => {
  const cfg = cfgOf(ctx);
  let found = false;
  try { found = runBin(cfg.bin, ['-V']).ok; } catch (_) { found = false; }
  return [
    { name: cfg.bin, ok: true, detail: found ? '실행 가능' : `${cfg.bin} 없음 — tab 동사는 exit 3 (선택 기능)` },
    { name: 'session', ok: true, detail: cfg.session },
  ];
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

const verbs = { 'tab.open': adapt(open), 'tab.done': adapt(done), 'tab.kill': adapt(kill) };

module.exports = { id: 'tmux', open, done, kill, verbs, doctor };
