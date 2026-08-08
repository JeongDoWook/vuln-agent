'use strict';

// mux 프로바이더 — cmux (계약 §2.7)
//
// 터미널 멀티플렉서는 **선택 기능**이다. cmux 실행 파일이 없으면 죽지 않고
// exit 3(미지원)으로 떨어진다 — 스킬은 그걸 받고 그냥 진행한다.
//
// label → workspace 참조(workspace:N)는 레지스트리 파일에 적어 둔다. cmux 는
// 이름으로 workspace 를 되찾는 조회 명령을 주지 않아서, done/kill 이 open 때
// 받은 참조를 다시 찾으려면 우리 쪽에 기록이 있어야 한다.

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const DEFAULTS = Object.freeze({
  bin: 'cmux',
  registry: '.pipeline/mux-cmux.json',
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

const cfgOf = (ctx) => Object.assign({}, DEFAULTS, ((ctx && ctx.config && ctx.config.mux) || {}).cmux || {});

const labelOf = (args) => {
  const label = String(flag(args, 'label') || positionals(args)[0] || '').trim();
  if (!label) throw fail('usage', '<label> 이 필요합니다', 1);
  return label;
};

// ── 실행 ─────────────────────────────────────────────────────

const runBin = (bin, argv) => {
  const r = cp.spawnSync(bin, argv, { encoding: 'utf8' });
  if (r.error) {
    // 실행 파일이 없다 = 이 프로바이더가 이 환경을 지원하지 않는다. 죽지 않는다.
    if (r.error.code === 'ENOENT') throw fail('unsupported', `'${bin}' 실행 파일을 찾을 수 없습니다 — mux 없이 진행하세요`, 3);
    throw fail('spawn_failed', `${bin} 실행 실패: ${r.error.message}`, 1);
  }
  return { ok: r.status === 0, status: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
};

// ── 레지스트리 ───────────────────────────────────────────────

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
    // 멱등 — 이미 열려 있는 라벨은 다시 열지 않는다.
    log(`[mux] '${label}' 는 이미 열려 있습니다 (${reg[label].ref})`);
    return { opened: false, label, ref: reg[label].ref, cwd: reg[label].cwd || cwd };
  }

  const r = runBin(cfg.bin, ['new-workspace', '--name', label, '--cwd', cwd]);
  const ref = (r.stdout.match(/workspace:\d+/) || [])[0];
  if (!r.ok || !ref) {
    throw fail('open_failed', `cmux workspace 생성 실패: ${r.stderr || r.stdout}`, 1);
  }
  log(`[mux] workspace 생성: ${label} (${ref})`);

  let surface = null;
  if (cmd) {
    const s = runBin(cfg.bin, ['list-pane-surfaces', '--workspace', ref]);
    surface = (s.stdout.match(/surface:\d+/) || [])[0] || null;
    if (surface) {
      runBin(cfg.bin, ['send', '--surface', surface, '--workspace', ref, `${cmd}\n`]);
      log(`[mux] 명령 전달: ${surface}`);
    } else {
      // 창은 만들어졌다 — 명령만 못 보냈을 뿐이라 실패로 만들지 않는다.
      log('[mux] surface 탐지 실패 — 명령은 수동 실행 필요');
    }
  }

  reg[label] = { ref, cwd, surface, openedAt: new Date().toISOString() };
  regWrite(ctx, reg);
  return { opened: true, label, ref, surface, cwd };
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
  if (entry.done) return { label, done: true, ref: entry.ref }; // 멱등.

  const name = `${cfg.donePrefix}${label}`;
  const r = runBin(cfg.bin, ['rename-workspace', '--workspace', entry.ref, name]);
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
    // 멱등 — 이미 없는 창을 닫으라고 해도 성공이다.
    log(`[mux] '${label}' 기록이 없습니다 — skip`);
    return { label, killed: false, skipped: true, reason: 'not_found' };
  }

  const r = runBin(cfg.bin, ['close-workspace', '--workspace', entry.ref]);
  delete reg[label];
  regWrite(ctx, reg);
  if (!r.ok) {
    log(`[mux] close 실패 (${label}): ${r.stderr} — 기록만 정리`);
    return { label, killed: false, ref: entry.ref, error: r.stderr };
  }
  log(`[mux] '${label}' 종료 (${entry.ref})`);
  return { label, killed: true, ref: entry.ref };
};

// ── doctor (계약 §2.8) ───────────────────────────────────────
// 실행 파일이 없다는 사실은 fail 이 아니다 — mux 는 선택 기능이고, 없으면
// tab 동사가 exit 3 으로 떨어질 뿐 파이프라인은 그대로 돈다.

const doctor = async (ctx) => {
  const bin = cfgOf(ctx).bin;
  let found = false;
  try { found = runBin(bin, ['--version']).ok; } catch (_) { found = false; }
  return [{ name: bin, ok: true, detail: found ? '실행 가능' : `${bin} 없음 — tab 동사는 exit 3 (선택 기능)` }];
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

module.exports = { id: 'cmux', open, done, kill, verbs, doctor };
