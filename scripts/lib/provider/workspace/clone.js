'use strict';

// workspace 프로바이더 — mode: "clone" (계약 §2.4의 기본값)
//
// 레포마다 독립된 .git 을 만든다. 한 세션의 `git reset --hard`·`gc`·reflog 조작이
// 다른 세션에 절대 닿지 않는 것이 이 모드의 존재 이유다. 디스크와 clone 시간을
// 대가로 지불하고 완전 격리를 산다.
//
// 이 모듈은 다른 프로바이더 모듈을 require 하지 않는다(계약 §4). 그래서
// worktree.js 와 경로 조립·상태 파일 로직이 일부 겹친다 — 계약이 금지한
// 상호 참조를 피하기 위한 의도적 중복이다.
//
// 계약 동사만 export 한다. 각 함수는 (args, ctx) => Promise<data>.
//   ctx = { config, repoRoot, log }   log 는 stderr 출력용.

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

// ── 계약 오류 ────────────────────────────────────────────────
// exitCode 는 계약 §1의 종료 코드와 1:1 대응한다. px.js 가 이 값을 읽는다.

const fail = (code, message, exitCode, extra) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (extra) e.data = extra;
  return e;
};

const unsupported = (verb) => fail('unsupported', `workspace(clone) 는 '${verb}' 를 지원하지 않습니다`, 3);

// ── 인자 읽기 ────────────────────────────────────────────────
// px.js 의 파서 형태를 단정하지 않는다. 위치 인자는 배열 자체 · `_` · `positional`
// · `args` 중 어느 형태로 와도 받고, 플래그는 kebab/camel 양쪽 이름을 본다.

const positionals = (args) => {
  if (!args) return [];
  if (Array.isArray(args)) return args.slice();
  for (const k of ['_', 'positional', 'positionals', 'args']) {
    if (Array.isArray(args[k])) return args[k].slice();
  }
  return [];
};

const flag = (args, ...names) => {
  if (!args || Array.isArray(args)) return undefined;
  for (const n of names) if (args[n] !== undefined) return args[n];
  return undefined;
};

const truthy = (v) => v === true || v === 'true' || v === 1 || v === '1' || v === 'yes';

const csv = (v) => (v === undefined || v === null || v === '')
  ? []
  : String(v).split(',').map((s) => s.trim()).filter(Boolean);

// ── 설정 ─────────────────────────────────────────────────────

const WS_DEFAULTS = Object.freeze({
  root: 'wt',
  dirPattern: '{MMDD}-{slug}',
  repoDirPattern: '{repo}-{issue}',
  branchPattern: 'feature/issue-{issue}-{slug}',
});

const STAGES = Object.freeze(['SPEC', 'IMPL', 'QA', 'REVIEW', 'PR', 'DONE']);
const STATE_FILE = '.ws-state.json';

const wsConfig = (ctx) => Object.assign({}, WS_DEFAULTS, (ctx.config && ctx.config.workspace) || {});

// 프로젝트 고유 사실(레포 이름·remote·base)은 전부 .pipeline.json 에서 온다.
// 이 파일에는 어떤 레포 이름도 하드코딩하지 않는다.
const repoDefs = (ctx, filter) => {
  const all = (ctx.config && Array.isArray(ctx.config.repos)) ? ctx.config.repos : [];
  if (all.length === 0) throw fail('config', '.pipeline.json 에 repos[] 가 없습니다', 1);
  const wanted = csv(filter);
  const picked = wanted.length === 0 ? all : wanted.map((id) => {
    const r = all.find((x) => x.id === id);
    if (!r) throw fail('config', `.pipeline.json repos[] 에 없는 repo: '${id}'`, 1);
    return r;
  });
  for (const r of picked) {
    if (!r.base) throw fail('config', `repos[${r.id}].base 가 없습니다 — 기준 브랜치는 추측하지 않습니다`, 1);
    if (!r.remote) throw fail('config', `repos[${r.id}].remote 가 없습니다 (clone 모드 필수)`, 1);
  }
  return picked;
};

// ── 경로 조립 ────────────────────────────────────────────────

const mmdd = () => {
  const d = new Date();
  return String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
};

const render = (pattern, vars) => String(pattern).replace(
  /\{(\w+)\}/g,
  (m, k) => (vars[k] === undefined || vars[k] === null ? m : String(vars[k]))
);

// slug/issue 가 경로 구분자를 품으면 workspace.root 밖으로 탈출한다. 삭제 동사가
// 있는 프로바이더라서 여기서 막는다.
const assertToken = (name, value) => {
  const s = String(value);
  if (!s) throw fail('usage', `${name} 가 비어 있습니다`, 1);
  if (/[\\/]|(^|[\\/])\.\.($|[\\/])/.test(s)) {
    throw fail('usage', `${name} 에 경로 구분자를 쓸 수 없습니다: '${s}'`, 1);
  }
  return s;
};

const toRel = (repoRoot, abs) => path.relative(repoRoot, abs).split(path.sep).join('/');

// ── git ──────────────────────────────────────────────────────

const git = (args, opts) => {
  const r = cp.spawnSync('git', args, Object.assign({ encoding: 'utf8' }, opts || {}));
  if (r.error) {
    return { ok: false, status: null, stdout: '', stderr: r.error.message, missing: r.error.code === 'ENOENT' };
  }
  return {
    ok: r.status === 0,
    status: r.status,
    stdout: (r.stdout || '').trim(),
    stderr: (r.stderr || '').trim(),
    missing: false,
  };
};

const gitIn = (dir, args, opts) => git(['-C', dir].concat(args), opts);

const isGitRepo = (dir) => fs.existsSync(path.join(dir, '.git')) && gitIn(dir, ['rev-parse', '--git-dir']).ok;

const revParse = (dir, ref) => {
  const r = gitIn(dir, ['rev-parse', ref]);
  return r.ok ? r.stdout : '';
};

// ── 상태 파일 ────────────────────────────────────────────────
// ws stage 가 기록하는 곳이자 verify/resolve/list/close 가 읽는 유일한 출처.
// 작업공간 루트에 두는 이유: 작업 디렉터리를 통째로 지우면 상태도 같이 사라져
// 고아 레코드가 남지 않는다.

const statePath = (wsRoot) => path.join(wsRoot, STATE_FILE);

const readState = (wsRoot) => {
  try {
    return JSON.parse(fs.readFileSync(statePath(wsRoot), 'utf8'));
  } catch (_) {
    return null;
  }
};

const writeState = (wsRoot, state) => {
  fs.mkdirSync(wsRoot, { recursive: true });
  fs.writeFileSync(statePath(wsRoot), JSON.stringify(state, null, 2) + '\n');
  return state;
};

const toWorkspace = (repoRoot, wsRoot, state) => ({
  slug: state.slug,
  issue: state.issue,
  root: toRel(repoRoot, wsRoot),
  mode: 'clone',
  stage: state.stage || null,
  repos: (state.repos || []).map((r) => ({ id: r.id, dir: r.dir, branch: r.branch, base: r.base })),
});

// slug → 작업공간 루트. dirPattern 에 {MMDD} 가 들어가면 오늘 날짜로는 어제 만든
// 작업공간을 못 찾는다. 그래서 패턴 조립으로 먼저 시도하고, 없으면 root 를 훑어
// 상태 파일의 slug 로 찾는다.
const findWsRoot = (ctx, slug) => {
  const cfg = wsConfig(ctx);
  const root = path.resolve(ctx.repoRoot, cfg.root);
  const guess = path.join(root, render(cfg.dirPattern, { MMDD: mmdd(), slug, issue: '', repo: '' }));
  if (fs.existsSync(statePath(guess))) return guess;

  if (!fs.existsSync(root)) return null;
  const hits = fs.readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => path.join(root, e.name))
    .filter((d) => {
      const s = readState(d);
      return s && s.slug === slug;
    });
  if (hits.length > 1) {
    throw fail('ambiguous', `slug '${slug}' 에 해당하는 작업공간이 ${hits.length}개입니다: ${hits.map((h) => path.basename(h)).join(', ')}`, 1);
  }
  return hits[0] || null;
};

const requireWsRoot = (ctx, slug) => {
  const found = findWsRoot(ctx, slug);
  if (!found) throw fail('not_found', `작업공간을 찾을 수 없습니다: '${slug}'`, 1);
  return found;
};

// ── create ───────────────────────────────────────────────────

const clonedRepo = (ctx, def, wsRoot, dirAbs, branch) => {
  const log = ctx.log || (() => {});

  if (!isGitRepo(dirAbs)) {
    if (fs.existsSync(dirAbs) && fs.readdirSync(dirAbs).length > 0) {
      throw fail('conflict', `작업 디렉터리가 git 저장소가 아닌데 비어 있지도 않습니다: ${dirAbs}`, 1);
    }
    fs.mkdirSync(path.dirname(dirAbs), { recursive: true });
    log(`[ws] clone ${def.id}: ${def.remote}`);
    const c = git(['clone', '--origin', 'origin', def.remote, dirAbs]);
    if (!c.ok) {
      // 부분 생성된 디렉터리를 남기면 다음 실행이 "git 저장소 아님"으로 막힌다.
      try { fs.rmSync(dirAbs, { recursive: true, force: true }); } catch (_) {}
      throw fail('clone_failed', `clone 실패 (${def.id}): ${c.stderr || c.stdout}`, 1);
    }
  } else {
    log(`[ws] ${def.id}: 기존 작업 디렉터리 재사용 (멱등)`);
  }

  // 로컬 브랜치가 아니라 원격 시점을 기준으로 삼기 위해 항상 fetch 부터.
  const f = gitIn(dirAbs, ['fetch', 'origin', def.base]);
  if (!f.ok) throw fail('fetch_failed', `fetch 실패 (${def.id}/${def.base}): ${f.stderr}`, 1);

  const originRef = `refs/remotes/origin/${def.base}`;
  const baseSha = revParse(dirAbs, originRef);
  if (!baseSha) throw fail('not_found', `origin/${def.base} 를 찾을 수 없습니다 (${def.id})`, 1);

  const current = gitIn(dirAbs, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const currentBranch = current.ok ? current.stdout : '';

  if (currentBranch === branch) {
    log(`[ws] ${def.id}: 이미 ${branch} — 브랜치 생성 생략`);
  } else {
    // 계약 §2.4 보장 ① — origin/{base} 시점에서 생성한다. 로컬 {base} 브랜치를
    // 기준으로 잡으면 clone 시점 기본 브랜치의 오래된 이력에서 출발할 수 있다.
    // --no-track: 이 브랜치는 origin/{base} 를 upstream 으로 삼지 않는다.
    const b = gitIn(dirAbs, ['checkout', '-B', branch, '--no-track', originRef]);
    if (!b.ok) throw fail('branch_failed', `브랜치 생성 실패 (${def.id}/${branch}): ${b.stderr}`, 1);
    log(`[ws] ${def.id}: ${branch} ← origin/${def.base} (${baseSha.slice(0, 12)})`);
  }

  // 계약 §2.4 보장 ② — 생성 직후 HEAD == origin/{base}. 다르면 계약 위반이므로
  // exit 2 다(재시도해도 같은 결과라서 exit 1 이 아니다).
  const head = revParse(dirAbs, 'HEAD');
  if (head !== baseSha) {
    throw fail(
      'head_drift',
      `[${def.id}] HEAD 가 origin/${def.base} 와 다릅니다 — HEAD=${head.slice(0, 12)} origin/${def.base}=${baseSha.slice(0, 12)}`,
      2
    );
  }

  return { id: def.id, dir: toRel(ctx.repoRoot, dirAbs), branch, base: def.base, baseSha, head };
};

const create = async (args, ctx) => {
  const pos = positionals(args);
  const slug = assertToken('slug', pos[0] || flag(args, 'slug') || '');
  const issue = assertToken('--issue', flag(args, 'issue') || '');
  const cfg = wsConfig(ctx);
  const defs = repoDefs(ctx, flag(args, 'repo', 'repos'));

  const wsRoot = path.resolve(ctx.repoRoot, cfg.root, render(cfg.dirPattern, { MMDD: mmdd(), slug, issue }));
  fs.mkdirSync(wsRoot, { recursive: true });

  const prev = readState(wsRoot) || {};
  const kept = (prev.repos || []).filter((r) => !defs.some((d) => d.id === r.id));
  const made = [];

  for (const def of defs) {
    const vars = { MMDD: mmdd(), slug, issue, repo: def.id };
    const dirAbs = path.join(wsRoot, render(cfg.repoDirPattern, vars));
    const branch = render(cfg.branchPattern, vars);
    made.push(clonedRepo(ctx, def, wsRoot, dirAbs, branch));
  }

  const state = writeState(wsRoot, {
    slug,
    issue,
    mode: 'clone',
    stage: prev.stage || null,
    createdAt: prev.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    repos: kept.concat(made.map((r) => ({ id: r.id, dir: r.dir, branch: r.branch, base: r.base }))),
  });

  return toWorkspace(ctx.repoRoot, wsRoot, state);
};

// ── verify ───────────────────────────────────────────────────
//
// create 직후에는 HEAD == origin/{base} 다. 하지만 작업이 시작되면 커밋이 쌓여
// 그 등식은 깨진다 — 그때도 지켜야 하는 불변식은 "이 브랜치가 origin/{base} 에서
// 뻗어 나왔는가" 다. 두 경우를 같은 체크 이름(head-matches-origin)으로 다룬다.
// 등식이 깨졌는데 조상 관계도 아니면 = 엉뚱한 기준에서 출발했다는 뜻이라 exit 2.

const verifyRepo = (ctx, wsRoot, rec) => {
  const dirAbs = path.resolve(ctx.repoRoot, rec.dir);
  const checks = [];
  const add = (name, ok, detail) => checks.push(Object.assign({ name: `${rec.id}:${name}`, ok }, detail || {}));

  if (!fs.existsSync(dirAbs)) { add('dir-exists', false, { dir: rec.dir }); return checks; }
  add('dir-exists', true, { dir: rec.dir });

  if (!isGitRepo(dirAbs)) { add('git-repo', false); return checks; }
  add('git-repo', true);

  const cur = gitIn(dirAbs, ['rev-parse', '--abbrev-ref', 'HEAD']);
  add('branch-matches', cur.ok && cur.stdout === rec.branch, { expected: rec.branch, actual: cur.ok ? cur.stdout : null });

  const baseSha = revParse(dirAbs, `refs/remotes/origin/${rec.base}`);
  if (!baseSha) { add('head-matches-origin', false, { reason: `origin/${rec.base} 없음` }); return checks; }

  const head = revParse(dirAbs, 'HEAD');
  const descends = gitIn(dirAbs, ['merge-base', '--is-ancestor', baseSha, 'HEAD']).ok;
  add('head-matches-origin', head === baseSha || descends, {
    head: head.slice(0, 12),
    origin: baseSha.slice(0, 12),
    relation: head === baseSha ? 'equal' : (descends ? 'descends' : 'diverged'),
  });

  return checks;
};

const verify = async (args, ctx) => {
  const pos = positionals(args);
  const slug = assertToken('slug', pos[0] || flag(args, 'slug') || '');
  const wsRoot = requireWsRoot(ctx, slug);
  const state = readState(wsRoot);

  const checks = (state.repos || []).reduce((acc, rec) => acc.concat(verifyRepo(ctx, wsRoot, rec)), []);
  const ok = checks.every((c) => c.ok);
  if (!ok) {
    const bad = checks.filter((c) => !c.ok).map((c) => c.name).join(', ');
    throw fail('verify_failed', `작업공간 검증 실패 (${slug}): ${bad}`, 2, { ok: false, checks });
  }
  return { ok: true, checks };
};

// ── stage ────────────────────────────────────────────────────

const stage = async (args, ctx) => {
  const pos = positionals(args);
  const slug = assertToken('slug', pos[0] || flag(args, 'slug') || '');
  const raw = pos[1] || flag(args, 'stage') || '';
  const next = String(raw).toUpperCase();
  if (!STAGES.includes(next)) {
    throw fail('usage', `알 수 없는 STAGE: '${raw}' (${STAGES.join('|')})`, 1);
  }

  const wsRoot = requireWsRoot(ctx, slug);
  const state = readState(wsRoot);
  // 멱등 — 같은 STAGE 를 다시 기록해도 성공이고 결과가 같다.
  state.stage = next;
  state.updatedAt = new Date().toISOString();
  writeState(wsRoot, state);
  return toWorkspace(ctx.repoRoot, wsRoot, state);
};

// ── resolve ──────────────────────────────────────────────────

const resolve = async (args, ctx) => {
  const start = path.resolve(String(flag(args, 'cwd') || positionals(args)[0] || process.cwd()));
  let dir = start;
  for (;;) {
    if (fs.existsSync(statePath(dir))) {
      const state = readState(dir);
      if (state) return toWorkspace(ctx.repoRoot, dir, state);
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  throw fail('not_found', `현재 디렉터리가 속한 작업공간이 없습니다: ${start}`, 1);
};

// ── list ─────────────────────────────────────────────────────

const list = async (_args, ctx) => {
  const root = path.resolve(ctx.repoRoot, wsConfig(ctx).root);
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => path.join(root, e.name))
    .map((d) => ({ d, s: readState(d) }))
    .filter((x) => x.s && x.s.mode === 'clone')
    .map((x) => toWorkspace(ctx.repoRoot, x.d, x.s));
};

// ── close ────────────────────────────────────────────────────

const close = async (args, ctx) => {
  const pos = positionals(args);
  const slug = assertToken('slug', pos[0] || flag(args, 'slug') || '');
  const filter = csv(flag(args, 'repo', 'repos'));
  const wsRoot = requireWsRoot(ctx, slug);
  const state = readState(wsRoot);

  const targets = (state.repos || []).filter((r) => filter.length === 0 || filter.includes(r.id));
  if (filter.length > 0 && targets.length === 0) {
    throw fail('not_found', `작업공간 '${slug}' 에 repo 가 없습니다: ${filter.join(',')}`, 1);
  }
  const wholeWs = targets.length === (state.repos || []).length;
  const plan = targets.map((r) => r.dir).concat(wholeWs ? [toRel(ctx.repoRoot, wsRoot)] : []);

  // 계약 §1 — 파괴적 동사는 --yes 없이 실행하지 않고, 무엇을 지울지 알린 뒤 exit 2.
  if (!truthy(flag(args, 'yes', 'y'))) {
    throw fail(
      'confirmation_required',
      `--yes 가 없어 삭제하지 않았습니다. 삭제 대상:\n  ${plan.join('\n  ')}`,
      2,
      { wouldRemove: plan, removed: [] }
    );
  }

  const rootResolved = path.resolve(ctx.repoRoot, wsConfig(ctx).root);
  const removed = [];
  for (const rel of plan) {
    const abs = path.resolve(ctx.repoRoot, rel);
    // 안전 가드 — workspace.root 밖은 어떤 이유로도 지우지 않는다.
    if (abs !== rootResolved && !abs.startsWith(rootResolved + path.sep)) {
      throw fail('unsafe_path', `workspace.root 밖의 경로는 삭제하지 않습니다: ${rel}`, 2);
    }
    if (abs === rootResolved) throw fail('unsafe_path', 'workspace.root 자체는 삭제하지 않습니다', 2);
    if (!fs.existsSync(abs)) continue; // 멱등 — 이미 지워졌으면 성공.
    fs.rmSync(abs, { recursive: true, force: true });
    removed.push(rel);
  }

  if (!wholeWs) {
    state.repos = (state.repos || []).filter((r) => !targets.some((t) => t.id === r.id));
    state.updatedAt = new Date().toISOString();
    writeState(wsRoot, state);
  }

  return { removed };
};

// ── doctor (계약 §2.8) ───────────────────────────────────────

const doctor = async (ctx) => {
  const c = { config: (ctx && ctx.config) || {}, repoRoot: (ctx && (ctx.repoRoot || ctx.rootDir)) || process.cwd() };
  const checks = [];
  const g = git(['--version']);
  checks.push({ name: 'git', ok: g.ok, detail: g.ok ? g.stdout : 'git 실행 파일 없음' });
  let defs = [];
  try { defs = repoDefs(c); checks.push({ name: 'repos', ok: true, detail: defs.map((r) => r.id).join(', ') }); }
  catch (e) { checks.push({ name: 'repos', ok: false, detail: e.message }); }
  for (const r of defs) {
    checks.push({ name: `repos.${r.id}.remote`, ok: Boolean(r.remote), detail: r.remote || 'remote 없음 (clone 모드 필수)' });
  }
  checks.push({ name: 'workspace.root', ok: true, detail: path.resolve(c.repoRoot, wsConfig(c).root) });
  return checks;
};

// ── px.js 접속부 ─────────────────────────────────────────────
// 위의 계약 동사 함수들이 이 모듈의 본체다. index.js 는 `verbs` 표와
// handler(ctx, args, flags) 인자 순서를 쓰므로 여기서 얇게 맞춰만 준다 —
// 어댑터가 하는 일은 인자 재배열과 ctx 키 이름 정규화뿐이다.

const adapt = (fn) => (ctx, args, flags) => fn(
  Object.assign({ _: Array.isArray(args) ? args : [] }, flags || {}),
  {
    config: (ctx && ctx.config) || {},
    repoRoot: (ctx && (ctx.repoRoot || ctx.rootDir)) || process.cwd(),
    log: (ctx && ctx.log) || ((m) => process.stderr.write(`${m}\n`)),
  }
);

// branch 그룹(계약 §2.3)은 clone/worktree 와 무관하게 동작이 같다 — 둘 다 origin 을 가진
// git 작업 트리 하나다. 그래서 공용 모듈을 합친다. branch-verbs.js 는 프로바이더 모듈이
// 아니라 중립 모듈이므로 계약 §4의 상호 참조 금지에 걸리지 않는다.
const branchVerbs = require('./branch-verbs').verbs;

const verbs = Object.assign({
  'ws.create': adapt(create),
  'ws.verify': adapt(verify),
  'ws.stage': adapt(stage),
  'ws.resolve': adapt(resolve),
  'ws.list': adapt(list),
  'ws.close': adapt(close),
}, branchVerbs);

module.exports = { id: 'clone', create, verify, stage, resolve, list, close, verbs, doctor, unsupported };
