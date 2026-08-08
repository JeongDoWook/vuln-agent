'use strict';

// workspace 프로바이더 — mode: "worktree" (계약 §2.4)
//
// ⚠️ 공유 .git 의 위험 — 이 모드를 고르기 전에 반드시 읽어야 하는 부분이다.
//
//   worktree 는 오브젝트 저장소와 ref 를 소스 저장소 하나에 몰아 쓴다. 작업 파일과
//   체크아웃된 브랜치는 격리되지만(같은 브랜치의 이중 체크아웃은 git 이 막는다),
//   저장소 전역을 건드리는 명령은 모든 워크트리에 동시에 영향을 준다:
//
//     - `git gc` / `git prune`  — 다른 워크트리가 참조 중인 오브젝트를 정리하면서
//                                  긴 stop-the-world 를 유발하고, 최악의 경우
//                                  reflog 만으로 살아 있던 커밋을 날린다.
//     - `git reset --hard`      — 대상 브랜치의 ref 를 옮긴다. 그 브랜치를 보고 있던
//                                  다른 워크트리는 통보 없이 다른 커밋 위에 앉는다.
//     - `git reflog expire`     — 위 두 가지의 복구 수단을 없앤다.
//     - `git config` / hooks    — 전역 설정이라 모든 워크트리가 같이 바뀐다.
//     - repack / fsck 중 손상   — 저장소 하나가 죽으면 모든 세션이 같이 죽는다.
//
//   즉 여기서는 "한 세션의 사고가 다른 세션에 닿지 않는다"는 clone 모드의 보장이
//   성립하지 않는다. 단일 레포 + 대용량 저장소라 clone 비용을 감당할 수 없을 때만
//   선택한다. 병렬 세션을 여러 개 굴리는 것이 목적이라면 clone 을 써라.
//
// 이 모듈은 다른 프로바이더 모듈을 require 하지 않는다(계약 §4). clone.js 와
// 겹치는 경로 조립·상태 파일 로직은 그 금지를 지키기 위한 의도적 중복이다.
//
// 계약 동사만 export 한다. 각 함수는 (args, ctx) => Promise<data>.
//   ctx = { config, repoRoot, log }   log 는 stderr 출력용.

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

// ── 계약 오류 ────────────────────────────────────────────────

const fail = (code, message, exitCode, extra) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (extra) e.data = extra;
  return e;
};

const unsupported = (verb) => fail('unsupported', `workspace(worktree) 는 '${verb}' 를 지원하지 않습니다`, 3);

// ── 인자 읽기 ────────────────────────────────────────────────

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
  // worktree 를 뻗어낼 소스 저장소를 둘 곳. repos[].path 가 있으면 그쪽이 우선이다.
  sourceRoot: '.pipeline/repo-cache',
});

const STAGES = Object.freeze(['SPEC', 'IMPL', 'QA', 'REVIEW', 'PR', 'DONE']);
const STATE_FILE = '.ws-state.json';

const wsConfig = (ctx) => Object.assign({}, WS_DEFAULTS, (ctx.config && ctx.config.workspace) || {});

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
    if (!r.remote && !r.path) throw fail('config', `repos[${r.id}] 에 remote 도 path 도 없습니다`, 1);
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

// 같은 브랜치를 두 번 체크아웃하려 하면 git 이 막는다 — 그건 오류가 아니라 계약이
// 지켜지고 있다는 증거다. 재시도해도 결과가 같으므로 exit 1(재시도 가능)이 아니라
// exit 2(진행하면 안 되는 상태)로 정규화한다.
const DOUBLE_CHECKOUT = /already (checked out|used by (another )?worktree)|is already checked out at/i;

// ── 상태 파일 ────────────────────────────────────────────────

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
  mode: 'worktree',
  stage: state.stage || null,
  repos: (state.repos || []).map((r) => ({ id: r.id, dir: r.dir, branch: r.branch, base: r.base })),
});

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

// ── 소스 저장소 ──────────────────────────────────────────────
// repos[].path 가 있으면 그 로컬 저장소에서 worktree 를 뻗는다. 없으면
// workspace.sourceRoot 아래에 레포당 한 번만 clone 해 두고 재사용한다.

const sourceRepo = (ctx, def) => {
  const log = ctx.log || (() => {});
  if (def.path) {
    const abs = path.resolve(ctx.repoRoot, def.path);
    if (!isGitRepo(abs)) throw fail('config', `repos[${def.id}].path 가 git 저장소가 아닙니다: ${abs}`, 1);
    return abs;
  }

  const cacheRoot = path.resolve(ctx.repoRoot, wsConfig(ctx).sourceRoot);
  const abs = path.join(cacheRoot, def.id);
  if (!isGitRepo(abs)) {
    fs.mkdirSync(cacheRoot, { recursive: true });
    log(`[ws] 소스 저장소 준비: ${def.id} ← ${def.remote}`);
    const c = git(['clone', '--origin', 'origin', def.remote, abs]);
    if (!c.ok) {
      try { fs.rmSync(abs, { recursive: true, force: true }); } catch (_) {}
      throw fail('clone_failed', `소스 저장소 clone 실패 (${def.id}): ${c.stderr || c.stdout}`, 1);
    }
  }
  return abs;
};

// ── create ───────────────────────────────────────────────────

const worktreeRepo = (ctx, def, dirAbs, branch) => {
  const log = ctx.log || (() => {});
  const src = sourceRepo(ctx, def);

  const f = gitIn(src, ['fetch', 'origin', def.base]);
  if (!f.ok) throw fail('fetch_failed', `fetch 실패 (${def.id}/${def.base}): ${f.stderr}`, 1);

  const originRef = `refs/remotes/origin/${def.base}`;
  const baseSha = revParse(src, originRef);
  if (!baseSha) throw fail('not_found', `origin/${def.base} 를 찾을 수 없습니다 (${def.id})`, 1);

  if (isGitRepo(dirAbs)) {
    // 멱등 — 이미 만들어진 워크트리는 다시 만들지 않고 그대로 쓴다.
    log(`[ws] ${def.id}: 기존 워크트리 재사용 (멱등)`);
  } else {
    if (fs.existsSync(dirAbs) && fs.readdirSync(dirAbs).length > 0) {
      throw fail('conflict', `워크트리 경로가 git 저장소가 아닌데 비어 있지도 않습니다: ${dirAbs}`, 1);
    }
    fs.mkdirSync(path.dirname(dirAbs), { recursive: true });
    // 삭제된 워크트리의 잔여 등록 정보가 남아 있으면 add 가 막힌다.
    gitIn(src, ['worktree', 'prune']);

    // 계약 §2.4 보장 ① — origin/{base} 시점에서 생성. 로컬 브랜치 기준 금지.
    const branchExists = gitIn(src, ['show-ref', '--verify', '--quiet', `refs/heads/${branch}`]).ok;
    const addArgs = branchExists
      ? ['worktree', 'add', dirAbs, branch]
      : ['worktree', 'add', '--no-track', '-b', branch, dirAbs, originRef];
    const a = gitIn(src, addArgs);
    if (!a.ok) {
      if (DOUBLE_CHECKOUT.test(a.stderr)) {
        throw fail(
          'branch_in_use',
          `[${def.id}] 브랜치 '${branch}' 는 이미 다른 워크트리가 체크아웃 중입니다 — 같은 브랜치를 두 곳에서 열 수 없습니다: ${a.stderr}`,
          2
        );
      }
      throw fail('worktree_failed', `worktree 생성 실패 (${def.id}/${branch}): ${a.stderr}`, 1);
    }
    log(`[ws] ${def.id}: ${branch} ← origin/${def.base} (${baseSha.slice(0, 12)})`);
  }

  // 계약 §2.4 보장 ② — 생성 직후 HEAD == origin/{base}.
  const head = revParse(dirAbs, 'HEAD');
  if (head !== baseSha) {
    throw fail(
      'head_drift',
      `[${def.id}] HEAD 가 origin/${def.base} 와 다릅니다 — HEAD=${head.slice(0, 12)} origin/${def.base}=${baseSha.slice(0, 12)}`,
      2
    );
  }

  return { id: def.id, dir: toRel(ctx.repoRoot, dirAbs), branch, base: def.base, source: toRel(ctx.repoRoot, src) };
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
    made.push(worktreeRepo(ctx, def, dirAbs, branch));
  }

  const state = writeState(wsRoot, {
    slug,
    issue,
    mode: 'worktree',
    stage: prev.stage || null,
    createdAt: prev.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    repos: kept.concat(made.map((r) => ({ id: r.id, dir: r.dir, branch: r.branch, base: r.base, source: r.source }))),
  });

  return toWorkspace(ctx.repoRoot, wsRoot, state);
};

// ── verify ───────────────────────────────────────────────────
// clone.js 와 같은 판정 기준: 생성 직후엔 HEAD == origin/{base}, 커밋이 쌓인 뒤엔
// origin/{base} 의 자손이어야 한다. 둘 다 아니면 엉뚱한 기준에서 출발한 것이다.

const verifyRepo = (ctx, rec) => {
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

  const checks = (state.repos || []).reduce((acc, rec) => acc.concat(verifyRepo(ctx, rec)), []);
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
    .filter((x) => x.s && x.s.mode === 'worktree')
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

  // 디렉터리를 그냥 지우면 소스 저장소에 죽은 워크트리 등록 정보가 남아, 같은
  // 브랜치를 다시 열 때 "already checked out" 으로 막힌다. remove → prune 순서.
  for (const rec of targets) {
    const dirAbs = path.resolve(ctx.repoRoot, rec.dir);
    const src = rec.source ? path.resolve(ctx.repoRoot, rec.source) : null;
    if (src && isGitRepo(src) && fs.existsSync(dirAbs)) {
      gitIn(src, ['worktree', 'remove', '--force', dirAbs]);
    }
    if (src && isGitRepo(src)) gitIn(src, ['worktree', 'prune']);
  }

  for (const rel of plan) {
    const abs = path.resolve(ctx.repoRoot, rel);
    if (abs !== rootResolved && !abs.startsWith(rootResolved + path.sep)) {
      throw fail('unsafe_path', `workspace.root 밖의 경로는 삭제하지 않습니다: ${rel}`, 2);
    }
    if (abs === rootResolved) throw fail('unsafe_path', 'workspace.root 자체는 삭제하지 않습니다', 2);
    if (!fs.existsSync(abs)) { removed.push(rel); continue; } // worktree remove 가 이미 지운 경우.
    fs.rmSync(abs, { recursive: true, force: true });
    removed.push(rel);
  }

  if (!wholeWs) {
    state.repos = (state.repos || []).filter((r) => !targets.some((t) => t.id === r.id));
    state.updatedAt = new Date().toISOString();
    writeState(wsRoot, state);
  }

  return { removed: removed.filter((r, i) => removed.indexOf(r) === i) };
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
  // 공유 .git 의 위험(파일 상단 주석)은 레포가 여럿일 때 병렬 세션 사고로 이어진다.
  checks.push({
    name: 'single-repo',
    ok: defs.length <= 1,
    detail: defs.length <= 1 ? `repos ${defs.length}개` : `repos 가 ${defs.length}개다 — worktree 는 단일 레포 + 대용량 저장소용이다. clone 모드를 고려해라.`,
  });
  checks.push({ name: 'workspace.root', ok: true, detail: path.resolve(c.repoRoot, wsConfig(c).root) });
  return checks;
};

// ── px.js 접속부 ─────────────────────────────────────────────
// 위의 계약 동사 함수들이 이 모듈의 본체다. index.js 는 `verbs` 표와
// handler(ctx, args, flags) 인자 순서를 쓰므로 여기서 얇게 맞춰만 준다.

const adapt = (fn) => (ctx, args, flags) => fn(
  Object.assign({ _: Array.isArray(args) ? args : [] }, flags || {}),
  {
    config: (ctx && ctx.config) || {},
    repoRoot: (ctx && (ctx.repoRoot || ctx.rootDir)) || process.cwd(),
    log: (ctx && ctx.log) || ((m) => process.stderr.write(`${m}\n`)),
  }
);

// branch 그룹(계약 §2.3)은 clone/worktree 와 무관하게 동작이 같다 — 워크트리도 결국
// origin 을 가진 git 작업 트리다. 공용 중립 모듈을 합친다(계약 §4의 상호 참조 금지는
// 프로바이더 모듈끼리의 이야기다).
const branchVerbs = require('./branch-verbs').verbs;

const verbs = Object.assign({
  'ws.create': adapt(create),
  'ws.verify': adapt(verify),
  'ws.stage': adapt(stage),
  'ws.resolve': adapt(resolve),
  'ws.list': adapt(list),
  'ws.close': adapt(close),
}, branchVerbs);

module.exports = { id: 'worktree', create, verify, stage, resolve, list, close, verbs, doctor, unsupported };
