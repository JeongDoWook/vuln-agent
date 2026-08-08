'use strict';

// 레포 디렉터리 해석 — 중립 공용 모듈
//
// "이 동사가 어느 저장소의, 어느 디렉터리에서 일해야 하는가"를 정하는 곳이다.
// 프로바이더 모듈이 아니다 — 계약 §4가 금지하는 것은 프로바이더끼리의 상호 참조이고,
// 공통 로직을 중립 모듈로 빼는 것은 오히려 §4가 지시하는 방향이다(http.js 와 같은 층).
// 진입점(px.js)·index.js 는 이 파일을 모른다.
//
// **왜 한 곳에 모으는가** (2026-08-07 실측):
//   $ cd wt/0807-relcheck/app-1     # 작업공간 clone 안
//   $ px run build                  → cwd 가 프로젝트 루트였다 (작업공간이어야 했다)
//   $ px release tags               → 태그 3개가 있는데 빈 배열 (프로젝트 루트를 봤다)
// branch 그룹만 올바른 해석을 갖고 있었고 run·release 는 각자 repos[].path 를 프로젝트
// 루트에 붙이고 있었다. 작업공간 격리가 무력해지는 결함이고, 벡터가 모듈마다 하나씩
// 있는 **결함 클래스**다. 한 경로만 고치면 다음 모듈에서 같은 버그가 다시 난다
// (kit/workflow/guardrails.md §4).
//
// 해석 순서:
//   1. cwd 에서 위로 올라가며 `.ws-state.json` 을 찾고, 그 작업공간의 repos[] 를 쓴다
//   2. 없으면 `.pipeline.json` 의 repos[].path (없으면 repos[].dir)
//   3. 그래도 디렉터리를 못 정하면 호출부가 고른 폴백(git 작업 트리 최상위 | 프로젝트 루트)
//   4. base 는 `.pipeline.json` 이 SSOT — 작업공간 상태 파일의 base 는 생성 시점 사본이라
//      그 뒤 설정이 바뀌었으면 낡아 있다
//
// 예외는 계약 §4.2 형태다 — 평범한 Error 에 code/exitCode/data 를 얹어 던진다.

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

// ── 계약 오류 (§4.2) ─────────────────────────────────────────

const fail = (code, message, exitCode, data) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (data !== undefined) e.data = data;
  return e;
};

// ── 플래그 읽기 ──────────────────────────────────────────────
// px.js 는 값 없는 플래그(--repo 만 쓴 경우)를 true 로 준다. "값이 있는가"를 여기서 판정한다.

const flagValue = (flags, ...names) => {
  if (!flags) return undefined;
  for (const n of names) {
    const v = flags[n];
    if (v === undefined || v === null || v === true || v === '') continue;
    return String(v);
  }
  return undefined;
};

// --repo be,fe → ['be','fe']. run 그룹이 쓰던 형태를 모든 그룹에서 같게 만든다.
const wantedIds = (flags) => {
  const raw = flagValue(flags, 'repo');
  if (raw === undefined) return null;
  const ids = raw.split(',').map((s) => s.trim()).filter(Boolean);
  return ids.length ? ids : null;
};

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

const isGitRepo = (dir) => {
  if (!fs.existsSync(dir)) return false;
  return gitIn(dir, ['rev-parse', '--git-dir']).ok;
};

// 계약 §2.3 / kit/workflow/guardrails.md §2 — 부수효과 명령을 쏘기 전에 대상 상태를 먼저 본다.
const requireGitDir = (dir, repoId) => {
  const label = repoId ? `[${repoId}] ` : '';
  if (!fs.existsSync(dir)) {
    throw fail('not_found', `${label}작업 디렉터리가 없습니다: ${dir}`, 1, { repo: repoId, dir });
  }
  if (!isGitRepo(dir)) {
    throw fail('not_found', `${label}git 저장소가 아닙니다: ${dir}`, 1, { repo: repoId, dir });
  }
  return dir;
};

// ── 작업공간 상태 ────────────────────────────────────────────
// clone.js / worktree.js 가 쓰는 것과 같은 파일이다. 그 두 모듈을 require 하면 계약 §4의
// 상호 참조 금지에 걸리므로 읽기 로직만 여기 둔다(쓰지는 않는다).

const STATE_FILE = '.ws-state.json';

const readState = (dir) => {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, STATE_FILE), 'utf8'));
  } catch (_) {
    return null;
  }
};

// cwd 에서 위로 올라가며 작업공간 상태 파일을 찾는다 (ws resolve 와 같은 규칙).
const findWorkspace = (startDir) => {
  let dir = path.resolve(startDir);
  for (;;) {
    const state = readState(dir);
    if (state) return { wsRoot: dir, state };
    const up = path.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
};

// ── 후보 목록 ────────────────────────────────────────────────

const repoRootOf = (ctx) => path.resolve((ctx && (ctx.repoRoot || ctx.rootDir)) || process.cwd());

const configRepos = (ctx) => ((ctx && ctx.config && Array.isArray(ctx.config.repos)) ? ctx.config.repos : []);

const contains = (parent, child) => {
  if (!parent) return false;
  const p = path.resolve(parent);
  const c = path.resolve(child);
  return c === p || c.startsWith(p + path.sep);
};

// 설정 항목이 알려주는 디렉터리. path 를 먼저 보고 dir 을 폴백으로 본다 —
// 두 이름이 모듈마다 다르게 쓰이고 있었다(release 는 dir||path, branch 는 path).
const configDir = (root, r) => {
  const rel = r && (r.path || r.dir);
  return rel ? path.resolve(root, rel) : null;
};

// items[].config 는 .pipeline.json 의 repos[] 원본이다. project(gitlab/github)·stack(run)처럼
// 디렉터리와 무관한 사실은 호출부가 여기서 읽는다 — 필드를 이 모듈이 하나씩 알 필요가 없다.
const candidateRepos = (ctx, cwd) => {
  const root = repoRootOf(ctx);
  const cfg = configRepos(ctx);
  const byId = (id) => cfg.find((r) => r.id === id);

  const ws = findWorkspace(cwd === undefined ? process.cwd() : cwd);
  if (ws && Array.isArray(ws.state.repos) && ws.state.repos.length > 0) {
    return {
      source: `작업공간 ${ws.state.slug || path.basename(ws.wsRoot)}`,
      items: ws.state.repos.map((r) => {
        const c = byId(r.id) || {};
        return {
          id: r.id,
          dir: path.resolve(root, r.dir),
          // base 는 .pipeline.json 이 SSOT다. 작업공간 상태 파일의 값은 생성 시점 사본이라
          // 그 뒤 설정이 바뀌었으면 낡아 있다.
          base: c.base || r.base || null,
          baseFrom: c.base ? 'repos[].base' : (r.base ? '작업공간 상태 파일' : null),
          config: c,
        };
      }),
    };
  }

  return {
    source: '.pipeline.json repos[]',
    items: cfg.map((r) => ({
      id: r.id,
      dir: configDir(root, r),
      base: r.base || null,
      baseFrom: r.base ? 'repos[].base' : null,
      config: r,
    })),
  };
};

// ── 해석 ─────────────────────────────────────────────────────
//
// opts:
//   single       true 면 반드시 하나만 고른다. --repo 가 없고 후보가 여럿이면
//                **조용히 첫 번째를 고르지 않고** 멈춘다 — 어느 레포에 무엇을 할지
//                틀리면 "한 브랜치를 병합해놓고 다른 브랜치로 PR 을 여는" 사고가 난다.
//                false 면 --repo 없을 때 전부를 돌려준다(run 의 test/build 처럼
//                "전 레포 대상"이 정상 동작인 동사용).
//   requireGit   대상 디렉터리가 실재하는 git 작업 트리인지 먼저 확인한다.
//   allowEmpty   repos[] 가 비어도 에러 대신 { id: null, dir: <폴백> } 하나를 준다
//                (repos[] 없이 굴리는 단일 레포 프로젝트).
//   dirFallback  후보가 디렉터리를 모를 때 무엇으로 떨어질지.
//                'root' = 프로젝트 루트 · 'git' = cwd 가 속한 git 작업 트리 최상위.

const DEFAULTS = { single: false, requireGit: false, allowEmpty: false, dirFallback: 'root' };

const resolveDir = (entry, ctx, cwd, o) => {
  if (entry.dir) return entry.dir;
  if (o.dirFallback === 'git') {
    const top = gitIn(cwd, ['rev-parse', '--show-toplevel']);
    if (!top.ok) {
      throw fail(
        'not_found',
        `${entry.id ? `[${entry.id}] ` : ''}작업 디렉터리를 찾을 수 없습니다 — repos[].path 를 적거나 해당 체크아웃 안에서 실행해라 (현재: ${cwd})`,
        1,
        { repo: entry.id, cwd }
      );
    }
    return path.resolve(top.stdout);
  }
  return repoRootOf(ctx);
};

const finish = (entry, ctx, cwd, o, source) => {
  const dir = resolveDir(entry, ctx, cwd, o);
  if (o.requireGit) requireGitDir(dir, entry.id);
  return {
    id: entry.id,
    dir,
    base: entry.base || null,
    baseFrom: entry.baseFrom || null,
    config: entry.config || {},
    source,
  };
};

const resolveRepos = (ctx, flags, cwd, opts) => {
  const o = Object.assign({}, DEFAULTS, opts || {});
  const at = path.resolve(cwd === undefined ? process.cwd() : cwd);
  const { source, items } = candidateRepos(ctx, at);
  const ids = items.map((r) => r.id);

  if (items.length === 0) {
    if (!o.allowEmpty) {
      throw fail('config', '.pipeline.json 에 repos[] 가 없습니다 — 어느 저장소를 다룰지 알 수 없습니다', 1);
    }
    return [finish({ id: null, dir: null, config: {} }, ctx, at, o, source)];
  }

  const wanted = wantedIds(flags);
  let picked;
  if (wanted) {
    picked = wanted.map((id) => {
      const hit = items.find((r) => r.id === id);
      if (!hit) {
        throw fail('config', `${source} 에 없는 repo: '${id}' (사용 가능: ${ids.join(', ')})`, 1, { repo: id, available: ids });
      }
      return hit;
    });
    if (o.single && picked.length > 1) {
      throw fail('usage', `이 동사는 레포 하나만 다룬다 — --repo 에 ${picked.length}개를 줬다 (${wanted.join(', ')})`, 1, { available: ids });
    }
  } else if (items.length === 1) {
    picked = [items[0]];
  } else if (o.single) {
    // 현재 위치가 어느 레포 디렉터리 안이면 그걸로 추론한다. 아니면 묻지 말고 멈춘다.
    const inside = items.find((r) => r.dir && contains(r.dir, at));
    if (!inside) {
      throw fail(
        'usage',
        `repos 가 ${items.length}개입니다 — --repo <id> 로 지정해라 (${ids.join(', ')})`,
        1,
        { available: ids }
      );
    }
    picked = [inside];
  } else {
    picked = items;
  }

  return picked.map((r) => finish(r, ctx, at, o, source));
};

const resolveRepo = (ctx, flags, cwd, opts) => resolveRepos(ctx, flags, cwd, Object.assign({}, opts, { single: true }))[0];

module.exports = { findWorkspace, candidateRepos, resolveRepo, resolveRepos };
