'use strict';

// branch 그룹 (계약 §2.3) — clone·worktree 공용 구현
//
// branch 동사는 작업 디렉터리가 어떻게 만들어졌는지(clone 인지 worktree 인지)를
// 알 필요가 없다. 둘 다 결국 "origin 을 가진 git 작업 트리" 하나이고, 여기서 하는
// 일은 그 디렉터리에서 fetch·branch·merge·rev-list 를 돌리는 것뿐이다. 그래서
// clone.js / worktree.js 가 각자 구현하지 않고 이 모듈을 verbs 에 합친다.
//
// 이 파일은 프로바이더 모듈이 아니다 — 계약 §4가 금지하는 것은 프로바이더 모듈끼리의
// 상호 참조이고, 공통 로직을 중립 모듈로 빼는 것은 오히려 §4가 지시하는 방향이다.
// 진입점(px.js)·index.js 도 require 하지 않는다.
//
// export 하는 것은 index.js 가 쓰는 동사 맵 형태 그대로다 (계약 §4.1):
//   verbs['branch.<verb>'] = (ctx, args, flags) => Promise<data>
// 예외는 계약 §4.2 형태로 던진다 — 평범한 Error 에 code/exitCode/data 를 얹는다.

const path = require('path');
const cp = require('child_process');

// 대상 레포·디렉터리 해석은 이 모듈이 갖고 있지 않다 — run·release 도 같은 판정을 해야
// 하는데 로직을 두 벌 두면 "작업공간이 아니라 프로젝트 루트에서 돈다"는 결함 클래스가
// 다시 살아난다(kit/workflow/guardrails.md §4). repo-dir.js 는 프로바이더가 아닌
// 중립 모듈이라 여기서 require 해도 계약 §4의 상호 참조 금지에 걸리지 않는다.
const repoDir = require('../repo-dir');

// ── 계약 오류 (§4.2) ─────────────────────────────────────────

const fail = (code, message, exitCode, extra) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (extra) e.data = extra;
  return e;
};

// ── 인자 읽기 ────────────────────────────────────────────────
// px.js 는 --add-labels 를 addLabels 로 정규화한다. 여기서 보는 플래그는 전부
// 한 단어라 변환이 없지만, 값 없는 플래그(--repo 만 쓴 경우)는 true 로 들어오므로
// "값이 있는가"를 한 곳에서 판정한다.

const flagValue = (flags, ...names) => {
  if (!flags) return undefined;
  for (const n of names) {
    const v = flags[n];
    if (v === undefined || v === null || v === true || v === '') continue;
    return String(v);
  }
  return undefined;
};

const arg = (args, i) => (Array.isArray(args) && args[i] !== undefined && args[i] !== '' ? String(args[i]) : undefined);

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

const revParse = (dir, ref) => {
  const r = gitIn(dir, ['rev-parse', ref]);
  return r.ok ? r.stdout : '';
};

const originRefOf = (target) => `refs/remotes/origin/${target}`;

// 같은 브랜치를 두 곳에서 체크아웃하려 하면 git 이 막는다 — 재시도해도 결과가 같으므로
// exit 1(재시도 가능)이 아니라 exit 2(진행하면 안 되는 상태)로 정규화한다.
const DOUBLE_CHECKOUT = /already (checked out|used by (another )?worktree)|is already checked out at/i;

// origin/{target} 을 최신화한다. 이걸 빼먹으면 drift-check 는 오래된 원격 사본과
// 비교하게 되고 **언제나 통과한다** — 이 동사의 존재 이유가 사라진다.
const fetchTarget = (dir, target, repoId, log) => {
  log(`[branch] ${repoId}: fetch origin ${target}`);
  const f = gitIn(dir, ['fetch', '--prune', 'origin', target]);
  if (!f.ok) {
    throw fail('fetch_failed', `[${repoId}] fetch 실패 (origin/${target}): ${f.stderr || f.stdout}`, 1, { repo: repoId, target });
  }
  const sha = revParse(dir, originRefOf(target));
  if (!sha) {
    throw fail('not_found', `[${repoId}] origin/${target} 를 찾을 수 없습니다`, 1, { repo: repoId, target });
  }
  return sha;
};

// ── 대상 레포 판정 ───────────────────────────────────────────
//
// branch 동사는 "어느 디렉터리에서 git 을 돌릴 것인가"를 먼저 정해야 한다. 그 판정은
// run·release 와 **같아야 하므로** repo-dir.js 가 한다. 여기서 고정하는 것은 branch 그룹
// 고유의 세 가지뿐이다:
//   single      — 레포가 여럿인데 --repo 가 없으면 조용히 첫 번째를 고르지 않는다
//   requireGit  — git 을 쏘기 전에 대상이 실재하는 작업 트리인지 먼저 본다(가드레일 §2)
//   dirFallback — 디렉터리를 못 정했으면 현재 위치가 속한 git 작업 트리 최상위
//                 (작업공간 밖에서 체크아웃 안에 들어가 부르는 경우)
const resolveRepo = (ctx, flags, cwd) => repoDir.resolveRepo(ctx, flags, cwd, {
  requireGit: true,
  dirFallback: 'git',
});

// --target 이 있으면 그게 1순위다(사용자가 명시한 값). 없으면 repos[].base.
const resolveTargetBranch = (repo, flags) => {
  const explicit = flagValue(flags, 'target');
  if (explicit) return { target: explicit, reason: '--target' };
  if (!repo.base) {
    throw fail(
      'config',
      `repos[${repo.id}].base 가 없습니다 — 기준 브랜치는 추측하지 않습니다`,
      1,
      { repo: repo.id }
    );
  }
  return { target: repo.base, reason: repo.baseFrom || 'repos[].base' };
};

// ── ctx 정규화 ───────────────────────────────────────────────
// index.js 의 ctx 는 { config, rootDir, ... } 이고 log 가 없다. clone.js 의 adapt 와
// 같은 방식으로 여기서 맞춘다 — log 는 stderr 전용이다(stdout 에 쓰면 봉투가 깨진다).

const logger = (ctx) => (ctx && ctx.log) || ((m) => process.stderr.write(`${m}\n`));

const cwdOf = (flags) => path.resolve(flagValue(flags, 'cwd') || process.cwd());

// ── branch resolve-target (계약 §2.3) ────────────────────────

const resolveTargetVerb = async (ctx, _args, flags) => {
  const repo = resolveRepo(ctx, flags, cwdOf(flags));
  const { target, reason } = resolveTargetBranch(repo, flags);
  return { target, reason };
};

// ── branch new <name> --base <ref> (계약 §2.3) ───────────────
//
// 계약 §2.4 보장 ①과 같은 규칙 — **origin/{base} 시점에서 만든다.** 로컬 {base}
// 브랜치는 clone 시점의 낡은 이력일 수 있고, 그 위에서 구현하면 PR diff 가
// 리뷰에서 본 diff 와 달라진다.

const newVerb = async (ctx, args, flags) => {
  const log = logger(ctx);
  const name = arg(args, 0) || flagValue(flags, 'name');
  if (!name) throw fail('usage', 'branch.new: <name> 인자가 필요합니다', 1);

  const base = flagValue(flags, 'base');
  if (!base) throw fail('usage', `branch.new: --base <ref> 가 필요합니다 (기준 브랜치는 추측하지 않습니다)`, 1);

  const repo = resolveRepo(ctx, flags, cwdOf(flags));

  // 브랜치 이름 검증은 git 에게 맡긴다 — 우리 정규식이 git 규칙보다 정확할 이유가 없다.
  if (!git(['check-ref-format', '--branch', name]).ok) {
    throw fail('usage', `브랜치 이름으로 쓸 수 없습니다: '${name}'`, 1, { name });
  }

  const baseSha = fetchTarget(repo.dir, base, repo.id, log);

  const exists = gitIn(repo.dir, ['show-ref', '--verify', '--quiet', `refs/heads/${name}`]).ok;
  const current = gitIn(repo.dir, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const currentBranch = current.ok ? current.stdout : '';

  if (exists) {
    // 계약 §1 멱등 — 이미 있는 브랜치는 **옮기지 않는다.** 기존 head 를 그대로 돌려준다.
    // 여기서 origin/{base} 로 리셋하면 재실행한 워커가 남의 커밋을 날린다.
    const head = revParse(repo.dir, `refs/heads/${name}`);
    if (currentBranch !== name) {
      const co = gitIn(repo.dir, ['checkout', name]);
      if (!co.ok) {
        if (DOUBLE_CHECKOUT.test(co.stderr)) {
          throw fail('branch_in_use', `[${repo.id}] 브랜치 '${name}' 는 이미 다른 워크트리가 체크아웃 중입니다: ${co.stderr}`, 2, { repo: repo.id, name });
        }
        throw fail('checkout_failed', `[${repo.id}] 기존 브랜치 '${name}' 체크아웃 실패: ${co.stderr || co.stdout}`, 1, { repo: repo.id, name });
      }
    }
    log(`[branch] ${repo.id}: '${name}' 이미 존재 — 기존 head ${head.slice(0, 12)} 유지 (멱등)`);
    return { name, base, head };
  }

  // --no-track: 작업 브랜치는 origin/{base} 를 upstream 으로 삼지 않는다. upstream 이
  // 붙으면 push/pull 이 base 브랜치를 향하게 된다(ws create 와 같은 이유).
  const co = gitIn(repo.dir, ['checkout', '-b', name, '--no-track', originRefOf(base)]);
  if (!co.ok) {
    if (DOUBLE_CHECKOUT.test(co.stderr)) {
      throw fail('branch_in_use', `[${repo.id}] 브랜치 '${name}' 는 이미 다른 워크트리가 체크아웃 중입니다: ${co.stderr}`, 2, { repo: repo.id, name });
    }
    throw fail('branch_failed', `[${repo.id}] 브랜치 생성 실패 ('${name}' ← origin/${base}): ${co.stderr || co.stdout}`, 1, { repo: repo.id, name, base });
  }

  const head = revParse(repo.dir, 'HEAD');
  if (head !== baseSha) {
    // 여기까지 왔는데 다르면 기준이 어긋난 것이다 — 재시도해도 같으므로 exit 2.
    throw fail(
      'head_drift',
      `[${repo.id}] 생성 직후 HEAD 가 origin/${base} 와 다릅니다 — HEAD=${head.slice(0, 12)} origin/${base}=${baseSha.slice(0, 12)}`,
      2,
      { repo: repo.id, name, base, head, baseSha }
    );
  }

  log(`[branch] ${repo.id}: ${name} ← origin/${base} (${baseSha.slice(0, 12)})`);
  return { name, base, head };
};

// ── branch sync (계약 §2.3) ──────────────────────────────────
//
// origin/{target} 을 fetch 한 뒤 **merge** 한다. rebase 는 쓰지 않는다 — 작업 브랜치는
// 이미 공유·푸시됐을 수 있고, 이력을 다시 쓰면 리뷰에서 본 diff 와 PR 의 diff 가 달라진다.
//
// merged 는 "이번 실행에서 merge 를 수행했는가"다. 이미 origin/{target} 을 품고 있으면
// merged:false + conflicts:[] 로 끝난다(= 이미 최신).

const conflictedFiles = (dir) => {
  const r = gitIn(dir, ['diff', '--name-only', '--diff-filter=U']);
  const files = (r.ok ? r.stdout : '').split('\n').map((s) => s.trim()).filter(Boolean);
  return files.filter((f, i) => files.indexOf(f) === i);
};

const syncVerb = async (ctx, _args, flags) => {
  const log = logger(ctx);
  const repo = resolveRepo(ctx, flags, cwdOf(flags));
  const { target } = resolveTargetBranch(repo, flags);

  // 병합 중인 상태에서 또 merge 를 걸면 git 이 막는다. 그 상태를 먼저 알려준다 —
  // 이전 실행의 충돌이 아직 해결되지 않았다는 뜻이다.
  const pending = conflictedFiles(repo.dir);
  if (pending.length > 0) {
    throw fail(
      'merge_conflict',
      `[${repo.id}] 아직 해결되지 않은 병합 충돌이 있습니다 (${pending.length}개):\n  ${pending.join('\n  ')}`,
      2,
      { target, merged: false, conflicts: pending, repo: repo.id }
    );
  }

  const targetSha = fetchTarget(repo.dir, target, repo.id, log);

  // 이미 품고 있으면 merge 를 돌리지 않는다 — 빈 merge 커밋도, 상태 변화도 만들지 않는다.
  if (gitIn(repo.dir, ['merge-base', '--is-ancestor', targetSha, 'HEAD']).ok) {
    log(`[branch] ${repo.id}: 이미 origin/${target} (${targetSha.slice(0, 12)}) 를 포함 — merge 생략`);
    return { target, merged: false, conflicts: [] };
  }

  const m = gitIn(repo.dir, ['merge', '--no-edit', originRefOf(target)]);
  if (m.ok) {
    log(`[branch] ${repo.id}: origin/${target} merge 완료`);
    return { target, merged: true, conflicts: [] };
  }

  const conflicts = conflictedFiles(repo.dir);
  if (conflicts.length > 0) {
    // **merge 를 되돌리지 않는다.** 어느 쪽이 맞는지는 요구사항을 아는 사람만 안다 —
    // abort 하면 그 판단 재료(충돌 마커가 든 작업 사본)가 사라진다. 계약 §1 exit 2.
    throw fail(
      'merge_conflict',
      `[${repo.id}] origin/${target} 병합 충돌 (${conflicts.length}개):\n  ${conflicts.join('\n  ')}`,
      2,
      { target, merged: false, conflicts, repo: repo.id }
    );
  }

  // 충돌이 아닌 실패(더러운 작업 트리 등) — 원인을 고치고 다시 부르면 되므로 exit 1.
  throw fail(
    'merge_failed',
    `[${repo.id}] origin/${target} 병합 실패: ${m.stderr || m.stdout}`,
    1,
    { target, merged: false, conflicts: [], repo: repo.id }
  );
};

// ── branch drift-check (계약 §2.3) ───────────────────────────
//
// behind > 0 이면 drifted:true + exit 2. push·PR 생성으로 진행하면 안 되는 상태다.
// ahead 는 정상이다 — 내가 쌓은 커밋이 곧 이 브랜치의 목적이다.

const driftCheckVerb = async (ctx, _args, flags) => {
  const log = logger(ctx);
  const repo = resolveRepo(ctx, flags, cwdOf(flags));
  const { target } = resolveTargetBranch(repo, flags);

  // fetch 를 먼저 하지 않으면 낡은 원격 사본과 비교하게 되고 언제나 통과한다.
  const targetSha = fetchTarget(repo.dir, target, repo.id, log);

  const counts = gitIn(repo.dir, ['rev-list', '--left-right', '--count', `${targetSha}...HEAD`]);
  if (!counts.ok) {
    throw fail('drift_check_failed', `[${repo.id}] origin/${target} 와 비교 실패: ${counts.stderr || counts.stdout}`, 1, { repo: repo.id, target });
  }
  const [left, right] = counts.stdout.split(/\s+/);
  const behind = Number(left) || 0;   // origin/{target} 에만 있는 커밋 = 내가 못 따라간 것
  const ahead = Number(right) || 0;   // 내 브랜치에만 있는 커밋 = 내 작업

  if (behind > 0) {
    throw fail(
      'drift',
      `[${repo.id}] origin/${target} 가 ${behind}커밋 앞서 있습니다 (내 브랜치 ahead ${ahead}) — 동기화 전에는 push·PR 로 진행하지 않습니다`,
      2,
      { drifted: true, ahead, behind, target, repo: repo.id }
    );
  }

  log(`[branch] ${repo.id}: origin/${target} 대비 ahead ${ahead} / behind 0`);
  return { drifted: false, ahead, behind };
};

// ── 동사 맵 (계약 §4.1) ──────────────────────────────────────
// 키는 `<group>.<verb>` 문자열 그대로다. clone.js / worktree.js 가 자기 verbs 에 spread 한다.

const verbs = {
  'branch.resolve-target': resolveTargetVerb,
  'branch.new': newVerb,
  'branch.sync': syncVerb,
  'branch.drift-check': driftCheckVerb,
};

module.exports = { verbs };
