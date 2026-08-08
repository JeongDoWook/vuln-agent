'use strict';

// release 프로바이더 — mode: "git" (계약 §2.9의 기본값)
//
// 트래커가 없어도 태그는 만들 수 있다. 그게 이 프로바이더가 기본값인 이유다 —
// GitLab/GitHub 토큰을 아직 안 붙인 프로젝트도 `release tag` 까지는 돌아야 한다.
//
// git 자체에는 **릴리스 노트라는 개념이 없다.** 태그 annotation 은 태그의 일부라
// 수명이 다르고, 본문을 따로 고칠 방법도 없다. 그래서 `release publish` / `release get`
// 은 흉내내지 않고 계약 §2.9 대로 exit 3 을 준다 — 스킬이 그때 GitLab/GitHub 로
// 폴백하거나 사용자에게 수동 처리를 요청한다.
//
// gitlab.js·github.js 를 require 하지 않는다(계약 §4). semver 비교기가 세 파일에
// 중복되는 것은 그 금지를 지키기 위한 의도적 중복이다(clone.js/worktree.js 와 같은 이유).

const cp = require('child_process');

// 어느 레포 디렉터리에서 태그를 읽고 만들지는 repo-dir.js 가 정한다. 이 모듈이
// repos[].path 를 프로젝트 루트에 붙이고 있었기 때문에 **작업공간 안에서 부른
// `release tags` 가 프로젝트 루트의 태그를 봤다**(2026-08-07 실측 — 태그 3개가
// 있는데 빈 배열이 나왔다). branch·run 도 같은 판정을 해야 하므로 중립 모듈
// 한 곳에 모은다(가드레일 §4). 프로바이더 모듈이 아니라 계약 §4에 걸리지 않는다.
const repoDir = require('../repo-dir');

const fail = (code, message, exitCode, data) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (data !== undefined) e.data = data;
  return e;
};

const log = (m) => process.stderr.write(`${m}\n`);

const unsupported = (verbKey) => fail(
  'unsupported',
  `release(git) 는 '${verbKey}' 를 지원하지 않는다 — git 에는 릴리스 노트 개념이 없다(계약 §2.9). 릴리스가 필요하면 providers.release 를 gitlab|github 으로 바꿔라.`,
  3,
);

// ── semver 비교 ──────────────────────────────────────────────
// 계약 §2.9 — `release tags` 는 버전 내림차순이다. 문자열 정렬이면 1.9.0 이 1.10.0 보다
// 뒤에 온다("9" > "1"). 그래서 숫자로 비교한다.
// v 접두사는 **비교할 때만** 떼고 name 에는 반영하지 않는다(계약이 명시).
const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseSemver(name) {
  const m = SEMVER.exec(String(name || '').trim());
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || null };
}

// 프리릴리스 비교(semver.org §11): 프리릴리스가 있으면 정식보다 낮다.
function comparePre(a, b) {
  if (a === b) return 0;
  if (a === null) return 1;    // 정식 > 프리릴리스
  if (b === null) return -1;
  const A = a.split('.');
  const B = b.split('.');
  for (let i = 0; i < Math.max(A.length, B.length); i += 1) {
    const x = A[i];
    const y = B[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) { if (+x !== +y) return +x - +y; continue; }
    if (nx !== ny) return nx ? -1 : 1;   // 숫자 식별자가 문자보다 낮다
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// 내림차순 비교기. semver 가 아닌 태그는 **죽지 않고 뒤로** 보낸다 —
// nightly-20260807 같은 태그가 섞여 있다고 목록 전체가 실패하면 안 된다.
function byVersionDesc(a, b) {
  const pa = parseSemver(a.name);
  const pb = parseSemver(b.name);
  if (pa && !pb) return -1;
  if (!pa && pb) return 1;
  if (!pa && !pb) return String(b.name).localeCompare(String(a.name));
  if (pa.major !== pb.major) return pb.major - pa.major;
  if (pa.minor !== pb.minor) return pb.minor - pa.minor;
  if (pa.patch !== pb.patch) return pb.patch - pa.patch;
  return -comparePre(pa.pre, pb.pre);
}

// ── git ──────────────────────────────────────────────────────
function git(cwd, args) {
  const r = cp.spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (r.error) {
    if (r.error.code === 'ENOENT') throw fail('not_found', 'git 실행 파일을 찾을 수 없다.', 1);
    throw fail('spawn_failed', `git ${args.join(' ')} 실패: ${r.error.message}`, 1);
  }
  return { ok: r.status === 0, status: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
}

function gitOrThrow(cwd, args, code) {
  const r = git(cwd, args);
  if (!r.ok) throw fail(code || 'git_failed', `git ${args.join(' ')} → ${r.stderr || r.stdout || `exit ${r.status}`}`, 1);
  return r;
}

// 대상 레포. 현재 위치가 작업공간 안이면 **그 작업공간의** 레포 디렉터리, 아니면
// repos[].path, 그것도 없으면 .pipeline.json 이 있는 곳.
// release 는 여러 레포를 한 번에 태깅하지 않는다 — 레포마다 버전이 다를 수 있고,
// 한 곳만 실패했을 때 "절반만 태그된" 상태를 만들면 되돌릴 방법이 없다. 그래서
// single: true 다(--repo 없이 레포가 여럿이면 멈춘다).
// allowEmpty: repos[] 없이 굴리는 단일 레포 프로젝트도 태그는 만들 수 있어야 한다.
function targetRepo(ctx, flags) {
  const r = repoDir.resolveRepo(ctx, flags, process.cwd(), {
    requireGit: true,
    allowEmpty: true,
    dirFallback: 'root',
  });
  return { id: r.id, dir: r.dir };
}

// for-each-ref 한 번으로 이름·타입·sha·메시지·날짜를 다 받는다.
// %(*objectname) 은 annotated 태그가 가리키는 **커밋** sha 다(태그 객체 sha 가 아니라).
const REF_FORMAT = [
  '%(refname:short)',
  '%(objecttype)',
  '%(objectname)',
  '%(*objectname)',
  '%(creatordate:iso-strict)',
  '%(contents:subject)',
].join('%09');   // TAB — 태그 이름과 메시지에 들어갈 일이 없는 구분자

function listTags(dir, pattern) {
  // 패턴은 'refs/tags' 를 **대체**한다. 둘 다 넘기면 for-each-ref 는 합집합으로 보므로
  // 'refs/tags' 가 전부를 잡아 필터가 통째로 무력해진다(2026-08-07 실측).
  const args = ['for-each-ref', `--format=${REF_FORMAT}`, pattern ? `refs/tags/${pattern}` : 'refs/tags'];
  const r = gitOrThrow(dir, args);
  if (!r.stdout) return [];
  return r.stdout.split('\n').map((line) => {
    const [name, objecttype, objectname, derefName, createdAt, subject] = line.split('\t');
    const commit = derefName || objectname;
    return {
      name,
      annotated: objecttype === 'tag',
      sha: commit,
      createdAt: createdAt || null,
      message: objecttype === 'tag' ? (subject || '') : null,   // lightweight 는 annotation 이 없다
    };
  });
}

function toTag(raw, repoId) {
  return {
    name: raw.name,
    // 계약의 Tag.ref 는 "태그를 만들 때 가리킨 것"이다. 이미 만들어진 태그에서
    // 그 브랜치 이름을 복원할 방법은 git 에 없다 — 커밋 sha 가 남은 전부다.
    ref: raw.ref !== undefined ? raw.ref : raw.sha,
    sha: raw.sha ? String(raw.sha).slice(0, 7) : null,
    message: raw.message === undefined ? null : raw.message,
    createdAt: raw.createdAt || null,
    repo: repoId,
  };
}

const verbs = {
  'release.tags': async (ctx, args, flags) => {
    const t = targetRepo(ctx, flags);
    const pattern = (flags.pattern !== undefined && flags.pattern !== true) ? String(flags.pattern) : null;
    const limit = Number(flags.limit) || 0;
    const tags = listTags(t.dir, pattern).sort(byVersionDesc).map((x) => toTag(x, t.id));
    return limit ? tags.slice(0, limit) : tags;
  },

  'release.tag': async (ctx, args, flags) => {
    const name = args[0];
    if (!name) throw fail('usage', 'release.tag: <name> 인자가 필요하다.', 1);
    if (flags.ref === undefined || flags.ref === true) {
      throw fail('usage', 'release.tag: --ref <branch|sha> 가 필요하다 — 무엇을 태깅할지 추측하지 않는다.', 1);
    }
    const ref = String(flags.ref);
    const message = (flags.message !== undefined && flags.message !== true) ? String(flags.message) : null;
    const t = targetRepo(ctx, flags);

    const resolved = git(t.dir, ['rev-parse', '--verify', `${ref}^{commit}`]);
    if (!resolved.ok) throw fail('not_found', `--ref '${ref}' 를 커밋으로 해석하지 못했다.`, 1);
    const wantSha = resolved.stdout;

    // 멱등하되 덮어쓰지 않는다(계약 §2.9). 같은 이름이 이미 있으면 기존 것을 돌려주고,
    // 다른 커밋을 가리키면 **옮기지 않고** exit 2 로 보고한다 — 배포된 태그를 옮기면
    // 그 태그를 받아간 모든 곳이 조용히 어긋난다.
    const existing = listTags(t.dir).find((x) => x.name === name);
    if (existing) {
      if (existing.sha === wantSha) {
        log(`↺ 태그 '${name}' 가 이미 같은 커밋(${wantSha.slice(0, 7)})을 가리킨다 — 새로 만들지 않는다.`);
        return toTag(Object.assign({}, existing, { ref }), t.id);
      }
      throw fail(
        'drift',
        `태그 '${name}' 는 이미 다른 커밋을 가리킨다 — 옮기지 않는다. 기존=${existing.sha.slice(0, 7)} 요청=${wantSha.slice(0, 7)}`,
        2,
        { name, existingSha: existing.sha, requestedSha: wantSha, requestedRef: ref, repo: t.id },
      );
    }

    if (message) gitOrThrow(t.dir, ['tag', '-a', name, wantSha, '-m', message]);
    else gitOrThrow(t.dir, ['tag', name, wantSha]);
    log(`✅ 태그 '${name}' 생성 — ${wantSha.slice(0, 7)}${message ? ' (annotated)' : ' (lightweight)'}`);

    // 푸시는 기본이 아니다. 로컬 태그는 지울 수 있지만 푸시된 태그는 사실상 못 되돌린다 —
    // 원격에 올릴지는 호출부가 --push 로 명시한다.
    let pushed = false;
    if (flags.push) {
      const remote = (flags.remote !== undefined && flags.remote !== true) ? String(flags.remote) : 'origin';
      gitOrThrow(t.dir, ['push', remote, `refs/tags/${name}`], 'push_failed');
      pushed = true;
      log(`✅ ${remote} 로 태그 '${name}' 푸시`);
    }

    const created = listTags(t.dir).find((x) => x.name === name);
    return Object.assign(toTag(Object.assign({}, created, { ref }), t.id), { pushed });
  },

  'release.publish': async () => { throw unsupported('release.publish'); },
  'release.get': async () => { throw unsupported('release.get'); },
};

async function doctor(ctx) {
  const checks = [];
  const v = git(process.cwd(), ['--version']);
  checks.push({ name: 'git', ok: v.ok, detail: v.ok ? v.stdout : 'git 실행 파일 없음' });
  if (!v.ok) return checks;

  // 동사와 **같은 해석**으로 진단한다. 설정만 보고 프로젝트 루트를 찍으면, 작업공간
  // 안에서 돌린 doctor 가 "태그 0개"라고 말하는데 같은 위치의 `release tags` 는 3개를
  // 돌려주는 상태가 된다 — 진단이 실제와 다르면 doctor 를 아무도 안 보게 된다(계약 §2.8).
  const targets = repoDir.resolveRepos(ctx, {}, process.cwd(), { allowEmpty: true, dirFallback: 'root' });
  for (const t of targets) {
    const dir = t.dir;
    const label = t.id ? `repo:${t.id}` : 'repo';
    const inside = git(dir, ['rev-parse', '--git-dir']);
    if (!inside.ok) { checks.push({ name: label, ok: false, detail: `git 저장소가 아니다: ${dir}` }); continue; }
    let count = 0;
    try { count = listTags(dir).length; } catch (_) { count = 0; }
    checks.push({ name: label, ok: true, detail: `${dir} · 태그 ${count}개` });
  }
  checks.push({ name: 'publish', ok: true, detail: 'git 은 릴리스 노트를 모른다 — release publish/get 은 exit 3(계약 §2.9)' });
  return checks;
}

module.exports = { id: 'git', verbs, doctor };
