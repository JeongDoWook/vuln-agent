'use strict';

// release 프로바이더 — GitLab (계약 §2.9)
//
// 태그는 /repository/tags, 릴리스는 /releases 로 **따로** 다룬다. 계약이 두 동사를
// 나눈 이유가 GitLab API 에도 그대로 있다 — 태그 message 는 태그 객체의 일부고,
// 릴리스 description 은 나중에 고칠 수 있는 별개 리소스다.
//
// github.js 를 require 하지 않는다(계약 §4). 공유하는 것은 ../http.js 뿐이고,
// semver 비교기가 release/*.js 세 곳에 중복되는 것은 그 금지를 지키기 위한 의도적 중복이다.

const http = require('../http');

// API 호출이라 디렉터리 자체는 안 쓴다. 그래도 **어느 repos[] 항목인지**를 고르는 일은
// branch·run·release/git 과 같아야 한다 — 작업공간 안에서 부른 `--repo` 해석이 모듈마다
// 다르면 같은 명령이 위치에 따라 다른 프로젝트를 가리킨다(가드레일 §4).
const repoDir = require('../repo-dir');

// 비밀값 해석은 index.js 한 곳에서만 한다(tokenEnv / tokenCommand 두 출처).
const { resolveSecret } = require('../index');

const fail = (code, message, exitCode, data) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (data !== undefined) e.data = data;
  return e;
};

const log = (m) => process.stderr.write(`${m}\n`);

// ── semver 내림차순 (계약 §2.9) ──────────────────────────────
// v 접두사는 비교할 때만 뗀다 — name 에는 원본을 그대로 남긴다(계약 명시).
// semver 가 아닌 태그는 죽이지 않고 뒤로 보낸다.
const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseSemver(name) {
  const m = SEMVER.exec(String(name || '').trim());
  return m ? { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || null } : null;
}

function comparePre(a, b) {
  if (a === b) return 0;
  if (a === null) return 1;
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
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

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

// ── 접속 정보 ────────────────────────────────────────────────
// host/project 는 tracker.gitlab 설정으로 폴백한다 — 같은 GitLab 을 두 번 적게 하면
// 한쪽만 고친 설정이 남는다. 다만 **토큰 값은 어느 경로로도 파일에서 읽지 않는다**:
// tokenEnv 가 가리키는 환경변수, 또는 tokenCommand 가 적은 명령의 stdout 만 본다(계약 §3).
function trackerSettings(ctx) {
  return ((ctx.config.tracker || {}).gitlab) || {};
}

function base(ctx) {
  const host = ctx.settings.host || trackerSettings(ctx).host;
  if (!host) throw fail('bad_config', 'release.gitlab.host (또는 tracker.gitlab.host) 가 없다 (예: https://gitlab.example.com)', 1);
  return `${String(host).replace(/\/+$/, '')}/api/v4`;
}

// tracker.gitlab 로 폴백하는 것은 host 만이 아니라 **토큰 출처**도 마찬가지다.
// 해석은 index.js 의 resolveSecret 한 곳에서만 한다 (release/github.js 와 같은 이유).
function tokenSource(ctx, optional) {
  return resolveSecret({
    settings: ctx.settings, fallback: trackerSettings(ctx),
    envKey: 'tokenEnv', label: 'release.gitlab', optional,
  });
}

function token(ctx) {
  try {
    return tokenSource(ctx, false).value;
  } catch (e) {
    throw fail(e.code || 'no_token', e.message, 1);
  }
}

function headers(ctx) {
  return { 'PRIVATE-TOKEN': token(ctx), 'User-Agent': 'spec-review-kit-px' };
}

function target(ctx, flags) {
  const picked = repoDir.resolveRepo(ctx, flags, process.cwd(), { allowEmpty: true, dirFallback: 'root' });
  const repo = picked.id ? picked.config : null;
  const project = (repo && repo.project) || ctx.settings.project || trackerSettings(ctx).project;
  if (!project) throw fail('bad_config', 'repos[].project 또는 release.gitlab.project 가 필요하다 (예: "org/app-be")', 1);
  return { project: encodeURIComponent(project), repoId: picked.id, raw: project };
}

async function api(ctx, method, apiPath, { query, body } = {}) {
  const res = await http.json(`${base(ctx)}${apiPath}${http.qs(query || {})}`, { method, headers: headers(ctx), body });
  return res.data;
}

async function apiOrNull(ctx, method, apiPath, opts = {}) {
  const res = await http.jsonOrNull(`${base(ctx)}${apiPath}${http.qs(opts.query || {})}`, {
    method, headers: headers(ctx), body: opts.body,
  });
  return res ? res.data : null;
}

// ── 정규화 (계약 §2.9) ───────────────────────────────────────
function toTag(raw, repoId, ref) {
  const commit = raw.commit || {};
  return {
    name: raw.name,                                  // 원본 그대로 — v 접두사를 떼지 않는다
    ref: ref !== undefined ? ref : (commit.id || raw.target || null),
    sha: String(commit.id || raw.target || '').slice(0, 7) || null,
    message: raw.message || null,                    // lightweight 태그는 null
    createdAt: commit.created_at || commit.committed_date || null,
    repo: repoId,
  };
}

function toRelease(raw, repoId) {
  return {
    tag: raw.tag_name,
    name: raw.name || raw.tag_name,
    body: raw.description || '',
    url: (raw._links && (raw._links.self || raw._links.closed_issues_url)) || null,
    repo: repoId,
  };
}

const verbs = {
  'release.tags': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const pattern = (flags.pattern !== undefined && flags.pattern !== true) ? String(flags.pattern) : null;
    const limit = Number(flags.limit) || 0;
    const items = await http.paginate(
      (page, perPage) => `${base(ctx)}/projects/${t.project}/repository/tags${http.qs({ page, per_page: perPage, search: pattern })}`,
      { headers: headers(ctx) },
    );
    // GitLab 의 search 는 부분 일치라 pattern 을 다시 적용한다. glob 은 여기서 정규식으로 바꾼다.
    const filtered = pattern ? items.filter((x) => globMatch(pattern, x.name)) : items;
    const tags = filtered.map((x) => toTag(x, t.repoId)).sort(byVersionDesc);
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
    const t = target(ctx, flags);

    // 멱등하되 덮어쓰지 않는다(계약 §2.9). 이미 있으면 가리키는 커밋을 비교만 한다 —
    // 배포된 태그를 옮기면 그 태그를 받아간 모든 곳이 조용히 어긋난다.
    const existing = await apiOrNull(ctx, 'GET', `/projects/${t.project}/repository/tags/${encodeURIComponent(name)}`);
    if (existing) {
      const want = await apiOrNull(ctx, 'GET', `/projects/${t.project}/repository/commits/${encodeURIComponent(ref)}`);
      const wantSha = want && want.id;
      const haveSha = existing.commit && existing.commit.id;
      if (!wantSha || wantSha === haveSha) {
        log(`↺ 태그 '${name}' 가 이미 있다 — 새로 만들지 않는다.`);
        return toTag(existing, t.repoId, ref);
      }
      throw fail(
        'drift',
        `태그 '${name}' 는 이미 다른 커밋을 가리킨다 — 옮기지 않는다. 기존=${String(haveSha).slice(0, 7)} 요청=${String(wantSha).slice(0, 7)}`,
        2,
        { name, existingSha: haveSha, requestedSha: wantSha, requestedRef: ref, repo: t.repoId },
      );
    }

    const body = { tag_name: name, ref };
    if (message) body.message = message;
    const created = await api(ctx, 'POST', `/projects/${t.project}/repository/tags`, { body });
    log(`✅ 태그 '${name}' 생성 — ${ref}`);
    return toTag(created, t.repoId, ref);
  },

  'release.publish': async (ctx, args, flags) => {
    const tag = args[0];
    if (!tag) throw fail('usage', 'release.publish: <tag> 인자가 필요하다.', 1);
    const t = target(ctx, flags);

    // 계약 §2.9 — 대상 태그가 이미 있어야 한다. 없으면 릴리스가 태그를 만들어버리는
    // GitLab 기본 동작(ref 를 주면 생성)을 타지 않도록 여기서 먼저 막는다.
    const tagObj = await apiOrNull(ctx, 'GET', `/projects/${t.project}/repository/tags/${encodeURIComponent(tag)}`);
    if (!tagObj) {
      throw fail('not_found', `태그 '${tag}' 가 없다 — release publish 는 태그를 만들지 않는다. 먼저 release tag 를 실행해라.`, 1, { tag, repo: t.repoId });
    }

    const existing = await apiOrNull(ctx, 'GET', `/projects/${t.project}/releases/${encodeURIComponent(tag)}`);
    if (existing) {
      // 멱등 — 이미 있으면 본문을 덮어쓰지 않고 기존 릴리스를 돌려준다(계약 §2.9).
      log(`↺ 릴리스 '${tag}' 가 이미 있다 — 본문을 덮어쓰지 않는다.`);
      return toRelease(existing, t.repoId);
    }

    const body = {
      tag_name: tag,
      name: (flags.name !== undefined && flags.name !== true) ? String(flags.name) : tag,
      description: (flags.body !== undefined && flags.body !== true) ? String(flags.body) : '',
    };
    const created = await api(ctx, 'POST', `/projects/${t.project}/releases`, { body });
    log(`✅ 릴리스 '${tag}' 발행`);
    return toRelease(created, t.repoId);
  },

  'release.get': async (ctx, args, flags) => {
    const tag = args[0];
    if (!tag) throw fail('usage', 'release.get: <tag> 인자가 필요하다.', 1);
    const t = target(ctx, flags);
    const found = await apiOrNull(ctx, 'GET', `/projects/${t.project}/releases/${encodeURIComponent(tag)}`);
    if (!found) throw fail('not_found', `릴리스 '${tag}' 가 없다.`, 1, { tag, repo: t.repoId });
    return toRelease(found, t.repoId);
  },
};

// "1.*" 같은 단순 glob 만 지원한다. 정규식을 그대로 받으면 프로바이더마다
// 문법이 달라져 계약의 --pattern 이 이식되지 않는다.
function globMatch(pattern, name) {
  const rx = new RegExp(`^${String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
  return rx.test(String(name));
}

async function doctor(ctx) {
  const checks = [];
  let auth;
  try {
    auth = headers(ctx);
    checks.push({ name: 'token', ok: true, detail: `${(tokenSource(ctx, true).source) || ctx.settings.tokenEnv || trackerSettings(ctx).tokenEnv} 에서 읽음` });
  } catch (e) {
    checks.push({ name: 'token', ok: false, detail: e.message });
    return checks;
  }
  let root;
  try {
    root = base(ctx);
    checks.push({ name: 'host', ok: true, detail: root });
  } catch (e) {
    checks.push({ name: 'host', ok: false, detail: e.message });
    return checks;
  }

  const repos = Array.isArray(ctx.config.repos) ? ctx.config.repos : [];
  const projects = repos.map((r) => r.project).filter(Boolean);
  if (!projects.length && (ctx.settings.project || trackerSettings(ctx).project)) {
    projects.push(ctx.settings.project || trackerSettings(ctx).project);
  }
  for (const p of projects) {
    try {
      const res = await http.json(`${root}/projects/${encodeURIComponent(p)}/repository/tags${http.qs({ per_page: 1 })}`, { headers: auth });
      checks.push({ name: `tags:${p}`, ok: true, detail: `읽기 가능 (${Array.isArray(res.data) ? res.data.length : 0}건 샘플)` });
    } catch (e) {
      checks.push({ name: `tags:${p}`, ok: false, detail: e.message });
    }
  }
  return checks;
}

module.exports = { id: 'gitlab', verbs, doctor };
