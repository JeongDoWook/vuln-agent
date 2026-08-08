'use strict';

// release 프로바이더 — GitHub (계약 §2.9)
//
// GitHub 에는 "태그 생성" API 가 없다. 있는 것은 git 객체 API 뿐이라 annotated 태그는
// **두 번의 요청**(태그 객체 → ref)으로 만든다. 이 번거로움이 프로바이더 안에 갇히는 것이
// 계약의 목적이다 — 스킬은 `release tag 1.5.0 --ref main` 한 문장만 안다.
//
// gitlab.js 를 require 하지 않는다(계약 §4). 공유하는 것은 ../http.js 뿐이고,
// semver 비교기가 release/*.js 세 곳에 중복되는 것은 그 금지를 지키기 위한 의도적 중복이다.

const http = require('../http');

// API 호출이라 디렉터리 자체는 안 쓴다. 그래도 **어느 repos[] 항목인지**를 고르는 일은
// branch·run·release/git 과 같아야 한다 — 작업공간 안에서 부른 `--repo` 해석이 모듈마다
// 다르면 같은 명령이 위치에 따라 다른 저장소를 가리킨다(가드레일 §4).
const repoDir = require('../repo-dir');

// 비밀값 해석은 index.js 한 곳에서만 한다(tokenEnv / tokenCommand 두 출처).
const { resolveSecret } = require('../index');

const DEFAULT_HOST = 'https://api.github.com';

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
// host/owner 는 tracker.github 로 폴백한다. 토큰 **값**은 어느 경로로도 파일에서 읽지 않는다 —
// tokenEnv 가 가리키는 환경변수, 또는 tokenCommand 가 적은 명령의 stdout 만 본다(계약 §3).
function trackerSettings(ctx) {
  return ((ctx.config.tracker || {}).github) || {};
}

function base(ctx) {
  return String(ctx.settings.host || trackerSettings(ctx).host || DEFAULT_HOST).replace(/\/+$/, '');
}

// tracker.github 로 폴백하는 것은 host/owner 만이 아니라 **토큰 출처**도 마찬가지다.
// 해석은 index.js 의 resolveSecret 한 곳에서만 한다 — 여기서 process.env 를 직접 읽던 시절,
// tokenCommand 같은 출처가 늘 때마다 이 함수만 조용히 뒤처졌다.
function tokenSource(ctx, optional) {
  return resolveSecret({
    settings: ctx.settings, fallback: trackerSettings(ctx),
    envKey: 'tokenEnv', label: 'release.github', optional,
  });
}

function token(ctx) {
  try {
    return tokenSource(ctx, false).value;
  } catch (e) {
    throw fail(e.code || 'no_token', e.message, 1);
  }
}

// User-Agent 가 없으면 GitHub API 는 403 으로 끊는다 — 옵션이 아니라 필수 헤더다.
function headers(ctx) {
  return {
    Authorization: `Bearer ${token(ctx)}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'spec-review-kit-px',
  };
}

function target(ctx, flags) {
  const picked = repoDir.resolveRepo(ctx, flags, process.cwd(), { allowEmpty: true, dirFallback: 'root' });
  const repo = picked.id ? picked.config : null;

  const owner = ctx.settings.owner || trackerSettings(ctx).owner;
  let slug = (repo && repo.project) || ctx.settings.repo || trackerSettings(ctx).repo || null;
  if (!slug) throw fail('bad_config', 'repos[].project 또는 release.github.repo 가 필요하다 (예: "org/app-be")', 1);
  if (!slug.includes('/')) {
    if (!owner) throw fail('bad_config', `'${slug}' 에 owner 가 없다 — release.github.owner 를 채우거나 "org/${slug}" 형태로 적어라.`, 1);
    slug = `${owner}/${slug}`;
  }
  const [o, r] = slug.split('/');
  return { slug, repoId: picked.id, path: `/repos/${encodeURIComponent(o)}/${encodeURIComponent(r)}` };
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
// GitHub 의 /tags 는 이름과 커밋 sha 만 준다. 태그별 날짜·annotation 을 채우려면
// 태그 수만큼 추가 요청이 필요해서, 목록에서는 채우지 않고 null 로 둔다 —
// 계약이 요구하는 것은 "정직한 null" 이지 N번의 왕복이 아니다.
function toTag(raw, repoId, extra) {
  const sha = (raw.commit && raw.commit.sha) || raw.sha || null;
  return Object.assign({
    name: raw.name,                                  // 원본 그대로 — v 접두사를 떼지 않는다
    ref: sha,
    sha: sha ? String(sha).slice(0, 7) : null,
    message: null,
    createdAt: null,
    repo: repoId,
  }, extra || {});
}

function toRelease(raw, repoId) {
  return {
    tag: raw.tag_name,
    name: raw.name || raw.tag_name,
    body: raw.body || '',
    url: raw.html_url || null,
    repo: repoId,
  };
}

// 태그 ref 가 가리키는 **커밋** sha. annotated 면 태그 객체를 한 번 더 벗긴다.
async function tagCommitSha(ctx, t, name) {
  const ref = await apiOrNull(ctx, 'GET', `${t.path}/git/ref/tags/${encodeURIComponent(name)}`);
  if (!ref || !ref.object) return null;
  if (ref.object.type !== 'tag') return ref.object.sha;
  const obj = await apiOrNull(ctx, 'GET', `${t.path}/git/tags/${encodeURIComponent(ref.object.sha)}`);
  return (obj && obj.object && obj.object.sha) || ref.object.sha;
}

const verbs = {
  'release.tags': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const pattern = (flags.pattern !== undefined && flags.pattern !== true) ? String(flags.pattern) : null;
    const limit = Number(flags.limit) || 0;
    const items = await http.paginate(
      (page, perPage) => `${base(ctx)}${t.path}/tags${http.qs({ page, per_page: perPage })}`,
      { headers: headers(ctx) },
    );
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

    const commit = await apiOrNull(ctx, 'GET', `${t.path}/commits/${encodeURIComponent(ref)}`);
    if (!commit || !commit.sha) throw fail('not_found', `--ref '${ref}' 를 커밋으로 해석하지 못했다.`, 1);
    const wantSha = commit.sha;

    // 멱등하되 덮어쓰지 않는다(계약 §2.9). 이미 있으면 가리키는 커밋만 비교한다 —
    // 배포된 태그를 옮기면 그 태그를 받아간 모든 곳이 조용히 어긋난다.
    const haveSha = await tagCommitSha(ctx, t, name);
    if (haveSha) {
      if (haveSha === wantSha) {
        log(`↺ 태그 '${name}' 가 이미 같은 커밋(${wantSha.slice(0, 7)})을 가리킨다 — 새로 만들지 않는다.`);
        return toTag({ name, sha: haveSha }, t.repoId, { ref });
      }
      throw fail(
        'drift',
        `태그 '${name}' 는 이미 다른 커밋을 가리킨다 — 옮기지 않는다. 기존=${haveSha.slice(0, 7)} 요청=${wantSha.slice(0, 7)}`,
        2,
        { name, existingSha: haveSha, requestedSha: wantSha, requestedRef: ref, repo: t.repoId },
      );
    }

    // annotated 태그: 태그 객체를 먼저 만들고, ref 는 그 객체를 가리킨다.
    // lightweight: ref 가 커밋을 바로 가리킨다.
    let pointTo = wantSha;
    let createdAt = null;
    if (message) {
      const tagObj = await api(ctx, 'POST', `${t.path}/git/tags`, {
        body: { tag: name, message, object: wantSha, type: 'commit' },
      });
      pointTo = tagObj.sha;
      createdAt = (tagObj.tagger && tagObj.tagger.date) || null;
    }
    await api(ctx, 'POST', `${t.path}/git/refs`, { body: { ref: `refs/tags/${name}`, sha: pointTo } });
    log(`✅ 태그 '${name}' 생성 — ${wantSha.slice(0, 7)}${message ? ' (annotated)' : ' (lightweight)'}`);

    return toTag({ name, sha: wantSha }, t.repoId, { ref, message: message || null, createdAt });
  },

  'release.publish': async (ctx, args, flags) => {
    const tag = args[0];
    if (!tag) throw fail('usage', 'release.publish: <tag> 인자가 필요하다.', 1);
    const t = target(ctx, flags);

    // 계약 §2.9 — 대상 태그가 이미 있어야 한다. POST /releases 는 없는 태그를
    // 만들어버리므로(target_commitish 기준) 여기서 먼저 막는다.
    const haveSha = await tagCommitSha(ctx, t, tag);
    if (!haveSha) {
      throw fail('not_found', `태그 '${tag}' 가 없다 — release publish 는 태그를 만들지 않는다. 먼저 release tag 를 실행해라.`, 1, { tag, repo: t.repoId });
    }

    const existing = await apiOrNull(ctx, 'GET', `${t.path}/releases/tags/${encodeURIComponent(tag)}`);
    if (existing) {
      // 멱등 — 이미 있으면 본문을 덮어쓰지 않고 기존 릴리스를 돌려준다(계약 §2.9).
      log(`↺ 릴리스 '${tag}' 가 이미 있다 — 본문을 덮어쓰지 않는다.`);
      return toRelease(existing, t.repoId);
    }

    const created = await api(ctx, 'POST', `${t.path}/releases`, {
      body: {
        tag_name: tag,
        name: (flags.name !== undefined && flags.name !== true) ? String(flags.name) : tag,
        body: (flags.body !== undefined && flags.body !== true) ? String(flags.body) : '',
        draft: Boolean(flags.draft),
        prerelease: Boolean(flags.prerelease),
      },
    });
    log(`✅ 릴리스 '${tag}' 발행 — ${created.html_url}`);
    return toRelease(created, t.repoId);
  },

  'release.get': async (ctx, args, flags) => {
    const tag = args[0];
    if (!tag) throw fail('usage', 'release.get: <tag> 인자가 필요하다.', 1);
    const t = target(ctx, flags);
    const found = await apiOrNull(ctx, 'GET', `${t.path}/releases/tags/${encodeURIComponent(tag)}`);
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
  checks.push({ name: 'host', ok: true, detail: base(ctx) });

  const repos = Array.isArray(ctx.config.repos) ? ctx.config.repos : [];
  const flagSets = repos.length ? repos.map((r) => ({ repo: r.id })) : [{}];
  for (const flags of flagSets) {
    let t;
    try { t = target(ctx, flags); } catch (e) {
      checks.push({ name: `repo:${flags.repo || '-'}`, ok: false, detail: e.message });
      continue;
    }
    try {
      const res = await http.json(`${base(ctx)}${t.path}/tags${http.qs({ per_page: 1 })}`, { headers: auth });
      checks.push({ name: `tags:${t.slug}`, ok: true, detail: `읽기 가능 (${Array.isArray(res.data) ? res.data.length : 0}건 샘플)` });
    } catch (e) {
      checks.push({ name: `tags:${t.slug}`, ok: false, detail: e.message });
    }
  }
  return checks;
}

module.exports = { id: 'github', verbs, doctor };
