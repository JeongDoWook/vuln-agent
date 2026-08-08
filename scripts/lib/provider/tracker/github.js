'use strict';

// GitHub 트래커 — /repos/{owner}/{repo} 를 계약 2.1(issue)·2.2(pr) 모양으로 번역한다.
// number → ref, body → body, PR → pr 로 맞추는 게 이 파일의 일이다(계약 §4).
// gitlab.js를 require하지 않는다 — 공통 로직은 ../http.js 에만 둔다.

const http = require('../http');
const { PxError, requireArg, requireFlag, requireYes, selectRepo, splitList } = require('../index');

const DEFAULT_HOST = 'https://api.github.com';

function base(ctx) {
  return String(ctx.settings.host || DEFAULT_HOST).replace(/\/+$/, '');
}

// User-Agent가 없으면 GitHub API는 403으로 끊는다 — 옵션이 아니라 필수 헤더다.
function headers(ctx) {
  return {
    Authorization: `Bearer ${ctx.secret('tokenEnv')}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'spec-review-kit-px',
  };
}

// repos[].project 가 "org/app-be" 면 그대로, "app-be" 면 tracker.github.owner 를 붙인다.
function target(ctx, flags) {
  const repo = selectRepo(ctx, flags);
  const owner = ctx.settings.owner;
  let slug = (repo && repo.project) || ctx.settings.repo || null;
  if (!slug) throw new PxError('bad_config', 'repos[].project 또는 tracker.github.repo 가 필요하다 (예: "org/app-be")');
  if (!slug.includes('/')) {
    if (!owner) throw new PxError('bad_config', `'${slug}' 에 owner가 없다 — tracker.github.owner 를 채우거나 "org/${slug}" 형태로 적어라.`);
    slug = `${owner}/${slug}`;
  }
  const [o, r] = slug.split('/');
  return { owner: o, name: r, slug, repoId: repo ? repo.id : null, path: `/repos/${encodeURIComponent(o)}/${encodeURIComponent(r)}` };
}

async function api(ctx, method, apiPath, { query, body } = {}) {
  const res = await http.json(`${base(ctx)}${apiPath}${http.qs(query || {})}`, { method, headers: headers(ctx), body });
  return res.data;
}

async function milestoneNumber(ctx, t, title) {
  const list = await api(ctx, 'GET', `${t.path}/milestones`, { query: { state: 'all', per_page: 100 } });
  const hit = Array.isArray(list) ? list.find((m) => m.title === title) : null;
  if (!hit) throw new PxError('not_found', `GitHub 마일스톤 '${title}' 를 찾지 못했다.`);
  return hit.number;
}

// ── 정규화 ───────────────────────────────────────────────────
function toIssue(raw, repoId) {
  return {
    ref: String(raw.number),                                  // number → ref (계약 §4)
    title: raw.title || '',
    body: raw.body || '',
    state: raw.state === 'closed' ? 'closed' : 'open',
    labels: (raw.labels || []).map((l) => (typeof l === 'string' ? l : l.name)),
    assignee: (raw.assignee && raw.assignee.login)
      || (raw.assignees && raw.assignees[0] && raw.assignees[0].login) || null,
    milestone: raw.milestone ? raw.milestone.title : null,
    url: raw.html_url || null,
    repo: repoId,
  };
}

function toPr(raw, repoId) {
  return {
    ref: String(raw.number),
    title: raw.title || '',
    state: raw.merged_at ? 'merged' : (raw.state === 'closed' ? 'closed' : 'open'),
    source: (raw.head && raw.head.ref) || null,
    target: (raw.base && raw.base.ref) || null,
    url: raw.html_url || null,
    draft: Boolean(raw.draft),
    repo: repoId,
  };
}

// GET /issues 는 PR도 같이 준다(GitHub에서 PR은 이슈의 하위 타입이다).
// pull_request 키가 붙은 항목을 걸러내지 않으면 issue list 에 MR이 섞여 나온다.
function onlyIssues(items) {
  return (items || []).filter((i) => !i.pull_request);
}

function str(flags, key) {
  const v = flags[key];
  return v === undefined || v === true ? null : String(v);
}

const verbs = {
  'issue.get': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.get');
    const t = target(ctx, flags);
    const raw = await api(ctx, 'GET', `${t.path}/issues/${encodeURIComponent(ref)}`);
    if (raw.pull_request) throw new PxError('not_found', `#${ref} 는 이슈가 아니라 PR이다 — pr get 을 써라.`);
    return toIssue(raw, t.repoId);
  },

  'issue.create': async (ctx, args, flags) => {
    const title = requireFlag(flags, 'title', 'issue.create');
    const t = target(ctx, flags);

    // 멱등성(계약 §1): 같은 제목의 열린 이슈가 있으면 그걸 돌려준다.
    // 검색 API(/search/issues)를 쓰지 않는 이유는 인덱싱 지연이다 — 방금 만든 이슈가
    // 검색에 안 잡혀서 중복 생성으로 이어진다. 목록을 직접 훑는 쪽이 정확하다.
    const open = onlyIssues(await http.paginate(
      (page, perPage) => `${base(ctx)}${t.path}/issues${http.qs({ state: 'open', page, per_page: perPage })}`,
      { headers: headers(ctx), maxPages: 5 },
    ));
    const dup = open.find((i) => i.title === title);
    if (dup) {
      process.stderr.write(`↺ 같은 제목의 열린 이슈 #${dup.number} 가 이미 있다 — 새로 만들지 않는다.\n`);
      return toIssue(dup, t.repoId);
    }

    const body = { title, body: str(flags, 'body') || '' };
    const labels = splitList(flags.labels);
    if (labels && labels.length) body.labels = labels;
    if (str(flags, 'assignee')) body.assignees = [str(flags, 'assignee')];
    if (str(flags, 'milestone')) body.milestone = await milestoneNumber(ctx, t, str(flags, 'milestone'));

    const created = await api(ctx, 'POST', `${t.path}/issues`, { body });
    process.stderr.write(`✅ 이슈 #${created.number} 생성 — ${created.html_url}\n`);
    return toIssue(created, t.repoId);
  },

  'issue.update': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.update');
    const t = target(ctx, flags);
    const body = {};
    if (str(flags, 'title')) body.title = str(flags, 'title');
    if (flags.body !== undefined) body.body = str(flags, 'body') || '';
    if (flags.assignee !== undefined) body.assignees = flags.assignee === true ? [] : [String(flags.assignee)];
    if (flags.milestone !== undefined) {
      body.milestone = flags.milestone === true ? null : await milestoneNumber(ctx, t, String(flags.milestone));
    }

    const add = splitList(flags.addLabels);
    const remove = splitList(flags.removeLabels);
    if ((add && add.length) || (remove && remove.length)) {
      // GitHub의 PATCH labels 는 "교체"다. 부분 추가/삭제를 하려면 현재 라벨을 읽어
      // 최종 집합을 만들어 보내야 한다 — GitLab의 add_labels/remove_labels 와 다른 지점.
      const current = await api(ctx, 'GET', `${t.path}/issues/${encodeURIComponent(ref)}`);
      const set = new Set((current.labels || []).map((l) => (typeof l === 'string' ? l : l.name)));
      (add || []).forEach((l) => set.add(l));
      (remove || []).forEach((l) => set.delete(l));
      body.labels = [...set];
    }
    if (!Object.keys(body).length) throw new PxError('usage', 'issue.update: 바꿀 필드를 하나도 주지 않았다.');
    return toIssue(await api(ctx, 'PATCH', `${t.path}/issues/${encodeURIComponent(ref)}`, { body }), t.repoId);
  },

  'issue.close': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.close');
    const t = target(ctx, flags);
    const current = await api(ctx, 'GET', `${t.path}/issues/${encodeURIComponent(ref)}`);
    if (current.state === 'closed') {
      process.stderr.write(`↺ 이슈 #${ref} 는 이미 closed 다.\n`);
      return toIssue(current, t.repoId);
    }
    requireYes(flags, 'issue.close', { ref: String(ref), title: current.title, url: current.html_url, willBecome: 'closed' });
    const closed = await api(ctx, 'PATCH', `${t.path}/issues/${encodeURIComponent(ref)}`, { body: { state: 'closed' } });
    return toIssue(closed, t.repoId);
  },

  'issue.list': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const state = str(flags, 'state') || 'open';
    if (!['open', 'closed', 'all'].includes(state)) {
      throw new PxError('usage', `--state 는 open|closed|all 중 하나다 — 받은 값: '${state}'`);
    }
    const labels = splitList(flags.labels);
    const query = {
      state,
      labels: labels && labels.length ? labels.join(',') : null,
      milestone: str(flags, 'milestone'),
    };
    const limit = Number(flags.limit) || 0;
    // limit은 PR을 걸러낸 뒤에 적용한다 — 페이지에 PR이 섞여 있어서
    // paginate 단계에서 자르면 실제 이슈가 limit보다 적게 나온다.
    const items = onlyIssues(await http.paginate(
      (page, perPage) => `${base(ctx)}${t.path}/issues${http.qs(Object.assign({}, query, { page, per_page: perPage }))}`,
      { headers: headers(ctx) },
    ));
    return (limit ? items.slice(0, limit) : items).map((i) => toIssue(i, t.repoId));
  },

  // ── pr ─────────────────────────────────────────────────────
  'pr.create': async (ctx, args, flags) => {
    const source = requireFlag(flags, 'source', 'pr.create');
    const targetBranch = requireFlag(flags, 'target', 'pr.create');
    const title = requireFlag(flags, 'title', 'pr.create');
    const t = target(ctx, flags);

    const open = await api(ctx, 'GET', `${t.path}/pulls`, {
      query: { head: `${t.owner}:${source}`, base: targetBranch, state: 'open' },
    });
    if (Array.isArray(open) && open.length) {
      process.stderr.write(`↺ ${source} → ${targetBranch} PR #${open[0].number} 가 이미 열려 있다.\n`);
      return toPr(open[0], t.repoId);
    }

    const created = await api(ctx, 'POST', `${t.path}/pulls`, {
      body: { head: source, base: targetBranch, title, body: str(flags, 'body') || '', draft: Boolean(flags.draft) },
    });

    // 라벨·담당자는 PR 엔드포인트가 아니라 이슈 엔드포인트로 붙인다(PR은 이슈의 하위 타입).
    const labels = splitList(flags.labels);
    const assignee = str(flags, 'assignee');
    if ((labels && labels.length) || assignee) {
      const patch = {};
      if (labels && labels.length) patch.labels = labels;
      if (assignee) patch.assignees = [assignee];
      await api(ctx, 'PATCH', `${t.path}/issues/${created.number}`, { body: patch });
    }
    process.stderr.write(`✅ PR #${created.number} 생성 — ${created.html_url}\n`);
    return toPr(created, t.repoId);
  },

  'pr.get': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const ref = args[0];
    if (ref) return toPr(await api(ctx, 'GET', `${t.path}/pulls/${encodeURIComponent(ref)}`), t.repoId);
    const source = str(flags, 'source');
    if (!source) throw new PxError('usage', 'pr.get: <ref> 또는 --source <branch> 가 필요하다.');
    const list = await api(ctx, 'GET', `${t.path}/pulls`, {
      query: { head: `${t.owner}:${source}`, state: 'all', sort: 'updated', direction: 'desc' },
    });
    if (!Array.isArray(list) || !list.length) throw new PxError('not_found', `source=${source} 인 PR이 없다.`);
    return toPr(list[0], t.repoId);
  },

  'pr.list': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const state = str(flags, 'state') || 'open';
    // GitHub의 pulls 목록에는 merged 상태 필터가 없다 — closed를 받아 merged_at 로 갈라낸다.
    const ghState = { open: 'open', closed: 'closed', merged: 'closed', all: 'all' }[state];
    if (!ghState) throw new PxError('usage', `--state 는 open|merged|closed|all 중 하나다 — 받은 값: '${state}'`);
    const query = { state: ghState, base: str(flags, 'target') };
    let items = await http.paginate(
      (page, perPage) => `${base(ctx)}${t.path}/pulls${http.qs(Object.assign({}, query, { page, per_page: perPage }))}`,
      { headers: headers(ctx) },
    );
    if (state === 'merged') items = items.filter((p) => p.merged_at);
    if (state === 'closed') items = items.filter((p) => !p.merged_at);
    const limit = Number(flags.limit) || 0;
    return (limit ? items.slice(0, limit) : items).map((p) => toPr(p, t.repoId));
  },

  'pr.merge': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'pr.merge');
    const t = target(ctx, flags);
    // 전략 판정은 네트워크보다 먼저 — 어차피 못 할 요청이면 왕복 없이 끝낸다.
    const strategy = str(flags, 'strategy') || 'merge';
    if (!['merge', 'squash', 'rebase'].includes(strategy)) {
      throw new PxError('usage', `--strategy 는 merge|squash|rebase 중 하나다 — 받은 값: '${strategy}'`);
    }
    const current = await api(ctx, 'GET', `${t.path}/pulls/${encodeURIComponent(ref)}`);
    if (current.merged_at) {
      process.stderr.write(`↺ PR #${ref} 는 이미 merged 다.\n`);
      return toPr(current, t.repoId);
    }
    requireYes(flags, 'pr.merge', {
      ref: String(ref), title: current.title, url: current.html_url,
      source: current.head && current.head.ref, target: current.base && current.base.ref, strategy,
    });
    await api(ctx, 'PUT', `${t.path}/pulls/${encodeURIComponent(ref)}/merge`, { body: { merge_method: strategy } });
    // merge 응답은 {merged, sha, message} 뿐이라 PR 스키마를 못 만든다 — 다시 읽어서 돌려준다.
    return toPr(await api(ctx, 'GET', `${t.path}/pulls/${encodeURIComponent(ref)}`), t.repoId);
  },
};

async function doctor(ctx) {
  const checks = [];
  checks.push({ name: 'host', ok: true, detail: base(ctx) });

  let auth;
  try {
    auth = headers(ctx);
    checks.push({ name: 'token', ok: true, detail: `${ctx.secretSource('tokenEnv') || ctx.settings.tokenEnv} 에서 읽음` });
  } catch (e) {
    checks.push({ name: 'token', ok: false, detail: e.message });
    return checks;
  }

  try {
    const me = await http.json(`${base(ctx)}/user`, { headers: auth });
    checks.push({ name: 'connect', ok: true, detail: `/user → ${me.data && me.data.login}` });
  } catch (e) {
    checks.push({ name: 'connect', ok: false, detail: e.message });
    return checks;
  }

  const repos = Array.isArray(ctx.config.repos) ? ctx.config.repos : [];
  const slugs = repos.length ? repos.map((r) => r.id) : (ctx.settings.repo ? [null] : []);
  for (const id of slugs) {
    let t;
    try {
      t = target(ctx, id ? { repo: id } : {});
    } catch (e) {
      checks.push({ name: `repo:${id || '(기본)'}`, ok: false, detail: e.message });
      continue;
    }
    try {
      const res = await http.json(`${base(ctx)}${t.path}`, { headers: auth });
      checks.push({ name: `repo:${t.slug}`, ok: true, detail: `기본 브랜치 ${res.data && res.data.default_branch}` });
    } catch (e) {
      checks.push({ name: `repo:${t.slug}`, ok: false, detail: e.message });
    }
  }
  return checks;
}

module.exports = { id: 'github', verbs, doctor };
