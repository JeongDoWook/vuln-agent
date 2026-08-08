'use strict';

// GitLab 트래커 — /api/v4 를 계약 2.1(issue)·2.2(pr) 모양으로 번역한다.
// 이 파일의 존재 이유는 번역 하나다: GitLab의 iid·description·opened·MR 을
// 계약의 ref·body·open·pr 로 바꾸는 책임이 프로바이더에 있기 때문이다(계약 §4).
// github.js를 require하지 않는다 — 공통 로직은 ../http.js 에만 둔다.

const http = require('../http');
const { PxError, requireArg, requireFlag, requireYes, selectRepo, splitList } = require('../index');

// ── 접속 정보 ────────────────────────────────────────────────
function base(ctx) {
  const host = ctx.settings.host;
  if (!host) throw new PxError('bad_config', 'tracker.gitlab.host 가 없다 (예: https://gitlab.example.com)');
  return `${String(host).replace(/\/+$/, '')}/api/v4`;
}

function headers(ctx) {
  return { 'PRIVATE-TOKEN': ctx.secret('tokenEnv'), 'User-Agent': 'spec-review-kit-px' };
}

// repos[].project("org/app-be") 우선, 없으면 tracker.gitlab.project.
// 프로젝트 경로는 URL 세그먼트라 통째로 인코딩해야 한다(슬래시 포함).
function target(ctx, flags) {
  const repo = selectRepo(ctx, flags);
  const project = (repo && repo.project) || ctx.settings.project;
  if (!project) {
    throw new PxError('bad_config', 'repos[].project 또는 tracker.gitlab.project 가 필요하다 (예: "org/app-be")');
  }
  return { project: encodeURIComponent(project), repoId: repo ? repo.id : null, raw: project };
}

async function api(ctx, method, apiPath, { query, body } = {}) {
  const res = await http.json(`${base(ctx)}${apiPath}${http.qs(query || {})}`, { method, headers: headers(ctx), body });
  return res.data;
}

// ── 조회 헬퍼 (이름 → 수치 id) ───────────────────────────────
// GitLab은 assignee/milestone을 id로만 받는다. 계약은 사람이 읽는 문자열
// (username·milestone title)을 쓰기로 했으니 그 변환은 여기서 흡수한다.
async function userId(ctx, username) {
  const users = await api(ctx, 'GET', '/users', { query: { username } });
  const hit = Array.isArray(users) ? users.find((u) => u.username === username) : null;
  if (!hit) throw new PxError('not_found', `GitLab 사용자 '${username}' 를 찾지 못했다.`);
  return hit.id;
}

async function milestoneId(ctx, project, title) {
  const list = await api(ctx, 'GET', `/projects/${project}/milestones`, { query: { title } });
  const hit = Array.isArray(list) ? list.find((m) => m.title === title) : null;
  if (!hit) throw new PxError('not_found', `GitLab 마일스톤 '${title}' 를 찾지 못했다.`);
  return hit.id;
}

// ── 정규화 ───────────────────────────────────────────────────
function toIssue(raw, repoId) {
  return {
    ref: String(raw.iid),                                   // iid → ref (계약 §4)
    title: raw.title || '',
    body: raw.description || '',
    state: raw.state === 'closed' ? 'closed' : 'open',      // GitLab은 'opened'
    labels: raw.labels || [],
    assignee: (raw.assignees && raw.assignees[0] && raw.assignees[0].username)
      || (raw.assignee && raw.assignee.username) || null,
    milestone: raw.milestone ? raw.milestone.title : null,
    url: raw.web_url || null,
    repo: repoId,
  };
}

function toPr(raw, repoId) {
  const state = raw.state === 'merged' ? 'merged' : raw.state === 'closed' ? 'closed' : 'open';
  return {
    ref: String(raw.iid),
    title: raw.title || '',
    state,                                                  // locked도 open으로 본다 — 스킬은 잠금을 모른다
    source: raw.source_branch || null,
    target: raw.target_branch || null,
    url: raw.web_url || null,
    draft: Boolean(raw.draft ?? raw.work_in_progress),
    repo: repoId,
  };
}

const STATE_TO_GITLAB = { open: 'opened', closed: 'closed', all: 'all' };

function str(flags, key) {
  const v = flags[key];
  return v === undefined || v === true ? null : String(v);
}

// ── issue ────────────────────────────────────────────────────
const verbs = {
  'issue.get': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.get');
    const t = target(ctx, flags);
    return toIssue(await api(ctx, 'GET', `/projects/${t.project}/issues/${encodeURIComponent(ref)}`), t.repoId);
  },

  'issue.create': async (ctx, args, flags) => {
    const title = requireFlag(flags, 'title', 'issue.create');
    const t = target(ctx, flags);

    // 멱등성(계약 §1): 같은 제목의 열린 이슈가 있으면 그걸 돌려준다.
    // search는 부분 일치라 제목 완전 일치로 한 번 더 거른다.
    const found = await api(ctx, 'GET', `/projects/${t.project}/issues`, {
      query: { search: title, in: 'title', state: 'opened', per_page: 100 },
    });
    const dup = Array.isArray(found) ? found.find((i) => i.title === title) : null;
    if (dup) {
      process.stderr.write(`↺ 같은 제목의 열린 이슈 !${dup.iid} 가 이미 있다 — 새로 만들지 않는다.\n`);
      return toIssue(dup, t.repoId);
    }

    const body = { title, description: str(flags, 'body') || '' };
    const labels = splitList(flags.labels);
    if (labels && labels.length) body.labels = labels.join(',');
    if (str(flags, 'assignee')) body.assignee_ids = [await userId(ctx, str(flags, 'assignee'))];
    if (str(flags, 'milestone')) body.milestone_id = await milestoneId(ctx, t.project, str(flags, 'milestone'));

    const created = await api(ctx, 'POST', `/projects/${t.project}/issues`, { body });
    process.stderr.write(`✅ 이슈 !${created.iid} 생성 — ${created.web_url}\n`);
    return toIssue(created, t.repoId);
  },

  'issue.update': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.update');
    const t = target(ctx, flags);
    const body = {};
    if (str(flags, 'title')) body.title = str(flags, 'title');
    if (flags.body !== undefined) body.description = str(flags, 'body') || '';
    const add = splitList(flags.addLabels);
    const remove = splitList(flags.removeLabels);
    if (add && add.length) body.add_labels = add.join(',');
    if (remove && remove.length) body.remove_labels = remove.join(',');
    if (flags.assignee !== undefined) {
      // assignee_ids: [0] 이 GitLab에서 "담당자 없음"이다 — 빈 배열은 무시된다.
      body.assignee_ids = flags.assignee === true ? [0] : [await userId(ctx, String(flags.assignee))];
    }
    if (flags.milestone !== undefined) {
      body.milestone_id = flags.milestone === true ? 0 : await milestoneId(ctx, t.project, String(flags.milestone));
    }
    if (!Object.keys(body).length) throw new PxError('usage', 'issue.update: 바꿀 필드를 하나도 주지 않았다.');
    return toIssue(await api(ctx, 'PUT', `/projects/${t.project}/issues/${encodeURIComponent(ref)}`, { body }), t.repoId);
  },

  'issue.close': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.close');
    const t = target(ctx, flags);
    const current = await api(ctx, 'GET', `/projects/${t.project}/issues/${encodeURIComponent(ref)}`);
    if (current.state === 'closed') {
      process.stderr.write(`↺ 이슈 !${ref} 는 이미 closed 다.\n`);
      return toIssue(current, t.repoId);
    }
    requireYes(flags, 'issue.close', { ref: String(ref), title: current.title, url: current.web_url, willBecome: 'closed' });
    const closed = await api(ctx, 'PUT', `/projects/${t.project}/issues/${encodeURIComponent(ref)}`, { body: { state_event: 'close' } });
    return toIssue(closed, t.repoId);
  },

  'issue.list': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const state = str(flags, 'state') || 'open';
    if (!STATE_TO_GITLAB[state]) throw new PxError('usage', `--state 는 open|closed|all 중 하나다 — 받은 값: '${state}'`);
    const labels = splitList(flags.labels);
    const query = {
      state: STATE_TO_GITLAB[state],
      labels: labels && labels.length ? labels.join(',') : null,
      milestone: str(flags, 'milestone'),
    };
    const items = await http.paginate(
      (page, perPage) => `${base(ctx)}/projects/${t.project}/issues${http.qs(Object.assign({}, query, { page, per_page: perPage }))}`,
      { headers: headers(ctx), limit: Number(flags.limit) || 0 },
    );
    return items.map((i) => toIssue(i, t.repoId));
  },

  // ── pr (GitLab MR) ─────────────────────────────────────────
  'pr.create': async (ctx, args, flags) => {
    const source = requireFlag(flags, 'source', 'pr.create');
    const targetBranch = requireFlag(flags, 'target', 'pr.create');
    const title = requireFlag(flags, 'title', 'pr.create');
    const t = target(ctx, flags);

    // 멱등성: 같은 source→target 의 열린 MR이 있으면 그걸 돌려준다.
    const open = await api(ctx, 'GET', `/projects/${t.project}/merge_requests`, {
      query: { source_branch: source, target_branch: targetBranch, state: 'opened' },
    });
    if (Array.isArray(open) && open.length) {
      process.stderr.write(`↺ ${source} → ${targetBranch} MR !${open[0].iid} 가 이미 열려 있다.\n`);
      return toPr(open[0], t.repoId);
    }

    // GitLab에는 create용 draft 파라미터가 없다 — 제목의 "Draft: " 접두사가 곧 draft 상태다.
    const body = {
      source_branch: source,
      target_branch: targetBranch,
      title: flags.draft && !/^draft:/i.test(title) ? `Draft: ${title}` : title,
      description: str(flags, 'body') || '',
    };
    const labels = splitList(flags.labels);
    if (labels && labels.length) body.labels = labels.join(',');
    if (str(flags, 'assignee')) body.assignee_ids = [await userId(ctx, str(flags, 'assignee'))];

    const created = await api(ctx, 'POST', `/projects/${t.project}/merge_requests`, { body });
    process.stderr.write(`✅ MR !${created.iid} 생성 — ${created.web_url}\n`);
    return toPr(created, t.repoId);
  },

  'pr.get': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const ref = args[0];
    if (ref) {
      return toPr(await api(ctx, 'GET', `/projects/${t.project}/merge_requests/${encodeURIComponent(ref)}`), t.repoId);
    }
    const source = str(flags, 'source');
    if (!source) throw new PxError('usage', 'pr.get: <ref> 또는 --source <branch> 가 필요하다.');
    const list = await api(ctx, 'GET', `/projects/${t.project}/merge_requests`, {
      query: { source_branch: source, state: 'all', order_by: 'updated_at' },
    });
    if (!Array.isArray(list) || !list.length) throw new PxError('not_found', `source=${source} 인 MR이 없다.`);
    return toPr(list[0], t.repoId);
  },

  'pr.list': async (ctx, args, flags) => {
    const t = target(ctx, flags);
    const state = str(flags, 'state') || 'open';
    const glState = { open: 'opened', merged: 'merged', closed: 'closed', all: 'all' }[state];
    if (!glState) throw new PxError('usage', `--state 는 open|merged|closed|all 중 하나다 — 받은 값: '${state}'`);
    const query = { state: glState, target_branch: str(flags, 'target') };
    const items = await http.paginate(
      (page, perPage) => `${base(ctx)}/projects/${t.project}/merge_requests${http.qs(Object.assign({}, query, { page, per_page: perPage }))}`,
      { headers: headers(ctx), limit: Number(flags.limit) || 0 },
    );
    return items.map((i) => toPr(i, t.repoId));
  },

  'pr.merge': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'pr.merge');
    const t = target(ctx, flags);
    // 전략 판정은 네트워크보다 먼저 한다 — 어차피 못 할 요청이면 왕복 없이 exit 3 을 준다.
    // GitLab의 rebase-merge 는 프로젝트 설정(merge_method)이지 요청 파라미터가 아니다.
    const strategy = str(flags, 'strategy') || 'merge';
    if (!['merge', 'squash'].includes(strategy)) {
      throw new PxError('unsupported', `GitLab은 요청 단위 --strategy ${strategy} 를 지원하지 않는다 (merge|squash 만 가능, rebase는 프로젝트 merge_method 설정).`);
    }
    const current = await api(ctx, 'GET', `/projects/${t.project}/merge_requests/${encodeURIComponent(ref)}`);
    if (current.state === 'merged') {
      process.stderr.write(`↺ MR !${ref} 는 이미 merged 다.\n`);
      return toPr(current, t.repoId);
    }
    requireYes(flags, 'pr.merge', {
      ref: String(ref), title: current.title, url: current.web_url,
      source: current.source_branch, target: current.target_branch, strategy,
    });
    const merged = await api(ctx, 'PUT', `/projects/${t.project}/merge_requests/${encodeURIComponent(ref)}/merge`, {
      body: { squash: strategy === 'squash' },
    });
    return toPr(merged, t.repoId);
  },
};

async function doctor(ctx) {
  const checks = [];
  const host = ctx.settings.host;
  checks.push({ name: 'host', ok: Boolean(host), detail: host || 'tracker.gitlab.host 없음' });

  let auth;
  try {
    auth = headers(ctx);
    checks.push({ name: 'token', ok: true, detail: `${ctx.secretSource('tokenEnv') || ctx.settings.tokenEnv} 에서 읽음` });
  } catch (e) {
    checks.push({ name: 'token', ok: false, detail: e.message });
    return checks;
  }
  if (!host) return checks;

  try {
    const me = await http.json(`${base(ctx)}/user`, { headers: auth });
    checks.push({ name: 'connect', ok: true, detail: `/user → ${me.data && me.data.username}` });
  } catch (e) {
    checks.push({ name: 'connect', ok: false, detail: e.message });
    return checks;
  }

  // 프로젝트 접근까지 봐야 "설정이 맞다"고 말할 수 있다 — 토큰은 유효한데
  // 그 프로젝트에는 권한이 없는 경우가 흔하다.
  const repos = Array.isArray(ctx.config.repos) ? ctx.config.repos : [];
  const projects = repos.map((r) => r.project).filter(Boolean);
  if (!projects.length && ctx.settings.project) projects.push(ctx.settings.project);
  for (const p of projects) {
    try {
      const res = await http.json(`${base(ctx)}/projects/${encodeURIComponent(p)}`, { headers: auth });
      checks.push({ name: `project:${p}`, ok: true, detail: `id=${res.data && res.data.id}` });
    } catch (e) {
      checks.push({ name: `project:${p}`, ok: false, detail: e.message });
    }
  }
  return checks;
}

module.exports = { id: 'gitlab', verbs, doctor };
