'use strict';

// local 트래커 — 이슈를 파일 하나당 하나씩 .pipeline/issues/<ref>.json 으로 둔다.
// GitLab/GitHub 없이도 라이프사이클 스킬 전체를 굴려볼 수 있게 하는 게 목적이라
// 네트워크도 토큰도 쓰지 않는다. doctor와 e2e 검증의 기준 구현이기도 하다.
//
// pr 계열은 여기 없다 — verbs 표에 없는 동사는 index.js가 exit 3(unsupported)으로
// 답한다. 계약 §4의 "미지원 동사는 던지지 말고 exit 3" 이 그 뜻이다.

const fs = require('fs');
const path = require('path');
const { PxError, requireArg, requireFlag, requireYes, selectRepo, splitList } = require('../index');

const DEFAULT_DIR = '.pipeline/issues';

function issuesDir(ctx) {
  const dir = ctx.settings.dir || DEFAULT_DIR;
  // 상대 경로는 .pipeline.json 이 있는 디렉터리 기준이다 — cwd 기준으로 하면
  // 워커가 하위 디렉터리에서 px를 부를 때마다 다른 저장소를 보게 된다.
  return path.isAbsolute(dir) ? dir : path.join(ctx.rootDir, dir);
}

function ensureDir(ctx) {
  const dir = issuesDir(ctx);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function filePath(ctx, ref) {
  if (!/^[\w.-]+$/.test(String(ref))) throw new PxError('usage', `이슈 ref 가 파일명으로 쓸 수 없는 모양이다: '${ref}'`);
  return path.join(issuesDir(ctx), `${ref}.json`);
}

function readIssue(ctx, ref) {
  const p = filePath(ctx, ref);
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    throw new PxError('bad_config', `${p} JSON 파싱 실패: ${e.message}`);
  }
}

function writeIssue(ctx, issue) {
  ensureDir(ctx);
  fs.writeFileSync(filePath(ctx, issue.ref), `${JSON.stringify(issue, null, 2)}\n`, 'utf8');
  return issue;
}

function listAll(ctx) {
  const dir = issuesDir(ctx);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => readIssue(ctx, f.slice(0, -5)))
    .filter(Boolean)
    .sort((a, b) => Number(a.ref) - Number(b.ref) || String(a.ref).localeCompare(String(b.ref)));
}

// 파일명의 최대 숫자 + 1. 동시 실행이면 겹칠 수 있지만, local 트래커는 한 사람이
// 오프라인으로 굴리는 용도라 락까지 두지 않았다 — 겹치면 뒤에 쓴 쪽이 이긴다.
function nextRef(ctx) {
  const nums = listAll(ctx).map((i) => Number(i.ref)).filter((n) => Number.isFinite(n));
  return String((nums.length ? Math.max(...nums) : 0) + 1);
}

function nowIso() {
  return new Date().toISOString();
}

function shape(issue) {
  // 계약 2.1의 Issue 스키마만 밖으로 내보낸다(createdAt 같은 내부 필드는 파일에만 남긴다).
  return {
    ref: issue.ref,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels || [],
    assignee: issue.assignee ?? null,
    milestone: issue.milestone ?? null,
    url: issue.url ?? null,     // 로컬 파일이라 URL은 항상 null
    repo: issue.repo ?? null,
  };
}

function repoId(ctx, flags) {
  const repo = selectRepo(ctx, flags);
  return repo ? repo.id : null;
}

const verbs = {
  'issue.get': async (ctx, args) => {
    const ref = requireArg(args, 0, 'ref', 'issue.get');
    const issue = readIssue(ctx, ref);
    if (!issue) throw new PxError('not_found', `이슈 ${ref} 가 없다 (${filePath(ctx, ref)})`);
    return shape(issue);
  },

  'issue.create': async (ctx, args, flags) => {
    const title = requireFlag(flags, 'title', 'issue.create');
    // 멱등성(계약 §1): 같은 제목의 열린 이슈가 이미 있으면 새로 만들지 않고 그걸 준다.
    // 워커가 재실행돼도 이슈가 두 개로 갈라지지 않아야 하기 때문이다.
    const dup = listAll(ctx).find((i) => i.state === 'open' && i.title === title);
    if (dup) {
      process.stderr.write(`↺ 같은 제목의 열린 이슈 ${dup.ref} 가 이미 있다 — 새로 만들지 않고 그대로 돌려준다.\n`);
      return shape(dup);
    }
    const ref = nextRef(ctx);
    const issue = {
      ref,
      title,
      body: flags.body === undefined || flags.body === true ? '' : String(flags.body),
      state: 'open',
      labels: splitList(flags.labels) || [],
      assignee: flags.assignee && flags.assignee !== true ? String(flags.assignee) : null,
      milestone: flags.milestone && flags.milestone !== true ? String(flags.milestone) : null,
      url: null,
      repo: repoId(ctx, flags),
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    writeIssue(ctx, issue);
    process.stderr.write(`✅ 이슈 ${ref} 생성 — ${filePath(ctx, ref)}\n`);
    return shape(issue);
  },

  'issue.update': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.update');
    const issue = readIssue(ctx, ref);
    if (!issue) throw new PxError('not_found', `이슈 ${ref} 가 없다 (${filePath(ctx, ref)})`);

    if (flags.title !== undefined && flags.title !== true) issue.title = String(flags.title);
    if (flags.body !== undefined && flags.body !== true) issue.body = String(flags.body);
    if (flags.assignee !== undefined) issue.assignee = flags.assignee === true ? null : String(flags.assignee);
    if (flags.milestone !== undefined) issue.milestone = flags.milestone === true ? null : String(flags.milestone);

    const add = splitList(flags.addLabels) || [];
    const remove = splitList(flags.removeLabels) || [];
    const labels = new Set(issue.labels || []);
    add.forEach((l) => labels.add(l));
    remove.forEach((l) => labels.delete(l));
    issue.labels = [...labels];

    issue.updatedAt = nowIso();
    writeIssue(ctx, issue);
    return shape(issue);
  },

  'issue.close': async (ctx, args, flags) => {
    const ref = requireArg(args, 0, 'ref', 'issue.close');
    const issue = readIssue(ctx, ref);
    if (!issue) throw new PxError('not_found', `이슈 ${ref} 가 없다 (${filePath(ctx, ref)})`);
    if (issue.state === 'closed') {
      // 이미 닫혀 있으면 --yes 없이도 성공이다. 멱등성이 확인 절차보다 먼저다 —
      // 여기서 exit 2를 주면 재실행하는 워커가 매번 막힌다.
      process.stderr.write(`↺ 이슈 ${ref} 는 이미 closed 다.\n`);
      return shape(issue);
    }
    requireYes(flags, 'issue.close', { ref, title: issue.title, willBecome: 'closed' });
    issue.state = 'closed';
    issue.updatedAt = nowIso();
    writeIssue(ctx, issue);
    return shape(issue);
  },

  'issue.list': async (ctx, args, flags) => {
    const state = flags.state && flags.state !== true ? String(flags.state) : 'open';
    if (!['open', 'closed', 'all'].includes(state)) {
      throw new PxError('usage', `--state 는 open|closed|all 중 하나다 — 받은 값: '${state}'`);
    }
    const wantLabels = splitList(flags.labels) || [];
    const milestone = flags.milestone && flags.milestone !== true ? String(flags.milestone) : null;
    const limit = Number(flags.limit) || 0;

    let items = listAll(ctx);
    if (state !== 'all') items = items.filter((i) => i.state === state);
    if (wantLabels.length) items = items.filter((i) => wantLabels.every((l) => (i.labels || []).includes(l)));
    if (milestone) items = items.filter((i) => i.milestone === milestone);
    if (limit) items = items.slice(0, limit);
    return items.map(shape);
  },
};

async function doctor(ctx) {
  const dir = issuesDir(ctx);
  const checks = [];
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.accessSync(dir, fs.constants.W_OK);
    checks.push({ name: 'issues-dir', ok: true, detail: `${dir} (쓰기 가능, 이슈 ${listAll(ctx).length}건)` });
  } catch (e) {
    checks.push({ name: 'issues-dir', ok: false, detail: `${dir} 사용 불가: ${e.message}` });
  }
  checks.push({ name: 'pr-verbs', ok: true, detail: 'local 트래커는 pr 계열 미지원 — 호출 시 exit 3' });
  return checks;
}

module.exports = { id: 'local', verbs, doctor };
