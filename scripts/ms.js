#!/usr/bin/env node
/**
 * ms.js — 마일스톤(다중 작업) 오케스트레이션 진입점.
 *
 * `pipeline` 이 이슈 1건의 주기를 안다면, `ms` 는 **여러 항목을 넘나드는 층**이다.
 * 트래커에 결합되지 않는 이유는 하나뿐이다 — 외부 시스템에 닿는 유일한 문이
 * `node scripts/px.js <동사>` 이고, 이 파일은 HTTP 클라이언트를 만들지 않는다.
 *
 * 사용법:
 *   node scripts/ms.js status
 *   node scripts/ms.js plan [--apply] [--force]
 *   node scripts/ms.js dispatch [--apply]
 *   node scripts/ms.js watch [--apply]
 *   node scripts/ms.js advance [--apply]
 *   node scripts/ms.js report [--apply] [--out <file.html>]
 *
 *   --apply 없는 기본은 **항상 dry-run** 이다. 아무것도 쓰지 않고 무엇을 할지만 보여준다.
 *   --json  봉투를 한 줄로 압축한다(기본은 2칸 들여쓴 JSON).
 *
 * 출력 규약(px.js 와 동일):
 *   stdout — 기계 판독용 JSON 봉투 한 덩어리만
 *   stderr — 사람이 읽을 진행/경고 메시지
 *
 * 종료 코드(px.js 와 동일):
 *   0 성공 · 1 사용법·설정·state 오류 · 2 게이트 위반(멈추고 보고) · 3 미지원
 *
 * 알고리즘 정본: kit/workflow/milestone-algorithm.md
 */

'use strict';

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const stateLib = require('./lib/milestone/state');
const priority = require('./lib/milestone/priority');
const planMerge = require('./lib/milestone/plan-merge');
const guard = require('./lib/milestone/guard');
const dispatchLib = require('./lib/milestone/dispatch-plan');
const advanceLib = require('./lib/milestone/advance-plan');
const { msError } = require('./lib/milestone/errors');
const { parseRef } = require('./lib/milestone/ref');

const PX_PATH = path.join(__dirname, 'px.js');
const GEN_MILESTONE = path.join(__dirname, 'gen-milestone.js');
const ADAPTER_NAME = '.review-kit.json';

const USAGE = `사용법: node scripts/ms.js <subcommand> [--apply] [--force] [--json]

  status                현재 Wave·슬롯·blocked 요약
  plan     [--apply]    항목 수집 → 병합 → Wave 제안 (--force: in-flight 배제 대상도 삭제)
  dispatch [--apply]    빈 슬롯 × 우선순위 × 의존 충족 → 착수
  watch    [--apply]    진행 관측 → 상태 전이
  advance  [--apply]    완료 감지 → 슬롯 회수 → 다음 후보 제시
  report   [--apply]    진행 표 (--apply: HTML 생성)

  --apply 가 없으면 항상 dry-run 이다. 설정은 ${ADAPTER_NAME} 의 "milestone" 절에서 온다.
  알고리즘 정본: kit/workflow/milestone-algorithm.md`;

// ── 인자 파싱 (px.js 와 같은 규칙: --flag value / --flag=value / --flag) ──
function parseArgv(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--') { positional.push(...argv.slice(i + 1)); break; }
    if (!a.startsWith('--')) { positional.push(a); continue; }

    const eq = a.indexOf('=');
    let key;
    let value;
    if (eq > 2) {
      key = a.slice(2, eq);
      value = a.slice(eq + 1);
    } else {
      key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) value = true;
      else { value = next; i += 1; }
    }
    flags[key.replace(/-([a-z0-9])/gi, (_, c) => c.toUpperCase())] = value;
  }
  return { positional, flags };
}

function emit(envelope, compact) {
  process.stdout.write(`${JSON.stringify(envelope, null, compact ? 0 : 2)}\n`);
}

const log = (s) => process.stderr.write(`${s}\n`);
const warn = (s) => process.stderr.write(`⚠️  ${s}\n`);

// ── 설정 ────────────────────────────────────────────────────
// 하드코딩된 트래커·저장소·라벨 이름은 이 파일 어디에도 없다. 전부 어댑터에서 온다.
const DEFAULTS = Object.freeze({
  statePath: stateLib.DEFAULT_STATE_PATH,
  reportPath: null,
  base: null,
  branchPattern: dispatchLib.DEFAULT_BRANCH_PATTERN,
  priorityLabels: priority.DEFAULT_PRIORITY_LABELS,
  selector: { repos: [], state: 'open', milestone: null, labels: [], limit: 100, excludeRefs: [], titleExclude: [] },
  concurrency: guard.DEFAULT_CONCURRENCY,
  drift: guard.DEFAULT_DRIFT,
  watch: { evidenceMissLimit: advanceLib.DEFAULT_EVIDENCE_MISS_LIMIT },
});

function loadConfig(cwd) {
  const p = path.join(cwd, ADAPTER_NAME);
  if (!fs.existsSync(p)) {
    throw msError('config_missing', `${ADAPTER_NAME} 없음(${cwd}) — milestone 절이 있어야 한다. 형태: kit/workflow/milestone-algorithm.md "어댑터 설정"`);
  }
  let adapter;
  try {
    adapter = JSON.parse(fs.readFileSync(p, 'utf8').replace(/^﻿/, ''));
  } catch (e) {
    throw msError('config_invalid', `${ADAPTER_NAME} 파싱 실패: ${e.message}`);
  }
  const m = adapter.milestone;
  if (!m || typeof m !== 'object') {
    throw msError('config_missing', `${ADAPTER_NAME} 에 "milestone" 절이 없다 — kit/workflow/milestone-algorithm.md "어댑터 설정" 참고`);
  }

  const cfg = {
    ...DEFAULTS,
    ...m,
    selector: { ...DEFAULTS.selector, ...(m.selector || {}) },
    concurrency: { ...DEFAULTS.concurrency, ...(m.concurrency || {}) },
    drift: { ...DEFAULTS.drift, ...(m.drift || {}) },
    watch: { ...DEFAULTS.watch, ...(m.watch || {}) },
  };
  cfg.statePathAbs = path.resolve(cwd, cfg.statePath);
  if (!cfg.name) cfg.name = m.name || adapter.milestoneName || 'milestone';
  return cfg;
}

// ── px 호출 ─────────────────────────────────────────────────
// 계약의 유일한 문. 여기 외에는 외부 시스템에 닿는 코드가 없다.
function px(args, { allowExit = [0] } = {}) {
  const r = cp.spawnSync(process.execPath, [PX_PATH, ...args, '--json'], {
    encoding: 'utf8',
    cwd: process.cwd(),
  });
  const code = r.status === null ? 1 : r.status;
  let envelope = null;
  const raw = (r.stdout || '').trim();
  if (raw) {
    try { envelope = JSON.parse(raw.split('\n').pop()); } catch { envelope = null; }
  }
  const ok = allowExit.includes(code) && envelope && envelope.ok !== false;
  return {
    ok,
    code,
    envelope,
    data: envelope && envelope.data,
    error: envelope && envelope.error,
    stderr: r.stderr || '',
    command: `px ${args.join(' ')}`,
  };
}

function pxOrThrow(args, what) {
  const r = px(args);
  if (r.ok) return r.data;
  const code = (r.error && r.error.code) || 'px_failed';
  // exit 3(미지원)·2(게이트)는 그대로 물려준다 — 스킬이 폴백/중단을 가려야 하기 때문.
  throw msError(code, `${what} 실패 (${r.command}): ${(r.error && r.error.message) || r.stderr.trim() || `exit ${r.code}`}`,
    { command: r.command, exitCode: r.code }, r.code === 3 ? 3 : r.code === 2 ? 2 : 1);
}

// ── 공통 ────────────────────────────────────────────────────
const nowIso = () => new Date().toISOString();

function loadOrEmpty(cfg) {
  if (!fs.existsSync(cfg.statePathAbs)) return stateLib.emptyState(cfg.name);
  return stateLib.loadState(cfg.statePathAbs);
}

function itemsByKey(items) {
  return new Map(items.map((i) => [i.key, i]));
}

function statusCounts(items) {
  const out = {};
  items.forEach((i) => { out[i.status] = (out[i.status] || 0) + 1; });
  return out;
}

function repoOf(issue, cfg) {
  if (issue.repo) return String(issue.repo).toLowerCase();
  const repos = cfg.selector.repos || [];
  if (repos.length === 1) return String(repos[0]).toLowerCase();
  throw msError('ambiguous_repo',
    `이슈 ${issue.ref} 에 repo 가 없고 selector.repos 가 ${repos.length}개다 — 어느 저장소의 항목인지 정할 수 없다. `
    + '트래커 프로바이더가 Issue.repo 를 채우게 하거나 selector.repos 를 하나로 좁힐 것');
}

function priorityOf(labels, priorityLabels) {
  const set = new Set((labels || []).map(String));
  return (priorityLabels || []).find((l) => set.has(String(l))) || null;
}

// 본문의 `#N` 참조 → 같은 저장소의 key 후보. 확정은 사람이 한다(plan 승인).
function refHintsFrom(body, repo) {
  return [...new Set((String(body || '').match(/#(\d+)/g) || []).map((s) => s.slice(1)))]
    .map((n) => `${repo}:${n}`);
}

function printWarnings(merged, dangling) {
  if (merged.orphans.length) {
    warn(`오펀 ${merged.orphans.length}건 보존 — 이번 수집에 없지만 지우지 않았다: ${merged.orphans.join(', ')}`);
    log('    (정상 종료인지 selector 실수로 이탈했는지 확인할 것. 지웠다면 status·workspace·branches·prs 가 통째로 사라졌다)');
  }
  if (merged.excluded.length) warn(`명시적 제외 ${merged.excluded.length}건 제거: ${merged.excluded.join(', ')}`);
  if (merged.excludedBlocked.length) {
    warn(`삭제 거부 ${merged.excludedBlocked.length}건 — 배제 대상이지만 이미 착수된 항목이라 지우지 않았다: ${merged.excludedBlocked.join(', ')}`);
    log('    이 항목의 workspace/branches/prs 가 유일한 기록이다. 정말 지우려면 --force 를 붙인다.');
  }
  if (merged.absorbed.length) {
    warn(`흡수 ${merged.absorbed.length}건 — 다른 항목이 이 ref 를 소유해 items 에서 뺐다: ${merged.absorbed.join(', ')}`);
    log('    남아있던 status/workspace/prs 가 소유 항목 쪽에 반영됐는지 확인할 것.');
  }
  merged.warnings.forEach((w) => warn(w));
  (dangling || []).forEach((d) => warn(`끊어진 선행 참조: ${d.key} → ${d.dependsOn} (state 에서 정정할 것)`));
}

// ── status ──────────────────────────────────────────────────
function cmdStatus(cfg) {
  const state = loadOrEmpty(cfg);
  const counts = statusCounts(state.items);
  const used = guard.slotsUsed(state.items);
  const slots = { used, max: cfg.concurrency.maxSlots, free: Math.max(0, cfg.concurrency.maxSlots - used) };
  const blocked = state.items.filter((i) => i.status === 'blocked')
    .map((i) => ({ key: i.key, blockedFrom: i.blockedFrom, reason: i.lastObservedReason }));

  log(`마일스톤 ${state.milestone} — 항목 ${state.items.length}건 · 슬롯 ${slots.used}/${slots.max}`);
  Object.entries(counts).forEach(([s, n]) => log(`  ${String(s).padEnd(12)} ${n}건`));
  (state.waves || []).forEach((w) => {
    const done = w.items.filter((k) => (stateLib.findItem(state, k) || {}).status === 'done').length;
    log(`  Wave ${w.id} — ${done}/${w.items.length} done${w.approvedAt ? ` · 승인 ${w.approvedAt}` : ' · 미승인'}`);
  });
  if (blocked.length) {
    log('\n  ⛔ blocked (사람 확인 필요 — 자동 복귀하지 않는다)');
    blocked.forEach((b) => log(`     ${b.key}  (${b.blockedFrom} 에서 멈춤)  ${b.reason || ''}`));
  }

  return { milestone: state.milestone, counts, slots, waves: state.waves || [], blocked, total: state.items.length };
}

// ── plan ────────────────────────────────────────────────────
function cmdPlan(cfg, flags) {
  const apply = Boolean(flags.apply);
  const force = Boolean(flags.force);

  // 네트워크를 타기 전에 selector 형식을 먼저 검증한다 — 오탈자가 "매치 안 됨"으로
  // 조용히 통과하면 스코핑이 fail-open 한다(빼려던 항목이 계획에 그대로 남는다).
  planMerge.assertValidSelector(cfg.selector);

  const prev = loadOrEmpty(cfg);

  const args = ['issue', 'list'];
  if (cfg.selector.state) args.push('--state', String(cfg.selector.state));
  if (cfg.selector.labels && cfg.selector.labels.length) args.push('--labels', cfg.selector.labels.join(','));
  if (cfg.selector.milestone) args.push('--milestone', String(cfg.selector.milestone));
  if (cfg.selector.limit) args.push('--limit', String(cfg.selector.limit));
  const issues = pxOrThrow(args, '이슈 수집');
  if (!Array.isArray(issues)) throw msError('px_contract', 'issue list 가 배열을 반환하지 않았다 — 트래커 프로바이더 확인 필요');

  const wantedRepos = new Set((cfg.selector.repos || []).map((r) => String(r).toLowerCase()));
  const raw = [];
  issues.forEach((i) => {
    const repo = repoOf(i, cfg);
    if (wantedRepos.size && !wantedRepos.has(repo)) return;
    raw.push({
      repo,
      id: String(i.ref),
      title: i.title || '',
      state: i.state,
      priority: priorityOf(i.labels, cfg.priorityLabels),
      refHints: refHintsFrom(i.body, repo),
    });
  });

  const classified = planMerge.classifyItems(raw, cfg.selector);
  const merged = planMerge.mergeItems(prev.items, classified.items, classified.excludedKeys, { force });
  const dangling = planMerge.danglingDependencies(merged.items);

  const waves = priority.computeWaves(merged.items, cfg.priorityLabels);
  if (!waves.ok) {
    printWarnings(merged, dangling);
    throw msError('graph_invalid', `Wave 산출 실패 — ${waves.error}`, { problem: waves.error });
  }
  const nextWaves = planMerge.mergeWaves(prev.waves, waves.waves);

  log(`수집 ${raw.length}건 → 포함 ${classified.items.length}건 · 명시적 제외 ${classified.excludedKeys.length}건`);
  printWarnings(merged, dangling);

  const byKey = itemsByKey(merged.items);
  log('\n── Wave 제안 ──');
  nextWaves.forEach((w) => {
    log(`  Wave ${w.id} (${w.items.length}건)${w.approvedAt ? ` · 승인 ${w.approvedAt}` : ''}`);
    w.items.forEach((k) => {
      const it = byKey.get(k) || {};
      const deps = (it.dependsOn || []).length ? ` ← ${it.dependsOn.join(', ')}` : '';
      log(`     ${k.padEnd(12)} ${String(it.priority || '-').padEnd(4)} ${it.status.padEnd(10)} ${String(it.title || '').slice(0, 48)}${deps}`);
    });
  });

  const next = {
    ...prev,
    version: stateLib.STATE_VERSION,
    milestone: prev.milestone || cfg.name,
    base: cfg.base || prev.base || null,
    items: merged.items,
    waves: nextWaves,
    integration: { ...(prev.integration || {}), lastPlannedAt: apply ? nowIso() : (prev.integration || {}).lastPlannedAt || null },
  };

  if (apply) {
    stateLib.saveState(cfg.statePathAbs, next);
    log(`\n✅ 저장: ${cfg.statePath} (직전 원본은 ${cfg.statePath}.bak — 한 단계 깊이뿐이다)`);
  } else {
    log('\nℹ️  dry-run — 아무것도 쓰지 않았다. Wave 를 검토·승인한 뒤 --apply 를 붙인다.');
  }

  return {
    applied: apply,
    fetched: raw.length,
    included: classified.items.length,
    excludedBySelector: classified.excludedKeys,
    orphans: merged.orphans,
    excluded: merged.excluded,
    excludedBlocked: merged.excludedBlocked,
    absorbed: merged.absorbed,
    warnings: merged.warnings,
    dangling,
    waves: nextWaves,
    items: merged.items.map((i) => ({ key: i.key, status: i.status, priority: i.priority, title: i.title, dependsOn: i.dependsOn })),
  };
}

// ── 드리프트 실측 ───────────────────────────────────────────
function measureDrift(cfg, repos) {
  const measured = {};
  repos.forEach((repo) => {
    const args = ['branch', 'drift-check', '--repo', repo];
    if (cfg.base) args.push('--target', cfg.base);
    const r = px(args, { allowExit: [0, 2] });
    // exit 3 은 "이 프로바이더는 드리프트를 모른다"는 계약상의 명시적 답이다 — 게이트를 끈다.
    // 그 외의 실패(설정 없음·네트워크·토큰)는 **실측하지 못한 것**이지 "드리프트 없음"이
    // 아니다. 안전 게이트를 fail-open 시키지 않고 드리프트로 간주해 멈춘다.
    if (r.code === 3) return;
    if (!r.ok && r.code !== 2) {
      measured[repo] = { drifted: true, error: (r.error && r.error.message) || r.stderr.trim() || `exit ${r.code}` };
      return;
    }
    const d = r.data || (r.error && r.error.data) || {};
    measured[repo] = {
      drifted: r.code === 2 || d.drifted === true,
      aheadCommits: typeof d.ahead === 'number' ? d.ahead : undefined,
      aheadFiles: typeof d.files === 'number' ? d.files : undefined,
    };
  });
  return measured;
}

// ── dispatch ────────────────────────────────────────────────
function cmdDispatch(cfg, flags) {
  const apply = Boolean(flags.apply);
  const state = stateLib.loadState(cfg.statePathAbs);

  const picked = guard.selectCandidates(state.items);
  const sorted = priority.sortItems(picked.candidates, cfg.priorityLabels);
  if (!sorted.ok) throw msError('graph_invalid', `우선순위 산출 실패 — ${sorted.error}`);

  const gate = dispatchLib.slugGate(sorted.items, cfg.statePath);
  const repos = [...new Set(state.items.flatMap((i) => Object.keys(i.refs)))];
  const drift = measureDrift(cfg, repos);

  const preflight = guard.dispatchPreflight({
    items: state.items,
    candidates: gate.ready,
    drift,
    concurrency: cfg.concurrency,
    driftLimits: cfg.drift,
  });
  const plan = dispatchLib.buildDispatchPlan({
    items: state.items, candidates: gate.ready, preflight, base: cfg.base,
    pxPath: path.relative(process.cwd(), PX_PATH).split(path.sep).join('/'),
  });

  log(`슬롯 ${plan.slots.used}/${plan.slots.max} · 후보 ${sorted.items.length}건`);
  gate.blocked.forEach((b) => warn(`보류 ${b.key} — ${b.reason}`));
  picked.deferred.forEach((d) => log(`  보류 ${d.key} — ${d.reason}`));
  plan.deferred.forEach((d) => log(`  보류 ${d.key} — ${d.reason}`));

  if (plan.gate) {
    log(`\n⛔ ${plan.gate.kind} 게이트 — 후보 전원 보류`);
    plan.gate.reasons.forEach((r) => log(`   ${r}`));
    throw msError('gate_blocked', `${plan.gate.kind} 게이트에 걸려 아무것도 착수하지 않았다 — ${plan.gate.reasons.join(' / ')}`,
      { gate: plan.gate, slots: plan.slots }, 2);
  }

  if (!plan.dispatch.length) {
    log('\n착수할 항목이 없다.');
    return { applied: false, dispatched: [], deferred: plan.deferred, blocked: gate.blocked, slots: plan.slots };
  }

  log('\n── 착수 대상 ──');
  plan.dispatch.forEach((d) => {
    log(`\n▶ ${d.key}  ${String(d.title || '').slice(0, 60)}`);
    d.commands.forEach((c) => log(`    ${c}`));
    log('    이후 이 워크스페이스에서 pipeline 한 주기를 돌린다(마일스톤 층은 직접 구현하지 않는다):');
    d.handoff.split('\n').forEach((l) => log(`      ${l}`));
  });

  if (!apply) {
    log('\nℹ️  dry-run — 실행하지 않았다. 위 명령을 검토한 뒤 --apply 를 붙인다.');
    return { applied: false, dispatched: plan.dispatch, deferred: plan.deferred, blocked: gate.blocked, slots: plan.slots };
  }

  // --apply — 부분 성공을 반드시 기록한다. 전부 처리한 뒤 실패가 있으면 그때 실패로 끝낸다.
  let next = state;
  const succeeded = [];
  const failed = [];

  plan.dispatch.forEach((d) => {
    const created = px(['ws', 'create', d.slug, '--issue', String(d.refs[d.key.split(':')[0]]), '--repo', Object.keys(d.refs).join(',')]);
    if (!created.ok) {
      failed.push({ key: d.key, step: 'ws create', message: (created.error && created.error.message) || created.stderr.trim() });
      return;
    }
    const verified = px(['ws', 'verify', d.slug], { allowExit: [0, 2] });
    if (!verified.ok) {
      failed.push({ key: d.key, step: 'ws verify', message: (verified.error && verified.error.message) || verified.stderr.trim() });
      return;
    }
    px(['ws', 'stage', d.slug, 'SPEC']);

    const ws = created.data || {};
    const branches = {};
    (ws.repos || []).forEach((r) => { if (r.id && r.branch) branches[r.id] = r.branch; });

    const item = stateLib.findItem(next, d.key);
    const walked = advanceLib.walkTo(item, 'dispatched', { reason: `dispatch (${d.slug})` });
    if (!walked.ok) {
      failed.push({ key: d.key, step: 'transition', message: walked.error });
      return;
    }
    next = stateLib.replaceItem(next, {
      ...walked.item,
      slug: d.slug,
      workspace: ws.root || d.slug,
      branches: { ...(item.branches || {}), ...branches },
    });
    succeeded.push({ key: d.key, workspace: ws.root || d.slug, branches });
    log(`✅ 착수 ${d.key} — ${ws.root || d.slug}`);
  });

  if (succeeded.length) {
    next = { ...next, integration: { ...(next.integration || {}), lastDispatchedAt: nowIso() } };
    stateLib.saveState(cfg.statePathAbs, next);
    log(`\n state 갱신: 착수 ${succeeded.length}건`);
  } else {
    log('\n state 갱신 없음 — 착수된 항목이 없다.');
  }
  failed.forEach((f) => warn(`착수 실패 ${f.key} (${f.step}): ${f.message}`));

  const result = { applied: true, dispatched: succeeded, failed, deferred: plan.deferred, blocked: gate.blocked, slots: plan.slots };
  if (failed.length) {
    throw msError('dispatch_partial',
      `착수 ${succeeded.length}건 성공 · ${failed.length}건 실패 — 성공분은 state 에 기록했다`, result, 1);
  }
  return result;
}

// ── 관측 ────────────────────────────────────────────────────
function observe(cfg, state) {
  const observations = {};

  // 워크스페이스 스테이지 — `ws list` 한 번으로 전부 얻는다(항목마다 조회하지 않는다).
  const wsList = px(['ws', 'list'], { allowExit: [0, 3] });
  const stageBySlug = new Map();
  if (wsList.ok && Array.isArray(wsList.data)) {
    wsList.data.forEach((w) => { if (w.slug) stageBySlug.set(w.slug, w.stage); });
  }

  state.items
    .filter((i) => stateLib.ACTIVE_STATUSES.has(i.status) && i.status !== 'blocked')
    .forEach((item) => {
      const branches = dispatchLib.branchesFor(item, cfg.branchPattern);
      const prStates = [];
      const observedRepos = [];
      let error = null;

      Object.entries(branches).forEach(([repo, branch]) => {
        if (!branch) return;
        const r = px(['pr', 'get', '--source', branch, '--repo', repo], { allowExit: [0] });
        // 조회 실패(Err)와 못 찾음(빈 결과)은 같게 취급한다 — 둘 다 "이번 라운드에 이
        // 저장소의 근거를 못 얻었다"는 같은 뜻이다. 사유 문구만 구분한다.
        if (!r.ok) {
          if (r.error && r.error.code !== 'not_found') error = r.error.message;
          return;
        }
        if (!r.data || !r.data.state) return;
        prStates.push(r.data.state);
        observedRepos.push(repo);
      });

      observations[item.key] = {
        stage: stageBySlug.get(item.slug) || null,
        prStates,
        observedRepos,
        error,
      };
    });

  return observations;
}

function runWatch(cfg, state, apply, integrationPatch) {
  const observations = observe(cfg, state);
  const plan = advanceLib.planTransitions({
    items: state.items,
    observations,
    evidenceMissLimit: cfg.watch.evidenceMissLimit,
    branchPattern: cfg.branchPattern,
  });

  plan.unobservable.forEach((u) => warn(`관측 불가 — ${u.reason}`));
  plan.held.forEach((h) => log(`  증거 불충분 미스 ${h.missCount}/${h.limit}회 — ${h.key} blocked 전이 보류 (${h.reason})`));

  if (plan.transitions.length) {
    log('\n── 감지된 전이 ──');
    plan.transitions.forEach((t) => {
      log(`  ${t.key}: ${t.from} → ${t.to}${t.path.length > 1 ? ` (경유: ${t.path.join(' → ')})` : ''}`);
      if (t.reason) log(`  └ ${t.reason}`);
    });
  } else {
    log('감지된 전이 없음.');
  }

  // 거부는 apply 도중 생긴 것까지 전부 확정된 뒤에 한 번에 출력한다.
  if (plan.rejected.length) {
    log('\n── 전이 거부(수동 확인 필요) ──');
    plan.rejected.forEach((r) => log(`  ${r.key}: 현재 ${r.from} · 관측 ${r.observed} — ${r.reason}`));
  }
  if (plan.blockedItems.length) {
    log('\n── ⛔ blocked (관측 대상에서 제외 — 자동 복귀하지 않는다) ──');
    plan.blockedItems.forEach((b) => log(`  ${b.key} (${b.blockedFrom} 에서 멈춤) ${b.reason || ''}`));
  }

  let saved = false;
  const changed = plan.items.some((it, idx) => it !== state.items[idx]);
  if (apply && (plan.appliedCount > 0 || changed)) {
    // 적용 0건이면 파일을 쓰지 않는다 — 내용은 그대로인데 mtime 만 새로 찍히면
    // "state 갱신 없음" 메시지와 실제 파일 상태가 어긋난다. 단 증거미스 카운터가
    // 올라간 것은 실제 내용 변화이므로 저장한다.
    stateLib.saveState(cfg.statePathAbs, {
      ...state,
      items: plan.items,
      integration: { ...(state.integration || {}), ...(integrationPatch || {}) },
    });
    saved = true;
    log(`\n state 갱신: 적용 ${plan.appliedCount}건 · 건너뜀 ${plan.rejected.length + plan.unobservable.length}건(수동 확인 필요)`);
  } else if (apply) {
    log('\n state 갱신 없음.');
  } else {
    log('\nℹ️  dry-run — 아무것도 쓰지 않았다.');
  }

  return { plan, saved, observations };
}

function cmdWatch(cfg, flags) {
  const state = stateLib.loadState(cfg.statePathAbs);
  const { plan, saved } = runWatch(cfg, state, Boolean(flags.apply));
  return {
    applied: Boolean(flags.apply) && saved,
    transitions: plan.transitions,
    rejected: plan.rejected,
    held: plan.held,
    unobservable: plan.unobservable,
    blocked: plan.blockedItems,
  };
}

// ── advance ─────────────────────────────────────────────────
function cmdAdvance(cfg, flags) {
  const apply = Boolean(flags.apply);
  const state = stateLib.loadState(cfg.statePathAbs);
  const { plan, saved } = runWatch(cfg, state, apply, { lastAdvancedAt: nowIso() });

  const after = { ...state, items: plan.items };
  const freed = advanceLib.reclaimedSlots(plan.transitions, itemsByKey(after.items));
  const used = guard.slotsUsed(after.items);
  const slots = { used, max: cfg.concurrency.maxSlots, free: Math.max(0, cfg.concurrency.maxSlots - used) };

  log(`\n슬롯 ${slots.used}/${slots.max} (이번 라운드 회수 ${freed})`);

  const picked = guard.selectCandidates(after.items);
  const sorted = priority.sortItems(picked.candidates, cfg.priorityLabels);
  const nextUp = sorted.ok ? sorted.items.slice(0, Math.max(0, slots.free)) : [];

  if (nextUp.length) {
    log('\n── 다음 착수 후보 ──');
    nextUp.forEach((i) => log(`  ${i.key.padEnd(12)} ${String(i.priority || '-').padEnd(4)} ${String(i.title || '').slice(0, 48)}`));
    log("\n  착수하려면: node scripts/ms.js dispatch --apply");
  } else {
    log('\n빈 슬롯에 넣을 후보가 없다.');
  }

  const waveDone = (after.waves || []).map((w) => ({
    id: w.id,
    done: w.items.filter((k) => (stateLib.findItem(after, k) || {}).status === 'done').length,
    total: w.items.length,
  }));
  waveDone.filter((w) => w.total > 0 && w.done === w.total)
    .forEach((w) => log(`\n✅ Wave ${w.id} 전 항목 done — 통합 시점이다(통합은 호스트 프로젝트 절차를 따른다).`));

  return {
    applied: apply && saved,
    transitions: plan.transitions,
    rejected: plan.rejected,
    freedSlots: freed,
    slots,
    nextUp: nextUp.map((i) => ({ key: i.key, priority: i.priority, title: i.title })),
    waves: waveDone,
  };
}

// ── report ──────────────────────────────────────────────────
function cmdReport(cfg, flags) {
  const state = stateLib.loadState(cfg.statePathAbs);
  const byKey = itemsByKey(state.items);

  log(`마일스톤 ${state.milestone} — 항목 ${state.items.length}건`);
  (state.waves || []).forEach((w) => {
    const done = w.items.filter((k) => (byKey.get(k) || {}).status === 'done').length;
    log(`\n  Wave ${w.id} — ${done}/${w.items.length} done`);
    w.items.forEach((k) => {
      const it = byKey.get(k) || {};
      log(`    ${k.padEnd(12)} ${String(it.status || '?').padEnd(11)} ${String(it.priority || '-').padEnd(4)} ${String(it.title || '').slice(0, 44)}`);
    });
  });

  if (!flags.apply) {
    log('\nℹ️  dry-run — HTML 을 만들지 않았다. --apply 를 붙이면 gen-milestone.js 로 렌더링한다.');
    return { applied: false, milestone: state.milestone, waves: state.waves || [] };
  }

  const out = flags.out || cfg.reportPath || null;
  const args = [GEN_MILESTONE, cfg.statePathAbs];
  if (out) args.push(path.resolve(process.cwd(), out));
  const r = cp.spawnSync(process.execPath, args, { encoding: 'utf8' });
  process.stderr.write(r.stdout || '');
  if (r.status !== 0) {
    throw msError('report_failed', `gen-milestone 실패: ${(r.stderr || '').trim() || `exit ${r.status}`}`);
  }
  const written = (r.stdout || '').match(/gen-milestone 완료: (.+)/);
  return { applied: true, milestone: state.milestone, output: written ? written[1].trim() : (out || null) };
}

// ── 본체 ────────────────────────────────────────────────────
const COMMANDS = { status: cmdStatus, plan: cmdPlan, dispatch: cmdDispatch, watch: cmdWatch, advance: cmdAdvance, report: cmdReport };

function main() {
  const { positional, flags } = parseArgv(process.argv.slice(2));
  const compact = Boolean(flags.json);
  const sub = positional[0];

  if (!sub || sub === 'help' || flags.help) {
    process.stderr.write(`${USAGE}\n`);
    process.exit(sub ? 0 : 1);
  }

  const handler = COMMANDS[sub];
  if (!handler) {
    process.stderr.write(`❌ 알 수 없는 서브커맨드: ${sub}\n\n${USAGE}\n`);
    emit({ ok: false, verb: `ms.${sub}`, error: { code: 'usage', message: `알 수 없는 서브커맨드: ${sub}` } }, compact);
    process.exit(1);
  }

  const verb = `ms.${sub}`;
  try {
    const cfg = loadConfig(process.cwd());
    const data = handler(cfg, flags);
    emit({ ok: true, verb, data: data === undefined ? null : data }, compact);
    process.exit(0);
  } catch (e) {
    const code = typeof e.code === 'string' ? e.code : 'internal';
    const exitCode = typeof e.exitCode === 'number' ? e.exitCode : 1;
    const error = { code, message: e.message };
    if (e.data !== undefined) error.data = e.data;
    emit({ ok: false, verb, error }, compact);

    const icon = exitCode === 2 ? '⛔' : exitCode === 3 ? '➖' : '❌';
    process.stderr.write(`${icon} ${e.message}\n`);
    if (code === 'internal' && e.stack) process.stderr.write(`${e.stack}\n`);
    process.exit(exitCode);
  }
}

if (require.main === module) main();

module.exports = { parseArgv, loadConfig, priorityOf, refHintsFrom, repoOf, DEFAULTS };
