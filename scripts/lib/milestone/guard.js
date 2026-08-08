'use strict';

/**
 * guard.js — dispatch 사전조건: 슬롯 회계 · 의존 판정 · 드리프트 · 머신 부하 (순수 함수)
 *
 * 슬롯은 **저장소 작업 디렉터리 = 세션** 단위로 센다. 두 저장소를 동시에 건드리는 항목
 * 하나는 2슬롯이다. 슬롯 상한이 곧 "이 기계에서 동시에 돌릴 수 있는 작업 수"다.
 *
 * 드리프트 게이트: 대상 브랜치가 마일스톤 base 보다 임계 이상 앞서면 슬롯이 남아도 착수를
 * 막는다. 오래된 base 위에서 병렬로 착수하면 통합 시점에 충돌이 한꺼번에 터진다.
 */

const os = require('os');

const { msError } = require('./errors');
const { ACTIVE_STATUSES } = require('./state');

const DEFAULT_CONCURRENCY = Object.freeze({ maxSlots: 4, loadavgLimit: 12 });
const DEFAULT_DRIFT = Object.freeze({ maxCommits: 30, maxFiles: 60 });

// 착수 후보가 될 수 있는 상태 — 아직 워크스페이스를 잡지 않은 것들.
const DISPATCHABLE_STATUSES = Object.freeze(new Set(['queued', 'ready', 'specced']));

// refs 가 없으면 `Object.keys(undefined)` 가 원시 TypeError 로 죽는다 — 어떤 항목이
// 문제인지 전혀 알려주지 않는다. 조용한 기본값(0슬롯)으로 덮으면 슬롯 회계가 틀린 채로
// 계속 진행돼 더 늦게, 더 알아보기 어려운 곳에서 터진다.
const slotsOf = (item) => {
  if (!item || typeof item.refs !== 'object' || item.refs === null || Array.isArray(item.refs)) {
    throw msError('item_corrupt',
      `guard.slotsOf: 항목 ${(item && item.key) || '(key 없음)'} 에 refs 가 없다 — state 손편집으로 손상됐을 수 있다`);
  }
  return Object.keys(item.refs).length;
};

const slotsUsed = (items) => items
  .filter((i) => ACTIVE_STATUSES.has(i.status))
  .reduce((n, i) => n + slotsOf(i), 0);

// {ok, missing:[key]} — 선행이 전부 done 이어야 착수한다.
const dependenciesMet = (item, statusByKey) => {
  const missing = (item.dependsOn || []).filter((d) => statusByKey.get(d) !== 'done');
  return { ok: missing.length === 0, missing };
};

const statusMap = (items) => new Map(items.map((i) => [i.key, i.status]));

// {ok, reasons[]} — measured: {be:{aheadCommits, aheadFiles}, ...}
const driftStatus = (measured = {}, limits = DEFAULT_DRIFT) => {
  const max = { ...DEFAULT_DRIFT, ...(limits || {}) };
  const reasons = [];
  Object.entries(measured).forEach(([repo, m]) => {
    if (!m) return;
    // 프로바이더가 스스로 "드리프트다"라고 답한 경우(계약의 `branch drift-check` 가 exit 2 로
    // 거부한 경우)는 임계와 무관하게 그 판정을 존중한다 — 프로바이더가 우리보다 더 많은
    // 사실(파일 수, 보호 브랜치 규칙 등)을 알 수 있다.
    if (m.drifted === true) {
      reasons.push(m.error
        ? `${repo}: 드리프트를 실측하지 못했다 — ${m.error} (실측 실패를 "드리프트 없음"으로 넘기지 않는다)`
        : `${repo}: 프로바이더가 드리프트로 판정 (ahead ${m.aheadCommits === undefined ? '?' : m.aheadCommits})`);
      return;
    }
    if (typeof m.aheadCommits === 'number' && m.aheadCommits > max.maxCommits) {
      reasons.push(`${repo}: 대상 브랜치가 ${m.aheadCommits}커밋 앞섬 (임계 ${max.maxCommits})`);
    }
    if (typeof m.aheadFiles === 'number' && m.aheadFiles > max.maxFiles) {
      reasons.push(`${repo}: 대상 브랜치가 ${m.aheadFiles}파일 앞섬 (임계 ${max.maxFiles})`);
    }
  });
  return { ok: reasons.length === 0, reasons };
};

// {ok, load, limit} — limit 이 없거나 0 이하면 부하 게이트를 끈다(항상 통과).
const loadStatus = (limit, load = os.loadavg()[0]) => {
  if (typeof limit !== 'number' || limit <= 0) return { ok: true, load, limit: null };
  return { ok: load <= limit, load, limit };
};

// 착수 후보 — 상태가 착수 가능하고 선행이 전부 done 인 항목. 정렬은 호출자(priority)가 한다.
// {candidates, deferred:[{key, reason}]}
const selectCandidates = (items) => {
  const byKey = statusMap(items);
  const candidates = [];
  const deferred = [];
  items.filter((i) => DISPATCHABLE_STATUSES.has(i.status)).forEach((i) => {
    const dep = dependenciesMet(i, byKey);
    if (dep.ok) candidates.push(i);
    else deferred.push({ key: i.key, reason: `의존 미충족 — ${dep.missing.join(', ')} 가 아직 done 이 아니다` });
  });
  return { candidates, deferred };
};

// {allowed, deferred:[{key, reason}], slots:{used, free, max}}
//
// 게이트 순서가 곧 정책이다: 드리프트 → 부하 → 의존 → 슬롯.
// 드리프트/부하는 **후보 전원**을 한꺼번에 보류시키는 전역 게이트이므로 슬롯 계산보다 먼저다.
const dispatchPreflight = ({ items, candidates, drift = {}, load, concurrency = {}, driftLimits = {} }) => {
  const conc = { ...DEFAULT_CONCURRENCY, ...(concurrency || {}) };
  const used = slotsUsed(items);
  const slots = { used, free: Math.max(0, conc.maxSlots - used), max: conc.maxSlots };

  const d = driftStatus(drift, driftLimits);
  if (!d.ok) {
    return {
      allowed: [],
      deferred: candidates.map((c) => ({ key: c.key, reason: `드리프트 초과 — ${d.reasons.join(' / ')}` })),
      slots,
      gate: { kind: 'drift', reasons: d.reasons },
    };
  }

  const l = loadStatus(conc.loadavgLimit, load === undefined ? undefined : load);
  if (!l.ok) {
    return {
      allowed: [],
      deferred: candidates.map((c) => ({ key: c.key, reason: `부하 초과 — loadavg ${l.load} > ${l.limit}` })),
      slots,
      gate: { kind: 'load', reasons: [`loadavg ${l.load} > ${l.limit}`] },
    };
  }

  const byKey = statusMap(items);
  const allowed = [];
  const deferred = [];
  let running = used;

  candidates.forEach((c) => {
    const dep = dependenciesMet(c, byKey);
    if (!dep.ok) {
      deferred.push({ key: c.key, reason: `의존 미충족 — ${dep.missing.join(', ')} 가 아직 done 이 아니다` });
      return;
    }
    const need = slotsOf(c);
    if (running + need <= conc.maxSlots) { allowed.push(c); running += need; }
    else deferred.push({ key: c.key, reason: `슬롯 부족 — ${need}슬롯 필요, 잔여 ${conc.maxSlots - running}` });
  });

  return { allowed, deferred, slots, gate: null };
};

module.exports = {
  DEFAULT_CONCURRENCY, DEFAULT_DRIFT, DISPATCHABLE_STATUSES,
  slotsOf, slotsUsed, dependenciesMet, statusMap, driftStatus, loadStatus, selectCandidates, dispatchPreflight,
};
