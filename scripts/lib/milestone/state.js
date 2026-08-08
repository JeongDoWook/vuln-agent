'use strict';

/**
 * state.js — 마일스톤 state 의 스키마 검증 · I/O · 상태 전이
 *
 * state 파일은 JSON 이다(기본 경로 `.review-kit-milestone.json`). 스키마 정본은
 * `scripts/schema/milestone-state.schema.json`, 이 파일은 그 스키마 중 **런타임이 실제로
 * 의존하는 최소 불변식**만 코드로 강제한다.
 *
 * ## state 손편집 방어 — 왜 로드 시점에 한 번에 검증하나
 *
 * 알고리즘 문서는 여러 지점에서 "state 를 직접 고쳐라"라고 안내한다(dependsOn 확정,
 * slug 확정, blocked 복귀). 즉 손상된 state 는 드문 사고가 아니라 **예상 가능한 입력**이다.
 * 검증이 없으면 `guard.slotsOf` 의 `Object.keys(item.refs)` 가 원시 TypeError 로 죽거나,
 * `priority.minId` 의 `Math.min()` 이 조용히 `Infinity` 를 돌려줘 그 항목이 정렬 맨 뒤로
 * 밀리는 **티 안 나는 오답**을 낸다 — 어느 쪽도 "어떤 항목의 어떤 필드가 문제인지"를
 * 말해주지 않는다.
 *
 * 그래서 로드하는 바로 그 순간(문제를 가장 진단하기 쉬운 시점)에 **필드 이름을 대며**
 * 실패한다. `guard.slotsOf`·`priority.minId` 에도 같은 방어를 남겨둔다(벨트+서스펜더) —
 * 두 함수는 손으로 만든 item 으로 직접 단위테스트되기도 하고, loadState 를 우회하는
 * 호출 경로를 완전히 배제할 수 없기 때문이다.
 *
 * ## 쓰기 직전 백업
 *
 * saveState 는 items 를 통째로 덮어쓸 수 있는 유일한 지점이다(exclude 삭제 포함).
 * 원본이 있을 때만 `{name}.json.bak` 으로 복사한 뒤 쓴다 — **한 단계 깊이뿐이다.**
 * 연속 `--apply` 는 직전 `.bak` 을 덮어쓴다(복구용 아카이브가 아니라 직전 스냅샷).
 */

const fs = require('fs');
const path = require('path');

const { msError } = require('./errors');
const { isRef, parseRef } = require('./ref');

const DEFAULT_STATE_PATH = '.review-kit-milestone.json';
const STATE_VERSION = 1;

// 워크스페이스가 살아있어 슬롯을 점유하는 상태.
//
// - `merged` 를 포함하는 이유: 병합돼도 `finish`(작업공간 정리) 전까지 clone 과 세션이 남아 있다.
// - `blocked` 를 포함하는 이유: 멈춘 항목도 워크스페이스·세션은 그대로 살아 있다. 빼두면
//   dual(2저장소) 항목이 blocked 로 멈추는 즉시 슬롯 2개가 조용히 풀려, 실제로는 꽉 찬
//   용량 위로 dispatch 가 새 작업을 얹는다(원본에서 controller 로 실증된 사고다).
//
// 주의 — 이 집합은 "슬롯 점유 여부"만 정한다. "watch 가 이 상태의 항목을 자동으로 재관측해
// 되돌려도 되는가"는 별개다. blocked 의 자동 복귀는 하지 않는다(advance-plan 의 observable
// 분리 참고) — 복귀는 사람이 `blockedFrom` 으로 직접 되돌릴 때만 일어난다.
const ACTIVE_STATUSES = Object.freeze(new Set(['dispatched', 'impl', 'qa_ok', 'pr_open', 'merged', 'blocked']));

const TRANSITIONS = Object.freeze({
  queued:     ['ready', 'blocked'],
  ready:      ['specced', 'blocked'],
  specced:    ['dispatched', 'blocked'],
  dispatched: ['impl', 'blocked'],
  impl:       ['qa_ok', 'blocked'],
  qa_ok:      ['pr_open', 'blocked'],
  pr_open:    ['merged', 'blocked'],
  merged:     ['done', 'blocked'],
  done:       [],
  blocked:    [],  // 복귀는 blockedFrom 으로만 — canTransition 에서 특수 처리
});

const STATUSES = Object.freeze(Object.keys(TRANSITIONS));

// 아직 착수하지 않은(= 배제해도 잃을 기록이 없는) 상태.
const BACKLOG_STATUS = 'queued';

// {ok:true} | {ok:false, error}
const canTransition = (item, next) => {
  if (item.status === 'blocked') {
    return next === item.blockedFrom
      ? { ok: true }
      : { ok: false, error: `blocked 복귀는 blockedFrom(${item.blockedFrom})으로만 가능 — 요청: ${next}` };
  }
  const allowed = TRANSITIONS[item.status];
  if (!allowed) return { ok: false, error: `알 수 없는 상태: ${item.status}` };
  return allowed.includes(next)
    ? { ok: true }
    : { ok: false, error: `전이 불가: ${item.status} → ${next}` };
};

// {ok:true, item} | {ok:false, error}
//
// `notes` 는 사람 소유 필드라 **절대 건드리지 않는다.** 기계 관측(시각·사유)은
// lastObservedAt/lastObservedReason 에만 남긴다 — watch 가 한 라운드에 여러 게이트를
// 연쇄 적용하는 다단계 전이가 일상이라, 관측 사유를 notes 에 밀어넣으면 한 번의
// `watch --apply` 가 사람이 쓴 메모를 스텝 수만큼 덮어쓴다.
const applyTransition = (item, next, { reason = '', at = null } = {}) => {
  const c = canTransition(item, next);
  if (!c.ok) return c;
  const observation = {
    lastObservedAt: at || new Date().toISOString(),
    lastObservedReason: reason || null,
  };
  const patch = next === 'blocked'
    ? { status: 'blocked', blockedFrom: item.status, ...observation }
    : { status: next, blockedFrom: null, ...observation };
  return { ok: true, item: { ...item, ...patch } };
};

// 항목 하나의 필수 필드를 검사한다. 문제가 있으면 **어느 항목의 어느 필드인지** 담은
// 문자열, 없으면 null.
const validateItemShape = (item, idx) => {
  const label = (item && typeof item.key === 'string' && item.key) || `items[${idx}]`;
  if (!item || typeof item !== 'object' || Array.isArray(item)) return `${label}: 항목이 객체가 아니다`;
  if (typeof item.key !== 'string' || item.key === '') return `${label}: key 가 없거나 비문자열이다`;
  if (!isRef(item.key)) return `${label}: key 가 "<repo>:<id>" 형식이 아니다`;

  if (!item.refs || typeof item.refs !== 'object' || Array.isArray(item.refs)) {
    return `${label}: refs 가 없거나 객체가 아니다(손 편집으로 필드가 지워졌을 수 있다)`;
  }
  const repos = Object.keys(item.refs);
  if (repos.length === 0) return `${label}: refs 가 비어있다(최소 1개 "<repo>": "<id>" 필요)`;
  for (const repo of repos) {
    if (!isRef(`${repo}:${item.refs[repo]}`)) {
      return `${label}: refs.${repo} 값이 "<repo>:<id>" 로 조합되지 않는다(현재: ${JSON.stringify(item.refs[repo])})`;
    }
  }

  if (typeof item.status !== 'string' || item.status === '') return `${label}: status 가 없거나 비문자열이다`;
  if (!TRANSITIONS[item.status]) return `${label}: status 가 알 수 없는 값이다(${item.status}) — 허용: ${STATUSES.join(', ')}`;
  if (item.status === 'blocked' && item.blockedFrom && !TRANSITIONS[item.blockedFrom]) {
    return `${label}: blockedFrom 이 알 수 없는 상태다(${item.blockedFrom})`;
  }

  if (item.dependsOn !== undefined && !Array.isArray(item.dependsOn)) return `${label}: dependsOn 이 배열이 아니다`;
  for (const dep of item.dependsOn || []) {
    if (!isRef(dep)) return `${label}: dependsOn 의 ${JSON.stringify(dep)} 가 "<repo>:<id>" 형식이 아니다`;
  }

  if (item.evidenceMissCount !== undefined
      && (typeof item.evidenceMissCount !== 'number' || !Number.isFinite(item.evidenceMissCount))) {
    return `${label}: evidenceMissCount 가 유한한 숫자가 아니다`;
  }
  return null;
};

// state 전체의 최소 불변식. 문제가 있으면 문자열, 없으면 null.
const validateState = (state) => {
  if (!state || typeof state !== 'object' || Array.isArray(state)) return 'state 최상위가 객체가 아니다';
  if (typeof state.milestone !== 'string' || state.milestone === '') return 'milestone: 마일스톤 이름이 없거나 비문자열이다';
  if (!Array.isArray(state.items)) return 'items: 배열이 아니다';

  const seen = new Set();
  for (let i = 0; i < state.items.length; i += 1) {
    const problem = validateItemShape(state.items[i], i);
    if (problem) return problem;
    const { key } = state.items[i];
    if (seen.has(key)) return `${key}: 같은 key 를 가진 항목이 둘 이상이다`;
    seen.add(key);
  }

  if (state.waves !== undefined) {
    if (!Array.isArray(state.waves)) return 'waves: 배열이 아니다';
    for (let i = 0; i < state.waves.length; i += 1) {
      const w = state.waves[i];
      if (!w || typeof w !== 'object') return `waves[${i}]: 객체가 아니다`;
      if (typeof w.id !== 'number') return `waves[${i}]: id 가 숫자가 아니다`;
      if (!Array.isArray(w.items)) return `waves[${i}](id=${w.id}): items 가 배열이 아니다`;
    }
  }
  return null;
};

const emptyState = (milestone) => ({
  version: STATE_VERSION,
  milestone,
  base: null,
  items: [],
  waves: [],
  integration: { lastPlannedAt: null, lastDispatchedAt: null, lastAdvancedAt: null },
});

// state 객체 — 손상이면 필드 이름을 대며 던진다.
const parseState = (raw, where = 'state') => {
  let parsed;
  try {
    // BOM 제거 — Windows 도구가 쓴 UTF-8 JSON 에는 BOM 이 흔하고 JSON.parse 는 이를
    // 문법 오류로 본다. state 는 손으로 고치는 파일이라 여기서 흡수한다.
    parsed = JSON.parse(String(raw).replace(/^﻿/, ''));
  } catch (e) {
    throw msError('state_corrupt', `state 파싱 실패(${where}): ${e.message}`, { path: where });
  }
  const problem = validateState(parsed);
  if (problem) throw msError('state_invalid', `state 손상(${where}) — ${problem}`, { path: where, problem });
  return parsed;
};

const loadState = (filePath) => {
  if (!fs.existsSync(filePath)) {
    throw msError('state_missing', `state 파일 없음: ${filePath} — 먼저 'node scripts/ms.js plan --apply' 로 만든다`, { path: filePath });
  }
  return parseState(fs.readFileSync(filePath, 'utf8'), filePath);
};

// 절대경로를 직접 받는 순수 I/O 헬퍼로 분리해 둔다 — 기본 state 경로를 거치지 않고도
// "백업 후 쓰기" 계약 자체를 임의 경로(테스트의 os.tmpdir())에서 검증할 수 있게 하려는 것.
const backupThenWrite = (filePath, content) => {
  if (fs.existsSync(filePath)) fs.copyFileSync(filePath, `${filePath}.bak`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
};

const saveState = (filePath, state) => {
  const problem = validateState(state);
  if (problem) throw msError('state_invalid', `저장 거부 — ${problem}`, { path: filePath, problem });
  const dir = path.dirname(filePath);
  if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });
  return backupThenWrite(filePath, `${JSON.stringify(state, null, 2)}\n`);
};

const findItem = (state, key) => state.items.find((i) => i.key === key) || null;
const replaceItem = (state, item) => ({ ...state, items: state.items.map((i) => (i.key === item.key ? item : i)) });

// 새 항목의 기본 형태 — 사람 소유 필드는 전부 비어 있다(slug 는 사람이 채운다).
const newItem = ({ key, repo, id, title = '', priority = null, refHints = [] }) => {
  const r = parseRef(key || `${repo}:${id}`, 'key');
  return {
    key: r.key,
    refs: { [r.repo]: r.id },
    title,
    priority,
    dependsOn: [],
    status: BACKLOG_STATUS,
    slug: null,
    workspace: null,
    branches: {},
    prs: {},
    specVerified: false,
    gate: null,
    blockedFrom: null,
    notes: '',
    lastObservedAt: null,
    lastObservedReason: null,
    evidenceMissCount: 0,
    refHints,
  };
};

module.exports = {
  DEFAULT_STATE_PATH, STATE_VERSION, ACTIVE_STATUSES, TRANSITIONS, STATUSES, BACKLOG_STATUS,
  canTransition, applyTransition, validateItemShape, validateState,
  emptyState, parseState, loadState, saveState, backupThenWrite, findItem, replaceItem, newItem,
};
