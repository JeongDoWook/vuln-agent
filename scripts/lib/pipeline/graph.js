'use strict';

/**
 * pipeline/graph.js — 파이프라인 그래프 실행 모델(v2)의 순수 함수 모듈.
 *
 * 서술은 kit/workflow/pipeline-algorithm.md 「그래프 실행 모델 (v2)」 절이 SSOT 다.
 * 이 파일은 그 절을 그대로 코드로 옮긴 것이고, 부수효과가 없다 —
 * 파일·시계·난수·네트워크를 쓰지 않는다. 상태를 받으면 새 상태를 돌려주고
 * 입력을 변형하지 않는다. 시각·커밋해시 같은 값은 호출자가 채워 넣는다.
 *
 * v1(평평한 배열 + current 정수)은 v2 의 부분집합이다 — normalize() 가 암묵적
 * dependsOn 으로 승격하고, recordsOf() 가 v1 history 를 v2 노드 상태로 읽는다.
 * 따라서 v1 어댑터·v1 상태 파일을 그대로 이 엔진에 넣어도 동작한다.
 */

const NODE_TYPES = ['auto', 'gate', 'external'];
const ACTIVATIONS = ['required', 'optional'];
const NODE_STATES = [
  'ready', 'running', 'done', 'gate_wait', 'external_wait', 'skipped', 'bypassed', 'failed',
];

// 정착(settled) — 하위 노드가 더 기다릴 이유가 없는 상태.
const SETTLED_STATES = ['done', 'skipped', 'bypassed', 'failed'];
// 부재(absent) — 정착했지만 소비할 산출물을 남기지 않은 상태.
const ABSENT_STATES = ['skipped', 'bypassed'];
// 대기 — 사람/외부 신호를 기다리느라 멈춘 상태.
const WAITING_STATES = ['gate_wait', 'external_wait'];

// v1 status → v2 state. 문서의 대응표와 같은 표다(둘 중 하나만 고치지 않는다).
const V1_STATUS_TO_STATE = {
  done: 'done',
  skipped: 'skipped',
  external_skipped: 'skipped',
  external_done: 'done',
  gate_wait: 'gate_wait',
  external_wait: 'external_wait',
};

const has = (list, v) => list.indexOf(v) !== -1;

// ── 정규화 ───────────────────────────────────────────────────

function toStageArray(pipelineConfig) {
  if (pipelineConfig == null) return [];
  if (Array.isArray(pipelineConfig)) return pipelineConfig;
  if (typeof pipelineConfig !== 'object') {
    throw new TypeError('pipelineConfig: 배열 또는 { stages: [...] } 객체여야 한다');
  }
  if (Array.isArray(pipelineConfig.stages)) return pipelineConfig.stages;
  if (Array.isArray(pipelineConfig.nodes)) return pipelineConfig.nodes;
  throw new TypeError('pipelineConfig: stages/nodes 배열이 없다');
}

/**
 * normalize(pipelineConfig) → { nodes, index, dependents, groups, linear }
 *
 * v1 승격 규칙: **한 노드도 dependsOn 을 선언하지 않았을 때만** 배열 순서를
 * 의존으로 읽어 각 노드에 `dependsOn: [직전 노드]` 를 부여한다. 하나라도
 * 선언했으면 전부 v2 로 읽고, 미선언 노드는 뿌리(의존 없음)가 된다 —
 * 섞어서 해석하면 dependsOn 을 한 곳만 적은 어댑터가 나머지를 조용히
 * 직렬로 묶어 작성자 의도와 다른 그래프가 나온다.
 */
function normalize(pipelineConfig) {
  const raw = toStageArray(pipelineConfig);
  const linear = !raw.some((s) => s && Array.isArray(s.dependsOn));

  const nodes = [];
  const index = Object.create(null);

  raw.forEach((s, i) => {
    if (!s || typeof s !== 'object' || Array.isArray(s)) {
      throw new TypeError(`노드 #${i}: 객체가 아니다`);
    }
    const id = typeof s.id === 'string' ? s.id.trim() : '';
    if (!id) throw new TypeError(`노드 #${i}: id 가 없다`);
    if (index[id]) throw new TypeError(`노드 id 중복: ${id}`);

    const type = s.type == null ? 'auto' : String(s.type);
    if (!has(NODE_TYPES, type)) {
      throw new TypeError(`노드 ${id}: 알 수 없는 type "${type}" (${NODE_TYPES.join('|')})`);
    }

    // activation 이 명시되면 그것이 이긴다. 없으면 v1 의 optional:true 를 읽는다.
    const activation = s.activation != null
      ? String(s.activation)
      : (s.optional === true ? 'optional' : 'required');
    if (!has(ACTIVATIONS, activation)) {
      throw new TypeError(`노드 ${id}: 알 수 없는 activation "${activation}" (${ACTIVATIONS.join('|')})`);
    }

    let dependsOn;
    if (Array.isArray(s.dependsOn)) {
      dependsOn = [];
      for (const d of s.dependsOn) {
        const dep = typeof d === 'string' ? d.trim() : '';
        if (!dep) throw new TypeError(`노드 ${id}: dependsOn 원소가 문자열이 아니다`);
        if (dependsOn.indexOf(dep) === -1) dependsOn.push(dep);
      }
    } else if (linear && i > 0) {
      dependsOn = [nodes[i - 1].id];
    } else {
      dependsOn = [];
    }

    const node = {
      id,
      skill: s.skill == null ? null : String(s.skill),
      type,
      group: s.group == null ? null : String(s.group),
      dependsOn,
      activation,
      wait: s.wait === true,
      cutlineGate: s.cutlineGate === true,
      skipCondition: s.skipCondition == null ? null : String(s.skipCondition),
      note: s.note == null ? null : String(s.note),
      order: i,
    };
    nodes.push(node);
    index[id] = node;
  });

  // 의존 대상 검증 — 없는 id 를 가리키면 그래프가 성립하지 않는다.
  const dependents = Object.create(null);
  for (const n of nodes) dependents[n.id] = [];
  for (const n of nodes) {
    for (const d of n.dependsOn) {
      if (!index[d]) throw new TypeError(`노드 ${n.id}: 존재하지 않는 의존 대상 "${d}"`);
      dependents[d].push(n.id);
    }
  }

  // 그룹은 첫 등장 순서를 유지한다. group 없는 노드는 id:null 그룹에 모인다.
  const groups = [];
  const groupIndex = new Map();
  for (const n of nodes) {
    const key = n.group;
    if (!groupIndex.has(key)) {
      const g = { id: key, nodes: [] };
      groupIndex.set(key, g);
      groups.push(g);
    }
    groupIndex.get(key).nodes.push(n);
  }

  return { nodes, index, dependents, groups, linear };
}

// ── 사이클 ───────────────────────────────────────────────────

/**
 * detectCycles(graph) → 순환에 참여한 노드 id 배열(정렬됨). 없으면 [].
 * 실행 전에 반드시 부르고, 비어 있지 않으면 실행을 거부한다.
 *
 * Kahn 으로 위상 정렬해 남은 잔여집합을 얻은 뒤, 그 안에서 자기 자신에게
 * 되돌아오는 노드만 고른다 — 잔여집합에는 순환의 **하류**도 섞여 있는데,
 * 그들은 순환 노드가 아니라 순환의 피해자다.
 */
function detectCycles(graph) {
  const remaining = new Set(graph.nodes.map((n) => n.id));
  let moved = true;
  while (moved) {
    moved = false;
    for (const id of Array.from(remaining)) {
      const node = graph.index[id];
      if (node.dependsOn.every((d) => !remaining.has(d))) {
        remaining.delete(id);
        moved = true;
      }
    }
  }
  if (!remaining.size) return [];

  const onCycle = [];
  for (const id of remaining) {
    const seen = new Set();
    const stack = graph.index[id].dependsOn.filter((d) => remaining.has(d));
    let found = false;
    while (stack.length) {
      const cur = stack.pop();
      if (cur === id) { found = true; break; }
      if (seen.has(cur)) continue;
      seen.add(cur);
      for (const d of graph.index[cur].dependsOn) if (remaining.has(d)) stack.push(d);
    }
    if (found) onCycle.push(id);
  }
  return onCycle.sort();
}

// ── 상태 읽기 ────────────────────────────────────────────────

function createState(opts) {
  const o = opts || {};
  // normalize() 가 돌려준 그래프를 그대로 넘기는 실수를 잡는다. 그냥 두면 pipeline 정의가
  // 빠진 상태 파일이 만들어지고, gen-status 가 **기록된 노드만** 그래프로 역산해
  // "전체 5개"처럼 조용히 축소된 진행률을 낸다. 틀린 숫자가 나오는 편보다 즉시 죽는 편이 낫다.
  if (o && Array.isArray(o.nodes) && o.index) {
    throw new TypeError('createState 에 그래프를 넘겼다. createState({ pipeline: <어댑터의 pipeline 절>, runId }) 형태로 부른다');
  }
  const state = {
    schemaVersion: 2,
    runId: o.runId == null ? null : String(o.runId),
    revision: o.revision == null ? 1 : o.revision,
    nodes: {},
    history: [],
  };
  if (o.pipeline != null) state.pipeline = o.pipeline;
  return state;
}

function isV2State(state) {
  if (!state || typeof state !== 'object') return false;
  if (state.schemaVersion >= 2) return true;
  return !!state.nodes && typeof state.nodes === 'object' && !Array.isArray(state.nodes);
}

/**
 * recordsOf(state) → { nodeId: record }
 * v2 면 nodes 를 그대로, v1({current, history}) 이면 history 를 대응표로 읽어
 * 같은 모양으로 돌려준다. 그래서 그래프 함수들이 v1 상태 파일에도 그대로 돈다.
 */
function recordsOf(state) {
  if (!state || typeof state !== 'object') return Object.create(null);
  if (isV2State(state)) return state.nodes || Object.create(null);

  const out = Object.create(null);
  for (const h of Array.isArray(state.history) ? state.history : []) {
    if (!h || typeof h !== 'object' || typeof h.id !== 'string') continue;
    const mapped = V1_STATUS_TO_STATE[h.status];
    if (!mapped) continue;
    out[h.id] = {
      state: mapped,
      reason: h.reason == null ? undefined : h.reason,
      completedAt: h.at == null ? undefined : h.at,
      gateApprovedAt: h.gate_approved_at == null ? undefined : h.gate_approved_at,
    };
  }
  return out;
}

function fromV1State(v1) {
  const state = createState({});
  const rec = recordsOf(v1);
  for (const id of Object.keys(rec)) state.nodes[id] = rec[id];
  for (const h of (v1 && Array.isArray(v1.history)) ? v1.history : []) {
    if (!h || typeof h.id !== 'string') continue;
    const mapped = V1_STATUS_TO_STATE[h.status];
    if (!mapped) continue;
    state.history.push({ id: h.id, state: mapped, at: h.at == null ? null : h.at });
  }
  return state;
}

function stateOf(records, id) {
  const r = records[id];
  return r && typeof r.state === 'string' ? r.state : null;
}

const isSettled = (s) => s != null && has(SETTLED_STATES, s);

// dep 이 산출물을 남기지 않았는가. skip/bypass 는 물론, optional 노드의 실패도
// 하위가 받는 입력 관점에서는 똑같이 "없음"이다.
function producedNothing(graph, records, depId) {
  const s = stateOf(records, depId);
  if (s == null) return false;
  if (has(ABSENT_STATES, s)) return true;
  const dep = graph.index[depId];
  return s === 'failed' && !!dep && dep.activation === 'optional';
}

// ── 차단 · bypass 전파 ───────────────────────────────────────

/**
 * blockedNodes(graph, state) → required 노드의 실패 때문에 실행할 수 없게 된 노드들.
 * optional 노드의 실패는 차단하지 않는다 — optional 은 "없어도 파이프라인이
 * 성립한다"는 선언이고, 그 산출물이 skip 으로 없든 실패로 없든 하위가 받는
 * 입력은 똑같이 "없음"이기 때문이다(실패 기록 자체는 지우지 않는다).
 */
function blockedNodes(graph, state) {
  const records = recordsOf(state);
  const blocked = new Set();
  const queue = [];

  for (const n of graph.nodes) {
    if (stateOf(records, n.id) === 'failed' && n.activation === 'required') queue.push(n.id);
  }
  while (queue.length) {
    const id = queue.shift();
    for (const child of graph.dependents[id] || []) {
      if (blocked.has(child)) continue;
      if (isSettled(stateOf(records, child))) continue; // 이미 끝난 노드는 막을 것이 없다
      blocked.add(child);
      queue.push(child);
    }
  }
  return graph.nodes.filter((n) => blocked.has(n.id));
}

/**
 * propagateBypass(graph, state) → 새 state.
 * 의존이 전부 "산출물 없음"으로 정착한 **optional** 노드를 bypassed 로 내린다.
 * required 노드는 내리지 않는다 — 입력이 빠진 채로라도 반드시 돌아야 한다는
 * 선언이 required 이기 때문이다. 고정점까지 반복하므로 optional 사슬 전체가
 * 한 번에 정리된다.
 */
function propagateBypass(graph, state) {
  let next = cloneState(state);
  const blocked = new Set(blockedNodes(graph, next).map((n) => n.id));

  for (;;) {
    const records = recordsOf(next);
    let changed = false;
    for (const n of graph.nodes) {
      if (n.activation !== 'optional') continue;
      if (stateOf(records, n.id) != null) continue;
      if (blocked.has(n.id)) continue;
      if (!n.dependsOn.length) continue;
      if (!n.dependsOn.every((d) => producedNothing(graph, records, d))) continue;
      next = advance(next, n.id, {
        state: 'bypassed',
        reason: `상위 ${n.dependsOn.join(', ')} 가 산출물 없이 지나가 소비할 입력이 없다`,
        bypassedDeps: n.dependsOn.slice(),
      });
      changed = true;
    }
    if (!changed) return next;
  }
}

// ── 실행 가능 노드 ───────────────────────────────────────────

/**
 * readyNodes(graph, state) → 지금 착수할 수 있는 노드 배열(그래프 순서).
 * 배열인 것이 요점이다 — 원소가 둘 이상이면 그 노드들은 서로 독립이라
 * 동시에 돌려도 된다. v1 의 `current` 정수는 이 사실을 표현할 수 없었다.
 */
function readyNodes(graph, state) {
  const records = recordsOf(state);
  const blocked = new Set(blockedNodes(graph, state).map((n) => n.id));
  return graph.nodes.filter((n) => {
    const s = stateOf(records, n.id);
    if (s != null && s !== 'ready') return false; // running/대기/정착은 착수 대상이 아니다
    if (blocked.has(n.id)) return false;
    return n.dependsOn.every((d) => isSettled(stateOf(records, d)));
  });
}

// ── 전진 ─────────────────────────────────────────────────────

function cloneState(state) {
  if (!isV2State(state)) return fromV1State(state);
  const nodes = {};
  for (const id of Object.keys(state.nodes || {})) {
    nodes[id] = Object.assign({}, state.nodes[id]);
  }
  const next = Object.assign({}, state, {
    schemaVersion: 2,
    nodes,
    history: (Array.isArray(state.history) ? state.history : []).slice(),
  });
  if (next.revision == null) next.revision = 1;
  if (next.runId === undefined) next.runId = null;
  return next;
}

/**
 * advance(state, nodeId, result) → 새 state. 입력은 변형하지 않는다.
 * result.state 는 저장 가능한 상태여야 한다 — `ready` 는 그래프와 다른 노드의
 * 상태에서 매번 파생되는 값이라 저장하지 않는다(저장하면 두 진실이 생긴다).
 */
function advance(state, nodeId, result) {
  if (typeof nodeId !== 'string' || !nodeId) throw new TypeError('advance: nodeId 가 필요하다');
  const r = result || {};
  const s = r.state;
  if (!has(NODE_STATES, s)) {
    throw new TypeError(`advance: 알 수 없는 state "${s}" (${NODE_STATES.join('|')})`);
  }
  if (s === 'ready') throw new TypeError('advance: ready 는 파생 상태라 저장하지 않는다');

  const next = cloneState(state);
  const prev = next.nodes[nodeId] || {};
  const record = Object.assign({}, prev, { state: s });

  for (const key of ['activation', 'reason', 'error', 'startedAt', 'completedAt', 'gateApprovedAt']) {
    if (r[key] !== undefined) record[key] = r[key];
  }
  if (r.bypassedDeps !== undefined) record.bypassedDeps = r.bypassedDeps.slice();
  if (r.at !== undefined && r.completedAt === undefined) record.completedAt = r.at;

  next.nodes[nodeId] = record;
  next.history = next.history.concat([{
    id: nodeId,
    state: s,
    at: record.completedAt === undefined ? null : record.completedAt,
  }]);
  return next;
}

// ── 요약 ─────────────────────────────────────────────────────

/**
 * summarize(graph, state) → { total, done, skipped, bypassed, failed, waiting,
 *                             running, ready, blocked, pending, percent }
 * percent 는 **정착한 노드 / 전체**다. skip·bypass 된 노드는 더 할 일이 없으므로
 * 분모에서 빼는 대신 분자에 넣는다 — 빼면 optional 을 끌수록 진행률이 제자리에
 * 머물러, "덜 하기로 한 결정"이 진척으로 보이지 않는다.
 */
function summarize(graph, state) {
  const records = recordsOf(state);
  const out = {
    total: graph.nodes.length,
    done: 0, skipped: 0, bypassed: 0, failed: 0,
    running: 0, waiting: 0, ready: 0, blocked: 0, pending: 0, percent: 0,
  };
  let settled = 0;
  for (const n of graph.nodes) {
    const s = stateOf(records, n.id);
    if (s === 'done') out.done++;
    else if (s === 'skipped') out.skipped++;
    else if (s === 'bypassed') out.bypassed++;
    else if (s === 'failed') out.failed++;
    else if (s === 'running') out.running++;
    if (s != null && has(WAITING_STATES, s)) out.waiting++;
    if (isSettled(s)) settled++;
  }
  out.ready = readyNodes(graph, state).length;
  out.blocked = blockedNodes(graph, state).length;
  out.pending = out.total - settled;
  out.percent = out.total ? Math.round((settled / out.total) * 100) : 0;
  return out;
}

module.exports = {
  NODE_TYPES,
  ACTIVATIONS,
  NODE_STATES,
  SETTLED_STATES,
  ABSENT_STATES,
  WAITING_STATES,
  V1_STATUS_TO_STATE,
  normalize,
  detectCycles,
  readyNodes,
  advance,
  propagateBypass,
  blockedNodes,
  summarize,
  createState,
  isV2State,
  recordsOf,
  fromV1State,
};
