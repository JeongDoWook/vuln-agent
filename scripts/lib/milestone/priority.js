'use strict';

/**
 * priority.js — 의존 그래프 · 위상정렬 · 우선순위 · Wave 산출 (순수 함수, I/O 없음)
 *
 * 정렬키(순서 자체가 계약이다):
 *   ① 위상 레벨 오름차순 (선행 없는 것 먼저) — 이 레벨이 곧 Wave 번호다
 *   ② 우선순위 라벨 순위 (어댑터의 `milestone.priorityLabels` 순서, 없는 값은 맨 뒤)
 *   ③ 다운스트림 차수 내림차순 (많이 물린 linchpin 먼저)
 *   ④ 최소 id 오름차순 (동률 시 결정성 확보 — 여기서 결정성이 깨지면 같은 입력이
 *      실행할 때마다 다른 Wave 를 내고, 사람의 Wave 승인이 무의미해진다)
 *
 * 우선순위 라벨을 하드코딩하지 않는 이유: `P0`/`P1` 은 한 조직의 관례일 뿐이다.
 * 어댑터가 `["critical","high"]` 를 주면 그 순서가 곧 순위가 된다.
 */

const { msError } = require('./errors');
const { numericId } = require('./ref');

const DEFAULT_PRIORITY_LABELS = Object.freeze(['P0', 'P1']);

// 라벨 목록 → {label: rank}. 목록에 없는 값(또는 null)은 항상 맨 뒤다.
const rankTable = (labels = DEFAULT_PRIORITY_LABELS) => {
  const t = new Map();
  (labels || []).forEach((l, i) => t.set(String(l), i));
  return t;
};

const rankOf = (priority, labels) => {
  const t = labels instanceof Map ? labels : rankTable(labels);
  const r = t.get(String(priority));
  return r === undefined ? t.size : r;
};

// 항목의 refs 중 가장 작은 숫자 id — 정렬의 최종 동률 처리 지점이라 항상 호출된다.
// refs 가 없거나 비어 있으면 `Math.min()` 이 조용히 Infinity 를 돌려주므로(그 항목이
// 티 안 나게 맨 뒤로 밀린다) 여기서 이름을 대며 죽는다. state.loadState 가 1차 방어선이지만
// 이 함수는 손으로 만든 item 으로도 직접 호출된다.
const minId = (item) => {
  const refs = item && item.refs;
  if (!refs || typeof refs !== 'object' || Object.keys(refs).length === 0) {
    throw msError('item_corrupt',
      `priority.minId: 항목 ${(item && item.key) || '(key 없음)'} 에 refs 가 없거나 비어있다 — state 손편집으로 손상됐을 수 있다`);
  }
  return Math.min(...Object.entries(refs).map(([repo, id]) => numericId(`${repo}:${id}`, `${item.key}.refs.${repo}`)));
};

// Map<key, number> — 이 항목을 (직접) 선행으로 지목한 항목 수
const downstreamCounts = (items) => {
  const counts = new Map(items.map((i) => [i.key, 0]));
  items.forEach((i) => (i.dependsOn || []).forEach((dep) => {
    if (counts.has(dep)) counts.set(dep, counts.get(dep) + 1);
  }));
  return counts;
};

// {ok:true, levels: Map<key, level>} | {ok:false, error} — Kahn
const topoLevels = (items) => {
  const keys = new Set(items.map((i) => i.key));
  for (const i of items) {
    for (const dep of i.dependsOn || []) {
      if (!keys.has(dep)) return { ok: false, error: `존재하지 않는 선행 참조: ${i.key} → ${dep}` };
    }
  }

  const level = new Map();
  const remaining = new Map(items.map((i) => [i.key, [...(i.dependsOn || [])]]));

  while (remaining.size > 0) {
    const ready = [...remaining.entries()].filter(([, deps]) => deps.every((d) => level.has(d)));
    if (ready.length === 0) {
      return { ok: false, error: `순환 의존 감지: ${[...remaining.keys()].join(', ')}` };
    }
    ready.forEach(([key, deps]) => {
      level.set(key, deps.length === 0 ? 0 : Math.max(...deps.map((d) => level.get(d))) + 1);
      remaining.delete(key);
    });
  }
  return { ok: true, levels: level };
};

// {ok:true, items} | {ok:false, error}
const sortItems = (items, priorityLabels) => {
  const lv = topoLevels(items);
  if (!lv.ok) return lv;
  const down = downstreamCounts(items);
  const table = rankTable(priorityLabels);

  const sorted = [...items].sort((a, b) => (
    (lv.levels.get(a.key) - lv.levels.get(b.key))
    || (rankOf(a.priority, table) - rankOf(b.priority, table))
    || (down.get(b.key) - down.get(a.key))
    || (minId(a) - minId(b))
  ));
  return { ok: true, items: sorted };
};

// {ok:true, waves:[{id, items:[key]}]} | {ok:false, error}
const computeWaves = (items, priorityLabels) => {
  const sorted = sortItems(items, priorityLabels);
  if (!sorted.ok) return sorted;
  const { levels } = topoLevels(items);

  const byLevel = new Map();
  sorted.items.forEach((i) => {
    const l = levels.get(i.key);
    if (!byLevel.has(l)) byLevel.set(l, []);
    byLevel.get(l).push(i.key);
  });

  return {
    ok: true,
    waves: [...byLevel.entries()].sort((a, b) => a[0] - b[0]).map(([id, keys]) => ({ id, items: keys })),
  };
};

module.exports = {
  DEFAULT_PRIORITY_LABELS, rankTable, rankOf, minId, downstreamCounts, topoLevels, sortItems, computeWaves,
};
