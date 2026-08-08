#!/usr/bin/env node
/**
 * gen-milestone.js — 마일스톤 state(.review-kit-milestone.json) HTML 렌더러
 *
 * 사용법:
 *   node scripts/gen-milestone.js <milestone-state.json> [output.html]
 *   node scripts/gen-milestone.js <state.json>  → 같은 디렉토리에 milestone-{timestamp}.html
 *
 * 입력 스키마 정본: scripts/schema/milestone-state.schema.json
 *   { "milestone": "...", "items": [...], "waves": [{id, approvedAt, items:[key]}] }
 *
 * 슬롯 상한은 state 가 아니라 어댑터(.review-kit.json 의 milestone.concurrency.maxSlots)에
 * 있다 — state 파일 옆이나 현재 디렉터리에서 찾아보고, 없으면 상한 없이 점유량만 보여준다.
 * 스타일 SSOT 는 scripts/assets/report.css 이며 빌드타임에 인라인 주입된다.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { loadInput, resolveOutputPath, writeReport } = require('./lib/report/io');
const { loadBaseCss } = require('./lib/report/css');
const { esc, alpha, chip } = require('./lib/report/html');
const { topoLevels } = require('./lib/milestone/priority');
const { slotsUsed, DEFAULT_CONCURRENCY } = require('./lib/milestone/guard');
const { danglingDependencies } = require('./lib/milestone/plan-merge');
const { isValidSlug } = require('./lib/milestone/dispatch-plan');
const { ACTIVE_STATUSES } = require('./lib/milestone/state');

const BASE_CSS = loadBaseCss();

const { inputPath, outputArg, data } = loadInput('Usage: node scripts/gen-milestone.js <milestone-state.json> [output.html]');
const outputPath = resolveOutputPath(inputPath, outputArg, 'milestone');

const items = Array.isArray(data.items) ? data.items : [];
const waves = Array.isArray(data.waves) ? data.waves : [];
const byKey = new Map(items.map((i) => [i.key, i]));

// ── 상태 표현 ────────────────────────────────────────────────
// 색은 전부 report.css 의 기존 토큰이다 — 새 색을 만들지 않았으므로 SSOT 는 그대로다.
const STATUS_COLOR = {
  queued: 'var(--dim)',
  ready: 'var(--blue)',
  specced: 'var(--cyan)',
  dispatched: 'var(--accent)',
  impl: 'var(--purple)',
  qa_ok: 'var(--cyan)',
  pr_open: 'var(--yellow)',
  merged: 'var(--green)',
  done: 'var(--green)',
  blocked: 'var(--red)',
};
const STATUS_LABEL = {
  queued: '대기', ready: '착수 준비', specced: '스펙 확정', dispatched: '착수됨',
  impl: '구현 중', qa_ok: 'QA 통과', pr_open: 'PR 열림', merged: '병합됨',
  done: '완료', blocked: 'blocked',
};

const colorOf = (s) => STATUS_COLOR[s] || 'var(--muted)';
const statusChip = (s) => chip(STATUS_LABEL[s] || s || '?', colorOf(s));

// ── 슬롯 ─────────────────────────────────────────────────────
function findMaxSlots() {
  const candidates = [path.join(path.dirname(inputPath), '.review-kit.json'), path.resolve('.review-kit.json')];
  for (const p of candidates) {
    try {
      const a = JSON.parse(fs.readFileSync(p, 'utf8').replace(/^﻿/, ''));
      const n = a && a.milestone && a.milestone.concurrency && a.milestone.concurrency.maxSlots;
      if (typeof n === 'number' && n > 0) return { max: n, from: path.basename(p) };
    } catch { /* 어댑터가 없거나 못 읽는 건 정상이다 — 상한 없이 렌더한다 */ }
  }
  return { max: null, from: null };
}

const used = items.length ? slotsUsed(items) : 0;
const { max: maxSlots, from: slotSource } = findMaxSlots();
const slotMax = maxSlots || Math.max(used, DEFAULT_CONCURRENCY.maxSlots);
const activeItems = items.filter((i) => ACTIVE_STATUSES.has(i.status));

function slotBar() {
  const cells = [];
  for (let i = 0; i < slotMax; i += 1) {
    const filled = i < used;
    cells.push(`<div style="flex:1;height:26px;border-radius:var(--r-sm);border:1px solid var(--border);
      background:${filled ? alpha('var(--accent)', 30) : 'var(--surface2)'}"></div>`);
  }
  return `<div style="display:flex;gap:6px;margin:10px 0">${cells.join('')}</div>`;
}

// ── 경고 수집 ────────────────────────────────────────────────
const warnings = [];
danglingDependencies(items).forEach((d) => warnings.push({
  level: 'crit', text: `끊어진 선행 참조: ${d.key} → ${d.dependsOn} — 이 상태로는 Wave 를 다시 계산할 수 없다`,
}));
items.filter((i) => i.status === 'blocked').forEach((i) => warnings.push({
  level: 'crit', text: `blocked: ${i.key} (${i.blockedFrom || '?'} 에서 멈춤) — 자동 복귀하지 않는다. ${i.lastObservedReason || ''}`,
}));
items.filter((i) => (i.evidenceMissCount || 0) > 0).forEach((i) => warnings.push({
  level: 'warn', text: `증거미스 ${i.evidenceMissCount}회 누적: ${i.key} — 브랜치명 컨벤션 불일치 여부부터 확인할 것`,
}));
items.filter((i) => ACTIVE_STATUSES.has(i.status) && !isValidSlug(i.slug)
  && Object.keys(i.branches || {}).length === 0).forEach((i) => warnings.push({
  level: 'warn', text: `slug 무효: ${i.key} (현재 ${JSON.stringify(i.slug)}) — 관측이 이 항목을 건너뛴다`,
}));
const orphanWave = items.filter((i) => !waves.some((w) => (w.items || []).includes(i.key)));
orphanWave.forEach((i) => warnings.push({
  level: 'info', text: `Wave 미배정: ${i.key} — plan 을 다시 돌리면 배정된다`,
}));

const WARN_COLOR = { crit: 'var(--crit)', warn: 'var(--warn)', info: 'var(--info)' };

// ── 의존 그래프 (인라인 SVG — 외부 의존성 0) ──────────────────
function renderGraph() {
  const edges = [];
  items.forEach((i) => (i.dependsOn || []).forEach((d) => { if (byKey.has(d)) edges.push([d, i.key]); }));
  if (!edges.length) {
    return '<p style="color:var(--dim);font-size:13px">의존 간선이 없다 — 모든 항목이 Wave 0 에서 독립적으로 착수 가능하다.</p>';
  }

  const lv = topoLevels(items);
  const levelOf = lv.ok ? lv.levels : new Map(items.map((i) => [i.key, 0]));

  // 간선에 닿는 항목만 그린다 — 고립 노드까지 그리면 그래프가 표를 반복할 뿐이다.
  const touched = new Set(edges.flat());
  const cols = new Map();
  [...touched].sort().forEach((k) => {
    const l = levelOf.get(k) || 0;
    if (!cols.has(l)) cols.set(l, []);
    cols.get(l).push(k);
  });

  const COL_W = 210;
  const ROW_H = 46;
  const NODE_W = 168;
  const NODE_H = 30;
  const levels = [...cols.keys()].sort((a, b) => a - b);
  const width = levels.length * COL_W + 40;
  const height = Math.max(...[...cols.values()].map((c) => c.length)) * ROW_H + 40;

  const pos = new Map();
  levels.forEach((l, ci) => cols.get(l).forEach((k, ri) => {
    pos.set(k, { x: 20 + ci * COL_W, y: 20 + ri * ROW_H });
  }));

  const lines = edges.filter(([a, b]) => pos.has(a) && pos.has(b)).map(([a, b]) => {
    const p = pos.get(a);
    const q = pos.get(b);
    const x1 = p.x + NODE_W;
    const y1 = p.y + NODE_H / 2;
    const x2 = q.x;
    const y2 = q.y + NODE_H / 2;
    const mid = (x1 + x2) / 2;
    return `<path d="M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}" fill="none"
      stroke="var(--border)" stroke-width="1.5" marker-end="url(#ms-arrow)"/>`;
  }).join('');

  const nodes = [...pos.entries()].map(([k, p]) => {
    const it = byKey.get(k) || {};
    return `<g>
      <rect x="${p.x}" y="${p.y}" width="${NODE_W}" height="${NODE_H}" rx="6"
        fill="${alpha(colorOf(it.status), 14)}" stroke="${colorOf(it.status)}" stroke-width="1"/>
      <text x="${p.x + 10}" y="${p.y + 19}" font-size="12" font-family="var(--mono)" fill="var(--text)">${esc(k)}</text>
      <text x="${p.x + NODE_W - 10}" y="${p.y + 19}" font-size="10" text-anchor="end"
        fill="${colorOf(it.status)}">${esc(STATUS_LABEL[it.status] || it.status || '')}</text>
    </g>`;
  }).join('');

  return `<div style="overflow-x:auto">
  <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="의존 그래프">
    <defs>
      <marker id="ms-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
        <path d="M0,0 L8,4 L0,8 z" fill="var(--border)"/>
      </marker>
    </defs>
    ${lines}${nodes}
  </svg>
  <div style="color:var(--dim);font-size:12px;margin-top:6px">왼쪽 → 오른쪽이 선행 → 후행이다. 열 번호가 곧 Wave 다.</div>
</div>`;
}

// ── Wave 표 ──────────────────────────────────────────────────
function renderWave(w) {
  const rows = (w.items || []).map((k) => {
    const it = byKey.get(k);
    if (!it) {
      return `<tr><td colspan="5" style="color:var(--crit)">${esc(k)} — items 에 없는 key (state 확인 필요)</td></tr>`;
    }
    const deps = (it.dependsOn || []).length
      ? `<span style="color:var(--muted);font-size:12px">← ${esc(it.dependsOn.join(', '))}</span>` : '';
    const refs = Object.entries(it.refs || {}).map(([r, id]) => `${r}:${id}`).join(' · ');
    return `<tr>
      <td style="font-family:var(--mono);white-space:nowrap">${esc(k)}</td>
      <td>${statusChip(it.status)}</td>
      <td style="white-space:nowrap">${it.priority ? chip(it.priority, 'var(--high)') : '<span style="color:var(--dim)">-</span>'}</td>
      <td>${esc(String(it.title || '').slice(0, 80))} ${deps}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--muted);white-space:nowrap">${esc(refs)}</td>
    </tr>`;
  }).join('');

  const done = (w.items || []).filter((k) => (byKey.get(k) || {}).status === 'done').length;
  const total = (w.items || []).length;
  const pct = total ? Math.round((done / total) * 100) : 0;

  return `<section class="card">
    <h2 class="section-title">Wave ${esc(String(w.id))} &nbsp;
      <span style="font-weight:400;color:var(--muted);font-size:13px">${done}/${total} done (${pct}%)</span>
      ${w.approvedAt ? chip(`승인 ${String(w.approvedAt).slice(0, 10)}`, 'var(--ok)') : chip('미승인', 'var(--dim)')}
    </h2>
    <div style="height:6px;border-radius:3px;background:var(--surface2);overflow:hidden;margin:0 0 12px">
      <div style="height:100%;width:${pct}%;background:var(--green)"></div>
    </div>
    <table>
      <thead><tr><th>항목</th><th>상태</th><th>우선</th><th>제목</th><th>refs</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" style="color:var(--dim)">항목 없음</td></tr>'}</tbody>
    </table>
  </section>`;
}

const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>마일스톤 ${esc(String(data.milestone || ''))}</title>
<style>
${BASE_CSS}
/* ── gen-milestone.js 고유 ── (공통분은 scripts/assets/report.css) */
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border-soft); vertical-align: top; }
th { color: var(--muted); font-size: 12px; font-weight: 600; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>마일스톤 ${esc(String(data.milestone || '(이름 없음)'))}</h1>
    <div class="meta">
      항목 ${items.length}건 · Wave ${waves.length}개 · 슬롯 ${used}/${slotMax}${slotSource ? ` (상한 출처: ${esc(slotSource)})` : ' (상한 미설정 — 기본값 표시)'}
      ${data.base ? ` · base ${esc(String(data.base))}` : ''}
    </div>
  </div>
</div>

<div class="container">

  <section class="card">
    <h2 class="section-title">슬롯 점유</h2>
    ${slotBar()}
    <div style="color:var(--muted);font-size:13px">
      점유 중인 항목 ${activeItems.length}건 — ${activeItems.length
        ? activeItems.map((i) => `${esc(i.key)}(${Object.keys(i.refs || {}).length}슬롯)`).join(' · ')
        : '없음'}
    </div>
    <div style="color:var(--dim);font-size:12px;margin-top:6px">
      슬롯은 저장소 작업 디렉터리 단위로 센다 — 두 저장소를 걸친 항목 하나는 2슬롯이다.
      blocked·merged 도 워크스페이스가 살아 있으므로 계속 점유한다.
    </div>
  </section>

  ${warnings.length ? `<section class="card">
    <h2 class="section-title">경고 ${warnings.length}건</h2>
    ${warnings.map((w) => `<div style="display:flex;gap:8px;padding:7px 0;border-bottom:1px solid var(--border-soft)">
      <span style="color:${WARN_COLOR[w.level]};font-weight:700">●</span>
      <span style="color:var(--text);font-size:13px">${esc(w.text)}</span>
    </div>`).join('')}
  </section>` : ''}

  ${waves.length ? waves.map(renderWave).join('') : '<section class="card"><p style="color:var(--dim)">Wave 가 없다 — <code>node scripts/ms.js plan --apply</code> 로 만든다.</p></section>'}

  <section class="card">
    <h2 class="section-title">의존 그래프</h2>
    ${renderGraph()}
  </section>

  <div class="meta-footer">
    상태 파일: ${esc(path.basename(inputPath))} &nbsp;·&nbsp; 스키마: scripts/schema/milestone-state.schema.json
  </div>
</div>
</body>
</html>`;

writeReport(outputPath, html);
console.log(`✅ gen-milestone 완료: ${outputPath}`);
console.log(`   Wave ${waves.length}개 · 항목 ${items.length}건 · 슬롯 ${used}/${slotMax} · 경고 ${warnings.length}건`);
