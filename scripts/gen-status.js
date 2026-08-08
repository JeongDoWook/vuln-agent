#!/usr/bin/env node
/**
 * gen-status.js — pipeline 상태 파일(.review-kit-state.json) HTML 렌더러
 *
 * 사용법:
 *   node scripts/gen-status.js <state.json> [output.html]
 *   node scripts/gen-status.js <state.json>  → 같은 디렉토리에 status-{timestamp}.html
 *
 * 입력은 두 형태를 받는다 (kit/workflow/pipeline-algorithm.md / scripts/schema/pipeline-state.schema.json):
 *
 *   v1 — 선형 { current, history[{id,status,...}] }
 *        status: done | skipped | external_skipped | external_done | gate_wait | external_wait
 *
 *   v2 — 그래프 { schemaVersion: 2, runId, revision, pipeline{stages[]}, nodes{ id: {state,...} } }
 *        state: running | done | gate_wait | external_wait | skipped | bypassed | failed
 *
 * v1 입력은 v1 렌더링을 그대로 낸다 — 하위호환이 깨지면 실패다.
 */

const path = require('path');
const { loadInput, resolveOutputPath, writeReport } = require('./lib/report/io');
const { loadBaseCss } = require('./lib/report/css');
const { esc, alpha, chip } = require('./lib/report/html');
const graphLib = require('./lib/pipeline/graph');

const BASE_CSS = loadBaseCss();

const { inputPath, outputArg, data } = loadInput('Usage: node scripts/gen-status.js <state.json> [output.html]');
const outputPath = resolveOutputPath(inputPath, outputArg, 'status');

// 두 뷰가 공유하는 껍데기. extraCss 는 공통 CSS 뒤에 이어붙는다(빈 문자열이면
// v1 산출물은 그래프 뷰 도입 전과 글자 단위로 같다).
function page(extraCss, meta, body) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pipeline 상태</title>
<style>
${BASE_CSS}
/* ── gen-status.js 고유 ── (공통분은 scripts/assets/report.css) */${extraCss}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>pipeline 상태</h1>
    <div class="meta">${meta}</div>
  </div>
</div>

<div class="container">
${body}
</div>
</body>
</html>`;
}

// ══ v1 — 선형 뷰 ═══════════════════════════════════════════════

const STATUS_COLOR = {
  done:             'var(--green)',
  external_done:    'var(--green)',
  skipped:          'var(--dim)',
  external_skipped: 'var(--blue)',
  gate_wait:        'var(--yellow)',
  external_wait:    'var(--yellow)',
};
const STATUS_LABEL = {
  done:             '완료',
  external_done:    '외부 완료',
  skipped:          'Skip',
  external_skipped: '호스트 소유(미실행)',
  gate_wait:        'Gate 대기',
  external_wait:    '외부 대기',
};

function renderV1() {
  const { current = 0, history = [] } = data;

  const statusChip = (s) => chip(STATUS_LABEL[s] || s, STATUS_COLOR[s] || 'var(--muted)');

  const renderStageRow = (h, idx) => {
    const isCurrent = idx === current;
    const extra = h.reason ? `<div style="color:var(--muted);font-size:12px;margin-top:4px">사유: ${esc(h.reason)}</div>` : '';
    const stamp = h.gate_approved_at ? `승인: ${h.gate_approved_at}` : (h.at ? `완료: ${h.at}` : '');
    const gateInfo = stamp
      ? `<div style="color:var(--muted);font-size:12px;margin-top:4px">${esc(stamp)}</div>` : '';
    return `
    <div style="display:flex;align-items:flex-start;gap:14px;padding:14px 0;border-bottom:1px solid var(--border)${isCurrent ? ';background:'+alpha('var(--accent)',6) : ''}">
      <div style="width:26px;height:26px;border-radius:50%;background:${alpha(STATUS_COLOR[h.status]||'var(--muted)',18)};
                  color:${STATUS_COLOR[h.status]||'var(--muted)'};display:flex;align-items:center;justify-content:center;
                  font-size:12px;font-weight:700;flex-shrink:0">${idx + 1}</div>
      <div style="flex:1">
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-weight:700;color:var(--text)">${esc(h.id)}</span>
          ${statusChip(h.status)}
          ${isCurrent ? chip('현재 위치', 'var(--accent)') : ''}
        </div>
        ${extra}${gateInfo}
      </div>
    </div>`;
  };

  const body = `  <section class="card">
    <h2 class="section-title">스테이지 진행 현황</h2>
    ${history.length ? history.map(renderStageRow).join('') : '<p style="color:var(--dim);font-size:13px">기록 없음 — 아직 파이프라인을 시작하지 않았다.</p>'}
  </section>

  <div class="meta-footer">
    current index: ${current} &nbsp;·&nbsp; 상태 파일: ${esc(path.basename(inputPath))}
  </div>`;

  return {
    html: page('', `처리 기록 ${history.length}건 · 현재 위치 ${current}`, body),
    log: `   현재 위치: ${current} / ${history.length}`,
  };
}

// ══ v2 — 그래프 뷰 ═════════════════════════════════════════════

const V2_CSS = `

.pg-bar { height: 8px; border-radius: 999px; background: var(--surface2); overflow: hidden; margin: 4px 0 18px; }
.pg-fill { height: 100%; background: var(--accent); border-radius: 999px; }
.pg-tiles { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 18px; }
.pg-tile { flex: 1 1 92px; background: var(--surface2); border: 1px solid var(--border);
           border-radius: var(--r); padding: 10px 12px; }
.pg-tile b { display: block; font-size: 19px; line-height: 1.2; }
.pg-tile span { font-size: 11px; color: var(--dim); }
.pg-group { border: 1px solid var(--border-soft); border-radius: var(--r); padding: 12px 14px; margin-bottom: 12px; }
.pg-group > h3 { font-size: 12px; color: var(--muted); letter-spacing: .05em; text-transform: uppercase; margin-bottom: 10px; }
.pg-node { display: flex; align-items: flex-start; gap: 12px; padding: 11px 0; border-bottom: 1px solid var(--border-soft); }
.pg-node:last-child { border-bottom: none; }
.pg-dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 6px; flex-shrink: 0; }
.pg-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.pg-id { font-weight: 700; color: var(--text); }
.pg-sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
.pg-dep { font-family: var(--mono); font-size: 11.5px; color: var(--dim); margin-top: 4px; }
.pg-off { opacity: .55; }
`;

const STATE_COLOR = {
  done:          'var(--green)',
  running:       'var(--cyan)',
  ready:         'var(--accent)',
  gate_wait:     'var(--yellow)',
  external_wait: 'var(--yellow)',
  skipped:       'var(--dim)',
  bypassed:      'var(--purple)',
  failed:        'var(--red)',
  blocked:       'var(--orange)',
};
const STATE_LABEL = {
  done:          '완료',
  running:       '진행 중',
  ready:         '실행 가능',
  gate_wait:     'Gate 대기',
  external_wait: '외부 대기',
  skipped:       'Skip',
  bypassed:      'Bypass',
  failed:        '실패',
  blocked:       '차단됨',
  pending:       '대기',
};
const TYPE_LABEL = { auto: 'auto', gate: 'gate', external: 'external' };

function fallbackConfig(records) {
  // pipeline 스냅샷이 없는 상태 파일 — 의존 관계를 알 수 없으므로 뿌리만 나열한다.
  // dependsOn 을 명시해야 v1 선형 승격(직전 노드에 의존)으로 잘못 읽히지 않는다.
  return { stages: Object.keys(records).map((id) => ({ id, dependsOn: [] })) };
}

function renderV2() {
  const records = graphLib.recordsOf(data);
  const config = (data.pipeline && Array.isArray(data.pipeline.stages) && data.pipeline.stages.length)
    ? data.pipeline
    : fallbackConfig(records);

  let graph;
  try {
    graph = graphLib.normalize(config);
  } catch (e) {
    console.error(`❌ 그래프 정의 오류: ${e.message}`);
    process.exit(1);
  }

  const cycles = graphLib.detectCycles(graph);
  const sum = graphLib.summarize(graph, data);
  const ready = new Set(graphLib.readyNodes(graph, data).map((n) => n.id));
  const blocked = new Set(graphLib.blockedNodes(graph, data).map((n) => n.id));
  const unknown = Object.keys(records).filter((id) => !graph.index[id]);

  const effectiveState = (n) => {
    const r = records[n.id];
    if (r && typeof r.state === 'string') return r.state;
    if (blocked.has(n.id)) return 'blocked';
    if (ready.has(n.id)) return 'ready';
    return 'pending';
  };

  const renderNode = (n) => {
    const st = effectiveState(n);
    const rec = records[n.id] || {};
    const color = STATE_COLOR[st] || 'var(--muted)';
    const dim = (st === 'skipped' || st === 'bypassed') ? ' pg-off' : '';

    const chips = [chip(STATE_LABEL[st] || st, color)];
    if (n.type !== 'auto') chips.push(chip(TYPE_LABEL[n.type], n.type === 'gate' ? 'var(--yellow)' : 'var(--blue)'));
    if (n.activation === 'optional') chips.push(chip('optional', 'var(--purple)'));
    if (n.cutlineGate) chips.push(chip('컷라인', 'var(--orange)'));
    if (n.wait) chips.push(chip('wait', 'var(--yellow)'));

    const lines = [];
    if (n.skill) lines.push(`skill: ${esc(n.skill)}`);
    if (rec.reason) lines.push(`사유: ${esc(rec.reason)}`);
    if (rec.error) lines.push(`오류: ${esc(rec.error)}`);
    if (rec.gateApprovedAt) lines.push(`승인: ${esc(rec.gateApprovedAt)}`);
    else if (rec.completedAt) lines.push(`완료: ${esc(rec.completedAt)}`);
    if (Array.isArray(rec.bypassedDeps) && rec.bypassedDeps.length) {
      lines.push(`입력 부재: ${esc(rec.bypassedDeps.join(', '))}`);
    }
    if (st === 'skipped' && !rec.reason && n.skipCondition) lines.push(`조건: ${esc(n.skipCondition)}`);
    if (st === 'blocked') lines.push('상위 required 노드가 실패해 진행할 수 없다.');

    const deps = n.dependsOn.length
      ? `<div class="pg-dep">← ${esc(n.dependsOn.join('  ·  '))}</div>`
      : '<div class="pg-dep">← (뿌리)</div>';

    return `
      <div class="pg-node${dim}">
        <div class="pg-dot" style="background:${color}"></div>
        <div style="flex:1;min-width:0">
          <div class="pg-head"><span class="pg-id">${esc(n.id)}</span>${chips.join('')}</div>
          ${lines.length ? `<div class="pg-sub">${lines.join(' &nbsp;·&nbsp; ')}</div>` : ''}
          ${deps}
        </div>
      </div>`;
  };

  const groupsHtml = graph.groups.map((g) => `
    <div class="pg-group">
      <h3>${esc(g.id == null ? '그룹 없음' : g.id)} <span style="color:var(--dim);font-weight:400">· ${g.nodes.length}개</span></h3>
      ${g.nodes.map(renderNode).join('')}
    </div>`).join('');

  const tile = (n, label, color) =>
    `<div class="pg-tile"><b style="color:${color}">${n}</b><span>${label}</span></div>`;

  const cycleCard = cycles.length ? `
  <section class="card" style="border-color:${alpha('var(--red)', 40)}">
    <h2 class="section-title" style="color:var(--red)">순환 의존 — 실행 거부</h2>
    <p style="font-size:13px;color:var(--muted)">다음 노드가 순환에 참여한다. 순환은 실행 중에 고칠 수 있는
    상태가 아니라 정의의 오류이므로, 이 그래프는 실행하지 않는다.</p>
    <div class="code-block">${esc(cycles.join('  ·  '))}</div>
  </section>` : '';

  const readyList = graph.nodes.filter((n) => ready.has(n.id));
  const readyCard = `
  <section class="card">
    <h2 class="section-title">지금 실행 가능 ${readyList.length > 1 ? `· ${readyList.length}개 동시 가능` : ''}</h2>
    ${readyList.length
      ? `<div class="btn-group">${readyList.map((n) => chip(n.id, 'var(--accent)')).join('')}</div>`
      : '<p style="color:var(--dim);font-size:13px">없다 — 모두 정착했거나, 대기/차단 상태다.</p>'}
  </section>`;

  const unknownCard = unknown.length ? `
  <section class="card">
    <h2 class="section-title">정의에 없는 노드 ${unknown.length}개</h2>
    <p style="font-size:13px;color:var(--muted)">상태 파일에는 기록이 있으나 pipeline 스냅샷에 없다.
    그래프 정의가 바뀌었다면 revision 을 올린다.</p>
    <div class="code-block">${esc(unknown.join('  ·  '))}</div>
  </section>` : '';

  const body = `${cycleCard}
  <section class="card">
    <h2 class="section-title">진행률 ${sum.percent}%</h2>
    <div class="pg-bar"><div class="pg-fill" style="width:${sum.percent}%"></div></div>
    <div class="pg-tiles">
      ${tile(sum.total, '전체', 'var(--text)')}
      ${tile(sum.done, '완료', 'var(--green)')}
      ${tile(sum.skipped, 'Skip', 'var(--dim)')}
      ${tile(sum.bypassed, 'Bypass', 'var(--purple)')}
      ${tile(sum.waiting, '대기', 'var(--yellow)')}
      ${tile(sum.failed, '실패', 'var(--red)')}
      ${tile(sum.blocked, '차단', 'var(--orange)')}
    </div>
  </section>

${readyCard}

  <section class="card">
    <h2 class="section-title">노드 그래프</h2>
    ${graph.nodes.length ? groupsHtml : '<p style="color:var(--dim);font-size:13px">노드 없음 — 아직 파이프라인을 시작하지 않았다.</p>'}
  </section>

${unknownCard}

  <div class="meta-footer">
    run: ${esc(data.runId == null ? '(없음)' : String(data.runId))} &nbsp;·&nbsp; revision: ${esc(String(data.revision == null ? 1 : data.revision))}
    &nbsp;·&nbsp; 상태 파일: ${esc(path.basename(inputPath))}
  </div>`;

  const meta = `노드 ${sum.total}개 · 진행률 ${sum.percent}% · run ${esc(data.runId == null ? '-' : String(data.runId))}`
    + ` (rev ${esc(String(data.revision == null ? 1 : data.revision))})`;

  return {
    html: page(V2_CSS, meta, body),
    log: `   진행률: ${sum.percent}% (완료 ${sum.done} / 전체 ${sum.total}) · 실행 가능 ${sum.ready}개`
      + (sum.blocked ? ` · 차단 ${sum.blocked}개` : '')
      + (cycles.length ? ` · ⚠ 순환 ${cycles.length}개` : ''),
  };
}

// ══ 분기 ═══════════════════════════════════════════════════════

const out = graphLib.isV2State(data) ? renderV2() : renderV1();

writeReport(outputPath, out.html);
console.log(`✅ gen-status 완료: ${outputPath}`);
console.log(out.log);
