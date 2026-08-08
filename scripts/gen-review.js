#!/usr/bin/env node
/**
 * gen-review.js — wt-review Warning/Critical 결정 HTML 생성기
 *
 * 사용법:
 *   node scripts/gen-review.js <input.json> [output.html]
 *   node scripts/gen-review.js <input.json>  → wt/{slug}/docs/{repo}/review-{timestamp}.html
 *
 * 입력 JSON 스키마:
 * {
 *   "title": "BE-694 취약점 스냅샷",
 *   "date": "2026-05-28",
 *   "context": "feature/issue-694-... | abc1234",
 *   "items": [
 *     {
 *       "id": "1",
 *       "severity": "warning",          // critical | warning
 *       "perspective": "Quality",        // Quality | Security | Regression
 *       "impact": "High",                // High | Medium | Low
 *       "title": "N+1 쿼리 발생",
 *       "subtitle": "VulnSnapshotService.java:142",
 *       "file": "src/.../Service.java",
 *       "line": 142,
 *       "problem": "문제 상세 설명 (HTML 허용)",
 *       "current_code": "// 문제 코드\nfor (v : list) v.getAsset();",
 *       "solution": "해결 방향 텍스트",
 *       "solution_code": "// 수정 코드\n@EntityGraph(...)",
 *       "auto_fixable": false            // true: AI가 자동 수정 가능
 *     }
 *   ]
 * }
 */

const { loadInput, resolveOutputPath, writeReport } = require('./lib/report/io');
const { loadBaseCss } = require('./lib/report/css');
const { esc } = require('./lib/report/html');
const { PERSPECTIVE_COLOR } = require('./lib/report/perspective');

const BASE_CSS = loadBaseCss();

const { inputPath, outputArg, data } = loadInput('Usage: node scripts/gen-review.js <input.json> [output.html]');
const outputPath = resolveOutputPath(inputPath, outputArg, 'review');

const { title = '코드 리뷰', date = new Date().toISOString().slice(0, 10), context = '', items = [] } = data;

// ── 헬퍼 함수 ────────────────────────────────────────────────
function badgeClass(severity, impact) {
  if (severity === 'critical') return 'badge-critical';
  if (impact === 'High')       return 'badge-high';
  if (impact === 'Medium')     return 'badge-medium';
  return 'badge-low';
}

function badgeLabel(severity, impact) {
  if (severity === 'critical') return 'Critical';
  return `Warning · ${impact || '?'}`;
}

function perspectiveTag(p = '') {
  // 색상은 SSOT 토큰에서 유도한다 (인쇄 시 자동으로 흑백 팔레트로 뒤집히도록).
  // 매핑 자체는 gen-report.js와 공유 — lib/report/perspective.js 참고.
  const color = PERSPECTIVE_COLOR[p] || 'var(--dim)';
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;`
       + `background:color-mix(in srgb, ${color} 13%, transparent);color:${color};`
       + `border:1px solid color-mix(in srgb, ${color} 27%, transparent);letter-spacing:.06em">${esc(p)}</span>`;
}

function codeBlock(code) {
  if (!code) return '';
  return `<div class="code-block">${esc(code)}</div>`;
}

function circleNum(n) {
  const nums = '①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳';
  return nums[n - 1] || `(${n})`;
}

// ── 카드 블록 생성 ────────────────────────────────────────────
function renderCard(item, idx) {
  const n          = String(idx);
  const bClass     = badgeClass(item.severity, item.impact);
  const bLabel     = badgeLabel(item.severity, item.impact);
  const autoTag    = item.auto_fixable
    ? `<span style="font-size:10px;padding:2px 7px;border-radius:4px;font-weight:700;`
      + `background:color-mix(in srgb, var(--green) 15%, transparent);color:var(--green);`
      + `border:1px solid color-mix(in srgb, var(--green) 30%, transparent)">AUTO</span>`
    : '';

  const solutionBlock = item.solution_code
    ? codeBlock(item.solution_code)
    : item.solution ? `<p>${esc(item.solution)}</p>` : '';

  const currentCodeBlock = item.current_code ? `
      <div>
        <div class="sub-title">현재 코드</div>
        ${codeBlock(item.current_code)}
      </div>` : '';

  return `
  <div class="gap-card" id="card-${n}">
    <div class="card-header" onclick="toggleCard('card-${n}')">
      <span class="badge ${bClass}">${bLabel}</span>
      <div style="flex:1">
        <div class="card-title">${circleNum(idx)} ${esc(item.title)} ${autoTag}</div>
        <div class="card-subtitle" style="display:flex;gap:8px;align-items:center;margin-top:4px">
          ${perspectiveTag(item.perspective)}
          <span>${esc(item.subtitle || (item.file ? `${item.file}${item.line ? ':' + item.line : ''}` : ''))}</span>
        </div>
      </div>
      <span class="chevron">›</span>
    </div>
    <div class="card-body">
      <div class="two-col">
        <div>
          <div class="sub-title">현재 문제</div>
          <p>${item.problem || ''}</p>
          ${currentCodeBlock}
        </div>
        <div>
          <div class="sub-title">해결 방향</div>
          ${solutionBlock}
        </div>
      </div>
    </div>
    <div class="decision-area">
      <span class="label">결정</span>
      <div class="btn-group">
        <button class="dec-btn do"    onclick="decide('${n}','do')">✓ 이번에 처리</button>
        <button class="dec-btn defer" onclick="decide('${n}','defer')">→ 다음 이터레이션</button>
        <button class="dec-btn skip"  onclick="decide('${n}','skip')">✕ 제외</button>
      </div>
      <div class="comment-wrap">
        <textarea class="comment-input" id="comment-${n}" rows="2" placeholder="코멘트 (선택)"></textarea>
      </div>
    </div>
  </div>`;
}

function renderSummaryRow(item, idx) {
  const n = String(idx);
  return `
      <div class="summary-row" id="sum-${n}">
        <span class="s-num">${circleNum(idx)}</span>
        <span class="s-title">${esc(item.title)}</span>
        <span class="s-badge none">미결정</span>
      </div>`;
}

// ── 통계 배너 ─────────────────────────────────────────────────
function renderStats(items) {
  const critical = items.filter(i => i.severity === 'critical').length;
  const warning  = items.filter(i => i.severity === 'warning').length;
  const high     = items.filter(i => i.severity !== 'critical' && i.impact === 'High').length;
  const auto     = items.filter(i => i.auto_fixable).length;
  const byPersp  = {};
  items.forEach(i => { byPersp[i.perspective] = (byPersp[i.perspective] || 0) + 1; });

  const perspTags = Object.entries(byPersp)
    .map(([p, n]) => perspectiveTag(p) + ` <span style="color:var(--muted);font-size:12px">${n}건</span>`)
    .join(' ');

  return `
<div style="background:var(--surface);border-bottom:1px solid var(--border);padding:12px 48px;display:flex;gap:24px;align-items:center;flex-wrap:wrap">
  ${critical ? `<span style="color:var(--crit);font-size:13px;font-weight:700">Critical ${critical}건</span>` : ''}
  ${warning  ? `<span style="color:var(--warn);font-size:13px;font-weight:700">Warning ${warning}건</span>` : ''}
  ${high     ? `<span style="color:var(--high);font-size:12px">High Impact ${high}건</span>` : ''}
  ${auto     ? `<span style="color:var(--ok);font-size:12px">자동수정 가능 ${auto}건</span>` : ''}
  <span style="margin-left:auto;display:flex;gap:8px;align-items:center">${perspTags}</span>
</div>`;
}

// ── 타이틀 맵 (JS) ───────────────────────────────────────────
const titlesJS = items
  .map((item, i) => `  '${i + 1}': ${JSON.stringify(item.title)}`)
  .join(',\n');

// ── 전체 HTML 조립 ────────────────────────────────────────────
const cards       = items.map((item, i) => renderCard(item, i + 1)).join('\n');
const summaryRows = items.map((item, i) => renderSummaryRow(item, i + 1)).join('\n');
const statsBanner = renderStats(items);
const total       = items.length;

const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<style>
${BASE_CSS}
/* ── gen-review.js 고유 (결정 UI) ── 공통분은 scripts/assets/report.css */

  /* 상단 고정 헤더 + 진행바 */
  .header { position: sticky; top: 0; z-index: 100; padding: 14px 48px; }
  .header h1 { white-space: nowrap; }
  .header-progress { flex: 1; display: flex; align-items: center; gap: 10px; min-width: 0; }
  .header-progress .progress-track { flex: 1; height: 5px; background: var(--border); }
  .progress-bar-wrap { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 48px; display: flex; align-items: center; gap: 20px; height: auto; border-radius: 0; }
  .progress-track { flex: 1; height: 6px; background: var(--border); border-radius: 99px; }
  .progress-fill  { background: linear-gradient(90deg, var(--accent), var(--green)); border-radius: 99px; transition: width .4s; }
  .copy-btn { margin-right: 8px; padding: 9px 14px; color: var(--dim); }
  .copy-btn:hover { color: var(--muted); }
  .export-btn:hover { filter: brightness(1.12); }

  .container { max-width: 920px; }

  /* 결함 카드 (접이식) */
  .gap-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-lg); margin-bottom: 20px; overflow: hidden; transition: border-color .2s; }
  .gap-card.decided { border-color: var(--dim); opacity: .75; }
  .gap-card.decided .card-body { display: none; }
  .card-header { padding: 18px 20px; cursor: pointer; user-select: none; align-items: flex-start; gap: 14px; }
  .card-header:hover { background: rgba(255,255,255,.02); }
  .badge { flex-shrink: 0; margin-top: 2px; }
  .card-title { font-size: 15px; font-weight: 600; margin-bottom: 0; }
  .chevron { margin-left: auto; color: var(--dim); font-size: 16px; transition: transform .2s; flex-shrink: 0; margin-top: 2px; }

  .card-body { padding: 0 20px 20px; border-top: 1px solid var(--border); }
  .two-col   { display: flex; flex-direction: column; gap: 0; padding-top: 18px; }
  .sub-title { font-size: 11px; font-weight: 600; color: var(--dim); text-transform: uppercase; letter-spacing: .08em; margin: 14px 0 8px; }
  .card-body p { color: var(--muted); font-size: 13px; line-height: 1.7; }
  .code-block { margin-top: 10px; white-space: pre; }

  /* 결정 영역 */
  .decision-area { padding: 16px 20px; border-top: 1px solid var(--border); background: var(--surface2); display: flex; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
  .decision-area .label { font-size: 12px; color: var(--dim); white-space: nowrap; padding-top: 8px; }
  .dec-btn { border: 1px solid; border-radius: 7px; padding: 6px 14px; font-size: 12px; font-weight: 600; background: transparent; transition: all .15s; }
  .dec-btn.do    { border-color: color-mix(in srgb, var(--green) 40%, transparent);  color: var(--green); }
  .dec-btn.defer { border-color: color-mix(in srgb, var(--yellow) 40%, transparent); color: var(--yellow); }
  .dec-btn.skip  { border-color: color-mix(in srgb, var(--muted) 25%, transparent);  color: var(--dim); }
  .dec-btn.do:hover    { background: color-mix(in srgb, var(--green) 10%, transparent); }
  .dec-btn.defer:hover { background: color-mix(in srgb, var(--yellow) 10%, transparent); }
  .dec-btn.skip:hover  { background: color-mix(in srgb, var(--muted) 8%, transparent); }
  .dec-btn.active.do    { background: color-mix(in srgb, var(--green) 15%, transparent);  border-color: var(--green);  box-shadow: 0 0 0 1px var(--green); }
  .dec-btn.active.defer { background: color-mix(in srgb, var(--yellow) 15%, transparent); border-color: var(--yellow); box-shadow: 0 0 0 1px var(--yellow); }
  .dec-btn.active.skip  { background: color-mix(in srgb, var(--muted) 10%, transparent);  border-color: var(--muted);  box-shadow: 0 0 0 1px var(--muted); }

  .comment-wrap  { flex: 1; min-width: 200px; }
  .comment-input { border-radius: 7px; padding: 7px 11px; resize: vertical; line-height: 1.5; font-size: 12px; }
  .comment-input:focus       { outline: none; border-color: var(--accent); }
  .comment-input::placeholder { color: var(--dim); }

  .decided-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 99px; border: none; }
  .decided-badge.do    { background: color-mix(in srgb, var(--green) 12%, transparent);  color: var(--green); }
  .decided-badge.defer { background: color-mix(in srgb, var(--yellow) 12%, transparent); color: var(--yellow); }
  .decided-badge.skip  { background: color-mix(in srgb, var(--muted) 8%, transparent);   color: var(--muted); }

  /* 요약 */
  .summary-section { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-lg); padding: 24px; margin-top: 36px; }
  .summary-section h3 { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin-bottom: 16px; }
  #summary-list { display: flex; flex-direction: column; gap: 8px; }
  .summary-row { display: flex; align-items: center; gap: 12px; padding: 10px 14px; background: var(--surface2); border-radius: var(--r); font-size: 13px; }
  .summary-row .s-num   { color: var(--dim); font-size: 12px; flex-shrink: 0; }
  .summary-row .s-title { flex: 1; color: var(--text); }
  .summary-row .s-badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: var(--r-sm); white-space: nowrap; }
  .summary-row .s-badge.do    { background: color-mix(in srgb, var(--green) 15%, transparent);  color: var(--green); }
  .summary-row .s-badge.defer { background: color-mix(in srgb, var(--yellow) 15%, transparent); color: var(--yellow); }
  .summary-row .s-badge.skip  { background: color-mix(in srgb, var(--muted) 10%, transparent);  color: var(--muted); }
  .summary-row .s-badge.none  { background: color-mix(in srgb, var(--muted) 5%, transparent);   color: var(--dim); }
  .summary-row .s-comment     { font-size: 12px; color: var(--dim); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* JSON export */
  .export-result { display: none; margin-top: 20px; }
  .export-result.visible { display: block; }
  .export-json-wrap { position: relative; background: var(--surface2); border: 1px solid var(--green); border-radius: var(--r); padding: 16px; }
  .export-json-wrap pre { font-family: var(--mono); font-size: 12px; white-space: pre-wrap; word-break: break-all; line-height: 1.6; max-height: 320px; overflow-y: auto; border: none; background: none; padding: 0; }
  .export-copy-bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .export-copy-bar span { font-size: 11px; font-weight: 700; color: var(--green); text-transform: uppercase; letter-spacing: .06em; }
  .export-copy-btn { background: color-mix(in srgb, var(--green) 15%, transparent); color: var(--green); border: 1px solid color-mix(in srgb, var(--green) 40%, transparent); border-radius: 6px; padding: 4px 12px; font-size: 12px; font-weight: 600; }
  .export-copy-btn:hover { background: color-mix(in srgb, var(--green) 25%, transparent); }
  .export-copy-btn.copied { background: color-mix(in srgb, var(--green) 30%, transparent); border-color: var(--green); }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>${esc(title)}</h1>
    <div class="meta">${esc(date)} · ${esc(context)}</div>
  </div>
  <div class="header-progress">
    <div class="progress-track"><div class="progress-fill" id="header-progress-fill"></div></div>
    <span class="progress-count" id="header-progress-count">0 / ${total}</span>
  </div>
  <button class="export-btn" onclick="submitDecisions()">제출 (copy)</button>
</div>

${statsBanner}

<div class="progress-bar-wrap">
  <span class="progress-label">결정 완료</span>
  <div class="progress-track"><div class="progress-fill" id="progress-fill" style="width:0%"></div></div>
  <span class="progress-count" id="progress-count">0 / ${total}</span>
</div>

<div class="container">

${cards}

  <div class="summary-section">
    <h3>결정 요약</h3>
    <div id="summary-list">
${summaryRows}
    </div>
    <div class="export-result" id="export-result">
      <div class="export-json-wrap">
        <div class="export-copy-bar">
          <span>✓ 제출 완료 — 아래 JSON을 Claude에 붙여넣으세요</span>
          <button class="export-copy-btn" id="recopy-btn" onclick="recopyJSON()">다시 복사</button>
        </div>
        <pre id="export-json-content"></pre>
      </div>
    </div>
  </div>

</div>

<script>
  const TOTAL = ${total};
  const labels = { do: '이번에 처리', defer: '다음 이터레이션', skip: '제외' };
  const titles = {
${titlesJS}
  };
  const state = {};

  function decide(id, choice) {
    state[id] = choice;
    document.querySelector('#card-' + id + ' .decision-area')
      .querySelectorAll('.dec-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('#card-' + id + ' .dec-btn.' + choice).classList.add('active');

    const header = document.querySelector('#card-' + id + ' .card-header');
    const old = header.querySelector('.decided-badge');
    if (old) old.remove();
    const badge = document.createElement('span');
    badge.className = 'decided-badge ' + choice;
    badge.textContent = labels[choice];
    header.insertBefore(badge, header.querySelector('.chevron'));

    updateSummary(id, choice);
    updateProgress();
  }

  function updateSummary(id, choice) {
    const row = document.getElementById('sum-' + id);
    const badge = row.querySelector('.s-badge');
    badge.className = 's-badge ' + choice;
    badge.textContent = labels[choice];
    let c = row.querySelector('.s-comment');
    if (!c) { c = document.createElement('span'); c.className = 's-comment'; row.appendChild(c); }
    c.textContent = (document.getElementById('comment-' + id) || {}).value || '';
  }

  function updateProgress() {
    const done = Object.keys(state).length;
    const pct = (done / TOTAL * 100) + '%';
    document.getElementById('progress-fill').style.width = pct;
    document.getElementById('progress-count').textContent = done + ' / ' + TOTAL;
    document.getElementById('header-progress-fill').style.width = pct;
    document.getElementById('header-progress-count').textContent = done + ' / ' + TOTAL;
  }

  function toggleCard(id) {
    const body    = document.querySelector('#' + id + ' .card-body');
    const chevron = document.querySelector('#' + id + ' .chevron');
    const hidden  = body.style.display === 'none';
    body.style.display      = hidden ? '' : 'none';
    chevron.style.transform = hidden ? '' : 'rotate(-90deg)';
  }

  document.querySelectorAll('.comment-input').forEach(el => {
    el.addEventListener('input', () => {
      const id = el.id.replace('comment-', '');
      if (state[id]) updateSummary(id, state[id]);
    });
  });

  function buildDecisionData() {
    const decisions = [];
    for (let i = 1; i <= TOTAL; i++) {
      const s = String(i);
      decisions.push({
        id: s,
        title: titles[s] || '',
        decision: state[s] || 'undecided',
        comment: (document.getElementById('comment-' + s) || {}).value || ''
      });
    }
    return { title: ${JSON.stringify(title)}, date: ${JSON.stringify(date)}, decisions };
  }

  let _lastJSON = '';

  function submitDecisions() {
    _lastJSON = JSON.stringify(buildDecisionData(), null, 2);

    // JSON 표시
    document.getElementById('export-json-content').textContent = _lastJSON;
    const box = document.getElementById('export-result');
    box.classList.add('visible');
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // 클립보드 복사
    navigator.clipboard?.writeText(_lastJSON);

    // 버튼 피드백
    const btn = document.querySelector('.export-btn');
    btn.textContent = '✓ 복사됨';
    btn.style.background = 'var(--green)';
    setTimeout(() => { btn.textContent = '제출 (copy)'; btn.style.background = ''; }, 2000);
  }

  function recopyJSON() {
    navigator.clipboard?.writeText(_lastJSON);
    const btn = document.getElementById('recopy-btn');
    btn.textContent = '✓ 복사됨';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '다시 복사'; btn.classList.remove('copied'); }, 1500);
  }
</script>
</body>
</html>`;

// ── 파일 쓰기 ────────────────────────────────────────────────
writeReport(outputPath, html);
console.log(`✅ gen-review 완료: ${outputPath}`);
console.log(`   항목 수: ${total}건 (Critical: ${items.filter(i=>i.severity==='critical').length} / Warning: ${items.filter(i=>i.severity==='warning').length})`);
