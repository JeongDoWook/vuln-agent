#!/usr/bin/env node
/**
 * gen-qa.js — wt-qa Self QA 결과 HTML 생성기
 *
 * 사용법:
 *   node scripts/gen-qa.js <qa.json> [output.html]
 *   node scripts/gen-qa.js <qa.json>  → 같은 디렉토리에 qa-{timestamp}.html
 *
 * 입력 JSON 스키마:
 * {
 *   "title":  "BE-694 QA 결과",
 *   "date":   "2026-05-28 14:30",
 *   "repo":   "be",
 *   "branch": "feature/issue-694-slug",
 *   "sha":    "abc1234",
 *   "static_check": {
 *     "typecheck": "pass" | "fail",
 *     "lint":      "pass" | "fail" | "skip",
 *     "test":      "pass" | "fail" | "skip",
 *     "errors_fixed": ["수정 내용1", "수정 내용2"]
 *   },
 *   "review": {
 *     "score":       92,
 *     "grade":       "PASS" | "CAUTION" | "BLOCKED",
 *     "report_path": "docs/BE-694/report-20260528-1430.html"
 *   },
 *   "ac": {
 *     "pass":     8,
 *     "total":    9,
 *     "failures": [
 *       { "id": "AC-3", "desc": "필터 미적용 케이스", "note": "원인 설명" }
 *     ]
 *   },
 *   "edge_cases": ["발견된 엣지케이스1"],
 *   "commit": {
 *     "hash":    "abc1234",
 *     "message": "test: QA 검증 커밋"
 *   }
 * }
 */

const { loadInput, resolveOutputPath, writeReport } = require('./lib/report/io');
const { loadBaseCss } = require('./lib/report/css');
const { esc, alpha } = require('./lib/report/html');

const BASE_CSS = loadBaseCss();

const { inputPath, outputArg, data } = loadInput('Usage: node scripts/gen-qa.js <qa.json> [output.html]');
const outputPath = resolveOutputPath(inputPath, outputArg, 'qa');

// ── 데이터 해체 ───────────────────────────────────────────────
const {
  title         = 'QA 결과',
  date          = new Date().toISOString().slice(0, 16).replace('T', ' '),
  repo          = '',
  branch        = '',
  sha           = '',
  static_check  = {},
  review        = {},
  ac            = {},
  edge_cases    = [],
  commit        = {},
} = data;

const { typecheck = 'skip', lint = 'skip', test = 'skip', errors_fixed = [] } = static_check;
const { score = null, grade = null, report_path = null } = review;
const { pass: ac_pass = 0, total: ac_total = 0, failures: ac_failures = [] } = ac;

// ── 헬퍼 ─────────────────────────────────────────────────────
const STATUS_COLOR = { pass: 'var(--green)', fail: 'var(--red)', skip: 'var(--dim)' };
const STATUS_LABEL = { pass: 'PASS', fail: 'FAIL', skip: 'SKIP' };
const GRADE_COLOR  = { PASS: 'var(--green)', CAUTION: 'var(--yellow)', BLOCKED: 'var(--red)' };

function statusBadge(s) {
  const c = STATUS_COLOR[s] || 'var(--dim)';
  return `<span style="padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700;`
       + `background:${alpha(c, 13)};color:${c};border:1px solid ${alpha(c, 27)}">${STATUS_LABEL[s] || s}</span>`;
}

function overallStatic() {
  if ([typecheck, lint, test].some(s => s === 'fail')) return 'fail';
  if ([typecheck, lint, test].every(s => s === 'skip')) return 'skip';
  return 'pass';
}

// ── 요약 카드 ─────────────────────────────────────────────────
function renderSummaryCards() {
  const staticStatus = overallStatic();
  const acStatus     = ac_total === 0 ? 'skip' : (ac_pass === ac_total ? 'pass' : 'fail');
  const edgeStatus   = edge_cases.length === 0 ? 'pass' : 'fail';

  const gradeColor = grade ? (GRADE_COLOR[grade] || 'var(--muted)') : 'var(--dim)';
  const scoreText  = score !== null ? `${score}/100` : '—';
  const gradeText  = grade || '—';

  const cards = [
    { label: '정적 검증', status: staticStatus },
    { label: 'AC 검증', status: acStatus, sub: `${ac_pass}/${ac_total}` },
    { label: '엣지케이스', status: edgeStatus, sub: edge_cases.length > 0 ? `${edge_cases.length}건` : '없음' },
  ];

  const cardHtml = cards.map(c => {
    const col = STATUS_COLOR[c.status] || 'var(--dim)';
    return `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 22px;text-align:center;min-width:120px">
      <div style="font-size:18px;font-weight:700;color:${col}">${STATUS_LABEL[c.status] || c.status}</div>
      <div style="font-size:11px;color:var(--dim);margin-top:4px">${esc(c.label)}</div>
      ${c.sub ? `<div style="font-size:12px;color:var(--muted);margin-top:2px">${esc(c.sub)}</div>` : ''}
    </div>`;
  }).join('');

  const reviewCard = `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 22px;text-align:center;min-width:120px">
      <div style="font-size:18px;font-weight:700;color:${gradeColor}">${esc(scoreText)}</div>
      <div style="font-size:11px;color:var(--dim);margin-top:4px">리뷰 점수</div>
      <div style="font-size:12px;color:${gradeColor};margin-top:2px">${esc(gradeText)}</div>
    </div>`;

  return cardHtml + reviewCard;
}

// ── 정적 검증 섹션 ────────────────────────────────────────────
function renderStaticCheck() {
  const rows = [
    { name: 'Typecheck', status: typecheck },
    { name: 'Lint',      status: lint },
    { name: 'Test',      status: test },
  ].map(r => `
      <tr>
        <td style="color:var(--muted);font-weight:500">${r.name}</td>
        <td>${statusBadge(r.status)}</td>
      </tr>`).join('');

  const errorRows = errors_fixed.length ? `
    <h3 style="font-size:11px;color:var(--dim);margin-top:18px;margin-bottom:10px;text-transform:uppercase;letter-spacing:.06em">수정된 오류</h3>
    ${errors_fixed.map(e => `
    <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin-bottom:6px;font-size:13px;color:var(--muted)">${esc(e)}</div>`).join('')}` : '';

  return `
  <section class="card">
    <h2 class="section-title">정적 검증</h2>
    <table class="data-table" style="width:auto">
      <tbody>${rows}</tbody>
    </table>
    ${errorRows}
  </section>`;
}

// ── 코드 리뷰 요약 ────────────────────────────────────────────
function renderReviewSummary() {
  if (score === null && !report_path) return '';
  const gc       = grade ? (GRADE_COLOR[grade] || 'var(--muted)') : 'var(--muted)';
  const linkHtml = report_path
    ? `<a href="${esc(report_path)}" style="color:var(--blue);font-size:12px;margin-left:12px">리포트 보기 →</a>`
    : '';
  return `
  <section class="card">
    <h2 class="section-title">코드 리뷰</h2>
    <div style="display:flex;align-items:center;gap:12px">
      <span style="font-size:32px;font-weight:700;color:${gc}">${score !== null ? score : '—'}</span>
      <div>
        <span style="color:var(--dim);font-size:14px">/100</span>
        ${grade ? `<span style="margin-left:8px;padding:3px 10px;border-radius:5px;font-size:12px;font-weight:700;background:${alpha(gc, 13)};color:${gc};border:1px solid ${alpha(gc, 27)}">${grade}</span>` : ''}
        ${linkHtml}
      </div>
    </div>
  </section>`;
}

// ── AC 검증 ───────────────────────────────────────────────────
function renderAC() {
  if (ac_total === 0) return '';
  const allPass = ac_pass === ac_total;
  const passColor = allPass ? 'var(--green)' : 'var(--yellow)';

  const failItems = ac_failures.map(f => `
    <div style="background:${alpha('var(--red)', 8)};border:1px solid ${alpha('var(--red)', 25)};border-radius:7px;padding:10px 14px;margin-top:8px;font-size:13px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="color:var(--red)">☐</span>
        <span style="font-weight:600;color:var(--red)">${esc(f.id)}</span>
        <span style="color:var(--text)">${esc(f.desc)}</span>
      </div>
      ${f.note ? `<div style="color:var(--muted);margin-top:4px;margin-left:20px">${esc(f.note)}</div>` : ''}
    </div>`).join('');

  const passCount = ac_pass;
  const failCount = ac_total - ac_pass;

  return `
  <section class="card">
    <h2 class="section-title">AC 검증</h2>
    <div style="display:flex;gap:16px;margin-bottom:16px">
      <span style="font-size:28px;font-weight:700;color:${passColor}">${passCount}/${ac_total}</span>
      <div style="padding-top:6px">
        ${passCount > 0 ? `<span style="color:var(--green);font-size:13px">통과 ${passCount}건</span>` : ''}
        ${failCount > 0 ? `<span style="color:var(--red);font-size:13px;margin-left:12px">실패 ${failCount}건</span>` : ''}
      </div>
    </div>
    ${failItems || '<div style="color:var(--green);font-size:13px">모든 AC 통과</div>'}
  </section>`;
}

// ── 엣지케이스 ────────────────────────────────────────────────
function renderEdgeCases() {
  return `
  <section class="card">
    <h2 class="section-title">엣지케이스</h2>
    ${edge_cases.length === 0
      ? '<p style="color:var(--green);font-size:13px">발견 없음</p>'
      : edge_cases.map(e => `
    <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin-bottom:6px;font-size:13px;color:var(--muted)">
      <span style="color:var(--yellow);margin-right:8px">⚠</span>${esc(e)}
    </div>`).join('')}
  </section>`;
}

// ── 커밋 정보 ─────────────────────────────────────────────────
function renderCommit() {
  if (!commit.hash && !commit.message) return '';
  return `
  <section class="card">
    <h2 class="section-title">검증 커밋</h2>
    <div style="display:flex;gap:12px;align-items:baseline">
      <code style="color:var(--blue);font-size:12px">${esc(commit.hash || '-')}</code>
      <span style="color:var(--muted);font-size:13px">${esc(commit.message || '-')}</span>
    </div>
  </section>`;
}

// ── 전체 HTML ─────────────────────────────────────────────────
const overallColor = overallStatic() === 'fail' || (ac_total > 0 && ac_pass < ac_total)
  ? 'var(--red)' : 'var(--green)';

const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<style>
${BASE_CSS}
/* ── gen-qa.js 고유 ── (공통분은 scripts/assets/report.css) */
  /* 키-값 나열용 표: 좌측 패딩 없이 붙여 읽는다 */
  .data-table    { width: auto; }
  .data-table td { padding: 8px 16px 8px 0; border-bottom: none; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>${esc(title)}</h1>
    <div class="meta">${esc(date)} · ${esc(branch)} · ${esc(sha)}</div>
  </div>
  <span style="padding:5px 14px;border-radius:8px;font-size:13px;font-weight:700;background:${alpha(overallColor, 13)};color:${overallColor};border:1px solid ${alpha(overallColor, 27)}">
    ${overallStatic() === 'fail' ? 'FAIL' : (ac_pass < ac_total ? 'AC 미통과' : 'PASS')}
  </span>
</div>

<div class="container">
  <div class="summary-cards">
    ${renderSummaryCards()}
  </div>
  ${renderStaticCheck()}
  ${renderReviewSummary()}
  ${renderAC()}
  ${renderEdgeCases()}
  ${renderCommit()}
</div>
</body>
</html>`;

writeReport(outputPath, html);
console.log(`✅ gen-qa 완료: ${outputPath}`);
console.log(`   정적검증: ${overallStatic()} | AC: ${ac_pass}/${ac_total} | 엣지케이스: ${edge_cases.length}건`);
