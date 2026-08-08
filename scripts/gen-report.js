#!/usr/bin/env node
/**
 * gen-report.js — wt-review 최종 리포트 HTML 생성기
 *
 * 사용법:
 *   node scripts/gen-report.js <report.json> [output.html]
 *   node scripts/gen-report.js <report.json>  → 같은 디렉토리에 report-{timestamp}.html
 *
 * 입력 JSON 스키마:
 * {
 *   "title":    "BE-694 리뷰 리포트",
 *   "date":     "2026-05-28",
 *   "context":  "feature/issue-694-slug | abc1234",
 *   "repo_type": "FE" | "BE",
 *   "score":    92,
 *   "grade":    "PASS" | "CAUTION" | "BLOCKED",
 *   "cutline":  85,
 *   "score_adjusted": null | 95,           // pre_accepted 조정 후 점수 (없으면 null)
 *   "adjustment_note": null | "사전합의 2건 제외 (+3점)",
 *   "summary": {
 *     "critical_fixed": 2,
 *     "warning_fixed":  3,
 *     "warning_mr":     1,
 *     "warning_accepted": 2,
 *     "info":           5,
 *     "iterations":     1
 *   },
 *   "deductions": [
 *     { "perspective": "Quality",    "result": "fix",    "count": 2, "points": -16 },
 *     { "perspective": "Security",   "result": "accept", "count": 1, "points": -18 }
 *   ],
 *   "critical_history": [
 *     { "iteration": 1, "perspective": "Security", "loc": "File.java:42", "summary": "SQL Injection 수정" }
 *   ],
 *   "warning_results": [
 *     { "result": "fix",        "perspective": "Quality",    "loc": "A.java:10", "title": "제목", "impact": "High" },
 *     { "result": "mr_comment", "perspective": "Regression", "loc": "B.java:20", "title": "제목", "impact": "Medium" },
 *     { "result": "accept",     "perspective": "Security",   "loc": "C.java:30", "title": "제목", "impact": "Low",
 *       "reason": "내부망 전용", "plan": "다음 이슈" }
 *   ],
 *   "fix_commits": [
 *     { "hash": "abc1234", "message": "fix: SQL Injection 수정 (review-it1)" }
 *   ],
 *   "meta": {
 *     "last_reviewed_commit": "abc1234",
 *     "last_reviewed_tree":   "clean"
 *   }
 * }
 */

const { loadInput, resolveOutputPath, writeReport } = require('./lib/report/io');
const { loadBaseCss } = require('./lib/report/css');
const { esc, alpha, chip } = require('./lib/report/html');
const { perspectiveBadge } = require('./lib/report/perspective');

const BASE_CSS = loadBaseCss();

const { inputPath, outputArg, data } = loadInput('Usage: node scripts/gen-report.js <report.json> [output.html]');
const outputPath = resolveOutputPath(inputPath, outputArg, 'report');

// ── 데이터 해체 ───────────────────────────────────────────────
const {
  title        = '리뷰 리포트',
  date         = new Date().toISOString().slice(0, 10),
  context      = '',
  repo_type    = 'BE',
  score        = 0,
  grade        = 'PASS',
  cutline      = 85,
  score_adjusted   = null,
  adjustment_note  = null,
  summary      = {},
  deductions   = [],
  critical_history = [],
  warning_results  = [],
  fix_commits      = [],
  meta         = {},
} = data;

const displayScore = score_adjusted !== null ? score_adjusted : score;

// ── 헬퍼 ─────────────────────────────────────────────────────
const GRADE_COLOR = { PASS: 'var(--green)', CAUTION: 'var(--yellow)', BLOCKED: 'var(--red)' };
const RESULT_COLOR = { fix: 'var(--green)', mr_comment: 'var(--blue)', accept: 'var(--yellow)' };
const RESULT_LABEL = { fix: '수정', mr_comment: 'MR코멘트', accept: '감수' };
const IMPACT_COLOR = { High: 'var(--orange)', Medium: 'var(--yellow)', Low: 'var(--muted)' };

function gradeStyle(g) {
  const c = GRADE_COLOR[g] || 'var(--muted)';
  return `background:${alpha(c, 13)};color:${c};border:1px solid ${alpha(c, 33)}`;
}

function resultBadge(r) {
  const c = RESULT_COLOR[r] || 'var(--muted)';
  return chip(RESULT_LABEL[r] || r, c);
}

const perspBadge = perspectiveBadge;

function impactBadge(i) {
  return chip(i, IMPACT_COLOR[i] || 'var(--dim)');
}

// ── 요약 카드 4개 ──────────────────────────────────────────────
function renderSummaryCards() {
  const cards = [
    { label: 'Critical 수정', value: summary.critical_fixed ?? 0, color: 'var(--red)' },
    { label: 'Warning 수정',  value: summary.warning_fixed  ?? 0, color: 'var(--green)' },
    { label: 'MR 코멘트',     value: summary.warning_mr     ?? 0, color: 'var(--blue)' },
    { label: '감수',          value: summary.warning_accepted ?? 0, color: 'var(--yellow)' },
  ];
  return cards.map(c => `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 22px;text-align:center;min-width:110px">
      <div style="font-size:28px;font-weight:700;color:${c.color}">${c.value}</div>
      <div style="font-size:11px;color:var(--dim);margin-top:4px">${esc(c.label)}</div>
    </div>`).join('');
}

// ── 점수 섹션 ─────────────────────────────────────────────────
function renderScoreSection() {
  const gc    = GRADE_COLOR[grade] || 'var(--muted)';
  const rows  = deductions.map(d => `
      <tr>
        <td>${perspBadge(d.perspective)}</td>
        <td>${resultBadge(d.result)}</td>
        <td style="text-align:center;color:var(--text)">${d.count}건</td>
        <td style="text-align:right;color:var(--red);font-weight:600">${d.points}점</td>
      </tr>`).join('');

  const adjRow = (score_adjusted !== null && adjustment_note) ? `
    <div style="margin-top:10px;font-size:12px;color:var(--muted)">
      ※ ${esc(adjustment_note)}
      <span style="margin-left:8px;color:var(--dim)">${score}점 → ${score_adjusted}점</span>
    </div>` : '';

  return `
  <section class="card">
    <h2 class="section-title">리뷰 점수</h2>
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px">
      <span style="font-size:48px;font-weight:800;color:${gc};line-height:1">${displayScore}</span>
      <div>
        <span style="font-size:16px;color:var(--dim)">/100</span>
        <div style="margin-top:6px">
          <span style="padding:4px 12px;border-radius:6px;font-size:13px;font-weight:700;${gradeStyle(grade)}">${grade}</span>
          <span style="margin-left:8px;font-size:12px;color:var(--dim)">${esc(repo_type)} 커트라인 ${cutline}점</span>
        </div>
        ${adjRow}
      </div>
    </div>
    ${deductions.length ? `
    <table class="data-table">
      <thead><tr><th>관점</th><th>처리</th><th>건수</th><th>감점</th></tr></thead>
      <tbody>${rows}</tbody>
      <tfoot><tr>
        <td colspan="3" style="text-align:right;color:var(--muted);font-size:12px">합계 감점</td>
        <td style="text-align:right;color:var(--red);font-weight:700">${deductions.reduce((s,d)=>s+d.points,0)}점</td>
      </tr></tfoot>
    </table>` : '<p style="color:var(--dim);font-size:13px">감점 없음</p>'}
  </section>`;
}

// ── Critical 수정 이력 ─────────────────────────────────────────
function renderCriticalHistory() {
  if (!critical_history.length) {
    return `
  <section class="card">
    <h2 class="section-title">Critical 수정 이력</h2>
    <p style="color:var(--dim);font-size:13px">Critical 없음</p>
  </section>`;
  }
  const rows = critical_history.map(h => `
      <tr>
        <td style="text-align:center;color:var(--muted)">${h.iteration}</td>
        <td>${perspBadge(h.perspective)}</td>
        <td style="color:var(--muted);font-family:monospace;font-size:12px">${esc(h.loc)}</td>
        <td style="color:var(--text)">${esc(h.summary)}</td>
      </tr>`).join('');
  return `
  <section class="card">
    <h2 class="section-title">Critical 수정 이력</h2>
    <table class="data-table">
      <thead><tr><th>Iter</th><th>관점</th><th>위치</th><th>수정 내용</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

// ── Warning 처리 결과 ──────────────────────────────────────────
function renderWarningResults() {
  if (!warning_results.length) {
    return `
  <section class="card">
    <h2 class="section-title">Warning 처리 결과</h2>
    <p style="color:var(--dim);font-size:13px">Warning 없음</p>
  </section>`;
  }
  const rows = warning_results.map(w => `
      <tr>
        <td>${resultBadge(w.result)}</td>
        <td>${perspBadge(w.perspective)}</td>
        <td style="color:var(--muted);font-family:monospace;font-size:12px">${esc(w.loc)}</td>
        <td style="color:var(--text)">${esc(w.title)}</td>
        <td>${impactBadge(w.impact)}</td>
      </tr>`).join('');

  const acceptedItems = warning_results.filter(w => w.result === 'accept' && (w.reason || w.plan));
  const acceptSection = acceptedItems.length ? `
    <h3 style="font-size:12px;color:var(--dim);margin-top:24px;margin-bottom:12px;text-transform:uppercase;letter-spacing:.06em">감수 상세</h3>
    ${acceptedItems.map(w => `
    <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:8px;font-size:13px">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">
        ${perspBadge(w.perspective)}
        <code style="color:var(--muted);font-size:12px">${esc(w.loc)}</code>
        <span style="color:var(--text)">${esc(w.title)}</span>
        ${impactBadge(w.impact)}
      </div>
      ${w.reason ? `<div style="color:var(--muted)"><span style="color:var(--dim)">사유: </span>${esc(w.reason)}</div>` : ''}
      ${w.plan   ? `<div style="color:var(--muted);margin-top:2px"><span style="color:var(--dim)">계획: </span>${esc(w.plan)}</div>` : ''}
    </div>`).join('')}` : '';

  return `
  <section class="card">
    <h2 class="section-title">Warning 처리 결과</h2>
    <table class="data-table">
      <thead><tr><th>처리</th><th>관점</th><th>위치</th><th>항목</th><th>Impact</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${acceptSection}
  </section>`;
}

// ── 수정 커밋 목록 ────────────────────────────────────────────
function renderCommits() {
  if (!fix_commits.length) return '';
  const items = fix_commits.map(c => `
    <div style="display:flex;gap:12px;align-items:baseline;padding:8px 0;border-bottom:1px solid var(--border)">
      <code style="color:var(--blue);font-size:12px;flex-shrink:0">${esc(c.hash)}</code>
      <span style="color:var(--muted);font-size:13px">${esc(c.message)}</span>
    </div>`).join('');
  return `
  <section class="card">
    <h2 class="section-title">수정 커밋</h2>
    ${items}
  </section>`;
}

// ── 전체 HTML ─────────────────────────────────────────────────
const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<style>
${BASE_CSS}
/* ── gen-report.js 고유 ── (공통분은 scripts/assets/report.css) */
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>${esc(title)}</h1>
    <div class="meta">${esc(date)} · ${esc(context)}</div>
  </div>
  <span style="padding:5px 14px;border-radius:8px;font-size:13px;font-weight:700;${gradeStyle(grade)}">${grade} ${displayScore}/100</span>
</div>

<div class="container">

  <div class="summary-cards">
    ${renderSummaryCards()}
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 22px;text-align:center;min-width:110px">
      <div style="font-size:28px;font-weight:700;color:var(--muted)">${summary.info ?? 0}</div>
      <div style="font-size:11px;color:var(--dim);margin-top:4px">Info</div>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 22px;text-align:center;min-width:110px">
      <div style="font-size:28px;font-weight:700;color:var(--dim)">${summary.iterations ?? 1}</div>
      <div style="font-size:11px;color:var(--dim);margin-top:4px">재시도 횟수</div>
    </div>
  </div>

  ${renderScoreSection()}
  ${renderCriticalHistory()}
  ${renderWarningResults()}
  ${renderCommits()}

  <div class="meta-footer">
    commit: ${esc(meta.last_reviewed_commit || '-')} &nbsp;·&nbsp;
    tree: ${esc(meta.last_reviewed_tree || '-')} &nbsp;·&nbsp;
    score: ${displayScore} &nbsp;·&nbsp; grade: ${grade} &nbsp;·&nbsp; ${repo_type}
  </div>

</div>
</body>
<!-- wt-review-meta
last_reviewed_commit: ${meta.last_reviewed_commit || '-'}
last_reviewed_tree: ${meta.last_reviewed_tree || '-'}
review_score: ${displayScore}
review_grade: ${grade}
review_repo_type: ${repo_type}
-->
</html>`;

writeReport(outputPath, html);
console.log(`✅ gen-report 완료: ${outputPath}`);
console.log(`   점수: ${displayScore}/100 [${grade}] | 수정: ${summary.critical_fixed ?? 0}C + ${summary.warning_fixed ?? 0}W`);
