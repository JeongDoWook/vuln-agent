'use strict';

// 리뷰 관점 색상 매핑 — code-review 5관점 전부. 여기 없는 관점은 회색으로 뭉개지므로
// review.json 의 perspective 값(code-review-algorithm.md 스키마)과 항상 같이 간다. — gen-review.js와
// gen-report.js가 동일한 배지로 표시하므로 여기 하나만 둔다.
const { chip } = require('./html');

const PERSPECTIVE_COLOR = {
  Quality:    'var(--accent)',
  Security:   'var(--red)',
  Regression: 'var(--orange)',
  CodeAudit:  'var(--purple)',
  RuntimeTrap:'var(--yellow)',
};

function perspectiveBadge(p) {
  return chip(p || '', PERSPECTIVE_COLOR[p] || 'var(--dim)');
}

module.exports = { PERSPECTIVE_COLOR, perspectiveBadge };
