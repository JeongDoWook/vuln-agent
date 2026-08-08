'use strict';

// gen-review.js/gen-report.js/gen-status.js가 공유하는 최소 HTML 헬퍼 —
// 이스케이프와 SSOT 색상 토큰 기반 배지(chip) 렌더링만 담당한다.

function esc(str = '') {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// 색상은 SSOT 토큰(var(--*))이므로 알파는 color-mix로 유도한다.
// (hex+"22" 접미사 방식은 var()와 함께 쓸 수 없다)
function alpha(color, pct) {
  return `color-mix(in srgb, ${color} ${pct}%, transparent)`;
}

function chip(text, color) {
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;`
       + `background:${alpha(color, 13)};color:${color};border:1px solid ${alpha(color, 27)}">${esc(text)}</span>`;
}

module.exports = { esc, alpha, chip };
