// popup.js — 팝업 UI: monitor/enforce 토글, 최근 위반 목록, 로그 비우기
// detectors.js 의 VG_CATEGORIES 로 저장된 type -> 한글 라벨을 구한다(DRY).
'use strict';

document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadViolations();
  document.getElementById('mode-toggle').addEventListener('change', onModeToggle);
  document.getElementById('clear-btn').addEventListener('click', onClear);
  document.getElementById('options-link').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
});

function vgSetModeLabel(mode) {
  document.getElementById('mode-label').textContent = mode === 'enforce' ? '차단(enforce)' : '감시(monitor)';
}

function loadSettings() {
  chrome.storage.local.get(['settings'], (data) => {
    const mode = (data.settings && data.settings.mode) || 'monitor';
    document.getElementById('mode-toggle').checked = mode === 'enforce';
    vgSetModeLabel(mode);
  });
}

function onModeToggle(e) {
  const mode = e.target.checked ? 'enforce' : 'monitor';
  chrome.storage.local.get(['settings'], (data) => {
    const settings = Object.assign({}, data.settings, { mode });
    chrome.storage.local.set({ settings }, () => vgSetModeLabel(mode));
  });
}

function onClear() {
  chrome.storage.local.set({ violations: [] }, () => {
    chrome.action.setBadgeText({ text: '' });
    loadViolations();
  });
}

function vgEscape(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

function loadViolations() {
  chrome.storage.local.get(['violations'], (data) => {
    const violations = data.violations || [];
    document.getElementById('total-count').textContent = violations.length;

    const list = document.getElementById('violation-list');
    list.innerHTML = '';
    if (violations.length === 0) {
      list.innerHTML = '<div class="vg-empty">아직 감지된 위반이 없습니다.</div>';
      return;
    }

    violations.slice(0, 50).forEach((v) => {
      const matches = v.matches || [];
      const badges = matches
        .map((m) => `<span class="vg-badge">${vgEscape(VG_CATEGORIES[m.type] || m.type)}</span>`)
        .join('');
      const snippet = matches.map((m) => m.match).join(', ');
      const time = new Date(v.time).toLocaleString('ko-KR');

      const item = document.createElement('div');
      item.className = 'vg-item';
      item.innerHTML = `
        <div class="vg-item-head">
          <span class="vg-site">${vgEscape(v.site)}</span>
          <span class="vg-time">${vgEscape(time)}</span>
        </div>
        <div class="vg-badges">${badges}</div>
        <div class="vg-snippet">${vgEscape(snippet)}</div>
      `;
      list.appendChild(item);
    });
  });
}
