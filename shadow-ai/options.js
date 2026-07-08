// options.js — 상세 설정: 카테고리 on/off, 로그 모드, webhook URL
// 카테고리 체크박스 목록은 detectors.js 의 VG_CATEGORIES 에서 만든다.
// 새 탐지 카테고리를 detectors.js 에 추가하면 이 화면에 자동으로 노출된다(OCP).
'use strict';

document.addEventListener('DOMContentLoaded', () => {
  renderCategories();
  loadSettings();
  document.getElementById('save-btn').addEventListener('click', save);
});

function renderCategories() {
  const container = document.getElementById('category-list');
  container.innerHTML = '';
  Object.keys(VG_CATEGORIES).forEach((key) => {
    const label = document.createElement('label');
    label.className = 'vg-checkbox';
    label.innerHTML = `<input type="checkbox" data-category="${key}" /> ${VG_CATEGORIES[key]}`;
    container.appendChild(label);
  });
}

function loadSettings() {
  chrome.storage.local.get(['settings'], (data) => {
    const settings = data.settings || {};
    const categories = settings.categories || {};
    document.querySelectorAll('#category-list input[type="checkbox"]').forEach((cb) => {
      cb.checked = categories[cb.dataset.category] !== false;
    });

    const logMode = settings.logMode || 'violations-only';
    const radio = document.querySelector(`input[name="logMode"][value="${logMode}"]`);
    if (radio) radio.checked = true;

    document.getElementById('webhook-url').value = settings.webhookUrl || '';
  });
}

function save() {
  const categories = {};
  document.querySelectorAll('#category-list input[type="checkbox"]').forEach((cb) => {
    categories[cb.dataset.category] = cb.checked;
  });
  const logModeInput = document.querySelector('input[name="logMode"]:checked');
  const logMode = logModeInput ? logModeInput.value : 'violations-only';
  const webhookUrl = document.getElementById('webhook-url').value.trim();

  chrome.storage.local.get(['settings'], (data) => {
    const settings = Object.assign({}, data.settings, { categories, logMode, webhookUrl });
    chrome.storage.local.set({ settings }, () => {
      const status = document.getElementById('save-status');
      status.textContent = '저장됨';
      setTimeout(() => { status.textContent = ''; }, 1500);
    });
  });
}
