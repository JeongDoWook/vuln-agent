// background.js — content.js 가 보낸 위반 로그를 저장하고 배지/웹훅을 처리하는 서비스워커
'use strict';

const VG_DEFAULT_SETTINGS = {
  mode: 'monitor', // 'monitor' | 'enforce'
  categories: { rrn: true, card: true, phone: true, email: true, apikey: true },
  logMode: 'violations-only', // 'violations-only' | 'full-prompt'
  webhookUrl: ''
};

const VG_MAX_VIOLATIONS = 500;

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['settings', 'violations'], (data) => {
    if (!data.settings) chrome.storage.local.set({ settings: VG_DEFAULT_SETTINGS });
    if (!data.violations) chrome.storage.local.set({ violations: [] });
  });
});

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.action !== 'vg-violation') return;

  chrome.storage.local.get(['violations', 'settings'], (data) => {
    const settings = Object.assign({}, VG_DEFAULT_SETTINGS, data.settings);
    const violations = data.violations || [];

    const entry = {
      time: new Date().toISOString(),
      site: msg.site,
      url: msg.url,
      mode: msg.mode,
      matches: msg.matches
    };
    // 옵션에서 "전체 프롬프트 저장"을 켠 경우에만 원문을 함께 남긴다(감사용)
    if (settings.logMode === 'full-prompt') {
      entry.fullText = msg.fullText;
    }

    violations.unshift(entry);
    if (violations.length > VG_MAX_VIOLATIONS) violations.length = VG_MAX_VIOLATIONS;

    chrome.storage.local.set({ violations }, () => {
      chrome.action.setBadgeText({ text: violations.length > 999 ? '999+' : String(violations.length) });
      chrome.action.setBadgeBackgroundColor({ color: '#e5484d' });
    });

    // 웹훅이 설정돼 있으면 함께 전송. 실패해도 로컬 로그는 이미 저장됐으므로 조용히 무시(PoC).
    if (settings.webhookUrl) {
      fetch(settings.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(entry)
      }).catch(() => {});
    }
  });
});
