// content.js — 챗봇 입력창을 감시해 민감정보 입력을 탐지/경고/차단
// detectors.js 가 먼저 주입되므로 vgScan/vgMask 를 전역에서 바로 쓸 수 있다.
'use strict';

(function () {
  let vgSettings = {
    mode: 'monitor',
    categories: { rrn: true, card: true, phone: true, email: true, apikey: true }
  };

  function vgLoadSettings() {
    chrome.storage.local.get(['settings'], (data) => {
      if (data.settings) {
        vgSettings = Object.assign({}, vgSettings, data.settings);
      }
    });
  }
  vgLoadSettings();

  // 옵션/팝업에서 설정이 바뀌면 즉시 반영
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.settings) {
      vgSettings = Object.assign({}, vgSettings, changes.settings.newValue);
    }
  });

  function vgDebounce(fn, wait) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  function vgGetText(el) {
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') return el.value || '';
    return el.innerText || el.textContent || '';
  }

  // 입력창 바로 위에 경고 배너를 붙인다 (입력창당 하나, 재사용)
  function vgShowBanner(input, matches) {
    let banner = input.__vgBanner;
    if (!banner || !banner.isConnected) {
      banner = document.createElement('div');
      banner.setAttribute('data-vg-banner', '1');
      banner.style.cssText = [
        'background:#3a0d10', 'color:#ff8080', 'border:1px solid #e5484d',
        'border-radius:6px', 'padding:8px 12px', 'margin:6px 0',
        'font-size:13px', 'font-family:sans-serif', 'line-height:1.5',
        'position:relative', 'z-index:2147483647'
      ].join(';');
      input.insertAdjacentElement('beforebegin', banner);
      input.__vgBanner = banner;
    }
    const types = [...new Set(matches.map((m) => m.label))].join(', ');
    banner.textContent = `⚠ 민감정보 감지: ${types} — 회사 정책상 AI 입력 금지`;
    banner.style.display = 'block';
  }

  function vgHideBanner(input) {
    if (input.__vgBanner) input.__vgBanner.style.display = 'none';
  }

  function vgReportViolation(matches, fullText) {
    chrome.runtime.sendMessage({
      action: 'vg-violation',
      site: location.hostname,
      url: location.href,
      mode: vgSettings.mode,
      // 라벨은 저장하지 않고 type만 보낸다. popup.js 가 VG_CATEGORIES 로 라벨을 다시 구한다(DRY).
      matches: matches.map((m) => ({ type: m.type, match: m.match })),
      fullText
    });
  }

  function vgHandleInput(input) {
    const text = vgGetText(input);
    const matches = vgScan(text, vgSettings.categories);
    if (matches.length > 0) {
      vgShowBanner(input, matches);
      vgReportViolation(matches, text);
    } else {
      vgHideBanner(input);
    }
  }
  const vgHandleInputDebounced = vgDebounce(vgHandleInput, 300);

  function vgBindInput(input) {
    if (input.__vgBound) return;
    input.__vgBound = true;
    input.addEventListener('input', () => vgHandleInputDebounced(input));
    input.addEventListener('paste', () => vgHandleInputDebounced(input));

    // enforce 모드: Enter 로 전송하려는 순간을 가로채 차단
    input.addEventListener(
      'keydown',
      (e) => {
        if (e.key !== 'Enter' || e.shiftKey) return;
        if (vgSettings.mode !== 'enforce') return;
        const matches = vgScan(vgGetText(input), vgSettings.categories);
        if (matches.length > 0) {
          e.preventDefault();
          e.stopPropagation();
          vgShowBanner(input, matches);
        }
      },
      true
    );
  }

  function vgScanForInputs() {
    document.querySelectorAll('textarea, [contenteditable="true"]').forEach(vgBindInput);
  }

  // enforce 모드: 전송 버튼 클릭도 가로채 차단 (Enter 우회 방지)
  document.addEventListener(
    'click',
    (e) => {
      if (vgSettings.mode !== 'enforce') return;
      const btn = e.target.closest(
        'button[type="submit"], button[data-testid*="send"], button[aria-label*="Send"], button[aria-label*="보내기"]'
      );
      if (!btn) return;
      const inputs = document.querySelectorAll('textarea, [contenteditable="true"]');
      for (const input of inputs) {
        const matches = vgScan(vgGetText(input), vgSettings.categories);
        if (matches.length > 0) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();
          vgShowBanner(input, matches);
          return;
        }
      }
    },
    true
  );

  vgScanForInputs();

  // SPA 라우팅으로 입력창이 갈아끼워지는 경우 재바인딩
  const vgObserver = new MutationObserver(vgDebounce(vgScanForInputs, 300));
  vgObserver.observe(document.documentElement, { childList: true, subtree: true });
})();
