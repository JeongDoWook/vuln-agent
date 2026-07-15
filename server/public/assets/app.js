/* =============================================================================
 * app.js — 전역 로더. 페이지마다 코드를 넣지 않도록 이벤트 위임 한 곳에서 처리한다.
 * =============================================================================
 *  1) 상단 진행바 : 페이지 이동(링크·폼 GET·페이저·per_page 셀렉트)이 시작되면 표시.
 *  2) 버튼 스피너 : 폼 제출 시 누른 버튼에 스피너 + 이중제출 차단.
 *                   data-loading="…" 을 주면 그 문구로 라벨을 바꾼다.
 *  3) vgLoading() : fetch 처럼 스스로 도는 비동기 작업용 공개 헬퍼.
 *
 *  주의: confirm() 취소로 제출이 막힌 경우(defaultPrevented) 로더를 켜지 않는다.
 *        뒤로가기(bfcache)로 돌아오면 pageshow 에서 모든 로딩 상태를 되돌린다.
 * ========================================================================== */
(function () {
  'use strict';

  // --- 상단 진행바 --------------------------------------------------------
  var bar = null;

  function progressEl() {
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'vg-progress';
      document.body.appendChild(bar);
    }
    return bar;
  }

  function startProgress() {
    var el = progressEl();
    el.classList.remove('is-done');
    // 리플로우를 강제해야 scaleX(0) → 애니메이션이 다시 시작된다.
    el.style.transform = 'scaleX(0)';
    void el.offsetWidth;
    el.classList.add('is-active');
    el.style.transform = 'scaleX(0.92)';   // 8초에 걸쳐 92% 까지, 완료 시 100%
    document.body.classList.add('is-busy');
  }

  function resetProgress() {
    if (!bar) { return; }
    bar.classList.remove('is-active', 'is-done');
    bar.style.transform = 'scaleX(0)';
    document.body.classList.remove('is-busy');
  }

  function doneProgress() {
    if (!bar || !bar.classList.contains('is-active')) { return; }
    bar.classList.remove('is-active');
    bar.classList.add('is-done');
    bar.style.transform = '';
    document.body.classList.remove('is-busy');
    setTimeout(resetProgress, 400);
  }

  // --- 버튼 로딩 상태 -----------------------------------------------------
  function busyButton(btn) {
    if (!btn || btn.getAttribute('aria-busy') === 'true') { return; }
    btn.setAttribute('aria-busy', 'true');
    var label = btn.getAttribute('data-loading');
    if (label) {
      btn.setAttribute('data-label', btn.textContent);
      btn.textContent = label;
    }
  }

  function idleButton(btn) {
    if (!btn) { return; }
    btn.removeAttribute('aria-busy');
    var label = btn.getAttribute('data-label');
    if (label !== null) {
      btn.textContent = label;
      btn.removeAttribute('data-label');
    }
  }

  // --- 폼 제출 ------------------------------------------------------------
  // 버튼을 disabled 로 만들면 그 name/value 가 전송되지 않는다. aria-busy +
  // 폼 플래그로 이중제출만 막고, 버튼은 활성 상태로 둔다(CSS 가 클릭을 무효화).
  document.addEventListener('submit', function (e) {
    if (e.defaultPrevented) { return; }   // confirm() 취소 등
    var form = e.target;
    if (form.dataset.vgSubmitting === '1') {
      e.preventDefault();
      return;
    }
    form.dataset.vgSubmitting = '1';
    busyButton(e.submitter || form.querySelector('button[type=submit], button:not([type])'));
    startProgress();
  });

  // --- 클립보드 복사 ------------------------------------------------------
  // 토큰은 발급 화면에서 한 번만 보인다 — 손으로 긁다 흘리면 재발급뿐이라 버튼을 준다.
  // navigator.clipboard 는 보안 컨텍스트(https·localhost)에서만 산다. 사내 http 로 열면
  // 없을 수 있어서, 그때는 숨긴 textarea + execCommand 로 떨어진다(구식이지만 아직 먹는다).
  function legacyCopy(text) {
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
      ta.remove();
      ok ? resolve() : reject(new Error('copy failed'));
    });
  }

  function copyText(text) {
    // 있다고 되는 게 아니다 — 권한이 막히면 writeText 가 거부(reject)된다. 그때도 폴백한다.
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(function () { return legacyCopy(text); });
    }
    return legacyCopy(text);
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-copy]');
    if (!btn) { return; }
    e.preventDefault();
    var label = btn.dataset.label || btn.textContent.trim();
    btn.dataset.label = label;
    copyText(btn.getAttribute('data-copy')).then(function () {
      btn.classList.add('is-done');
      btn.textContent = '복사됨';
    }).catch(function () {
      btn.textContent = '복사 실패 — 직접 선택하세요';
    });
    setTimeout(function () {
      btn.classList.remove('is-done');
      btn.textContent = label;
    }, 2000);
  });

  // --- 페이지 이동 --------------------------------------------------------
  document.addEventListener('click', function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { return; }
    var a = e.target.closest('a[href]');
    if (!a || a.target === '_blank' || a.hasAttribute('download')) { return; }
    var href = a.getAttribute('href');
    if (!href || href.charAt(0) === '#' || href.indexOf('javascript:') === 0) { return; }
    if (a.origin !== location.origin) { return; }   // 외부 링크는 이 탭을 안 떠날 수도 있다
    startProgress();
  });

  // per_page 셀렉트처럼 change 로 이동하는 컨트롤(이동 자체는 인라인 onchange 가 한다)
  document.addEventListener('change', function (e) {
    if (e.target.matches('select[data-nav]')) { startProgress(); }
  });

  // 필터 셀렉트: 고르는 즉시 폼 제출. requestSubmit() 은 submit 이벤트를 쏘므로
  // 위의 제출 핸들러가 진행바·검색버튼 스피너를 그대로 붙여준다(form.submit() 은 안 쏜다).
  // 폼에 page 필드가 없으니 제출하면 자연히 1페이지로 돌아간다.
  document.addEventListener('change', function (e) {
    var sel = e.target.closest('select[data-autosubmit]');
    if (!sel || !sel.form) { return; }
    if (sel.form.requestSubmit) {
      sel.form.requestSubmit();
    } else {
      startProgress();      // 구형 브라우저 폴백 — submit 이벤트가 안 나므로 직접 켠다
      sel.form.submit();
    }
  });

  // --- 모달 ---------------------------------------------------------------
  // 네이티브 <dialog>. showModal() 이 포커스 가둠·ESC 닫기·backdrop 을 해주므로
  // 여기서는 열고 닫기만 한다. 폼 자체는 평범한 POST 폼이라 JS 가 죽어도 서버는 동작한다.
  document.addEventListener('click', function (e) {
    var open = e.target.closest('[data-modal]');
    if (open) {
      var dlg = document.getElementById(open.getAttribute('data-modal'));
      if (dlg && typeof dlg.showModal === 'function') {
        e.preventDefault();
        dlg.showModal();
      }
      return;
    }

    var close = e.target.closest('[data-modal-close]');
    if (close) {
      e.preventDefault();
      var owner = close.closest('dialog');
      if (owner) { owner.close(); }
      return;
    }

    // backdrop 클릭으로 닫기. <dialog> 자체가 이벤트 대상이면 바깥을 누른 것이다
    // (내용은 .modal__head/.modal__body 가 받는다).
    if (e.target.tagName === 'DIALOG') { e.target.close(); }
  });

  // 모달이 열리면 첫 입력에 커서를 둔다 — 열자마자 바로 타이핑할 수 있게.
  document.addEventListener('click', function (e) {
    var open = e.target.closest('[data-modal]');
    if (!open) { return; }
    var dlg = document.getElementById(open.getAttribute('data-modal'));
    if (!dlg) { return; }
    var first = dlg.querySelector('input:not([type=hidden]):not([disabled]), select, textarea');
    if (first) { first.focus(); }
  });

  // 서버가 "이 모달을 다시 열어라" 고 표시한 경우(폼 검증 실패 등) — 뜨자마자 연다.
  // <dialog open> 속성은 backdrop 없는 인라인 표시라 모달이 아니다. showModal() 로 열어야 한다.
  document.addEventListener('DOMContentLoaded', function () {
    var auto = document.querySelector('dialog[data-modal-autoopen]');
    if (auto && typeof auto.showModal === 'function' && !auto.open) { auto.showModal(); }
  });

  // 뒤로가기(bfcache)로 복귀하면 멈춰있던 스피너를 되돌린다.
  window.addEventListener('pageshow', function (e) {
    if (!e.persisted) { return; }
    resetProgress();
    document.querySelectorAll('[aria-busy="true"]').forEach(idleButton);
    document.querySelectorAll('form[data-vg-submitting]').forEach(function (f) {
      delete f.dataset.vgSubmitting;
    });
  });

  // --- 테마 토글 (Light/Dark) --------------------------------------------
  // head 의 인라인 스크립트가 첫 페인트 전에 data-theme 를 이미 적용해 뒀다.
  // 여기서는 세그먼트 버튼 클릭으로 전환·저장하고, 로드 시 버튼 상태를 맞춘다.
  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }
  function syncThemeButtons() {
    var t = currentTheme();
    document.querySelectorAll('[data-theme-set]').forEach(function (b) {
      b.classList.toggle('on', b.getAttribute('data-theme-set') === t);
    });
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-theme-set]');
    if (!b) { return; }
    e.preventDefault();
    var v = b.getAttribute('data-theme-set');
    document.documentElement.setAttribute('data-theme', v);
    try { localStorage.setItem('vg-theme', v); } catch (err) {}
    syncThemeButtons();
  });
  document.addEventListener('DOMContentLoaded', syncThemeButtons);

  /**
   * fetch 등 자체 비동기 작업용. 시작 시 busy(true), 끝나면 busy(false).
   *   vgLoading(button, true) → 버튼 스피너 + 상단 진행바
   */
  window.vgLoading = function (btn, busy) {
    if (busy) {
      busyButton(btn);
      startProgress();
    } else {
      idleButton(btn);
      doneProgress();
    }
  };
})();
