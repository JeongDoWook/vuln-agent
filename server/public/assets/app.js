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

  // 뒤로가기(bfcache)로 복귀하면 멈춰있던 스피너를 되돌린다.
  window.addEventListener('pageshow', function (e) {
    if (!e.persisted) { return; }
    resetProgress();
    document.querySelectorAll('[aria-busy="true"]').forEach(idleButton);
    document.querySelectorAll('form[data-vg-submitting]').forEach(function (f) {
      delete f.dataset.vgSubmitting;
    });
  });

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
