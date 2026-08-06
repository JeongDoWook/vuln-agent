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

  // --- 중요 작업 확인 -----------------------------------------------------
  function confirmAction(message, submitter) {
    return new Promise(function (resolve) {
      var dlg = document.createElement('dialog');
      dlg.className = 'modal confirm-modal';
      dlg.setAttribute('aria-labelledby', 'confirmTitle');
      dlg.innerHTML = '<div class="modal__head"><strong id="confirmTitle">작업을 진행할까요?</strong>'
        + '<button type="button" class="modal__x" data-confirm-cancel aria-label="닫기">✕</button></div>'
        + '<div class="modal__body"><p class="confirm-modal__message"></p>'
        + '<div class="modal__foot"><button type="button" class="btn btn--ghost" data-confirm-cancel>취소</button>'
        + '<button type="button" class="btn btn--danger" data-confirm-ok>계속</button></div></div>';
      dlg.querySelector('.confirm-modal__message').textContent = message;
      var action = dlg.querySelector('[data-confirm-ok]');
      if (submitter && submitter.textContent.trim()) { action.textContent = submitter.textContent.trim(); }
      function finish(ok) { dlg.close(); dlg.remove(); resolve(ok); }
      dlg.querySelectorAll('[data-confirm-cancel]').forEach(function (b) { b.addEventListener('click', function () { finish(false); }); });
      action.addEventListener('click', function () { finish(true); });
      dlg.addEventListener('cancel', function (e) { e.preventDefault(); finish(false); });
      document.body.appendChild(dlg); dlg.showModal(); action.focus();
    });
  }

  // --- 폼 제출 ------------------------------------------------------------
  // 버튼을 disabled 로 만들면 그 name/value 가 전송되지 않는다. aria-busy +
  // 폼 플래그로 이중제출만 막고, 버튼은 활성 상태로 둔다(CSS 가 클릭을 무효화).
  document.addEventListener('submit', function (e) {
    if (e.defaultPrevented) { return; }
    var form = e.target;
    var confirmMessage = form.getAttribute('data-confirm');
    if (confirmMessage && form.dataset.vgConfirmed !== '1') {
      e.preventDefault();
      var submitter = e.submitter;
      confirmAction(confirmMessage, submitter).then(function (ok) {
        if (!ok) { return; }
        form.dataset.vgConfirmed = '1';
        if (form.requestSubmit) { form.requestSubmit(submitter || undefined); }
        else { form.submit(); }
      });
      return;
    }
    delete form.dataset.vgConfirmed;
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

  // --- 모바일 필터 패널 ---------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form.toolbar').forEach(function (form) {
      var fields = form.querySelectorAll('input:not([type=hidden]), select, input[type=hidden][data-reset="1"]');
      if (!fields.length) { return; }
      var active = Array.prototype.some.call(fields, function (field) { return field.value !== ''; });
      var toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'toolbar__toggle';
      toggle.innerHTML = '<span>검색 및 필터</span><i aria-hidden="true"></i>';
      toggle.setAttribute('aria-expanded', active ? 'true' : 'false');
      form.classList.add('has-filter-toggle');
      if (active) { form.classList.add('is-open'); }
      form.insertBefore(toggle, form.firstChild);
      toggle.addEventListener('click', function () {
        var open = form.classList.toggle('is-open');
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
    });
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

  // --- 전체 에이전트 수집 현황 ---------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    var overview = document.querySelector('[data-collection-overview]');
    if (!overview) { return; }
    var dialog = overview.closest('dialog');
    var badge = document.querySelector('[data-collection-status-count]');
    var list = overview.querySelector('[data-overview-list]');
    var timer = null;

    function duration(seconds) {
      seconds = Math.max(0, Number(seconds) || 0);
      if (seconds < 60) { return Math.floor(seconds) + '초'; }
      return Math.floor(seconds / 60) + '분 ' + Math.floor(seconds % 60) + '초';
    }
    function statusLabel(status) {
      return {running: '수집 중', pending: '대기 중', done: '완료', failed: '실패'}[status] || status;
    }
    function text(tag, className, value) {
      var node = document.createElement(tag);
      if (className) { node.className = className; }
      node.textContent = value;
      return node;
    }
    function renderCommand(command) {
      var item = document.createElement('article');
      item.className = 'collection-item is-' + command.status;
      var head = document.createElement('div');
      head.className = 'collection-item__head';
      var identity = document.createElement('div');
      identity.appendChild(text('strong', '', command.hostname || command.fqdn));
      identity.appendChild(text('span', '', command.fqdn));
      head.appendChild(identity);
      head.appendChild(text('span', 'collection-item__state', statusLabel(command.status)));
      item.appendChild(head);

      var pct = command.status === 'done' ? 100 : Number(command.progress_percent || 0);
      var progress = document.createElement('progress');
      progress.max = 100;
      progress.value = pct;
      progress.textContent = pct + '%';
      item.appendChild(progress);

      var meta = document.createElement('div');
      meta.className = 'collection-item__meta';
      var message = command.progress_message;
      if (!message) { message = command.status === 'pending' ? '다음 poll에서 실행됩니다.' : statusLabel(command.status); }
      meta.appendChild(text('span', '', pct + '% · ' + message));
      var timing = command.elapsed_seconds === null ? '' : '경과 ' + duration(command.elapsed_seconds);
      if (command.status === 'running' && command.heartbeat_age !== null) {
        timing += ' · ' + (Number(command.heartbeat_age) > 180 ? '통신 지연' : '통신 정상');
        if (Number(command.heartbeat_age) > 180) { item.classList.add('is-stale'); }
      }
      meta.appendChild(text('span', '', timing));
      item.appendChild(meta);
      var link = document.createElement('a');
      link.href = '/host.php?id=' + encodeURIComponent(command.host_id);
      link.className = 'collection-item__link';
      link.setAttribute('aria-label', (command.hostname || command.fqdn) + ' 자산 상세 열기');
      item.appendChild(link);
      return item;
    }
    function render(data) {
      var summary = data.summary || {};
      overview.querySelector('[data-overview-active]').textContent = String(summary.active || 0);
      overview.querySelector('[data-overview-running]').textContent = String(summary.running || 0);
      overview.querySelector('[data-overview-pending]').textContent = String(summary.pending || 0);
      overview.querySelector('[data-overview-progress]').textContent = (summary.progress_percent || 0) + '%';
      var active = Number(summary.active || 0);
      badge.textContent = String(active);
      badge.hidden = active === 0;
      badge.closest('.collection-status-btn').classList.toggle('is-active', active > 0);
      list.replaceChildren();
      if (!data.commands || !data.commands.length) {
        list.appendChild(text('div', 'collection-overview__empty', '현재 또는 최근 수집 작업이 없습니다.'));
        return;
      }
      data.commands.forEach(function (command) { list.appendChild(renderCommand(command)); });
    }
    function refresh(schedule) {
      fetch('/agent-command-overview.php', {headers: {'Accept': 'application/json'}})
        .then(function (response) { if (!response.ok) { throw new Error('status'); } return response.json(); })
        .then(render)
        .catch(function () {
          if (dialog.open) { list.replaceChildren(text('div', 'collection-overview__empty', '수집 현황을 불러오지 못했습니다.')); }
        })
        .then(function () {
          window.clearTimeout(timer);
          timer = window.setTimeout(function () { refresh(true); }, dialog.open ? 3000 : 15000);
        });
    }
    dialog.addEventListener('close', function () { window.clearTimeout(timer); refresh(true); });
    document.querySelector('[data-collection-status-open]').addEventListener('click', function () { refresh(true); });
    refresh(true);
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

  // --- 모바일 내비게이션 -------------------------------------------------
  function setMobileNav(open) {
    document.body.classList.toggle('nav-open', open);
    var toggle = document.querySelector('[data-nav-toggle]');
    if (toggle) {
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.setAttribute('aria-label', open ? '메뉴 닫기' : '메뉴 열기');
    }
  }
  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-nav-toggle]')) {
      e.preventDefault();
      setMobileNav(!document.body.classList.contains('nav-open'));
      return;
    }
    if (e.target.closest('[data-nav-close]') || e.target.closest('.side a.link')) {
      setMobileNav(false);
    }
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.body.classList.contains('nav-open')) {
      setMobileNav(false);
    }
  });

  // --- 사이드바 아코디언 (접이식 그룹) ------------------------------------
  // 서버는 모든 그룹을 <details open> 으로 렌더한다 → JS 가 죽어도 전부 펼쳐져 링크 접근 가능.
  // 여기서는 데스크톱에서 접힘 상태를 그룹명(data-grp) 기준 localStorage 에 기억·복원하되,
  // 활성 그룹(현재 페이지)은 저장값보다 우선해 항상 편다. 모바일(<=860px)에선 항상 펼침.
  var NAV_KEY = 'vg-nav';
  var navMq = window.matchMedia('(max-width: 860px)');
  function navState() {
    try { return JSON.parse(localStorage.getItem(NAV_KEY)) || {}; }
    catch (err) { return {}; }
  }
  function saveNavState(s) {
    try { localStorage.setItem(NAV_KEY, JSON.stringify(s)); } catch (err) {}
  }
  function applyNavAccordion() {
    var groups = document.querySelectorAll('.side details.nav-grp');
    if (!groups.length) { return; }
    if (navMq.matches) {                          // 모바일: 접이식 없이 항상 전부 펼침
      groups.forEach(function (d) { d.open = true; });
      return;
    }
    var saved = navState();
    groups.forEach(function (d) {
      if (d.querySelector('a.link.active')) {      // 활성 그룹은 저장값보다 우선
        d.open = true;
      } else {
        d.open = saved[d.getAttribute('data-grp')] !== false;   // 기본은 펼침
      }
    });
  }
  function bindNavAccordion() {
    document.querySelectorAll('.side details.nav-grp').forEach(function (d) {
      d.addEventListener('toggle', function () {
        if (navMq.matches) { return; }             // 모바일 상태는 저장하지 않는다
        if (d.querySelector('a.link.active')) { return; }  // 활성 그룹은 항상 펼침이 우선
        var s = navState();
        s[d.getAttribute('data-grp')] = d.open;
        saveNavState(s);
      });
    });
  }
  document.addEventListener('DOMContentLoaded', function () {
    applyNavAccordion();   // 복원을 먼저 — 그 뒤에 리스너를 걸어 초기 복원이 저장을 덮지 않게
    bindNavAccordion();
  });
  if (navMq.addEventListener) { navMq.addEventListener('change', applyNavAccordion); }
  else if (navMq.addListener) { navMq.addListener(applyNavAccordion); }

  // 카드·표의 overflow 안에서도 잘리지 않는 공통 툴팁. body 직속 fixed 레이어로 띄운 뒤
  // 좌우 화면 경계를 기준으로 위치를 보정한다. 서버가 출력한 title 과 SVG <title> 도
  // data-tip 으로 바꿔 브라우저 기본 툴팁의 긴 대기시간·OS별 모양 차이를 없앤다.
  var infoTip = null;
  var infoTipOwner = null;
  function prepareTooltips(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var titled = [];
    if (root && root.nodeType === 1 && root.hasAttribute('title')) { titled.push(root); }
    scope.querySelectorAll('[title]').forEach(function (el) { titled.push(el); });
    titled.forEach(function (el) {
      var message = el.getAttribute('title');
      if (!message) { return; }
      el.setAttribute('data-tip', message);
      el.removeAttribute('title');
    });

    var svgTitles = [];
    if (root && root.nodeType === 1 && root.matches('svg title')) { svgTitles.push(root); }
    scope.querySelectorAll('svg title').forEach(function (el) { svgTitles.push(el); });
    svgTitles.forEach(function (title) {
      var owner = title.parentElement;
      var message = title.textContent.trim();
      if (owner && message) { owner.setAttribute('data-tip', message); }
      title.remove();
    });
  }
  function hideInfoTip() {
    if (infoTipOwner) { infoTipOwner.removeAttribute('aria-describedby'); }
    if (infoTip) { infoTip.remove(); }
    infoTip = null;
    infoTipOwner = null;
  }
  function showInfoTip(owner) {
    var message = owner.getAttribute('data-tip');
    if (!message) { return; }
    hideInfoTip();
    infoTipOwner = owner;
    infoTip = document.createElement('div');
    infoTip.id = 'vg-info-tooltip';
    infoTip.className = 'info-tooltip';
    infoTip.setAttribute('role', 'tooltip');
    infoTip.textContent = message;
    document.body.appendChild(infoTip);
    owner.setAttribute('aria-describedby', infoTip.id);

    var ownerRect = owner.getBoundingClientRect();
    var tipRect = infoTip.getBoundingClientRect();
    var gutter = 12;
    var left = ownerRect.left + ownerRect.width / 2 - tipRect.width / 2;
    left = Math.max(gutter, Math.min(left, window.innerWidth - tipRect.width - gutter));
    var top = ownerRect.bottom + 9;
    var above = false;
    if (top + tipRect.height > window.innerHeight - gutter) {
      top = ownerRect.top - tipRect.height - 9;
      above = true;
    }
    infoTip.style.left = Math.round(left) + 'px';
    infoTip.style.top = Math.round(Math.max(gutter, top)) + 'px';
    infoTip.classList.toggle('info-tooltip--above', above);
    infoTip.style.setProperty('--tip-anchor', Math.round(ownerRect.left + ownerRect.width / 2 - left) + 'px');
  }
  document.addEventListener('DOMContentLoaded', function () {
    prepareTooltips(document);
    new MutationObserver(function (records) {
      records.forEach(function (record) {
        record.addedNodes.forEach(function (node) {
          if (node.nodeType === 1) { prepareTooltips(node); }
        });
      });
    }).observe(document.body, { childList: true, subtree: true });
  });
  document.addEventListener('mouseover', function (event) {
    var owner = event.target.closest('[data-tip]');
    if (owner && (!event.relatedTarget || !owner.contains(event.relatedTarget))) { showInfoTip(owner); }
  });
  document.addEventListener('mouseout', function (event) {
    if (infoTipOwner && event.target.closest('[data-tip]') === infoTipOwner
        && (!event.relatedTarget || !infoTipOwner.contains(event.relatedTarget))) { hideInfoTip(); }
  });
  document.addEventListener('focusin', function (event) {
    var owner = event.target.closest('[data-tip]');
    if (owner) { showInfoTip(owner); }
  });
  document.addEventListener('focusout', function (event) {
    if (event.target === infoTipOwner) { hideInfoTip(); }
  });
  window.addEventListener('scroll', hideInfoTip, true);
  window.addEventListener('resize', hideInfoTip);
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { hideInfoTip(); }
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
