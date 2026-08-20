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
      var dlg = document.getElementById('vgConfirmDialog');
      if (!dlg || typeof dlg.showModal !== 'function') {
        resolve(window.confirm(message));
        return;
      }
      dlg.querySelector('[data-confirm-message]').textContent = message;
      var action = dlg.querySelector('[data-confirm-ok]');
      var cancelButtons = dlg.querySelectorAll('[data-confirm-cancel]');
      action.textContent = submitter && submitter.textContent.trim() ? submitter.textContent.trim() : '계속';
      var settled = false;
      function cleanup() {
        cancelButtons.forEach(function (button) { button.removeEventListener('click', cancel); });
        action.removeEventListener('click', accept);
        dlg.removeEventListener('cancel', cancelEvent);
        dlg.removeEventListener('close', closed);
      }
      function finish(ok) {
        if (settled) { return; }
        settled = true;
        cleanup();
        if (dlg.open) { dlg.close(); }
        resolve(ok);
      }
      function cancel() { finish(false); }
      function accept() { finish(true); }
      function cancelEvent(e) { e.preventDefault(); finish(false); }
      function closed() { finish(false); }
      cancelButtons.forEach(function (button) { button.addEventListener('click', cancel); });
      action.addEventListener('click', accept);
      dlg.addEventListener('cancel', cancelEvent);
      dlg.addEventListener('close', closed);
      dlg.showModal();
      action.focus();
    });
  }

  // --- 폼 제출 ------------------------------------------------------------
  // 버튼을 disabled 로 만들면 그 name/value 가 전송되지 않는다. aria-busy +
  // 폼 플래그로 이중제출만 막고, 버튼은 활성 상태로 둔다(CSS 가 클릭을 무효화).
  document.addEventListener('submit', function (e) {
    if (e.defaultPrevented) { return; }
    var form = e.target;
    var confirmMessage = form.getAttribute('data-confirm');
    // data-confirm-if 가 있으면 그 선택자에 걸린 체크박스가 켜졌을 때만 확인창을 띄운다.
    //   한 폼이 가벼운 동작과 무거운 옵션(예: 무결성 검사 포함 수집)을 함께 쏠 때, 옵션을
    //   끈 채로 누른 사람까지 확인창으로 막지 않기 위한 것이다.
    var confirmIf = form.getAttribute('data-confirm-if');
    if (confirmMessage && confirmIf) {
      var gate = form.querySelector(confirmIf);
      if (!gate || !gate.checked) { confirmMessage = null; }
    }
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

  // 전체 선택: data-checkall="<체크박스 name>" 을 단 체크박스가 같은 폼 안의 그 name 을 모두 맞춘다.
  // 범위를 폼으로 한정하는 게 핵심이다 — 문서 전체로 잡으면 다른 표의 선택까지 건드린다.
  document.addEventListener('change', function (e) {
    var all = e.target.closest('input[data-checkall]');
    if (!all || !all.form) { return; }
    var name = all.getAttribute('data-checkall');
    all.form.querySelectorAll('input[type=checkbox][name="' + name + '"]').forEach(function (box) {
      box.checked = all.checked;
    });
  });

  // 일괄 조작 바: data-bulk-open="<체크박스 name>" 을 단 **모달 여는 버튼**이 같은 폼 안의
  // 선택 개수를 싣는다. 0개면 비활성 — 안 그러면 아무것도 안 고르고 눌러 서버까지 갔다가
  // 오류로 돌아온다. 이름 목록은 textContent 로만 넣는다(HTML 로 조립하지 않는다).
  function syncBulkBar(form) {
    var btn = form.querySelector('[data-bulk-open]');
    if (!btn) { return; }
    var name = btn.getAttribute('data-bulk-open');
    var sel = 'input[type=checkbox][name="' + name + '"]';
    var total = form.querySelectorAll(sel).length;
    var picked = form.querySelectorAll(sel + ':checked');
    btn.disabled = picked.length === 0;

    // 누를 수 없는 버튼은 누를 수 있는 것처럼 보이지 않게 한다 — 비활성인데 primary(파란) 톤이면
    // opacity 만 낮아진 채 여전히 "이걸 누르라" 고 읽힌다. 고른 게 있을 때만 primary 로 올린다.
    btn.classList.toggle('btn--primary', !btn.disabled);
    btn.classList.toggle('btn--ghost', btn.disabled);

    // 라벨은 서버가 준 틀({n} = 개수)로만 만든다 — 문구를 여기 적어두면 화면과 갈린다.
    var label = btn.getAttribute('data-bulk-label');
    if (label) { btn.textContent = label.replace('{n}', String(picked.length)); }

    var summary = form.querySelector('[data-bulk-summary]');
    if (summary) {
      summary.textContent = picked.length
        ? picked.length + '대를 확정합니다: ' + Array.prototype.map.call(picked, function (box) {
            return box.getAttribute('data-name') || box.value;
          }).join(', ')
        : '선택한 자산이 없습니다.';
    }
    // 일부만 고른 상태를 전체선택 체크박스가 그대로 말한다(체크도 해제도 아닌 중간 표시).
    var all = form.querySelector('input[data-checkall="' + name + '"]');
    if (all) {
      all.checked = total > 0 && picked.length === total;
      all.indeterminate = picked.length > 0 && picked.length < total;
    }
  }

  // 위의 data-checkall 핸들러보다 **뒤에** 붙는다 — 같은 change 에서 전체선택이 먼저 반영돼야
  // 여기서 세는 개수가 맞다(문서 리스너는 등록 순서대로 불린다).
  document.addEventListener('change', function (e) {
    if (!e.target.matches('input[type=checkbox]') || !e.target.form) { return; }
    syncBulkBar(e.target.form);
  });
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-bulk-open]').forEach(function (btn) {
      if (btn.form) { syncBulkBar(btn.form); }
    });
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
  // 여기서는 열기 전 포커스를 기억해 닫힐 때 돌려준다. 폼 자체는 평범한 POST 폼이라
  // JS 가 죽어도 서버는 동작한다.
  var modalOpeners = new WeakMap();
  function openModal(dlg, opener) {
    if (!dlg || typeof dlg.showModal !== 'function' || dlg.open) { return; }
    if (opener) { modalOpeners.set(dlg, opener); }
    dlg.showModal();
    var first = dlg.querySelector('[autofocus], input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), a[href]');
    if (first) { first.focus(); }
  }
  document.addEventListener('click', function (e) {
    var open = e.target.closest('[data-modal]');
    if (open) {
      var dlg = document.getElementById(open.getAttribute('data-modal'));
      if (dlg && typeof dlg.showModal === 'function') {
        e.preventDefault();
        openModal(dlg, open);
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

  document.addEventListener('close', function (e) {
    if (!e.target.matches || !e.target.matches('dialog')) { return; }
    var opener = modalOpeners.get(e.target);
    modalOpeners.delete(e.target);
    if (opener && opener.isConnected) { opener.focus(); }
  }, true);

  // 서버가 "이 모달을 다시 열어라" 고 표시한 경우(폼 검증 실패 등) — 뜨자마자 연다.
  // <dialog open> 속성은 backdrop 없는 인라인 표시라 모달이 아니다. showModal() 로 열어야 한다.
  document.addEventListener('DOMContentLoaded', function () {
    var auto = document.querySelector('dialog[data-modal-autoopen]');
    if (auto) { openModal(auto, null); }
    if (window.location.hash) {
      var hashModal = document.querySelector(window.location.hash);
      if (hashModal && hashModal.matches('dialog')) { openModal(hashModal, null); }
    }
  });

  // 설치 안내처럼 짧은 순서형 모달. JS가 없으면 네 패널이 모두 보이고, 있으면 한 단계씩 보인다.
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-stepper]').forEach(function (root) {
      var panels = Array.from(root.querySelectorAll('[data-install-step-panel]'));
      var tabs = Array.from(root.querySelectorAll('[data-install-step]'));
      if (!panels.length || panels.length !== tabs.length) { return; }
      function show(index, moveFocus) {
        index = Math.max(0, Math.min(index, panels.length - 1));
        tabs.forEach(function (tab, i) {
          var on = i === index;
          tab.setAttribute('aria-selected', on ? 'true' : 'false');
          tab.setAttribute('tabindex', on ? '0' : '-1');
          panels[i].hidden = !on;
        });
        if (moveFocus) { tabs[index].focus(); }
      }
      tabs.forEach(function (tab, i) {
        tab.addEventListener('click', function () { show(i, false); });
        tab.addEventListener('keydown', function (event) {
          if (event.key === 'ArrowRight') { event.preventDefault(); show((i + 1) % tabs.length, true); }
          if (event.key === 'ArrowLeft') { event.preventDefault(); show((i + tabs.length - 1) % tabs.length, true); }
        });
      });
      root.addEventListener('click', function (event) {
        var next = event.target.closest('[data-step-next]');
        var prev = event.target.closest('[data-step-prev]');
        if (next) { show(Number(next.getAttribute('data-step-next')), true); }
        if (prev) { show(Number(prev.getAttribute('data-step-prev')), true); }
      });
      show(0, false);
    });
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
    function compactDateTime(value) {
      var match = String(value || '').match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/);
      return match ? match[1] + '.' + match[2] + '.' + match[3] + ' ' + match[4] + ':' + match[5] : String(value || '');
    }
    function statusLabel(status) {
      return {running: '수집 중', pending: '대기 중', done: '완료', failed: '실패'}[status] || status;
    }
    function stageLabel(stage) {
      return {
        initializing: '초기화', system: '시스템', packages: '설치 패키지', patches: '패치',
        runtimes: '런타임', containers: '컨테이너', exposure: '노출 분석',
        pkg_origins: '패키지 출처', security: '보안 설정', packaging: '결과 조립',
        uploading: '전송', complete: '완료', failed: '실패', cancelled: '중단'
      }[stage] || stage || '';
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
      var detail = '';
      if (command.status === 'running') {
        detail = pct + '% · ' + (stageLabel(command.progress_stage) || '수집 준비');
      } else if (command.status === 'pending') {
        detail = command.run_at ? '예약 실행' : '즉시 실행 · 다음 poll 대기';
      } else {
        detail = command.progress_message || statusLabel(command.status);
      }
      meta.appendChild(text('span', 'collection-item__stage', detail));
      var timing = '';
      if (command.status === 'pending' && command.run_at) {
        timing = '예약 ' + compactDateTime(command.run_at);
      } else if (command.started_at) {
        timing = '시작 ' + compactDateTime(command.started_at);
        if (command.elapsed_seconds !== null) { timing += ' · 경과 ' + duration(command.elapsed_seconds); }
      }
      if (command.status === 'running' && command.heartbeat_age !== null) {
        timing += (timing ? ' · ' : '') + '통신 ' + compactDateTime(command.heartbeat_at)
          + (Number(command.heartbeat_age) > 180 ? ' 지연' : ' 정상');
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
    function refresh() {
      fetch('/agent-command-overview.php', {headers: {'Accept': 'application/json'}})
        .then(function (response) { if (!response.ok) { throw new Error('status'); } return response.json(); })
        .then(render)
        .catch(function () {
          if (dialog.open) { list.replaceChildren(text('div', 'collection-overview__empty', '수집 현황을 불러오지 못했습니다.')); }
        })
        .then(function () {
          window.clearTimeout(timer);
          timer = window.setTimeout(refresh, dialog.open ? 3000 : 15000);
        });
    }
    dialog.addEventListener('close', function () { window.clearTimeout(timer); refresh(); });
    document.querySelector('[data-collection-status-open]').addEventListener('click', refresh);
    refresh();
  });

  // 뒤로가기뿐 아니라 새 창 제출 등으로 기존 문서가 남았다 다시 표시되는 경우에도
  // 멈춰 있던 스피너와 이중 제출 잠금을 되돌린다.
  window.addEventListener('pageshow', function () {
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
      var selected = b.getAttribute('data-theme-set') === t;
      b.classList.toggle('on', selected);
      b.setAttribute('aria-pressed', selected ? 'true' : 'false');
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
  function setMobileNav(open, restoreFocus) {
    document.body.classList.toggle('nav-open', open);
    var toggle = document.querySelector('[data-nav-toggle]');
    if (toggle) {
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.setAttribute('aria-label', open ? '메뉴 닫기' : '메뉴 열기');
    }
    if (open) {
      var firstLink = document.querySelector('.side a.link');
      if (firstLink) { firstLink.focus(); }
    } else if (restoreFocus && toggle) {
      toggle.focus();
    }
  }
  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-nav-toggle]')) {
      e.preventDefault();
      setMobileNav(!document.body.classList.contains('nav-open'), true);
      return;
    }
    if (e.target.closest('[data-nav-close]')) {
      setMobileNav(false, true);
      return;
    }
    if (e.target.closest('.side a.link')) {
      setMobileNav(false, false);
    }
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.body.classList.contains('nav-open')) {
      setMobileNav(false, true);
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
  function normalizedText(value) {
    return String(value || '').replace(/\s+/g, ' ').trim();
  }
  function titleRepeatsVisibleText(owner, message) {
    if (normalizedText(owner.textContent) !== normalizedText(message)) { return false; }
    if (owner.matches('.clamp-2, [class*="clamp-"]')) { return false; }
    return owner.scrollWidth <= owner.clientWidth && owner.scrollHeight <= owner.clientHeight;
  }
  function prepareTooltips(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var titled = [];
    if (root && root.nodeType === 1 && root.hasAttribute('title')) { titled.push(root); }
    scope.querySelectorAll('[title]').forEach(function (el) { titled.push(el); });
    titled.forEach(function (el) {
      var message = el.getAttribute('title');
      if (!message) { return; }
      if (titleRepeatsVisibleText(el, message)) {
        el.removeAttribute('title');
        return;
      }
      el.setAttribute('data-tip', message);
      el.removeAttribute('title');
      if (!el.matches('a[href],button,input,select,textarea,[tabindex]')) { el.setAttribute('tabindex', '0'); }
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
