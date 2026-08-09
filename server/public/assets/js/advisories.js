// advisories.js — 보안 공지 화면 전용 JS. app.js(공용) 뒤에 defer 로 붙는다(layout.php 관례).
//   "영향 자산" 배지를 누르면 단일 모달(#advisoryAssetsModal)에 해당 공지의 호스트·패키지·
//   CVE·심각도를 채운다(host.php 의 data-finding-detail 모달과 같은 패턴, data 속성명만 분리).
(function () {
  var modal = document.getElementById('advisoryAssetsModal');
  if (!modal) { return; }

  var SEV_TONE = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low' };

  function link(href, text) {
    var a = document.createElement('a');
    a.href = href;
    a.textContent = text;
    return a;
  }

  function badge(sev) {
    var span = document.createElement('span');
    span.className = 'badge tone-' + (SEV_TONE[sev] || 'muted');
    span.textContent = sev || '–';
    return span;
  }

  function cell(tag, node) {
    var el = document.createElement(tag);
    if (typeof node === 'string') { el.textContent = node; }
    else { el.appendChild(node); }
    return el;
  }

  function openAssetsModal(el) {
    var detail;
    try { detail = JSON.parse(el.getAttribute('data-advisory-assets') || '{}'); }
    catch (error) { return; }

    var title = modal.querySelector('[data-advisory-assets-title]');
    if (title) { title.textContent = detail.title || ''; }

    var body = modal.querySelector('[data-advisory-assets-body]');
    if (body) {
      body.textContent = '';
      var table = document.createElement('table');
      table.className = 'data-table';
      var thead = document.createElement('thead');
      var headRow = document.createElement('tr');
      ['호스트', '패키지', '설치 버전', 'CVE', '심각도'].forEach(function (label) {
        headRow.appendChild(cell('th', label));
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      var tbody = document.createElement('tbody');
      (detail.rows || []).forEach(function (r) {
        var tr = document.createElement('tr');
        tr.appendChild(cell('td', link(r.host_url, r.host_fqdn)));
        tr.appendChild(cell('td', r.package));
        tr.appendChild(cell('td', r.installed));
        tr.appendChild(cell('td', link(r.cve_url, r.cve)));
        tr.appendChild(cell('td', badge(r.severity)));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      body.appendChild(table);
    }

    var more = modal.querySelector('[data-advisory-assets-more]');
    if (more) {
      var shown = (detail.rows || []).length;
      var total = Number(detail.total || shown);
      more.textContent = '';
      if (total > shown) {
        more.appendChild(document.createTextNode(total + '건 중 ' + shown + '건 표시 · '));
      }
      if (detail.detail_url) {
        more.appendChild(link(detail.detail_url, '전체 영향 자산 보기 →'));
      }
    }

    if (typeof modal.showModal === 'function') { modal.showModal(); }
  }

  document.addEventListener('click', function (event) {
    var el = event.target.closest && event.target.closest('[data-advisory-assets]');
    if (!el) { return; }
    openAssetsModal(el);
  });
  document.addEventListener('keydown', function (event) {
    var el = event.target.closest && event.target.closest('[data-advisory-assets]');
    if (!el || event.target !== el || (event.key !== 'Enter' && event.key !== ' ')) { return; }
    event.preventDefault();
    openAssetsModal(el);
  });
})();
