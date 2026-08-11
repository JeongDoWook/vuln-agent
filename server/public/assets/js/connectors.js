// connectors.php 전용 JS. 공용 동작(vgLoading 등)은 app.js 가 갖고, 이 화면에서만 쓰는
//   "API 미리보기" + 범용 API 커넥터(generic_api) 전용 동적 폼을 여기 둔다.
//   view.php 가 페이지 이름(connectors)으로 이 파일을 자동 로드한다.

// 타입 → 수집 방식·노출 필드. PHP 의 카탈로그(src/feeds.php VG_CONNECTOR_TYPES)가 유일한
//   근거이고, vgGenericInit 이 폼의 data-type-meta 에서 읽어 채운다. 미리보기·폼 토글이 함께 쓴다.
var VG_TYPE_META = {};

// 외부 소스를 직접 치는 요청이라 수 초 걸린다 → 버튼 스피너 + 상단 진행바(app.js 의 vgLoading).
//   data-feed-preview 버튼은 아래 이벤트 위임에서 호출한다.
function vgPreview(btn) {
  var f = document.getElementById('connForm');
  var out = document.getElementById('vgPrev');
  out.hidden = false;
  out.classList.add('is-loading');
  out.textContent = '조회 중…';
  vgLoading(btn, true);

  var req;
  if (f.connector_type.value === 'generic_api') {
    var body = new URLSearchParams({ type: 'generic_api', g_config_json: vgGenericSerialize() });
    req = fetch('/feed_preview.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
  } else {
    // 이 타입이 실제로 읽는 필드만 보낸다 — 숨긴 칸에 남은 남의 값(osv 를 보다 kev 로 바꿨을 때의
    //   ecosystem)을 실어 보내면 미리보기가 저장될 설정과 다른 걸 보게 된다.
    var qs = new URLSearchParams({ type: f.connector_type.value });
    var meta = VG_TYPE_META[f.connector_type.value];
    ((meta && meta.fields) || []).forEach(function (k) {
      if (f[k]) { qs.set(k, f[k].value); }
    });
    req = fetch('/feed_preview.php?' + qs.toString());
  }

  req.then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.ok) { out.textContent = '오류: ' + (j.error || '알 수 없음'); return; }
      var head = '총 ' + (j.count != null ? j.count : '?') + '건' + (j.note ? ' · ' + j.note : '') + ' (아래는 최대 10건)\n\n';
      out.textContent = head + JSON.stringify(j.sample, null, 2);
    })
    .catch(function (e) { out.textContent = '요청 실패: ' + e; })
    .finally(function () {
      out.classList.remove('is-loading');
      vgLoading(btn, false);
    });
}

document.addEventListener('click', function (event) {
  var button = event.target.closest('[data-feed-preview]');
  if (!button) { return; }
  event.preventDefault();
  vgPreview(button);
});

// ─────────────────────────────────────────────────────────────────────────
// 범용 API 커넥터(generic_api) 전용 동적 폼.
//   설계: .omc/plans/generic-api-connector-design.md 4장(role별 매핑표) · 6장(UI).
//   서버는 connection_json 구조를 그대로 받는다(server/src/feeds/generic_api.php
//   vg_generic_parse_config 가 파싱) — 그래서 여기서도 같은 shape 로 직렬화한다.
// ─────────────────────────────────────────────────────────────────────────
var VG_GENERIC_ROLE_FIELDS = {
  identity: [
    { key: 'cve_id', label: 'CVE ID', required: true },
    { key: 'summary', label: '요약', required: false },
    { key: 'cvss', label: 'CVSS 점수', required: false },
    { key: 'published', label: '공개일', required: false },
    { key: 'cvss_vector', label: 'CVSS 벡터', required: false },
    { key: 'cwe', label: 'CWE', required: false },
    { key: 'package_name', label: '영향 패키지명', required: false },
    { key: 'ecosystem', label: '생태계(ecosystem)', required: false },
    { key: 'fixed_version', label: '조치 버전', required: false }
  ],
  priority: [
    { key: 'cve_id', label: 'CVE ID', required: true },
    { key: 'date_added', label: '등재일', required: false },
    { key: 'note', label: '설명', required: false },
    { key: 'due_date', label: '조치 기한', required: false },
    { key: 'ransomware', label: '랜섬웨어 연관', required: false },
    { key: 'epss', label: 'EPSS 점수', required: false },
    { key: 'epss_percentile', label: 'EPSS 백분위', required: false }
  ],
  vendor: [
    { key: 'cve_id', label: 'CVE ID', required: true },
    { key: 'vendor', label: '벤더', required: true },
    { key: 'release_major', label: '배포판 메이저 버전', required: true },
    { key: 'pkg_name', label: '패키지명', required: true },
    { key: 'fixed_evr', label: '조치 버전(epoch:version-release)', required: true },
    { key: 'advisory', label: '권고 ID', required: false },
    { key: 'severity', label: '심각도', required: false }
  ]
};
// PHP 의 VG_GENERIC_ROLE_LABELS(connectors.php)가 유일한 근거 — vgGenericInit 이 폼의
//   data-role-labels 에서 읽어 채운다(data-type-meta 와 같은 수법).
var VG_GENERIC_ROLE_LABELS = {};

function vgKvRow(container, labelHtml, value, placeholder, removable) {
  var row = document.createElement('div');
  row.className = 'kvrow';
  var label = document.createElement('div');
  label.className = 'kvrow__label';
  label.innerHTML = labelHtml;
  var input = document.createElement('input');
  input.type = 'text';
  input.value = value || '';
  if (placeholder) { input.placeholder = placeholder; }
  row.appendChild(label);
  row.appendChild(input);
  if (removable) {
    var rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'btn btn--sm btn--ghost';
    rm.textContent = '삭제';
    rm.addEventListener('click', function () { row.remove(); });
    row.appendChild(rm);
  } else {
    row.appendChild(document.createElement('span')); // 열 정렬 유지
  }
  container.appendChild(row);
  return input;
}

// 헤더 행: 키 입력 + 값 입력 + 삭제 버튼 (자유 입력이라 label 대신 key input 을 둔다)
function vgHeaderRow(container, key, value) {
  var row = document.createElement('div');
  row.className = 'kvrow';
  var kInput = document.createElement('input');
  kInput.type = 'text'; kInput.placeholder = '헤더 이름 (예: Authorization)'; kInput.value = key || '';
  kInput.className = 'g-h-key';
  var vInput = document.createElement('input');
  vInput.type = 'text'; vInput.placeholder = '값'; vInput.value = value || '';
  vInput.className = 'g-h-val';
  var rm = document.createElement('button');
  rm.type = 'button'; rm.className = 'btn btn--sm btn--ghost'; rm.textContent = '삭제';
  rm.addEventListener('click', function () { row.remove(); });
  row.appendChild(kInput); row.appendChild(vInput); row.appendChild(rm);
  container.appendChild(row);
}

function vgRenderFieldMap(role, existingMapping) {
  var wrap = document.getElementById('gFieldMap');
  if (!wrap) { return; }
  wrap.innerHTML = '';
  wrap.dataset.role = role;
  var defs = VG_GENERIC_ROLE_FIELDS[role] || [];
  var mapping = existingMapping || {};
  defs.forEach(function (d) {
    var labelHtml = (d.required ? '<strong class="kvrow__label is-required">' : '<span class="kvrow__label">') + d.label + (d.required ? '*' : '') + (d.required ? '</strong>' : '</span>');
    var input = vgKvRow(wrap, labelHtml, mapping[d.key], '예: data.' + d.key, false);
    input.className = 'g-fm-val';
    input.dataset.fmKey = d.key;
  });
  var lbl = document.getElementById('gRoleLabel');
  if (lbl) { lbl.textContent = '(' + (VG_GENERIC_ROLE_LABELS[role] || role) + ')'; }
  var notice = document.getElementById('gRoleNotice');
  if (notice) {
    notice.hidden = role === '' || Object.prototype.hasOwnProperty.call(VG_GENERIC_ROLE_LABELS, role);
    // app.css 의 .alert 는 display:flex 라 작성자 스타일이 [hidden] 의 display:none 을 이긴다 —
    //   hidden 만 세우면 "역할을 더 이상 지원하지 않습니다" 경고가 새 커넥터에도 늘 떠 있었다.
    //   색·레이아웃은 여전히 app.css 소유이고, 여기서는 보임/숨김만 강제한다.
    notice.style.display = notice.hidden ? 'none' : '';
  }
}

function vgGenericCollect() {
  var form = document.getElementById('connForm');
  var role = document.getElementById('gRole').value;
  var headers = {};
  document.querySelectorAll('#gHeaders .kvrow').forEach(function (row) {
    var k = row.querySelector('.g-h-key').value.trim();
    var v = row.querySelector('.g-h-val').value.trim();
    if (k !== '' && v !== '') { headers[k] = v; }
  });
  var fieldMapping = {};
  document.querySelectorAll('#gFieldMap .g-fm-val').forEach(function (input) {
    var v = input.value.trim();
    if (v !== '') { fieldMapping[input.dataset.fmKey] = v; }
  });
  var pageSize = parseInt(document.getElementById('gPageSize').value, 10);
  var pagination = { type: document.getElementById('gPageType').value };
  if (!isNaN(pageSize) && pageSize > 0) { pagination.page_size = pageSize; }
  var totalPath = document.getElementById('gTotalPath').value.trim();
  if (totalPath !== '') { pagination.total_path = totalPath; }
  return {
    role: role,
    url_template: document.getElementById('gUrlTemplate').value.trim(),
    method: document.getElementById('gMethod').value,
    headers: headers,
    pagination: pagination,
    response: {
      items_path: document.getElementById('gItemsPath').value.trim(),
      field_mapping: fieldMapping
    }
  };
}

function vgGenericSerialize() {
  var json = JSON.stringify(vgGenericCollect());
  var hidden = document.getElementById('gConfigJson');
  if (hidden) { hidden.value = json; }
  return json;
}

function vgGenericInit() {
  var form = document.getElementById('connForm');
  if (!form) { return; }
  // PHP 가 hidden 으로 그려 둔 역할 경고를 첫 화면에서도 실제로 감춘다 — .alert 의 display:flex 가
  //   [hidden] 을 이기므로(위 vgRenderFieldMap 주석 참고) 처음부터 늘 떠 있었다.
  var roleNotice0 = document.getElementById('gRoleNotice');
  if (roleNotice0 && roleNotice0.hidden) { roleNotice0.style.display = 'none'; }
  var typeSel = document.getElementById('connType');
  var std = document.getElementById('stdFields');
  var generic = document.getElementById('genericFields');
  if (!typeSel || !std || !generic) { return; }

  var editRaw = form.dataset.editGeneric;
  var editConfig = null;
  if (editRaw) {
    try { editConfig = JSON.parse(editRaw); } catch (e) { editConfig = null; }
  }

  // 카탈로그를 PHP 에서 넘겨받는다(data-edit-generic 과 같은 수법) — 표를 JS 에 복붙하면
  //   커넥터가 늘 때 한쪽만 고쳐진다.
  try { VG_TYPE_META = JSON.parse(form.dataset.typeMeta || '{}'); } catch (e) { VG_TYPE_META = {}; }
  try { VG_GENERIC_ROLE_LABELS = JSON.parse(form.dataset.roleLabels || '{}'); } catch (e) { VG_GENERIC_ROLE_LABELS = {}; }
  if (Object.keys(VG_GENERIC_ROLE_LABELS).length === 0) {
    console.warn('vgGenericInit: data-role-labels 가 비었거나 파싱 실패 — 역할 select 가 원시 키로 표시됩니다.');
  }

  function toggle() {
    var isGeneric = typeSel.value === 'generic_api';
    std.hidden = isGeneric;
    generic.hidden = !isGeneric;

    var meta = VG_TYPE_META[typeSel.value];
    if (!meta) { return; }

    // 수집 방식 뱃지 + 한 줄 설명. PHP 가 그린 첫 화면과 같은 모양으로 다시 그린다.
    var badge = document.querySelector('#connTransport .badge');
    if (badge) {
      badge.textContent = meta.transport;
      badge.className = 'badge tone-' + meta.tone;
    }
    var desc = document.getElementById('connTransportDesc');
    if (desc) { desc.textContent = meta.desc; }

    // 이 타입이 실제로 읽는 필드만 남긴다. 라벨도 방식에 맞게 바꾼다(kev 는 API 가 아니다).
    std.querySelectorAll('[data-field]').forEach(function (box) {
      box.hidden = meta.fields.indexOf(box.dataset.field) === -1;
    });
    var urlLabel = document.getElementById('urlLabel');
    if (urlLabel && meta.urlLabel) { urlLabel.textContent = meta.urlLabel; }
  }

  // 선택한 스케줄에 필요한 입력만 보여준다. 수동 수집인데 interval/daily/cron 입력을
  // 한꺼번에 노출하면 어떤 값이 저장되는지 오해하기 쉽다.
  var schedule = document.getElementById('connSchedule');
  function toggleSchedule() {
    if (!schedule) { return; }
    form.querySelectorAll('[data-schedule-field]').forEach(function (box) {
      box.hidden = box.dataset.scheduleField !== schedule.value;
    });
  }

  document.getElementById('gRole').addEventListener('change', function () {
    vgRenderFieldMap(this.value, null);
  });
  document.getElementById('gHeaderAdd').addEventListener('click', function () {
    vgHeaderRow(document.getElementById('gHeaders'), '', '');
  });

  typeSel.addEventListener('change', toggle);
  if (schedule) { schedule.addEventListener('change', toggleSchedule); }
  toggle();
  toggleSchedule();

  if (editConfig) {
    var editRole = editConfig.role || 'identity';
    document.getElementById('gRole').value = editRole;
    document.getElementById('gMethod').value = editConfig.method || 'GET';
    document.getElementById('gUrlTemplate').value = editConfig.url_template || '';
    var headers = editConfig.headers || {};
    Object.keys(headers).forEach(function (k) { vgHeaderRow(document.getElementById('gHeaders'), k, headers[k]); });
    var pg = editConfig.pagination || {};
    document.getElementById('gPageType').value = pg.type || 'none';
    document.getElementById('gPageSize').value = pg.page_size || '';
    document.getElementById('gTotalPath').value = pg.total_path || '';
    var resp = editConfig.response || {};
    document.getElementById('gItemsPath').value = resp.items_path || '';
    vgRenderFieldMap(editRole, resp.field_mapping || {});
  } else {
    vgRenderFieldMap('identity', null);
  }

  // 네이티브 제출 직전에 현재 DOM 상태를 g_config_json 으로 굳힌다(저장/미리보기가 같은 shape).
  form.addEventListener('submit', function () {
    if (typeSel.value === 'generic_api') { vgGenericSerialize(); }
  });
}

document.addEventListener('DOMContentLoaded', vgGenericInit);
