// host.js — 호스트 상세 화면 전용 JS. app.js(공용) 뒤에 defer 로 붙는다(layout.php 관례).
//   예약 실행 입력에 flatpickr(의존성 0, vendor/ 자체호스팅)를 입힌다. 네이티브
//   datetime-local 이 여전히 폼 값을 들고 있어야 하므로 dateFormat 을 그 형식에 맞춘다
//   (백엔드 agentcommand.php 의 strtotime() 파싱은 그대로 둔다 — 값 형식만 유지하면 된다).
(function () {
  var input = document.querySelector('input[name="run_at"]');
  if (input && typeof flatpickr !== 'undefined') { flatpickr(input, {
    locale: {
      weekdays: {
        shorthand: ['일', '월', '화', '수', '목', '금', '토'],
        longhand: ['일요일', '월요일', '화요일', '수요일', '목요일', '금요일', '토요일'],
      },
      months: {
        shorthand: ['1월', '2월', '3월', '4월', '5월', '6월', '7월', '8월', '9월', '10월', '11월', '12월'],
        longhand: ['1월', '2월', '3월', '4월', '5월', '6월', '7월', '8월', '9월', '10월', '11월', '12월'],
      },
      firstDayOfWeek: 0,
      time_24hr: true,
      yearAriaLabel: '년',
      hourAriaLabel: '시간',
      minuteAriaLabel: '분',
    },
    enableTime: true,
    time_24hr: true,
    minuteIncrement: 5,
    minDate: 'today',
    monthSelectorType: 'static',
    disableMobile: true,
    dateFormat: 'Y-m-d\\TH:i',
    altInput: true,
    altFormat: 'Y년 m월 d일 H:i',
    altInputClass: 'agent-control__datetime',
  }); }

  var findingModal = document.getElementById('findingDetailModal');
  function syncFindingNoteRequired() {
    var fixStatus = findingModal && findingModal.querySelector('[data-finding-fix-status]');
    var fixNote = findingModal && findingModal.querySelector('[data-finding-fix-note]');
    if (!fixStatus || !fixNote) { return; }
    fixNote.required = fixStatus.value === 'EXCEPTED';
  }
  function openFindingDetail(row) {
    if (!findingModal) { return; }
    var detail;
    try { detail = JSON.parse(row.getAttribute('data-finding-detail') || '{}'); }
    catch (error) { return; }
    ['severity', 'status', 'cve', 'package', 'installed', 'fixed', 'epss', 'rationale', 'action'].forEach(function (field) {
      var node = findingModal.querySelector('[data-finding-' + field + ']');
      if (node) { node.textContent = detail[field] || '–'; }
    });
    var severity = findingModal.querySelector('[data-finding-severity]');
    if (severity) {
      severity.className = 'badge tone-' + ({CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low'}[detail.severity] || 'muted');
    }
    // 조치 상태 폼 — 어느 행을 눌렀는지에 따라 대상(자연키)과 현재 상태가 바뀐다.
    //   폼이 없는 경우(권한 없는 역할)는 읽기 전용 라벨만 채운다.
    var fixFields = {ref: 'container_ref', cve: 'cve', package: 'package'};
    Object.keys(fixFields).forEach(function (name) {
      var node = findingModal.querySelector('[data-finding-fix-' + name + ']');
      if (node) { node.value = detail[fixFields[name]] || ''; }
    });
    var fixStatus = findingModal.querySelector('[data-finding-fix-status]');
    if (fixStatus) { fixStatus.value = detail.fix_status || 'OPEN'; }
    var fixNote = findingModal.querySelector('[data-finding-fix-note]');
    if (fixNote) { fixNote.value = detail.fix_note || ''; }
    syncFindingNoteRequired();
    var fixLabel = findingModal.querySelector('[data-finding-fix-status-label]');
    if (fixLabel) { fixLabel.textContent = detail.fix_status_label || '미조치'; }

    var cveLink = findingModal.querySelector('[data-finding-cve-link]');
    var historyLink = findingModal.querySelector('[data-finding-history]');
    if (cveLink) { cveLink.setAttribute('href', detail.cve_url || '#'); }
    if (historyLink) { historyLink.setAttribute('href', detail.history_url || '#'); }
    if (typeof findingModal.showModal === 'function') { findingModal.showModal(); }
  }
  var findingFixStatus = findingModal && findingModal.querySelector('[data-finding-fix-status]');
  if (findingFixStatus) { findingFixStatus.addEventListener('change', syncFindingNoteRequired); }
  document.addEventListener('click', function (event) {
    var row = event.target.closest && event.target.closest('tr[data-finding-detail]');
    if (!row || event.target.closest('a, button, input, select, textarea, label')) { return; }
    openFindingDetail(row);
  });
  document.addEventListener('keydown', function (event) {
    var row = event.target.closest && event.target.closest('tr[data-finding-detail]');
    if (!row || event.target !== row || (event.key !== 'Enter' && event.key !== ' ')) { return; }
    event.preventDefault();
    openFindingDetail(row);
  });

  var progress = document.querySelector('[data-agent-progress]');
  if (!progress) { return; }
  var hostId = progress.getAttribute('data-host-id');
  var initialState = progress.getAttribute('data-state');
  function duration(seconds) {
    seconds = Math.max(0, Number(seconds) || 0);
    if (seconds < 60) { return Math.floor(seconds) + '초'; }
    return Math.floor(seconds / 60) + '분 ' + Math.floor(seconds % 60) + '초';
  }
  function pollProgress() {
    fetch('/agent-command-status.php?id=' + encodeURIComponent(hostId), {headers: {'Accept': 'application/json'}})
      .then(function (response) { if (!response.ok) { throw new Error('status'); } return response.json(); })
      .then(function (data) {
        var command = data.command;
        if (!command) { window.location.reload(); return; }
        if ((command.status === 'done' || command.status === 'failed' || command.status === 'cancelled') && initialState !== command.status) {
          window.location.reload(); return;
        }
        var running = command.status === 'running';
        var pct = running ? Number(command.progress_percent || 0) : 0;
        progress.setAttribute('data-state', command.status);
        progress.querySelector('[data-progress-title]').textContent = running ? '수집 진행 중' : '명령 대기 중';
        progress.querySelector('[data-progress-percent]').textContent = pct + '%';
        progress.querySelector('[data-progress-bar]').value = pct;
        progress.querySelector('[data-progress-message]').textContent = running
          ? (command.progress_message || '수집을 진행하고 있습니다.')
          : (command.run_at ? '예약 시각이 되면 다음 poll에서 시작합니다.' : '에이전트의 다음 poll을 기다리고 있습니다.');
        var time = progress.querySelector('[data-progress-time]');
        if (running) {
          // 패키지·컨테이너 조사 단계는 수분 걸릴 수 있으므로 짧은 무응답을 장애로 오인하지 않는다.
          var stale = command.heartbeat_age !== null && Number(command.heartbeat_age) > 180;
          time.textContent = '경과 ' + duration(command.elapsed_seconds) + ' · ' + (stale ? '마지막 통신 지연' : '방금 통신');
          progress.classList.toggle('is-stale', stale);
        }
      })
      .catch(function () {})
      .then(function () { window.setTimeout(pollProgress, 3000); });
  }
  window.setTimeout(pollProgress, 1000);
})();

// --- AI 보고서(host/report.php 카드) -----------------------------------------
//   생성 버튼 → 프록시(POST /report-job-create.php) → 상태 폴링(GET /report-job-status.php).
//   폴링 간격·상한은 **설정값**이라 카드의 data-* 로 내려온다(스크립트가 숫자를 갖지 않는다).
//   외부 보고서 서비스는 망이 갈려 못 닿을 수 있다 — 그때 화면이 깨지지 않고 오류 배지로
//   떨어지는 게 정상 경로다. 결과 본문은 형식이 정해지지 않은 plain text 라 textContent 로만
//   넣는다(HTML 로 해석하지 않는다).
//   결과가 PDF 링크면 서버가 download_url(우리 프록시 경로)을 함께 준다 — 그때는 본문 대신
//   [PDF 다운로드] 를 보인다. blob 을 만들지 않는다: 평범한 <a> 로 충분하다.
(function () {
  var card = document.querySelector('[data-report-job]');
  if (!card) { return; }

  var hostId = card.getAttribute('data-host-id');
  var csrf = card.getAttribute('data-csrf');
  var interval = Math.max(1, Number(card.getAttribute('data-poll-interval')) || 3) * 1000;
  var maxAttempts = Math.max(1, Number(card.getAttribute('data-poll-max')) || 60);
  var createBtn = card.querySelector('[data-report-create]');
  var statusBox = card.querySelector('[data-report-status]');
  var badge = card.querySelector('[data-report-badge]');
  var messageBox = card.querySelector('[data-report-message]');
  var resultBox = card.querySelector('[data-report-result]');
  var downloadBox = card.querySelector('[data-report-download]');
  var downloadLink = card.querySelector('[data-report-download-link]');

  function setStatus(tone, label, text) {
    if (!statusBox) { return; }
    statusBox.hidden = false;
    badge.className = 'badge tone-' + tone;
    badge.textContent = label;
    messageBox.textContent = text;
  }
  function showResult(text) {
    if (!resultBox) { return; }
    resultBox.textContent = text || '';
    resultBox.hidden = !text;
  }
  // 결과가 파일이면 본문 대신 다운로드 버튼. href 는 **서버가 준 우리 프록시 경로**만 쓴다
  //   (외부 주소는 애초에 화면으로 내려오지 않는다).
  function showDownload(href) {
    if (!downloadBox || !downloadLink) { return; }
    if (href) { downloadLink.setAttribute('href', href); }
    downloadBox.hidden = !href;
  }
  function busy(on) {
    if (createBtn) { createBtn.disabled = on; }
  }
  // 응답이 JSON 이 아닐 수도 있다(권한 거부의 평문 'forbidden' 등) — 본문을 먼저 읽고 판단한다.
  function readJson(response) {
    return response.text().then(function (body) {
      var data = null;
      try { data = JSON.parse(body); } catch (error) { data = null; }
      if (!response.ok || !data || !data.ok) {
        throw new Error((data && data.error) || '요청을 처리하지 못했습니다.');
      }
      return data;
    });
  }
  function failed(error) {
    setStatus('crit', '오류', (error && error.message) || '요청을 처리하지 못했습니다.');
    busy(false);
  }

  // 화면이 아는 상태는 셋뿐이다(서버의 vg_report_state 와 같은 어휘). 완료·실패면 폴링을 멈춘다.
  function apply(job) {
    if (!job) { return false; }
    if (job.state === 'done') {
      setStatus('ok', job.state_label, job.download_url ? '보고서 파일이 준비되었습니다.' : '보고서가 준비되었습니다.');
      showDownload(job.download_url);
      showResult(job.download_url ? '' : (job.result || '(내용이 비어 있습니다)'));
      return true;
    }
    if (job.state === 'failed') {
      setStatus('crit', job.state_label, job.error_message || '보고서 생성에 실패했습니다.');
      showResult('');
      showDownload('');
      return true;
    }
    setStatus('info', job.state_label, '보고서를 만들고 있습니다.');
    return false;
  }

  function poll(jobId, attempt) {
    fetch('/report-job-status.php?job=' + encodeURIComponent(jobId), {headers: {'Accept': 'application/json'}})
      .then(readJson)
      .then(function (data) {
        if (apply(data.job)) { busy(false); return; }
        if (attempt >= maxAttempts) {
          // 폴링은 무한이 아니다. 작업 자체는 서버에 남아 있으므로 나중에 이 화면에서 이어서 본다.
          setStatus('med', '생성 중', '시간이 오래 걸립니다 — 나중에 이 페이지에서 다시 확인하세요.');
          busy(false);
          return;
        }
        window.setTimeout(function () { poll(jobId, attempt + 1); }, interval);
      })
      .catch(failed);
  }

  if (createBtn) {
    createBtn.addEventListener('click', function () {
      busy(true);
      showResult('');
      showDownload('');
      setStatus('info', '생성 중', '보고서 작업을 요청하고 있습니다.');
      var body = new URLSearchParams();
      body.append('csrf', csrf);
      body.append('id', hostId);
      fetch('/report-job-create.php', {
        method: 'POST',
        headers: {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
        body: body.toString()
      })
        .then(readJson)
        .then(function (data) {
          if (!data.job) { throw new Error('작업 번호를 받지 못했습니다.'); }
          if (apply(data.job)) { busy(false); return; }
          poll(data.job.report_job_id, 1);
        })
        .catch(failed);
    });
  }

  // 이력의 '결과 보기' — 이미 끝난 작업이라 서버가 외부를 다시 부르지 않고 저장된 본문을 준다.
  card.addEventListener('click', function (event) {
    var btn = event.target.closest && event.target.closest('[data-report-view]');
    if (!btn) { return; }
    var jobId = btn.getAttribute('data-report-view');
    setStatus('info', '불러오는 중', '저장된 보고서를 불러오고 있습니다.');
    fetch('/report-job-status.php?job=' + encodeURIComponent(jobId), {headers: {'Accept': 'application/json'}})
      .then(readJson)
      .then(function (data) { apply(data.job); })
      .catch(failed);
  });

  // 새로고침 전에 걸어 둔 작업이 아직 안 끝났으면 이어서 확인한다(서버가 그 사실을 알려준다).
  var activeJob = card.getAttribute('data-active-job');
  if (activeJob) {
    busy(true);
    poll(activeJob, 1);
  }
})();
