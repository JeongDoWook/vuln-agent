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
        if ((command.status === 'done' || command.status === 'failed') && initialState !== command.status) {
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
