// host.js — 호스트 상세 화면 전용 JS. app.js(공용) 뒤에 defer 로 붙는다(layout.php 관례).
//   예약 실행 입력에 flatpickr(의존성 0, vendor/ 자체호스팅)를 입힌다. 네이티브
//   datetime-local 이 여전히 폼 값을 들고 있어야 하므로 dateFormat 을 그 형식에 맞춘다
//   (백엔드 agentcommand.php 의 strtotime() 파싱은 그대로 둔다 — 값 형식만 유지하면 된다).
(function () {
  if (typeof flatpickr === 'undefined') { return; }
  var input = document.querySelector('input[name="run_at"]');
  if (!input) { return; }
  flatpickr(input, {
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
  });
})();
