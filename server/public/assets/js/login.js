// login.js — 브라우저 확장이나 modifier 클릭이 로그인 POST를 새 창으로
// 보내더라도 현재 탭에서만 처리한다. 네이티브 submit()은 submit 이벤트를
// 다시 발생시키지 않으므로 공통 app.js의 이중 제출 방지와도 충돌하지 않는다.
(function () {
  'use strict';

  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form.matches('#loginForm[data-same-context]') || event.defaultPrevented) { return; }

    event.preventDefault();
    form.setAttribute('target', '_self');
    if (event.submitter) { event.submitter.setAttribute('formtarget', '_self'); }
    HTMLFormElement.prototype.submit.call(form);
  });
})();
