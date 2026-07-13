// connectors.php 전용 JS. 공용 동작(vgLoading 등)은 app.js 가 갖고, 이 화면에서만 쓰는
//   "API 미리보기"만 여기 둔다. view.php 가 페이지 이름(connectors)으로 이 파일을 자동 로드한다.

// 외부 소스를 직접 치는 요청이라 수 초 걸린다 → 버튼 스피너 + 상단 진행바(app.js 의 vgLoading).
//   버튼의 onclick="vgPreview(this)" 에서 부른다.
function vgPreview(btn) {
  var f = document.getElementById('connForm');
  var out = document.getElementById('vgPrev');
  var qs = new URLSearchParams({
    type: f.connector_type.value, url: f.url.value,
    api_key: f.api_key.value, ecosystem: f.ecosystem.value, days: f.days.value
  });
  out.hidden = false;
  out.classList.add('is-loading');
  out.textContent = '조회 중…';
  vgLoading(btn, true);
  fetch('/feed_preview.php?' + qs.toString())
    .then(function (r) { return r.json(); })
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
