/* chart-kit.js — Chart.js 를 이 제품의 토큰 위에 앉히는 얇은 층.
 *
 * 왜 있나: 화면마다 Chart.js 설정을 복붙하면 팔레트·격자색·툴팁·다크 대응이 화면 수만큼
 *   갈라진다(app.css 가 예전에 리스킨 레이어 4겹으로 겪은 그 문제와 같다). 색은 여기서만
 *   정하고, 화면은 "무슨 데이터를 어떤 형태로" 만 말한다.
 *
 * 계약: 서버는 <canvas data-vg-chart='{"type":…,"data":…,"options":…}'> 를 그리고
 *   (server/src/view/charts.php 의 vg_chart()), 이 파일이 그것을 찾아 그린다.
 *   데이터셋에 색을 주지 않으면 범주형 팔레트(--cat-1..6)를 순서대로 배정한다.
 *   색을 직접 준 데이터셋은 건드리지 않는다(심각도처럼 의미가 고정된 색을 쓰는 경우).
 *
 * 다크: 색 값은 CSS 변수에서 읽는다. 테마가 바뀌면 <html data-theme> 이 바뀌므로
 *   그것을 감시해 색만 다시 칠하고 chart.update() 한다 — 다시 그리지 않는다(애니메이션 없음).
 */
(function () {
  'use strict';

  var charts = [];   // [{chart, spec}] — 테마 전환 때 색을 다시 칠할 대상

  function tok(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    v = (v || '').trim();
    return v !== '' ? v : fallback;
  }

  // 범주형 팔레트. --cat-6 은 항상 "기타·미분류" 자리다(app.css 주석의 계약).
  function palette() {
    var out = [];
    for (var i = 1; i <= 6; i++) { out.push(tok('--cat-' + i, '#8a94a6')); }
    return out;
  }

  // 면(도넛·막대)에는 옅게, 선에는 원색 그대로. 두 번째 인자는 alpha(0~1).
  function alpha(color, a) {
    var m = /^#([0-9a-f]{6})$/i.exec(color);
    if (!m) { return color; }
    var n = parseInt(m[1], 16);
    return 'rgb(' + ((n >> 16) & 255) + ' ' + ((n >> 8) & 255) + ' ' + (n & 255) + ' / ' + a + ')';
  }

  // 데이터셋에 색을 배정한다. 이미 색이 있으면 그대로 둔다.
  function paint(spec) {
    var pal = palette();
    var sets = (spec.data && spec.data.datasets) || [];
    var arcLike = isArcType(spec.type);
    sets.forEach(function (ds, si) {
      if (ds.vgKeepColors) { return; }
      if (arcLike) {
        // 조각마다 색 — 라벨 수만큼 순서대로 돌린다.
        var n = (spec.data.labels || []).length || (ds.data || []).length;
        var arr = [];
        for (var i = 0; i < n; i++) { arr.push(pal[i % pal.length]); }
        ds.backgroundColor = arr;
        ds.borderColor = tok('--surface', '#fff');
        ds.borderWidth = 2;
      } else {
        var c = pal[si % pal.length];
        ds.borderColor = c;
        ds.backgroundColor = spec.type === 'line' ? alpha(c, 0.16) : c;
      }
    });
  }

  function isArcType(type) {
    return type === 'doughnut' || type === 'pie' || type === 'polarArea';
  }

  // 축·격자·툴팁 — 전부 --chart-* 토큰에서 읽는다(그 토큰들은 기존 색 토큰을 가리킨다).
  //   도넛·파이에는 축을 주지 않는다 — 주면 Chart.js 가 없는 축을 만들어 격자와 0~5 눈금을
  //   조각 뒤에 깔아 버린다(실제로 그렇게 그려졌다).
  function surfaceOptions(type) {
    var grid = tok('--chart-grid', '#e2e8f0');
    var axis = tok('--chart-axis', '#808b99');
    var scale = {
      grid: { color: grid, drawTicks: false },
      border: { color: grid },
      ticks: { color: axis }
    };
    var base = {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { labels: { color: axis, boxWidth: 10, boxHeight: 10, usePointStyle: true } },
        tooltip: {
          backgroundColor: tok('--chart-tip-bg', '#fff'),
          borderColor: tok('--chart-tip-bd', '#cbd5e1'),
          borderWidth: 1,
          titleColor: tok('--text', '#191f28'),
          bodyColor: tok('--text-2', '#45505f'),
          displayColors: true,
          padding: 8
        }
      }
    };
    if (!isArcType(type)) { base.scales = { x: scale, y: scale }; }
    return base;
  }

  // 얕은 병합 두 단계 — 화면이 준 options 가 이긴다. 이 정도면 충분하고,
  //   깊은 병합기를 들이면 그 자체가 유지보수 대상이 된다(KISS).
  function merge(base, extra) {
    var out = {}, k;
    for (k in base) { if (Object.prototype.hasOwnProperty.call(base, k)) { out[k] = base[k]; } }
    for (k in extra) {
      if (!Object.prototype.hasOwnProperty.call(extra, k)) { continue; }
      var a = out[k], b = extra[k];
      if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(b)) {
        out[k] = merge(a, b);
      } else {
        out[k] = b;
      }
    }
    return out;
  }

  function draw(canvas) {
    var raw = canvas.getAttribute('data-vg-chart');
    if (!raw) { return; }
    var spec;
    try { spec = JSON.parse(raw); } catch (e) { return; }
    if (!spec || !spec.type || !window.Chart) { return; }
    paint(spec);
    var chart = new window.Chart(canvas, {
      type: spec.type,
      data: spec.data || {},
      options: merge(surfaceOptions(spec.type), spec.options || {})
    });
    charts.push({ chart: chart, spec: spec });
  }

  function repaintAll() {
    charts.forEach(function (entry) {
      paint(entry.spec);
      entry.chart.data = entry.spec.data;
      entry.chart.options = merge(surfaceOptions(entry.spec.type), entry.spec.options || {});
      entry.chart.update('none');
    });
  }

  function init() {
    document.querySelectorAll('[data-vg-chart]').forEach(draw);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // 테마 전환은 <html data-theme> 속성 변경으로 온다(app.js 의 테마 토글).
  //   색만 다시 읽어 칠한다 — 차트를 새로 만들면 스크롤 위치·툴팁 상태가 튄다.
  new MutationObserver(function (records) {
    for (var i = 0; i < records.length; i++) {
      if (records[i].attributeName === 'data-theme') { repaintAll(); return; }
    }
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
})();
