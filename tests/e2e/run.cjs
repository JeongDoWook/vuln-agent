/* =============================================================================
 * run.cjs — 브라우저 E2E 시나리오. tests/e2e.sh 가 전용 컨테이너에서 실행한다.
 * =============================================================================
 *  덮는 것은 **클라이언트 JS 동작뿐**이다(server/public/assets/app.js).
 *  "화면이 뜨는지"는 tests/smoke.sh 가 이미 curl 로 본다 — 여기서 다시 보지 않는다.
 *  curl 은 HTML 만 받으므로 이 JS 가 통째로 깨져도 smoke 는 전부 통과한다.
 *
 *  ⚠ 반드시 CommonJS(.cjs + require) 로 쓴다. playwright 는 이미지에 **전역 설치**돼
 *    있고 NODE_PATH 로 찾는데, NODE_PATH 는 CJS 전용 해석 경로다. ESM 의
 *    import 'playwright' 는 NODE_PATH 를 무시해 MODULE_NOT_FOUND 로 죽는다.
 *
 *  결과는 `PASS|메시지` / `FAIL|메시지` 를 한 줄씩 표준출력에 낸다 — ✓/✗ 렌더와 집계는
 *  e2e.sh 가 smoke.sh 와 같은 방식으로 한 곳에서 한다(DRY).
 *
 *  단언은 **데이터가 아니라 동작만** 본다. dev DB 는 여러 워크트리가 공유해서
 *  건수·정렬 기반 단언은 flaky 하다. 색상 리터럴도 박지 않는다(app.css 를 바꾸면 깨진다)
 *  — "라이트일 때와 다른 값" 처럼 관계로만 확인한다.
 *
 *  비밀값: 비밀번호는 VG_E2E_PASSWORD 로만 받고 어떤 출력에도 싣지 않는다(예외 메시지 포함).
 * ========================================================================== */
'use strict';

const { chromium } = require('playwright');

const BASE = (process.env.VG_E2E_BASE || '').replace(/\/+$/, '');
const USER = process.env.VG_E2E_USER || 'admin';
const PASS = process.env.VG_E2E_PASSWORD || '';

let failed = 0;
function pass(msg) { console.log('PASS|' + msg); }
function fail(msg, detail) { console.log('FAIL|' + msg + (detail ? '  (' + detail + ')' : '')); failed += 1; }
function check(cond, msg, detail) { cond ? pass(msg) : fail(msg, detail); }

/** 비밀번호가 예외 메시지 등을 타고 출력에 새지 않게 한다. */
function safe(text) {
  const s = String(text);
  return PASS ? s.split(PASS).join('***') : s;
}

/**
 * 한 번에 읽는 화면 상태. 테마·밀도가 같은 방식(문서 속성 + localStorage + 실제 CSS)으로
 * 검증되므로 스냅샷 하나로 묶는다.
 */
function snapshot(page) {
  return page.evaluate(() => {
    const on = document.querySelector('[data-theme-set].on');
    return {
      theme: document.documentElement.getAttribute('data-theme'),
      themeSaved: localStorage.getItem('vg-theme'),
      themeOn: on ? on.getAttribute('data-theme-set') : null,
      bg: getComputedStyle(document.body).backgroundColor,
      density: document.documentElement.getAttribute('data-density'),
      densitySaved: localStorage.getItem('vg-density'),
    };
  });
}

const navOpen = (page) => page.evaluate(() => document.body.classList.contains('nav-open'));

/**
 * 페이지 이동. waitUntil:'load' 는 defer 된 app.js 실행과 DOMContentLoaded 핸들러가
 * 모두 끝난 뒤에 온다 — 테마·밀도 복원은 그 핸들러가 하므로 이 시점이면 이미 반영돼 있다.
 */
const go = (page, path) => page.goto(BASE + path, { waitUntil: 'load' });

async function main() {
  if (!BASE) { fail('VG_E2E_BASE 가 비어 있다'); return; }

  const browser = await chromium.launch();
  // colorScheme 을 고정한다 — layout.php 의 테마 부트 스크립트는 저장값이 없으면
  // prefers-color-scheme 를 따르므로, 고정하지 않으면 초기 테마가 환경에 따라 달라진다.
  const ctx = await browser.newContext({ colorScheme: 'light' });
  const page = await ctx.newPage();

  try {
    // --- 1) 로그인 → 대시보드 ------------------------------------------------
    await go(page, '/login.php');
    await page.fill('input[name=username]', USER);
    await page.fill('input[name=password]', PASS);
    await page.click('button[type=submit]');
    await page.waitForURL((u) => new URL(String(u)).pathname === '/', { timeout: 20000 });
    check(new URL(page.url()).pathname === '/', '로그인 성공 → 대시보드(/)로 이동');
    const title = await page.title();
    check(title.indexOf('대시보드') >= 0, '대시보드 document.title', 'title=' + title);

    // --- 2) 테마 토글 지속성 -------------------------------------------------
    // 클릭 → 속성 적용 → 저장 → 다른 화면에서 복원 → 실제 CSS 변화까지 한 줄로 이어진다.
    let s = await snapshot(page);
    check(s.theme === 'light' && s.themeOn === 'light', '초기 테마는 라이트(.on 이 Light)',
      'theme=' + s.theme + ' on=' + s.themeOn);
    const lightBg = s.bg;

    await page.click('[data-theme-set="dark"]');
    s = await snapshot(page);
    check(s.themeOn === 'dark', 'Dark 클릭 → .on 이 Dark 로 이동', 'on=' + s.themeOn);
    check(s.theme === 'dark', "Dark 클릭 → documentElement data-theme='dark'", 'theme=' + s.theme);
    check(s.themeSaved === 'dark', "localStorage['vg-theme']='dark' 저장", 'saved=' + s.themeSaved);
    check(s.bg !== lightBg, '배경색이 실제로 바뀜(라이트와 다른 값)', 'light=' + lightBg + ' dark=' + s.bg);
    const darkBg = s.bg;

    await go(page, '/findings.php');
    s = await snapshot(page);
    check(s.theme === 'dark' && s.themeOn === 'dark', '다른 화면으로 이동해도 다크 복원',
      'theme=' + s.theme + ' on=' + s.themeOn);
    check(s.bg === darkBg && s.bg !== lightBg, '복원된 화면의 배경색도 다크(라이트와 다름)',
      'bg=' + s.bg + ' light=' + lightBg);

    // --- 3) 밀도 토글 --------------------------------------------------------
    await go(page, '/');
    s = await snapshot(page);
    check(s.density === 'comfortable', '초기 밀도는 comfortable', 'density=' + s.density);

    await page.click('[data-density-toggle]');
    s = await snapshot(page);
    check(s.density === 'compact', "밀도 클릭 → data-density='compact'", 'density=' + s.density);
    check(s.densitySaved === 'compact', "localStorage['vg-density']='compact' 저장", 'saved=' + s.densitySaved);
    const pressed = await page.getAttribute('[data-density-toggle]', 'aria-pressed');
    const label = (await page.textContent('.density-toggle__label') || '').trim();
    check(pressed === 'true', '밀도 버튼 aria-pressed=true', 'aria-pressed=' + pressed);
    check(label === '촘촘하게', '밀도 버튼 라벨이 촘촘하게로 바뀜', 'label=' + label);

    await go(page, '/findings.php');
    s = await snapshot(page);
    check(s.density === 'compact', '다른 화면으로 이동해도 촘촘한 밀도 복원', 'density=' + s.density);

    // --- 4) 모바일 사이드바 --------------------------------------------------
    await page.setViewportSize({ width: 375, height: 812 });
    await go(page, '/findings.php');
    const toggle = page.locator('.nav-toggle');
    check(await toggle.isVisible(), '모바일 폭(375)에서 햄버거 버튼 노출');

    await toggle.click();
    check(await navOpen(page), '햄버거 클릭 → 사이드바 열림(body.nav-open)');
    check(await page.locator('.nav-backdrop').isVisible(), '열리면 백드롭이 보인다');
    check(await toggle.getAttribute('aria-expanded') === 'true', '햄버거 aria-expanded=true');

    // 백드롭은 화면 전체를 덮지만 사이드바(폭 300px, z-index 60)가 그 위에 있다 —
    // 가운데를 누르면 사이드바가 클릭을 가로채므로 사이드바 바깥(오른쪽)을 누른다.
    await page.locator('.nav-backdrop').click({ position: { x: 340, y: 400 } });
    check(!(await navOpen(page)), '백드롭 클릭 → 사이드바 닫힘');

    await toggle.click();
    await page.keyboard.press('Escape');
    check(!(await navOpen(page)), 'Escape → 사이드바 닫힘');

    // 같은 폭에서 검색·필터 토글은 보여야 한다(데스크톱 폭에선 display:none 이 정상이다 —
    // 모르고 데스크톱에서 클릭하면 30초 타임아웃으로 실패한다).
    check(await page.locator('.toolbar__toggle').first().isVisible(),
      '모바일 폭에서 "검색 및 필터" 토글 노출');
  } catch (err) {
    fail('시나리오 실행 중 예외', safe(err && err.message ? err.message : err));
  } finally {
    await ctx.close();
    await browser.close();
  }
}

main().then(() => {
  process.exit(failed ? 1 : 0);
}).catch((err) => {
  fail('E2E 실행 실패', safe(err && err.message ? err.message : err));
  process.exit(1);
});
