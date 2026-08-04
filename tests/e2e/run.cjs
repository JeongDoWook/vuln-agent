/* =============================================================================
 * run.cjs — 브라우저 E2E 시나리오. tests/e2e.sh 가 전용 컨테이너에서 실행한다.
 * =============================================================================
 *  덮는 것은 **클라이언트 JS 동작뿐**이다(server/public/assets/app.js 와 화면 전용 JS).
 *  "화면이 뜨는지"는 tests/smoke.sh 가 이미 curl 로 본다 — 여기서 다시 보지 않는다.
 *  curl 은 HTML 만 받으므로 이 JS 가 통째로 깨져도 smoke 는 전부 통과한다.
 *
 *  ⚠ 부작용 금지: 외부 소스를 치거나 DB 를 바꾸는 버튼(커넥터 미리보기·지금 실행·저장·
 *    활성토글·삭제)은 **누르지 않는다.** 폼은 채우기만 하고 제출하지 않는다 — dev DB 는
 *    워크트리 공용이고, 수집 실행은 세션 락을 오래 쥔다.
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
 * 커넥터 폼의 타입을 고르고 화면 상태를 한 번에 읽는다(connectors.js 의 toggle()).
 * 값 비교는 PHP 카탈로그(#connForm data-type-meta)와 하고 여기 문자열을 박지 않는다 —
 * 그래야 카탈로그가 늘어도 안 깨지고, 오히려 "PHP 와 화면이 일치하는가" 를 검사하게 된다.
 */
async function selectConnType(page, type) {
  await page.selectOption('#connType', type);
  return page.evaluate(() => {
    const badge = document.querySelector('#connTransport .badge');
    const desc = document.getElementById('connTransportDesc');
    const urlLabel = document.getElementById('urlLabel');
    const fields = {};
    document.querySelectorAll('#stdFields [data-field]').forEach((box) => {
      fields[box.dataset.field] = !box.hidden;
    });
    return {
      badge: badge ? badge.textContent.trim() : null,
      badgeClass: badge ? badge.className : '',
      desc: desc ? desc.textContent.trim() : null,
      urlLabel: urlLabel ? urlLabel.textContent.trim() : null,
      fields,
      stdHidden: document.getElementById('stdFields').hidden,
      genericHidden: document.getElementById('genericFields').hidden,
    };
  });
}

/** 위에서 읽은 화면 상태가 카탈로그 한 줄(want)과 어긋나지 않는지. */
function checkTypeMatchesCatalog(type, got, want) {
  check(got.badge === want.transport, type + ': 수집 방식 뱃지가 카탈로그와 일치',
    'badge=' + got.badge + ' meta=' + want.transport);
  check(got.badgeClass.indexOf('tone-' + want.tone) >= 0, type + ': 뱃지 톤이 카탈로그와 일치',
    'class=' + got.badgeClass + ' meta=' + want.tone);
  check(got.desc === want.desc, type + ': 수집 방식 설명이 카탈로그와 일치');
  // url_label 이 빈 타입(설정할 값이 없는 커넥터)은 JS 가 라벨을 손대지 않는다 — 비교 대상이 아니다.
  if (want.urlLabel) {
    check(got.urlLabel === want.urlLabel, type + ': URL 라벨이 카탈로그와 일치',
      'label=' + got.urlLabel + ' meta=' + want.urlLabel);
  }
  const shown = Object.keys(got.fields).filter((k) => got.fields[k]).sort().join(',');
  const wanted = want.fields.slice().sort().join(',');
  check(shown === wanted, type + ': 카탈로그가 정한 필드만 노출', 'shown=[' + shown + '] meta=[' + wanted + ']');
}

/** 범용 API 커넥터의 역할 매핑 영역(vgRenderFieldMap 이 다시 그린 결과). */
const roleState = (page) => page.evaluate(() => ({
  role: document.getElementById('gFieldMap').dataset.role,
  keys: Array.from(document.querySelectorAll('#gFieldMap .g-fm-val')).map((i) => i.dataset.fmKey),
  label: (document.getElementById('gRoleLabel').textContent || '').trim(),
  notice: !document.getElementById('gRoleNotice').hidden,
}));

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
    const rootNav = (await page.locator('.side a.link--root span').allTextContents()).map((v) => v.trim());
    const navGroups = (await page.locator('.side summary.grp').allTextContents()).map((v) => v.trim());
    check(JSON.stringify(rootNav) === JSON.stringify(['대시보드', '자산', '데이터 수집']),
      '자주 쓰는 메뉴 3개는 접지 않고 바로 노출', 'links=' + rootNav.join(','));
    check(JSON.stringify(navGroups) === JSON.stringify(['취약점', '관리']),
      '사이드바 접이식 그룹은 취약점·관리만 유지', 'groups=' + navGroups.join(','));

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

    // --- 3) 모바일 사이드바 --------------------------------------------------
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

    // --- 4) 자산 취약점 행 상세 모달 -----------------------------------------
    await page.setViewportSize({ width: 1280, height: 900 });
    await go(page, '/assets.php');

    // 네이티브 title은 브라우저마다 오래 기다려야 하므로 app.js가 즉시 공통 tooltip로 바꾼다.
    const assetHelp = page.locator('.page-title .help').first();
    check(await assetHelp.count() === 1, '자산 상태 도움말 아이콘 제공');
    if (await assetHelp.count()) {
      await assetHelp.hover();
      const tip = page.locator('#vg-info-tooltip');
      check(await tip.isVisible(), '도움말 hover 즉시 공통 툴팁 표시');
      check((await tip.textContent() || '').includes('10초 poll 통신 기준'),
        '자산 상태 툴팁이 수집 주기와 poll 연결 상태를 구분');
      check(Boolean(await assetHelp.getAttribute('aria-describedby')),
        'hover 툴팁을 aria-describedby로 연결');
      await page.mouse.move(1100, 850);
      await assetHelp.focus();
      check(await tip.isVisible(), '키보드 focus로도 도움말 툴팁 표시');
    }

    await page.click('[data-modal="agentInstall"]');
    const installModal = page.locator('#agentInstall');
    check(await installModal.isVisible(), '에이전트 설치 안내 버튼 → 설치 모달 열림');
    const installText = (await installModal.textContent() || '').replace(/\s+/g, ' ');
    check(installText.includes('curl 또는 wget') && installText.includes('jq는 선택 사항'),
      '설치 모달이 실제 필수·선택 명령을 구분');
    check(installText.includes('10초마다 명령을 확인') && installText.includes('cron 정기수집만 지원'),
      '설치 모달이 systemd 기능과 cron 폴백 제약을 구분');
    await installModal.locator('[data-modal-close]').last().click();

    const hostHref = await page.locator('a[href^="/host.php?id="]').first().getAttribute('href');
    check(Boolean(hostHref), '자산 목록에서 상세 화면 링크 확인');
    if (hostHref) {
      await go(page, hostHref);
      const findingRow = page.locator('tr[data-finding-detail]').first();
      check(await findingRow.count() === 1, '취약점 행이 클릭 가능한 상세 데이터 제공');
      if (await findingRow.count()) {
        await findingRow.click({ position: { x: 5, y: 5 } });
        const findingModal = page.locator('#findingDetailModal');
        check(await findingModal.isVisible(), '취약점 행 클릭 → 상세 모달 열림');
        check((await findingModal.locator('[data-finding-rationale]').textContent() || '').trim().length > 0,
          '상세 모달에 전체 판정 근거 표시');
        await findingModal.locator('.modal__foot [data-modal-close]').click();
      }
    }

    // --- 5) 커넥터 화면 JS(connectors.js) + 모달 -----------------------------
    // ⚠ 이 화면엔 누르면 **외부 소스를 실제로 치거나 공용 dev DB 를 바꾸는** 버튼이 섞여 있다
    //   (미리보기·지금 실행·저장·활성토글·삭제). 여기서는 그중 무엇도 누르지 않고 **폼을 채우기만
    //   하고 절대 제출하지 않는다** — connectors.js 의 검증 가치는 네트워크 없는 DOM 조작에 있다.
    await page.setViewportSize({ width: 1280, height: 900 });   // 4)가 375 로 바꿔 놨다
    await go(page, '/connectors.php');

    const meta = await page.evaluate(() => {
      const f = document.getElementById('connForm');
      if (!f) { return null; }
      return { types: JSON.parse(f.dataset.typeMeta || '{}'), roles: JSON.parse(f.dataset.roleLabels || '{}') };
    });
    check(meta !== null && Object.keys(meta.types).length > 0,
      '#connForm 이 PHP 카탈로그(data-type-meta)를 화면에 넘긴다');
    check(meta !== null && Object.keys(meta.roles).length > 0,
      '#connForm 이 역할 라벨(data-role-labels)을 화면에 넘긴다');
    check(meta !== null && !Object.prototype.hasOwnProperty.call(meta.roles, 'compliance'),
      '미지원 compliance 역할을 범용 커넥터 선택지에서 제외');

    const modal = page.locator('#connModal');
    check(!(await modal.isVisible()), '처음엔 커넥터 모달이 닫혀 있다');
    await page.click('[data-modal="connModal"]');
    check(await modal.isVisible(), '[+ 데이터 소스] 클릭 → 모달 열림');

    // kev: 파일 다운로드 방식 — API 가 아니라 파일 라벨이어야 하고, url 말고는 안 보인다.
    const kev = await selectConnType(page, 'kev');
    check(!kev.stdHidden && kev.genericHidden, 'kev: 표준 필드 보이고 범용 폼 숨김');
    checkTypeMatchesCatalog('kev', kev, meta.types.kev);

    // osv: 방식이 바뀌고, kev 에선 숨어 있던 ecosystem 이 나타난다(타입별 fields 차이).
    const osv = await selectConnType(page, 'osv');
    checkTypeMatchesCatalog('osv', osv, meta.types.osv);
    check(osv.badge !== kev.badge, '타입을 바꾸면 수집 방식 뱃지가 실제로 바뀐다',
      'kev=' + kev.badge + ' osv=' + osv.badge);
    check(osv.fields.ecosystem === true && kev.fields.ecosystem === false,
      'ecosystem 필드는 osv 에서만 보인다(kev 에선 숨김)');

    // generic_api: 표준 폼 ↔ 범용 폼 전환.
    const generic = await selectConnType(page, 'generic_api');
    check(generic.stdHidden && !generic.genericHidden, 'generic_api: 범용 폼 보이고 표준 필드 숨김');

    // 역할 변경 → 필드 매핑·라벨·안내가 다시 그려진다(vgRenderFieldMap).
    const identity = await roleState(page);
    check(identity.role === 'identity' && identity.keys.length > 0,
      '범용 폼 초기 역할은 identity 이고 필드 매핑이 그려져 있다', 'role=' + identity.role);

    await page.selectOption('#gRole', 'vendor');
    const vendor = await roleState(page);
    check(vendor.role === 'vendor', '역할을 vendor 로 바꾸면 #gFieldMap 이 다시 그려진다', 'role=' + vendor.role);
    check(vendor.keys.join(',') !== identity.keys.join(','), '역할이 다르면 매핑 입력 목록도 다르다',
      'identity=' + identity.keys.length + '개 vendor=' + vendor.keys.length + '개');
    check(vendor.label === '(' + meta.roles.vendor + ')', '#gRoleLabel 이 PHP 라벨(data-role-labels)과 일치',
      'label=' + vendor.label);
    check(!vendor.notice, 'vendor 역할에선 미지원 안내가 뜨지 않는다');

    // 인증 헤더 행 추가/삭제(vgHeaderRow). 제출하지 않으므로 서버엔 닿지 않는다.
    const headerRows = page.locator('#gHeaders .kvrow');
    const before = await headerRows.count();
    await page.click('#gHeaderAdd');
    check(await headerRows.count() === before + 1, '[+ 헤더 추가] → .kvrow 한 줄 늘어남',
      'before=' + before + ' after=' + (await headerRows.count()));
    const lastRow = headerRows.last();
    check(await lastRow.locator('.g-h-key').count() === 1 && await lastRow.locator('.g-h-val').count() === 1,
      '추가된 행에 헤더 키·값 입력이 있다');
    await lastRow.locator('button').click();
    check(await headerRows.count() === before, '행의 [삭제] → 다시 줄어듦');

    // 닫기 — Escape(브라우저 네이티브)와 닫기 버튼(app.js data-modal-close) 둘 다.
    await page.keyboard.press('Escape');
    check(!(await modal.isVisible()), 'Escape → 커넥터 모달 닫힘');

    await page.click('[data-modal="connModal"]');
    check(await modal.isVisible(), '다시 열기 → 모달 열림');
    await modal.locator('.modal__foot [data-modal-close]').click();
    check(!(await modal.isVisible()), '[닫기] 버튼 → 커넥터 모달 닫힘');
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
