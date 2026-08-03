<?php
declare(strict_types=1);

/**
 * layout.php — 페이지 골격(head/body/사이드바 뼈대). vg_header() 로 시작해 vg_footer() 로 끝낸다.
 *   정적 자산 URL(vg_asset)도 골격의 일부라 여기 둔다.
 */

require_once __DIR__ . '/../format.php';
require_once __DIR__ . '/../audit.php';
require_once __DIR__ . '/nav.php';
require_once __DIR__ . '/components.php';

/** 정적 파일 URL + 캐시버스팅(mtime). 파일이 없으면 경로만 돌려준다. */
function vg_asset(string $path): string {
    $file = __DIR__ . '/../../public' . $path;
    $v = is_file($file) ? (string) filemtime($file) : '';
    return vg_h($path . ($v !== '' ? '?v=' . $v : ''));
}

function vg_header(string $title, string $active = ''): void {
    $user = function_exists('vg_current_user') ? vg_current_user() : null;
    if ($user !== null) {
        vg_log_page_view(vg_pdo(), (string) ($_SERVER['SCRIPT_NAME'] ?? ''), $title, $active);
    }
    ?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= vg_h($title) ?> · vuln-agent</title>
<?php // 테마 초기화 — 저장된 선택(없으면 OS 설정)을 첫 페인트 전에 적용해 깜빡임을 막는다.
      //   defer 되는 app.js 로는 늦다(스타일이 먼저 그려진다). 그래서 인라인·즉시 실행. ?>
<script>(function(){try{var t=localStorage.getItem('vg-theme');if(t!=='dark'&&t!=='light'){t=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}document.documentElement.setAttribute('data-theme',t);}catch(e){}})();</script>
<link rel="stylesheet" href="<?= vg_asset('/assets/app.css') ?>">
<script src="<?= vg_asset('/assets/app.js') ?>" defer></script>
<?php
// 페이지 전용 JS: 공용 app.js 뒤에, 이 페이지와 같은 이름의 assets/js/<페이지>.js 가 있으면
//   자동으로 붙는다(예: connectors.php → assets/js/connectors.js). 없으면 아무것도 안 붙는다.
//   공용 동작은 app.js 가, 한 화면에서만 쓰는 동작은 동일명 파일이 갖는다.
$pageJs = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''), '.php');
if ($pageJs !== '' && is_file(__DIR__ . "/../../public/assets/js/{$pageJs}.js")): ?>
<script src="<?= vg_asset("/assets/js/{$pageJs}.js") ?>" defer></script>
<?php endif; ?>
</head>
<body class="page page--<?= vg_h($pageJs !== '' ? $pageJs : 'default') ?><?= $user !== null ? ' is-authenticated' : ' is-guest' ?>">
<?php if ($user !== null): ?>
  <aside class="side">
    <?php if (vg_can('dashboard')): ?>
      <a class="brand" href="/" title="대시보드로 이동"><span class="brand__mark" aria-hidden="true">V</span><span>vuln-agent</span></a>
    <?php else: ?>
      <span class="brand"><span class="brand__mark" aria-hidden="true">V</span><span>vuln-agent</span></span>
    <?php endif; ?>
    <nav class="menu"><?php vg_nav($active); ?></nav>
    <?php // 사이드바 마크업 직후 동기 실행 — 저장된 접힘 상태를 첫 페인트 전에 반영(FOUC 방지). ?>
    <?php vg_nav_boot(); ?>
    <div class="foot">
      <span class="who"><?= vg_h($user['username']) ?> (<?= vg_h(vg_role_label(vg_role())) ?>)</span>
      <a href="/profile.php"<?= $active === 'profile' ? ' class="active"' : '' ?>>내 프로필</a>
      <a href="/logout.php">로그아웃</a>
    </div>
  </aside>
<?php endif; ?>
<div class="app">
<?php if ($user !== null): ?>
  <header class="topbar">
    <button type="button" class="nav-toggle" data-nav-toggle aria-label="메뉴 열기" aria-expanded="false">
      <span></span><span></span><span></span>
    </button>
    <?php vg_breadcrumb($active, $title); ?>
    <div class="topbar__right">
      <?php if (vg_can('assets')): ?>
        <button type="button" class="collection-status-btn" data-modal="collectionStatus" data-collection-status-open>
          <span class="collection-status-btn__dot" aria-hidden="true"></span>
          <span>수집 현황</span>
          <b data-collection-status-count hidden>0</b>
        </button>
      <?php endif; ?>
      <div class="seg" role="group" aria-label="테마 전환">
        <button type="button" class="seg__btn" data-theme-set="light" aria-label="밝은 테마">☀ Light</button>
        <button type="button" class="seg__btn" data-theme-set="dark" aria-label="어두운 테마">☾ Dark</button>
      </div>
      <?php // 사용자 칩 — 아바타(아이디 첫 글자) + 이름·역할. 누르면 내 프로필로. ?>
      <a class="topbar__user" href="/profile.php" title="내 프로필">
        <span class="avatar"><?= vg_h(mb_strtoupper(mb_substr($user['username'], 0, 1))) ?></span>
        <span class="topbar__who"><?= vg_h($user['username']) ?><i><?= vg_h(vg_role_label(vg_role())) ?></i></span>
      </a>
    </div>
  </header>
  <?php if (vg_can('assets')): ?>
    <?php vg_modal_open('collectionStatus', '전체 자산 수집 현황', 'modal--wide collection-status-modal'); ?>
      <div class="collection-overview" data-collection-overview>
        <div class="collection-overview__summary">
          <div><span>활성 작업</span><strong data-overview-active>확인 중</strong></div>
          <div><span>실행 중</span><strong data-overview-running>–</strong></div>
          <div><span>대기 중</span><strong data-overview-pending>–</strong></div>
          <div><span>전체 진행률</span><strong data-overview-progress>–</strong></div>
        </div>
        <p class="collection-overview__hint">실행·대기 작업을 우선해 최근 현황을 최대 10건 표시합니다. 3초마다 자동 갱신됩니다.</p>
        <div class="collection-overview__list" data-overview-list aria-live="polite">
          <div class="collection-overview__empty">수집 현황을 불러오는 중입니다.</div>
        </div>
      </div>
      <?php vg_modal_foot(null); ?>
    <?php vg_modal_close(); ?>
  <?php endif; ?>
  <button type="button" class="nav-backdrop" data-nav-close aria-label="메뉴 닫기"></button>
<?php endif; ?>
<main class="page__main">
<?php
}

function vg_footer(): void {
    ?>
</main>
</div>
</body>
</html>
<?php
}
