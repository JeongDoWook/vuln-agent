<?php
declare(strict_types=1);

/**
 * view.php — 공통 레이아웃(헤더/네비/푸터) + 다크 테마 CSS.
 *   vg_h() 이스케이프, vg_header($title,$active) 로 시작, vg_footer() 로 끝.
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

// 심각도 색상 (findings 공용)
function vg_sev_color(string $sev): string {
    $m = ['CRITICAL' => '#da3633', 'HIGH' => '#db6d28', 'MEDIUM' => '#9e6a03', 'LOW' => '#6e7681'];
    return $m[$sev] ?? '#6e7681';
}

function vg_header(string $title, string $active = ''): void {
    $user = function_exists('vg_current_user') ? vg_current_user() : null;
    ?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= vg_h($title) ?> · vuln-agent</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: system-ui,-apple-system,"Segoe UI",sans-serif; margin:0; background:#0f1115; color:#e6e6e6; }
  a { color:#58a6ff; text-decoration:none; } a:hover { text-decoration:underline; }
  nav { display:flex; align-items:center; gap:1.1rem; padding:.8rem 1.5rem; background:#171a21; border-bottom:1px solid #262b36; position:sticky; top:0; z-index:10; }
  nav .brand { font-weight:700; font-size:1rem; margin-right:.5rem; }
  nav a.link { color:#adbac7; font-size:.9rem; padding:.2rem 0; }
  nav a.link.active { color:#fff; border-bottom:2px solid #1f6feb; }
  nav .spacer { flex:1; }
  nav .who { color:#8b93a1; font-size:.82rem; }
  main { padding:1.8rem 1.5rem; max-width:1150px; margin:0 auto; }
  h1 { font-size:1.3rem; margin:0 0 .3rem; }
  .sub { color:#8b93a1; font-size:.85rem; margin-bottom:1.3rem; }
  .cards { display:flex; gap:.7rem; margin-bottom:1.3rem; flex-wrap:wrap; }
  .kpi { border-radius:10px; padding:.6rem 1rem; min-width:92px; }
  .kpi.big { background:#171a21; border:1px solid #262b36; }
  .kpi b { font-size:1.5rem; display:block; line-height:1.2; }
  .kpi span { font-size:.74rem; opacity:.85; }
  .card { background:#171a21; border:1px solid #262b36; border-radius:12px; padding:1rem 1.25rem; overflow-x:auto; margin-bottom:1.2rem; }
  table { width:100%; border-collapse:collapse; font-size:.87rem; }
  th,td { text-align:left; padding:.55rem .6rem; border-bottom:1px solid #262b36; vertical-align:top; }
  th { color:#8b93a1; font-weight:600; font-size:.74rem; text-transform:uppercase; letter-spacing:.04em; }
  tr:last-child td { border-bottom:none; }
  .badge { display:inline-block; padding:.12rem .55rem; border-radius:999px; font-size:.72rem; font-weight:700; color:#fff; }
  .pill { display:inline-block; padding:.1rem .5rem; border-radius:999px; background:#1f6feb22; color:#58a6ff; font-size:.76rem; }
  .why { color:#adbac7; font-size:.82rem; }
  .empty { color:#8b93a1; padding:2rem 0; text-align:center; }
  .err { background:#3b1418; border:1px solid #6e2830; color:#ffb3ba; padding:.8rem 1rem; border-radius:10px; margin-bottom:1rem; }
  code { background:#262b36; padding:.1rem .4rem; border-radius:6px; font-size:.85em; }
  form.card { max-width:360px; margin:3rem auto; }
  label { display:block; font-size:.82rem; color:#adbac7; margin:.8rem 0 .3rem; }
  input[type=text],input[type=password] { width:100%; padding:.55rem .65rem; background:#0f1115; border:1px solid #30363d; border-radius:8px; color:#e6e6e6; font-size:.95rem; }
  button { margin-top:1.1rem; width:100%; padding:.6rem; background:#238636; color:#fff; border:none; border-radius:8px; font-size:.95rem; font-weight:600; cursor:pointer; }
  button:hover { background:#2ea043; }
  .btn-sm { width:auto; margin:0; padding:.35rem .8rem; font-size:.82rem; }
</style>
</head>
<body>
<?php if ($user !== null): ?>
  <nav>
    <span class="brand">🛡️ vuln-agent</span>
    <a class="link <?= $active==='dashboard'?'active':'' ?>" href="/">대시보드</a>
    <a class="link <?= $active==='findings'?'active':'' ?>" href="/findings.php">취약점</a>
    <?php if (($user['role'] ?? '') === 'admin'): ?>
      <a class="link <?= $active==='users'?'active':'' ?>" href="/users.php">사용자</a>
    <?php endif; ?>
    <span class="spacer"></span>
    <span class="who"><?= vg_h($user['username']) ?> (<?= vg_h($user['role']) ?>)</span>
    <a class="link" href="/logout.php">로그아웃</a>
  </nav>
<?php endif; ?>
<main>
<?php
}

function vg_footer(): void {
    ?>
</main>
</body>
</html>
<?php
}
