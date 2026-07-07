<?php
declare(strict_types=1);

/**
 * index.php — 최소 상태 페이지 (1단계 검증용)
 *   "에이전트 돌리면 중앙 DB에 쌓인다" 를 눈으로 확인하기 위한 읽기 전용 화면.
 *   본격 대시보드(우선순위·노출 근거)는 3단계에서.
 */

require __DIR__ . '/../src/db.php';

$rows = [];
$err  = null;
try {
    $rows = vg_pdo()->query(
        'SELECT h.fqdn, h.os_id, h.os_version,
                s.id AS scan_id, s.collected_at, s.agent_version,
                s.package_count, s.exposure_count, s.received_at
         FROM scans s
         JOIN hosts h ON h.id = s.host_id
         ORDER BY s.received_at DESC
         LIMIT 50'
    )->fetchAll();
} catch (Throwable $e) {
    $err = $e->getMessage();
}

function h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}
?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vuln-agent · 수집 현황</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
         margin: 0; padding: 2rem; background: #0f1115; color: #e6e6e6; }
  h1 { font-size: 1.3rem; margin: 0 0 .3rem; }
  .sub { color: #8b93a1; font-size: .85rem; margin-bottom: 1.5rem; }
  .card { background: #171a21; border: 1px solid #262b36; border-radius: 12px;
          padding: 1rem 1.25rem; max-width: 1000px; }
  table { width: 100%; border-collapse: collapse; font-size: .88rem; }
  th, td { text-align: left; padding: .55rem .6rem; border-bottom: 1px solid #262b36; }
  th { color: #8b93a1; font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px;
           background: #1f6feb22; color: #58a6ff; font-size: .78rem; }
  .empty { color: #8b93a1; padding: 2rem 0; text-align: center; }
  .err { background: #3b1418; border: 1px solid #6e2830; color: #ffb3ba;
         padding: 1rem; border-radius: 10px; max-width: 1000px; }
  code { background: #262b36; padding: .12rem .4rem; border-radius: 6px; font-size: .85em; }
  .foot { color: #8b93a1; font-size: .8rem; margin-top: 1.2rem; max-width: 1000px; }
</style>
</head>
<body>
  <h1>🛡️ vuln-agent · 수집 현황</h1>
  <div class="sub">런타임 노출 맥락으로 오탐을 줄이는 자율 취약점 진단 에이전트 · 1단계(수집→전송→저장)</div>

<?php if ($err !== null): ?>
  <div class="err">
    <strong>DB 연결 오류</strong><br>
    <?= h($err) ?><br><br>
    컨테이너가 아직 기동 중이거나 <code>.env</code> 값이 안 맞을 수 있어요. 잠시 후 새로고침하세요.
  </div>
<?php elseif (count($rows) === 0): ?>
  <div class="card">
    <div class="empty">
      아직 수집된 스캔이 없습니다.<br>
      에이전트를 <code>--send</code> 옵션으로 실행하면 여기에 나타납니다.
    </div>
  </div>
<?php else: ?>
  <div class="card">
    <table>
      <thead>
        <tr>
          <th>호스트</th><th>OS</th><th>에이전트</th>
          <th>패키지</th><th>노출</th><th>수집시각</th><th>수신시각</th>
        </tr>
      </thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><strong><?= h($r['fqdn']) ?></strong></td>
          <td><?= h($r['os_id']) ?> <?= h($r['os_version']) ?></td>
          <td><span class="badge">v<?= h($r['agent_version']) ?></span></td>
          <td><?= (int) $r['package_count'] ?></td>
          <td><?= (int) $r['exposure_count'] ?></td>
          <td><?= h($r['collected_at']) ?></td>
          <td><?= h($r['received_at']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
<?php endif; ?>

  <div class="foot">
    수신 API: <code>POST /ingest.php</code> (헤더 <code>X-Agent-Token</code> 인증) ·
    최근 50건 표시.
  </div>
</body>
</html>
