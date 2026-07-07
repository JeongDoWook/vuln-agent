<?php
declare(strict_types=1);

/**
 * findings.php — 매처 판정 결과(우선순위 취약점) 뷰.
 *   ?scan_id=N 지정, 없으면 최신 스캔. 등급순 정렬 + 노출 근거(rationale) 표시.
 *   (로그인/대시보드 통합은 3단계)
 */

require __DIR__ . '/../src/db.php';

function h(?string $s): string { return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8'); }

$err = null; $scan = null; $rows = [];
try {
    $pdo = vg_pdo();
    if (isset($_GET['scan_id'])) {
        $scanId = (int) $_GET['scan_id'];
    } else {
        $scanId = (int) ($pdo->query('SELECT id FROM scans ORDER BY received_at DESC LIMIT 1')->fetchColumn() ?: 0);
    }
    if ($scanId > 0) {
        $st = $pdo->prepare('SELECT s.*, h.fqdn FROM scans s JOIN hosts h ON h.id=s.host_id WHERE s.id=?');
        $st->execute([$scanId]);
        $scan = $st->fetch() ?: null;

        // 등급 정렬: CRITICAL>HIGH>MEDIUM>LOW, 그다음 CVSS
        $st = $pdo->prepare(
            "SELECT f.*, c.summary
             FROM findings f LEFT JOIN cves c ON c.cve_id=f.cve_id
             WHERE f.scan_id=?
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), f.cvss DESC"
        );
        $st->execute([$scanId]);
        $rows = $st->fetchAll();
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

$sevColor = ['CRITICAL'=>'#da3633','HIGH'=>'#db6d28','MEDIUM'=>'#9e6a03','LOW'=>'#6e7681'];
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
foreach ($rows as $r) { $counts[$r['severity']] = ($counts[$r['severity']] ?? 0) + 1; }
?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vuln-agent · 취약점 우선순위</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui,-apple-system,"Segoe UI",sans-serif; margin:0; padding:2rem; background:#0f1115; color:#e6e6e6; }
  a { color:#58a6ff; text-decoration:none; }
  h1 { font-size:1.3rem; margin:0 0 .3rem; }
  .sub { color:#8b93a1; font-size:.85rem; margin-bottom:1.2rem; }
  .cards { display:flex; gap:.6rem; margin-bottom:1.2rem; flex-wrap:wrap; }
  .kpi { border-radius:10px; padding:.5rem .9rem; min-width:78px; color:#fff; }
  .kpi b { font-size:1.4rem; display:block; }
  .kpi span { font-size:.72rem; opacity:.9; }
  .card { background:#171a21; border:1px solid #262b36; border-radius:12px; padding:1rem 1.25rem; max-width:1100px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:.86rem; }
  th,td { text-align:left; padding:.55rem .6rem; border-bottom:1px solid #262b36; vertical-align:top; }
  th { color:#8b93a1; font-weight:600; font-size:.74rem; text-transform:uppercase; letter-spacing:.04em; }
  tr:last-child td { border-bottom:none; }
  .badge { display:inline-block; padding:.12rem .55rem; border-radius:999px; font-size:.72rem; font-weight:700; color:#fff; }
  .why { color:#adbac7; font-size:.82rem; }
  .empty { color:#8b93a1; padding:2rem 0; text-align:center; }
  .err { background:#3b1418; border:1px solid #6e2830; color:#ffb3ba; padding:1rem; border-radius:10px; max-width:1100px; }
  code { background:#262b36; padding:.1rem .4rem; border-radius:6px; }
</style>
</head>
<body>
  <h1>🎯 취약점 우선순위 <span style="font-size:.8rem;color:#8b93a1;">(매처 결과)</span></h1>
  <div class="sub">
    <a href="/">← 수집 현황</a> ·
    <?php if ($scan): ?>
      호스트 <strong><?= h($scan['fqdn']) ?></strong> · scan #<?= (int)$scan['id'] ?> · <?= h($scan['collected_at']) ?>
    <?php else: ?> 스캔 없음 <?php endif; ?>
  </div>

<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong><br><?= h($err) ?></div>
<?php elseif (!$rows): ?>
  <div class="card"><div class="empty">이 스캔에 대한 판정 결과가 없습니다.<br>에이전트로 수집하면 자동 매칭되거나, <code>/rematch.php</code> 로 재계산할 수 있어요.</div></div>
<?php else: ?>
  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi" style="background:<?= $sevColor[$s] ?>"><b><?= (int)$counts[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
  </div>
  <div class="card">
    <table>
      <thead><tr>
        <th>등급</th><th>CVE</th><th>패키지</th><th>버전</th><th>CVSS</th><th>KEV</th><th>근거 (왜 위험한가)</th>
      </tr></thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><span class="badge" style="background:<?= $sevColor[$r['severity']] ?? '#6e7681' ?>"><?= h($r['severity']) ?></span></td>
          <td><strong><?= h($r['cve_id']) ?></strong><?php if ($r['summary']): ?><div class="why"><?= h(mb_strimwidth((string)$r['summary'],0,70,'…')) ?></div><?php endif; ?></td>
          <td><?= h($r['package_name']) ?></td>
          <td><code><?= h($r['installed_version']) ?></code></td>
          <td><?= $r['cvss'] !== null ? h((string)$r['cvss']) : '-' ?></td>
          <td><?= $r['in_kev'] ? '✔' : '' ?></td>
          <td class="why"><?= h($r['rationale']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
<?php endif; ?>
</body>
</html>
