<?php
declare(strict_types=1);

// PHP 한도는 **반드시 이 프로세스가 도는 컨테이너의 mem_limit 보다 낮아야** 한다 — 높으면
//   PHP 가 자기 한도에 닿기 전에 cgroup 이 SIGKILL 해서 잡히는 오류 없이 즉사하고,
//   run 이 'running' 으로 굳어 다음 집행이 그 행을 영영 못 집는다(sync.php 와 같은 이유).
//   discover.php 는 web/scheduler 컨테이너에서 돈다(mem_limit 768m) → 512M 로 맞춘다.
//   스캔 자체는 메모리를 거의 안 쓰지만(/22 × 100포트여도 결과가 수만 행), 한도는 같은 기준으로 둔다.
ini_set('memory_limit', '512M');

/**
 * discover.php — 자산 탐색 스캔 집행(CLI 전용).
 *
 *   php bin/discover.php <discovery_target_id>   대역 1건을 즉시 스캔(run 을 만들고 바로 집행)
 *   php bin/discover.php --pending               status='pending' 인 run 을 전부 집행
 *
 *   웹 요청에서 스캔을 직접 돌리지 않는다 — 수백 소켓을 수십 초 드는 작업이라 요청이 묶인다.
 *   화면은 pending run 만 만들고, 집행은 이 CLI(수동 또는 스케줄러)가 한다.
 *
 *   종료코드: 0 정상 · 1 내부오류 · 2 인자오류
 */

require __DIR__ . '/../src/discovery.php';

$arg = (string) ($argv[1] ?? '');
if ($arg === '') {
    fwrite(STDERR, "사용법: php discover.php <discovery_target_id> | --pending\n");
    exit(2);
}

try {
    $pdo = vg_pdo();

    if ($arg === '--pending') {
        $ids = vg_discovery_pending_run_ids($pdo);
        if ($ids === []) {
            fwrite(STDOUT, "집행할 스캔이 없습니다.\n");
            exit(0);
        }
        $fail = 0;
        foreach ($ids as $runId) {
            // 선점에 실패하면 다른 프로세스가 이미 집어간 것이다 — 조용히 건너뛰지 말고 남긴다.
            if (!vg_discovery_claim_run($pdo, $runId)) {
                fwrite(STDOUT, "run $runId — 다른 프로세스가 집행 중, 건너뜀\n");
                continue;
            }
            $r = vg_discovery_execute_run($pdo, $runId);
            fwrite(STDOUT, vg_discover_line($r));
            if (empty($r['ok'])) { $fail++; }
        }
        exit($fail > 0 ? 1 : 0);
    }

    if (!preg_match('/^\d+$/', $arg)) {
        fwrite(STDERR, "대역 id 는 숫자여야 합니다. 사용법: php discover.php <discovery_target_id> | --pending\n");
        exit(2);
    }
    $targetId = (int) $arg;

    // 임의 CIDR 을 인자로 받지 않는다 — 스캔은 남의 네트워크에 흔적을 남기는 행위라
    //   등록·활성화된 대역(tb_discovery_target)만 대상으로 한다.
    $runId = vg_discovery_create_run($pdo, $targetId);
    if (!vg_discovery_claim_run($pdo, $runId)) {
        fwrite(STDERR, "run $runId 를 선점하지 못했습니다.\n");
        exit(1);
    }
    $r = vg_discovery_execute_run($pdo, $runId);
    fwrite(STDOUT, vg_discover_line($r));
    exit(empty($r['ok']) ? 1 : 0);
} catch (InvalidArgumentException $e) {
    // 사용자가 고칠 수 있는 입력 오류(없는 대역·비활성)는 그대로 보여준다.
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(2);
} catch (Throwable $e) {
    // 그 밖의 예외는 원문을 표준에러로 흘리지 않는다 — 상세는 서버 로그에만 남는다.
    error_log('[discover] ' . $e->getMessage());
    fwrite(STDERR, "스캔을 실행할 수 없습니다. 서버 로그를 확인하세요.\n");
    exit(1);
}

/** 한 run 의 결과를 사람이 읽는 한 줄로. 실패면 이유(일반화된 메시지)만 붙인다. */
function vg_discover_line(array $r): string {
    if (empty($r['ok'])) {
        return sprintf("run %d [%s] 실패 — %s\n", $r['run_id'], $r['cidr'], (string) ($r['error'] ?? ''));
    }
    return sprintf(
        "run %d [%s] 완료 — IP %d개 중 살아있음 %d · 시도 %d조합 · 열린포트 %d · 기존자산 매칭 %d · %.2fs\n",
        $r['run_id'], $r['cidr'], $r['ip_total'], $r['ip_alive'],
        $r['port_checked'], $r['open_total'], $r['matched'], $r['elapsed']
    );
}
