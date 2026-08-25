<?php
declare(strict_types=1);

/**
 * feeds.php — CVE 피드 커넥터 레지스트리 + 실행/스케줄/미리보기.
 *   커넥터 계약(VgFeedConnector)과 등록(vg_feed_make)만 여기 두고, 커넥터 구현과 공용
 *   헬퍼는 feeds/ 아래로 분할했다. 호출부(connectors.php·feed_preview.php·bin/*)는
 *   예전처럼 이 파일 하나만 require 하면 전체가 로드된다.
 *
 *   분할:
 *     feeds/http.php   — SSRF 가드 + curl(vg_http_*) + vg_conn_url
 *     feeds/upsert.php — tb_cve/kev/affected 공용 write + CVE-ID 형식검증 + VG_TEXT_MAX
 *     feeds/kev.php    — VgKevConnector
 *     feeds/osv.php    — VgOsvConnector + vg_osv_* + vg_osv_enrich_fixed
 *     feeds/nvd.php    — VgNvdConnector + vg_nvd_sync(백필 공용)
 *     feeds/kisa.php   — VgKisaConnector + KISA RSS/URL/HTML 파싱(공지 저장/본문 로직은 advisory.php)
 *     feeds/epss.php   — VgEpssConnector + vg_epss_fetch
 *     feeds/debtracker.php — VgDebtrackerConnector + 데비안 보안 트래커(백포트 오탐 억제 근거)
 *     feeds/kcve.php   — VgKcveConnector + 리눅스 커널 CNA(kernel.org — 커널 판정의 정본)
 *     feeds/rhoval.php — VgRhovalConnector + RHEL 계열 벤더 OVAL(Red Hat·AlmaLinux·Oracle Linux)
 *     feeds/rhunfixed.php — VgRhunfixedConnector + Red Hat 미수정 CVE(OVAL 이 못 담는 조치 불가)
 *     feeds/ssg.php    — VgSsgConnector + SCAP Security Guide 룰셋(CIS/NIST/STIG 참조 매핑)
 *     feeds/ubuntuoval.php — VgUbuntuOvalConnector + 우분투 보안 OVAL
 *     feeds/pkgregistry.php — VgPkgRegistryConnector + 패키지 레지스트리 메타데이터(Packagist/npm/PyPI/Maven)
 *     feeds/generic_api.php — VgGenericApiConnector + 화면에서 등록하는 범용 API 커넥터
 *
 *   새 피드 추가: feeds/<type>.php 에 VgFeedConnector 구현 + 여기 require 한 줄 +
 *   VG_CONNECTOR_TYPES 에 한 줄. 그 한 줄이 구현·폼 <select>·저장 검증·수집 방식 표시·
 *   노출 필드를 전부 정한다(예전엔 목록이 세 곳에 흩어져 있었다).
 *   run/preview 는 같은 클래스가 갖는다(미리보기가 실제 수집과
 *   다른 소스·기준을 보는 사고를 구조적으로 막는다 — 예전 NVD 발행일/수정일 불일치).
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/audit.php';   // vg_log_activity
require_once __DIR__ . '/distro.php';  // vg_osv_ecosystem (매처와 공유)
require_once __DIR__ . '/schedule.php'; // vg_cron_*/vg_schedule_* — 스케줄 계산(순수 함수)

// 공용 계층(커넥터들이 의존) — 커넥터 클래스보다 먼저 로드한다.
require_once __DIR__ . '/feeds/http.php';
require_once __DIR__ . '/feeds/upsert.php';

// ─────────────────────────────────────────────────────────────────────────
// 커넥터 계약: 각 타입은 run(PDO,$conn) → ['fetched'=>N,'upserted'=>N] 을 반환하고,
//   preview(PDO,$conn) 로 저장 없이 최대 10건 미리보기를 돌려준다(run 과 같은 소스·기준).
// ─────────────────────────────────────────────────────────────────────────
interface VgFeedConnector {
    public function run(PDO $pdo, array $conn): array;
    public function preview(PDO $pdo, array $conn): array;
}

// 커넥터 구현(계약 정의 뒤에 로드).
require_once __DIR__ . '/feeds/kev.php';
require_once __DIR__ . '/feeds/osv.php';
require_once __DIR__ . '/feeds/nvd.php';
require_once __DIR__ . '/feeds/kisa.php';
require_once __DIR__ . '/feeds/epss.php';
require_once __DIR__ . '/feeds/debtracker.php';
require_once __DIR__ . '/feeds/rhoval.php';
require_once __DIR__ . '/feeds/rhunfixed.php';
require_once __DIR__ . '/feeds/ssg.php';
require_once __DIR__ . '/feeds/kcve.php';
require_once __DIR__ . '/feeds/ubuntuoval.php';
require_once __DIR__ . '/feeds/pkgregistry.php';
require_once __DIR__ . '/feeds/generic_api.php';

// ─────────────────────────────────────────────────────────────────────────
// 커넥터 카탈로그 — 타입 하나당 한 줄. **타입에 관한 유일한 근거다.**
//   예전엔 같은 목록이 connectors.php 의 저장 검증(in_array)·폼 <select>·여기 vg_feed_make
//   세 곳에 흩어져 있었다. 커넥터가 늘 때 한 곳만 고치면 나머지가 조용히 어긋난다(OCP).
//
//   · class     — vg_feed_make 가 만들 구현
//   · label     — 폼 <select> 표기
//   · transport — **수집 방식**(VG_TRANSPORTS 의 키). "어떻게 가져오는가" 다.
//                 "무엇에 답하는가"(역할)와는 다른 축이고, 역할은 목록 화면의 그룹 카드가 보여준다.
//   · desc      — 방식 한 줄 설명(무엇을 받아서 어떻게 푸는지)
//   · fields    — 이 타입이 **실제로 읽는** 설정 필드. feeds/*.php 를 읽어 확인한 결과이며,
//                 여기 없는 필드는 폼에서 감춘다(그래야 라벨에 "(OSV용)" 같은 변명을 안 단다).
//   · url_label — url 필드 라벨. 절반이 API 가 아닌데 전부 "API URL" 이라 부르면 거짓말이다.
// ─────────────────────────────────────────────────────────────────────────
const VG_TRANSPORTS = [
    'api'    => ['label' => 'REST API',     'tone' => 'info'],
    'file'   => ['label' => '파일 다운로드', 'tone' => 'purple'],
    'feed'   => ['label' => 'RSS + HTML',   'tone' => 'ok'],
    'hybrid' => ['label' => 'API + 파일',    'tone' => 'low'],
];

const VG_CONNECTOR_TYPES = [
    'kev' => [
        'class' => VgKevConnector::class, 'label' => 'CISA KEV', 'transport' => 'file',
        'desc'  => '정적 JSON 파일 하나(known_exploited_vulnerabilities.json)를 받아 통째로 읽는다. API 가 아니다.',
        'fields' => ['url'], 'url_label' => 'JSON 파일 URL',
    ],
    'osv' => [
        'class' => VgOsvConnector::class, 'label' => 'OSV.dev', 'transport' => 'api',
        'desc'  => 'api.osv.dev/v1/querybatch 에 패키지 목록을 POST 로 배치 조회하고, 상세(/v1/vulns/{id})는 동시 8개로 받는다.',
        'fields' => ['url', 'ecosystem'], 'url_label' => 'API URL (querybatch)',
    ],
    'nvd' => [
        'class' => VgNvdConnector::class, 'label' => 'NVD 2.0', 'transport' => 'api',
        'desc'  => 'services.nvd.nist.gov REST API 를 startIndex 로 끝까지 페이지네이션한다. 수정일(lastMod) 기준이라 범위는 최대 120일.',
        'fields' => ['url', 'api_key', 'days'], 'url_label' => 'API URL',
    ],
    'kisa' => [
        'class' => VgKisaConnector::class, 'label' => 'KISA 보안공지', 'transport' => 'feed',
        'desc'  => 'boho.or.kr RSS 를 simplexml 로 읽고, 공지 본문은 상세 HTML 을 DOMDocument 로 훑어 평문으로 뽑는다.',
        'fields' => ['url'], 'url_label' => 'RSS URL (비우면 기본 3종을 모두 순회한다)',
    ],
    'epss' => [
        'class' => VgEpssConnector::class, 'label' => 'FIRST EPSS', 'transport' => 'file',
        'desc'  => 'gz 덤프(epss_scores-current.csv.gz)를 받아 gzdecode 로 풀고 CSV 로 읽는다.',
        'fields' => ['url'], 'url_label' => '덤프 파일 URL (csv.gz)',
    ],
    'debtracker' => [
        'class' => VgDebtrackerConnector::class, 'label' => '데비안 보안 트래커', 'transport' => 'file',
        'desc'  => '릴리스별 debsecan 덤프를 받아 zlib 으로 풀고 줄 단위로 읽는다. 대상 릴리스는 수집된 데비안 호스트에서 자동으로 정한다.',
        'fields' => ['url'], 'url_label' => '덤프 베이스 URL (뒤에 릴리스 코드네임이 붙는다)',
    ],
    'rhoval' => [
        'class' => VgRhovalConnector::class, 'label' => 'RHEL OVAL', 'transport' => 'file',
        'desc'  => 'OVAL XML 덤프를 벤더별 고정 주소에서 받아 XMLReader 로 스트리밍 파싱한다(Red Hat·Oracle 은 bz2, AlmaLinux 는 평문). 주소와 대상 릴리스 모두 코드·수집 호스트가 정하므로 설정할 값이 없다.',
        'fields' => [],
    ],
    'rhunfixed' => [
        'class' => VgRhunfixedConnector::class, 'label' => 'Red Hat 미수정', 'transport' => 'api',
        'desc'  => 'access.redhat.com hydra REST API 를 고정 주소로 동시 6개씩 조회한다. 대상 컴포넌트는 수집된 호스트에서 자동으로 정하므로 설정할 값이 없다.',
        'fields' => [],
    ],
    'ssg' => [
        'class' => VgSsgConnector::class, 'label' => 'SCAP 기준', 'transport' => 'hybrid',
        'desc'  => 'GitHub 릴리스 API 로 최신 자산 주소를 먼저 받고, 그 tar.bz2 파일을 내려받아 푼다 — 두 단계라 API 하나로도 파일 하나로도 부르기 어렵다.',
        'fields' => ['url'], 'url_label' => '릴리스 API URL (자산 주소를 여기서 찾는다)',
    ],
    'kcve' => [
        'class' => VgKcveConnector::class, 'label' => '커널 CNA', 'transport' => 'file',
        'desc'  => 'kernel.org vulns.git 스냅샷 tarball(약 20MB)을 받아 tar 를 직접 훑는다. CVE 당 개별 요청(1만 2천 회)을 피하려는 것이다.',
        'fields' => ['url'], 'url_label' => '스냅샷 tarball URL (tar.gz)',
    ],
    'ubuntuoval' => [
        'class' => VgUbuntuOvalConnector::class, 'label' => 'Ubuntu OVAL', 'transport' => 'file',
        'desc'  => 'OVAL XML 덤프(*.xml.bz2)를 릴리스별로 받아 푼다. 대상 릴리스는 수집된 우분투 호스트에서 자동으로 정한다.',
        'fields' => ['url'], 'url_label' => '덤프 URL 템플릿 ({C} 자리에 릴리스 코드네임이 들어간다)',
    ],
    'pkgregistry' => [
        'class' => VgPkgRegistryConnector::class, 'label' => '패키지 레지스트리 메타데이터', 'transport' => 'api',
        'desc'  => 'Packagist/npm/PyPI/Maven Central 에서 tb_package_dependency 의 부모 패키지가 설치버전보다 높은 버전에서 자식을 어떤 제약으로 요구하는지 받는다. 대상은 수집된 의존성 그래프에서 자동으로 정하므로 설정할 값이 없다.',
        'fields' => [],
    ],
    'generic_api' => [
        'class' => VgGenericApiConnector::class, 'label' => '사용자 API', 'transport' => 'api',
        'desc'  => '사용자가 지정하는 REST API. 주소·헤더·페이징·필드 매핑을 아래에서 직접 정의한다.',
        'fields' => [],
    ],
];

/** 이 타입이 실제로 읽는 설정 필드(카탈로그 확인 결과). 모르는 타입은 빈 배열. */
function vg_connector_fields(string $type): array {
    return VG_CONNECTOR_TYPES[$type]['fields'] ?? [];
}

/**
 * 표준 폼(connectors.php #stdFields)이 관리하는 설정 키 전체 = 카탈로그 fields 의 합집합.
 *   저장이 "폼이 소유한 키만" 갈아끼우고 나머지는 보존하도록 경계를 긋는다 — connection_json
 *   에는 폼이 모르는 키도 산다(releases · max_detail). 카탈로그에서 파생하므로 따로 안 늘린다.
 * @return list<string>
 */
function vg_connector_form_fields(): array {
    $out = [];
    foreach (VG_CONNECTOR_TYPES as $meta) {
        foreach ($meta['fields'] as $f) { $out[$f] = true; }
    }
    return array_keys($out);
}

function vg_feed_make(string $type): VgFeedConnector {
    $cls = VG_CONNECTOR_TYPES[$type]['class'] ?? null;
    if ($cls === null) {
        throw new InvalidArgumentException("알 수 없는 커넥터 타입: $type");
    }
    return new $cls();
}

// ─────────────────────────────────────────────────────────────────────────
// 실행 (cron/스케줄 계산은 schedule.php 로 분리 — vg_cron_*/vg_schedule_*)
// ─────────────────────────────────────────────────────────────────────────

/** 주어진 커넥터 id 중에 해당 타입이 있는가. 수집 후 후처리를 걸지 결정할 때 쓴다. */
function vg_feed_has_type(PDO $pdo, array $ids, string $type): bool {
    if (!$ids) { return false; }
    $in = implode(',', array_fill(0, count($ids), '?'));
    $st = $pdo->prepare("SELECT 1 FROM tb_feed_connector WHERE connector_type = ? AND feed_connector_id IN ($in) LIMIT 1");
    $st->execute(array_merge([$type], array_map('intval', $ids)));
    return (bool) $st->fetchColumn();
}

/** 커넥터 1건 실행: 로그(running→success/error) + 커넥터 상태/다음실행 갱신. */
function vg_feed_run(PDO $pdo, int $connectorId, string $triggerBy = 'schedule'): array {
    $st = $pdo->prepare('SELECT * FROM tb_feed_connector WHERE feed_connector_id = ? AND is_deleted = 0');
    $st->execute([$connectorId]);
    $c = $st->fetch();
    if (!$c) {
        throw new RuntimeException("커넥터 없음: $connectorId");
    }
    // 스케줄러가 돌리면 SYSTEM, 사람이 누르면 USER 로 감사 기록.
    $actor = $triggerBy === 'schedule' ? 'SYSTEM' : 'USER';
    $conn     = vg_json_col($c['connection_json']);
    $schedule = vg_json_col($c['schedule_json']);

    $lg = $pdo->prepare('INSERT INTO tb_feed_collection_log (feed_connector_id, trigger_by, status) VALUES (?,?,?)');
    $lg->execute([$connectorId, $triggerBy, 'running']);
    $logId = (int) $pdo->lastInsertId();
    $pdo->prepare('UPDATE tb_feed_connector SET last_status=?, last_run_at=NOW() WHERE feed_connector_id=?')->execute(['running', $connectorId]);

    try {
        $res = vg_feed_make((string) $c['connector_type'])->run($pdo, $conn);
        $msg = "fetched={$res['fetched']} upserted={$res['upserted']}";
        $pdo->prepare('UPDATE tb_feed_collection_log SET status=?, finished_at=NOW(), items_fetched=?, items_upserted=?, message=? WHERE feed_collection_log_id=?')
            ->execute(['success', $res['fetched'], $res['upserted'], $msg, $logId]);
        $pdo->prepare('UPDATE tb_feed_connector SET last_status=?, last_message=?, next_run_at=? WHERE feed_connector_id=?')
            ->execute(['success', $msg, vg_schedule_next($schedule), $connectorId]);
        vg_log_activity($pdo, 'CONNECTOR', $connectorId, 'feed_run', "수집 {$res['upserted']}건",
            ['fetched' => $res['fetched'], 'upserted' => $res['upserted'], 'status' => 'success'], null, $actor);
        return ['ok' => true] + $res;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $msg = mb_substr($e->getMessage(), 0, 480);
        $pdo->prepare('UPDATE tb_feed_collection_log SET status=?, finished_at=NOW(), message=? WHERE feed_collection_log_id=?')
            ->execute(['error', $msg, $logId]);
        $pdo->prepare('UPDATE tb_feed_connector SET last_status=?, last_message=?, next_run_at=? WHERE feed_connector_id=?')
            ->execute(['error', $msg, vg_schedule_next($schedule), $connectorId]);
        vg_log_activity($pdo, 'CONNECTOR', $connectorId, 'feed_run', "수집 실패: $msg",
            ['status' => 'error'], null, $actor);
        return ['ok' => false, 'error' => $msg];
    }
}

/**
 * 미리보기: 소스에서 최대 10건을 가져와 그대로 보여준다(저장 안 함).
 *   커넥터 설정 전에 URL/응답 형태를 눈으로 확인하는 용도. 각 커넥터의 preview() 로 위임한다
 *   — run 과 같은 클래스라 같은 소스·기준을 본다. 알 수 없는 타입은 미지원으로 응답한다.
 */
function vg_feed_preview(string $type, array $conn, PDO $pdo): array {
    try {
        $connector = vg_feed_make($type);
    } catch (InvalidArgumentException $e) {
        return ['ok' => false, 'error' => "미리보기 미지원 타입: $type"];
    }
    return $connector->preview($pdo, $conn);
}

/**
 * 중단된 실행 정리. vg_feed_run 은 try/catch 로 성공·실패 모두 로그를 닫지만,
 * PHP 가 통째로 죽으면(치명적 오류·CPU 시간 초과·컨테이너 재기동) catch 가 돌지 않아
 * 로그가 'running' 으로 영구히 굳는다. 실측: OSV 로그 1건이 27시간째 running 이었다.
 *
 * 시작 후 $hours 시간이 지난 running 을 실패로 마감한다. 정상 수집은 길어야 10분대라
 * 기본 6시간이면 진행 중인 실행을 잘못 죽일 위험이 없다.
 *
 * 마감할 때 next_run_at 도 다시 계산한다. 이 컬럼은 vg_feed_run() 이 실행을 **정상 종료할
 * 때만** 쓰므로, 프로세스가 즉사하면 직전 성공 때 계산된 값이 그대로 남아 화면의
 * "다음 실행"이 영구히 과거 시각으로 굳는다(실측: #7 rhoval 이 last_run_at 보다 하루 이른
 * next_run_at 을 달고 있었고, 그걸 보고 "스케줄러가 방치한다"고 오진했다).
 * 스케줄링 자체는 무관하다 — vg_feed_due() 는 next_run_at 을 읽지 않고 schedule_json +
 * last_run_at 으로 판정한다. 여기서 고치는 건 표시값뿐이다.
 *
 * @return int 정리한 로그 수
 */
function vg_feed_reap_stale(PDO $pdo, int $hours = 6): int {
    $hours = max(1, $hours);   // SQL 에 직접 넣으므로 정수로 못박는다
    $msg   = "중단된 실행으로 판단해 정리(시작 후 {$hours}시간 초과)";

    $st = $pdo->prepare(
        "UPDATE tb_feed_collection_log
            SET status = 'error', finished_at = NOW(), message = ?
          WHERE status = 'running' AND started_at < NOW() - INTERVAL $hours HOUR"
    );
    $st->execute([$msg]);
    $n = $st->rowCount();

    // 커넥터 마감은 로그 정리 건수($n)와 무관하게 매번 본다. 두 조건은 서로 다른 테이블의
    //   서로 다른 컬럼(started_at vs last_run_at)을 보므로 건수가 같이 움직이지 않는다 —
    //   앞선 tick 에서 로그만 먼저 마감되면($n=0) 커넥터는 영구히 'running' 으로 남았다.
    //   대상은 보통 0~1행이고 조건도 그대로라 매번 봐도 비용은 사실상 없다.
    $stale = $pdo->prepare(
        "SELECT feed_connector_id, schedule_json, enabled, last_run_at
           FROM tb_feed_connector
          WHERE last_status = 'running' AND last_run_at < NOW() - INTERVAL $hours HOUR"
    );
    $stale->execute();
    $rows = $stale->fetchAll();
    if (!$rows) { return $n; }

    // 커넥터마다 schedule_json 이 달라 한 줄 UPDATE 로는 안 된다 — 각자 계산해 개별 UPDATE.
    $upd = $pdo->prepare(
        'UPDATE tb_feed_connector SET last_status = ?, last_message = ?, next_run_at = ? WHERE feed_connector_id = ?'
    );
    foreach ($rows as $r) {
        $sch  = vg_json_col($r['schedule_json']);
        $mode = (string) ($sch['mode'] ?? 'manual');
        // interval 은 "마지막 실행 + N분" 이라야 vg_feed_due() 판정과 같은 값이 나온다.
        //   나머지 모드는 지금 기준(connector_actions.php 의 저장 시 계산과 같은 규칙).
        $from = ($mode === 'interval' && $r['last_run_at']) ? strtotime((string) $r['last_run_at']) : time();
        // manual 은 vg_schedule_next() 가 null 을 준다. 비활성 커넥터도 스케줄러가 건너뛰므로
        //   예정 시각이 없다 → 둘 다 NULL(스키마가 NULL 허용, "예정 없음"의 표기다).
        $next = ((int) $r['enabled'] === 1) ? vg_schedule_next($sch, $from) : null;
        $upd->execute(['error', $msg, $next, (int) $r['feed_connector_id']]);
    }
    return $n;
}

/** 스케줄러가 돌릴 대상: enabled=1 이고 스케줄(interval/daily/cron) 상 지금이 due. */
function vg_feed_due(PDO $pdo): array {
    $rows = $pdo->query('SELECT feed_connector_id, schedule_json, last_run_at FROM tb_feed_connector WHERE enabled = 1 AND is_deleted = 0')->fetchAll();
    $due = [];
    foreach ($rows as $r) {
        $sch = vg_json_col($r['schedule_json']);
        if (vg_schedule_due($sch, $r['last_run_at'])) {
            $due[] = (int) $r['feed_connector_id'];
        }
    }
    return $due;
}
