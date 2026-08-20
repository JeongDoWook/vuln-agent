<?php
declare(strict_types=1);

/**
 * host/report.php — 호스트 상세의 "AI 보고서" 카드(생성 버튼 · 진행 상태 · 지난 이력).
 *
 *   보고서 본문을 만드는 것은 외부 작업큐다. 이 카드는 job 을 만들라고 시키고(버튼 →
 *   report-job-create.php), 그 상태를 되묻고(assets/js/host.js 의 폴링 →
 *   report-job-status.php), 지난 job 을 목록으로 보인다.
 *
 *   폴링 간격·최대 횟수는 설정값이라 마크업의 data-* 로 내려보낸다 — 화면 스크립트가
 *   자기 숫자를 갖지 않게 한다(매직넘버 금지). 결과 본문은 형식이 정해지지 않은 plain text 라
 *   HTML/마크다운으로 가정하지 않고 <pre> 에 그대로 넣는다(이스케이프는 vg_h / textContent).
 *
 *   결과가 **PDF 다운로드 링크**로 오면(외부 API 담당자 확인 2026-08-20) 본문 대신
 *   [PDF 다운로드] 로 그린다 — 카드와 이력표 양쪽 모두. 링크는 우리 프록시
 *   (report-download.php)를 가리킨다: 외부 API 는 사내 주소라 브라우저에서 못 닿는다.
 *   지금은 아직 더미 텍스트가 오므로 두 경로가 모두 살아 있어야 한다.
 */

require_once __DIR__ . '/../report_job.php';
require_once __DIR__ . '/../ui_config.php';   // vg_ui_detail_preview_limit — 미리보기 목록 상한

/**
 * 이 호스트의 보고서 이력과 "아직 안 끝난 job" 을 읽는다.
 *   표가 아직 없거나(마이그레이션 미적용) 조회가 실패해도 **호스트 상세 전체가 죽으면 안 된다** —
 *   vg_settings_all() 과 같은 판단으로 로그만 남기고 빈 값으로 떨어진다.
 * @return array{jobs: array{rows: array<int,array>, total: int}, active: ?array}
 */
function vg_host_load_report_jobs(PDO $pdo, int $hostId): array {
    $empty = ['jobs' => ['rows' => [], 'total' => 0], 'active' => null];
    try {
        return [
            'jobs'   => vg_report_jobs_recent($pdo, $hostId, vg_ui_detail_preview_limit()),
            'active' => vg_report_job_active($pdo, $hostId),
        ];
    } catch (Throwable $e) {
        error_log('[host/report] ' . $e->getMessage());
        return $empty;
    }
}

/** AI 보고서 카드. $csrf 는 생성 요청(POST)에 실어 보낸다. */
function vg_host_render_report(int $hostId, string $csrf, array $jobs, ?array $active): void {
    $rows  = $jobs['rows'] ?? [];
    $total = (int) ($jobs['total'] ?? 0);
    ?>
    <section class="card" aria-labelledby="report-job-title"
             data-report-job
             data-host-id="<?= (int) $hostId ?>"
             data-csrf="<?= vg_h($csrf) ?>"
             data-poll-interval="<?= (int) vg_report_poll_interval() ?>"
             data-poll-max="<?= (int) vg_report_poll_max_attempts() ?>"
             data-active-job="<?= $active !== null ? (int) $active['report_job_id'] : '' ?>">
      <div class="report-job__heading">
        <strong id="report-job-title">AI 보고서</strong>
        <button class="btn btn--sm btn--primary" type="button" data-report-create>AI 보고서 생성</button>
      </div>
      <div class="card__body">
        <?php /* 상태 줄과 결과 상자는 스크립트가 채운다. 진행 중인 job 이 있으면 화면을 열자마자
                 폴링이 이어지므로(새로고침해도 이어 보인다) 처음부터 펼쳐 둔다. */ ?>
        <p class="report-job__status"<?= $active === null ? ' hidden' : '' ?> data-report-status>
          <span class="badge tone-info" data-report-badge>생성 중</span>
          <span data-report-message>보고서를 만들고 있습니다.</span>
        </p>
        <pre class="report-job__result" data-report-result hidden></pre>
        <?php /* 결과가 파일 링크면 본문 대신 이 버튼이 뜬다(스크립트가 href 를 채운다).
                 링크는 **우리 프록시**를 가리킨다 — 외부 API 는 사내 주소라 브라우저에서 안 닿는다. */ ?>
        <p class="report-job__download" hidden data-report-download>
          <a class="btn btn--sm btn--primary" href="#" target="_blank" rel="noopener" data-report-download-link>PDF 다운로드</a>
        </p>

        <?php
        vg_table(
            [
                ['label' => '요청 시각', 'key' => 'created_at', 'nowrap' => true],
                ['label' => '상태', 'key' => 'status', 'width' => '6rem'],
                ['label' => '요청자', 'key' => 'username'],
                ['label' => '결과', 'key' => 'result'],
            ],
            $rows,
            [
                'card'  => false,
                'class' => 'report-job__table',
                'empty' => '아직 생성한 보고서가 없습니다.',
                'cell'  => [
                    'status' => static function (array $r): string {
                        $state = vg_report_state((string) $r['status']);
                        // title 에 외부 원문 상태를 남긴다 — 라벨은 세 가지로 접히므로,
                        //   "무슨 값을 받았길래 생성 중인가" 를 볼 수 있어야 한다.
                        return vg_badge(vg_report_state_label($state), vg_report_state_tone($state),
                                        (string) $r['status']);
                    },
                    'username' => static function (array $r): string {
                        return vg_h((string) ($r['username'] ?? '')) ?: '<span class="why">–</span>';
                    },
                    'result' => static function (array $r): string {
                        // 결과가 파일 링크면 다운로드로, 아니면 예전처럼 본문 보기로 그린다.
                        //   판단은 카드·프록시와 같은 함수(vg_report_download_url)가 한 곳에서 한다.
                        if (vg_report_download_url($r['result_head'] ?? null) !== null) {
                            return '<a class="btn btn--sm btn--primary" target="_blank" rel="noopener" href="'
                                . vg_h(VG_REPORT_DOWNLOAD_PATH . '?job=' . (int) $r['report_job_id'])
                                . '">PDF 다운로드</a>';
                        }
                        if ((int) ($r['result_len'] ?? 0) > 0) {
                            return '<button type="button" class="btn btn--sm btn--ghost" data-report-view="'
                                . (int) $r['report_job_id'] . '">결과 보기</button>';
                        }
                        $err = trim((string) ($r['error_message'] ?? ''));
                        return $err !== ''
                            ? '<span class="why">' . vg_trunc($err, 80) . '</span>'
                            : '<span class="why">–</span>';
                    },
                ],
            ]
        );
        ?>
        <?php if ($total > count($rows)): ?>
          <p class="why">최근 <?= count($rows) ?>건만 보입니다 · 전체 <?= number_format($total) ?>건</p>
        <?php endif; ?>
      </div>
    </section>
    <?php
}
