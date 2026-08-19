<?php
declare(strict_types=1);

/**
 * host/hero.php — 자산 상세의 **머리**(탭 줄 위) 렌더 하나.
 *   식별부 히어로 + 즉시 스캔 버튼 + "판정 불가/수집 실패" 경고 + 위험 요약 KPI 줄.
 *   전부 탭과 무관하게 늘 같은 자리에 서는 것이라 한 파일로 묶는다(탭 본문은 tabs/*.php).
 *
 *   조회는 하지 않는다 — 쓰는 값은 전부 호출부가 $ctx 로 열거해 넘긴 것뿐이다
 *   (host/tabs.php 와 같은 규칙: 페이지 전역을 암묵적으로 주워 쓰지 않는다).
 */
function vg_host_render_hero(array $ctx): void {
    extract($ctx, EXTR_SKIP);
  $meta = [
      vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?: 'OS 미상',
      vg_asset_state(
          $scan !== null,
          $pollAge,
          $scanAge,
          (int) ($host['poll_schedule_seconds'] ?? 3600)
      ),
      '최신 수집 ' . vg_h($scan['collected_at']),
  ];
  /* '패키지 N개' 링크는 걷었다 — 탭 줄이 1단으로 내려오면서 '설치 패키지 N' 이 같은 숫자로
   *   바로 아래에 서게 됐다(같은 곳으로 가는 두 번째 문). $packageTotal 은 그 탭이 계속 쓴다. */
  /* 의존성 그래프 링크는 식별부에서 내렸다 — 자산 계열 화면(전체 설치 패키지·의존성 그래프)의
   *   진입점은 '구성 > 설치 패키지' 탭 한 곳으로 모은다. 링크 자체는 그 탭에 그대로 있다
   *   (엣지가 있는 자산에만 — 없는 자산에 걸면 빈 화면으로 보내게 된다). */
  if (!empty($host['last_seen_ip'])) { $meta[] = 'IP ' . vg_h($host['last_seen_ip']); }
  /* 에이전트 버전 — 자산 목록에서 내려온 값이다. 숫자만으론 그게 최신인지 알 수 없어
   *   목록이 달고 있던 '구버전' 뱃지도 같이 가져온다(신호를 옮기는 것이지 없애는 게 아니다). */
  if (!empty($scan['agent_version'])) {
      $av  = (string) $scan['agent_version'];
      $old = $latestAgent !== '' && version_compare($av, $latestAgent, '<');
      $meta[] = '에이전트 <code>' . vg_h($av) . '</code>'
          . ($old ? ' ' . vg_badge('구버전', 'med',
                "함대 최신은 {$latestAgent} — master 에서 deploy/agent_push.sh 로 갱신하세요") : '');
  }
  /* 자산 등급은 설정 탭으로 내려갔지만 "이 자산이 무엇인가"의 일부라 식별부에 남긴다 —
   *   옮기는 것이지 지우는 것이 아니다. 미확정이면 확정하러 갈 자리를 링크로 준다. */
  $meta[] = ($host['grade'] ?? '') !== ''
      ? '등급 ' . vg_asset_grade_badge((string) $host['grade'], false, (string) ($host['grade_reason'] ?? ''))
      : '<a href="' . vg_h(vg_qs(['tab' => 'manage', 'page' => null, 'q' => null])) . '">등급 미확정</a>';
  /* '자산 설정' 링크도 걷었다 — 2단 탭에서는 하위 탭이라 한 번에 못 닿아 여기 지름길을 뒀는데,
   *   지금은 탭 줄에 직접 서 있다(같은 자리로 가는 두 번째 문). */
  /* '대시보드'·'자산관리' 링크는 걷었다 — 둘 다 사이드바(vg_nav_sections)에 늘 서 있는 항목이라
   *   식별부에서 한 번 더 말하면 메타 줄만 길어진다(같은 자리로 가는 두 번째 문). */
  vg_hero(vg_h($host['fqdn']), $meta, $worst ?? '양호', $heroTone, '최고 위험도', '');
  /* 수집 제어(즉시 실행·예약·주기·속도 티어)는 '자산 설정' 탭으로 내려갔다.
   *   자산 상세를 여는 이유는 "이 서버가 얼마나 위험한가"이지 "수집 주기가 몇 분인가"가 아니다 —
   *   첫 화면을 설정 폼이 통째로 차지하면 위험 요약과 취약점 목록이 스크롤 아래로 밀린다.
   *   기능은 그대로 살아 있다(같은 폼·같은 action·같은 엔드포인트). */

  /* 취약점 스캔(즉시 실행)은 이 화면에서 가장 자주 누르는 동작인데 가장 깊은 곳에 있었다
   *   ('자산 설정' 탭 → 수집 제어 카드 → 즉시 실행 = 4단계). 식별부로 올린다 —
   *   폼·action·엔드포인트는 수집 제어 카드의 것과 **같은 것**이다(POST 처리는 한 곳뿐).
   *   예약 실행·수집 주기·속도 티어는 자주 쓰지 않아 설정 탭에 그대로 둔다.
   *   이미 대기·실행 중인 명령이 있으면 버튼 대신 그 상태를 말한다 — 같은 명령을 두 번
   *   넣어도 큐에 두 줄이 쌓일 뿐이라, 누르기 전에 "이미 돌고 있다"를 먼저 보여준다. */
  /* 처리 결과(등록/중단/오류)는 '자산 설정' 탭의 수집 제어 카드가 그린다 — 그런데 이 버튼은
   *   어느 탭에서든 눌리고, 리다이렉트는 누른 그 탭으로 돌아온다. 그 탭이 결과를 안 그리면
   *   플래시가 소비만 되고 사라져 "눌렀는데 아무 일도 안 일어난 것처럼" 보인다.
   *   설정 탭에서는 그리지 않는다 — 같은 메시지를 두 번 띄우게 된다. */
  if (($tab ?? '') !== 'manage') {
      vg_alert($agentMsg ?? null, 'ok');
      vg_alert($agentErr ?? null);
  }
  if (vg_can('assets')) {
      $running = $pendingCommands[0] ?? null;
      echo '<div class="actions">';
      if ($running !== null) {
          $label = ($running['status'] ?? '') === 'running' ? '수집 진행 중' : '실행 대기 중';
          echo '<a class="btn btn--sm btn--ghost" href="'
              . vg_h(vg_qs(['tab' => 'manage', 'page' => null, 'q' => null])) . '">'
              . vg_h($label) . ' · 진행 보기</a>';
      } else {
          echo '<form method="post" data-confirm="지금 이 호스트의 취약점 스캔을 실행할까요?">'
              . '<input type="hidden" name="csrf" value="' . vg_h($agentCsrf) . '">'
              . '<input type="hidden" name="action" value="agent_run_now">'
              . '<input type="hidden" name="id" value="' . (int) $hostId . '">'
              . '<button class="btn btn--sm btn--primary" type="submit"'
              . ' title="에이전트가 다음 poll(10초 이내)에서 실행합니다">지금 스캔</button>'
              . '</form>';
      }
      echo '</div>';
  }
  /* SBOM 내려받기는 여기서 내렸다 — 첫 화면 한 칸을 카드가 통째로 차지했는데, 자주 쓰는
   *   동작이 아니다. 부품표는 곧 설치 패키지 목록이라 '설치 패키지' 탭 아래가 제자리다
   *   (기능·URL 은 그대로다 — tabs/packages.php 가 같은 vg_sbom_links() 를 부른다). */

  // CVE 피드가 지원하지 않는 배포판이면 매칭 후보가 아예 없어 **취약점이 0건으로 뜬다.**
  //   운영자는 "안전하다"고 읽는다 — 침묵하는 미탐이라 반드시 화면에 알린다.
  $unsup = [];
  $u = vg_distro_unsupported($host['os_id'] ?? null, $host['os_version'] ?? null);
  if ($u !== null) { $unsup[] = '이 호스트 — ' . $u; }
  foreach ($unsupContainers as $c) {
      $unsup[] = '컨테이너 ' . $c['cid'] . ' — ' . $c['reason'];
  }
  if ($unsup) {
      vg_alert([
          'type'  => 'warn',
          'title' => '취약점 매칭이 수행되지 않습니다',
          'hints' => array_merge(
              [
                  '아래 대상은 피드가 모르는 배포판이거나, 패키지 DB 가 없어 무엇이 깔렸는지 알 수 없습니다.',
                  '취약점 0건은 "안전함"이 아니라 "판정 불가"입니다.',
              ],
              $unsup
          ),
      ]);
  }

  // 위 경고와 같은 주제("0건 = 안전"이 아닐 수 있다)의 세 번째 축.
  //   배포판·이미지 문제가 아니라 **에이전트가 그 항목을 못 걷은** 경우다 — 지금까진 침묵했다.
  if ($missingStages) {
      $stageHints = [
          '해당 항목의 0건은 "없음"이 아니라 "수집 실패"입니다.',
      ];
      // 'runtime_processes' MISSING 은 원인이 둘이다 — item_count 로 구분한다.
      //   > 0: 일부는 걷었는데 중간에 끊김 = 프로세스 스캔 시간 초과(agent PROC_SCAN_TIMEOUT).
      //   0  : 한 건도 못 걸음 = 권한·환경 문제(스캔 자체가 안 됨) — 여기는 시간초과가 아니다.
      //   그 외 단계는 원인이 불명확하므로 기존의 일반 안내를 유지한다.
      $procItemCount = (int) ($missingStageItemCounts['runtime_processes'] ?? 0);
      $stageHints[] = in_array('runtime_processes', $missingStageCodes ?? [], true) && $procItemCount > 0
          ? '프로세스 수가 많아 제한 시간 안에 전부 훑지 못했습니다.'
          : '에이전트 실행 권한·환경을 확인한 뒤 다시 수집하세요.';
      foreach ($missingStages as $s) { $stageHints[] = '수집 실패 — ' . $s; }
      vg_alert([
          'type'  => 'warn',
          'title' => '이 스캔은 일부 항목을 수집하지 못했습니다',
          'hints' => $stageHints,
      ]);
  }
  ?>

  <div class="cards">
    <?php /* 심각도 분포(CRITICAL/HIGH/MEDIUM/LOW 네 칸)는 여기서 내렸다 — 취약점 탭의 필터 바로
             아래 범례(vg_legend)가 같은 값을 같은 순서로 그리고 있었다. 둘 중 목록을 읽는 자리에
             붙은 쪽을 남긴다. 이 줄엔 분포로는 못 읽는 축(악용·노출·설정)만 세운다.
             $counts 는 히어로 톤·'최고 위험도' 뱃지가 계속 쓴다. */ ?>
    <div class="kpi kpi--sm tone-<?= $kevCount > 0 ? 'crit' : 'muted' ?>"
         title="KEV — 실제 악용이 확인된 취약점(CISA Known Exploited Vulnerabilities)">
      <b><?= number_format($kevCount) ?></b><span>KEV 악용확인</span>
    </div>
    <a class="kpi kpi--sm tone-<?= $externalFindings > 0 ? 'crit' : 'ok' ?>"
       href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>&amp;st=EXTERNAL">
      <b><?= number_format($externalFindings) ?></b><span>외부노출 취약점</span>
    </a>
    <a class="kpi kpi--sm" href="<?= vg_h(vg_qs(['tab' => 'runtime', 'page' => null, 'q' => null])) ?>">
      <b><?= number_format($exposureCount) ?></b><span>노출 소켓</span>
    </a>
    <a class="kpi kpi--sm tone-<?= $cceFail > 0 ? 'high' : 'ok' ?>" href="<?= vg_h(vg_qs(['tab' => 'cce', 'page' => null])) ?>">
      <b><?= (int) $cceFail ?></b><span>설정 취약</span>
    </a>
  </div>
<?php
}
