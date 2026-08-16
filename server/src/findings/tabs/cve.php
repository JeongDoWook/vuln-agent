<?php
/**
 * findings/tabs/cve.php — CVE 탭(경고 · 행동 큐 · 등급 카드 · 툴바 · 표).
 *   쓰는 값(findings.php 가 $ctx 로 넘긴다):
 *     $unsupBy $actionCounts $counts $notes $firstSeen $policy
 *     $rows $total $page $perPage $scan $scanId $hostId $hostOptions
 *     $q $sev $st $fx $fst $sort $stOptions
 */
?>
  <?php if ($unsupBy):
      // 기본은 **사유별 대수 요약**만 펴 둔다. 예전엔 사유 한 줄에 그 사유가 걸린 대상 이름을
      //   전부 이어 붙여서, 미지원 호스트가 199개인 환경에선 배너 혼자 화면 6줄을 먹고 KPI·필터·
      //   표를 아래로 밀어냈다(실측). 대상 이름은 지우지 않고 접힘 안으로 내린다 — 닫혀 있어도
      //   HTML 에는 그대로 있어 Ctrl+F 검색과 tests/smoke.sh 의 '컨테이너 nodb' 단언이 같이 산다.
      // 경고 제목은 한 글자도 바꾸지 않았다: "0건 = 안전 아님" 은 이 제품이 허위 안심을 막는
      //   핵심 문구이고 smoke 가 '판정 불가' 를 단언한다(tests/smoke.sh 의 [미지원 배포판 경고]).
      $unsupTotal = 0;
      foreach ($unsupBy as $names) { $unsupTotal += count($names); }
      // 많은 사유부터 세운다 — 두세 대짜리 사유가 맨 위에 오면 요약이 대표성을 잃는다.
      uasort($unsupBy, static fn(array $a, array $b): int => count($b) <=> count($a));
      $hints = []; $unsupItems = [];
      foreach ($unsupBy as $reason => $names) {
          $line = $reason . ' · ' . number_format(count($names)) . '개 대상';
          if (count($hints) < VG_UNSUP_HINT_PREVIEW) {
              // 요약 줄은 **한 줄**이어야 뜻이 있다 — 사유 중에는 괄호 안 설명까지 붙어 100자를
              //   넘는 것이 있어(패키지 DB 없는 이미지) 좁은 폭에서 혼자 두 줄이 된다. 미리보기
              //   에서만 줄이고, 온전한 문장은 바로 아래 접힘 안에 그대로 둔다.
              //   vg_trunc 를 안 쓰는 이유: vg_alert 의 hints 는 순수 문자열이라 여기서 HTML 을
              //   넘기면 vg_h() 로 다시 이스케이프돼 태그가 글자로 보인다.
              $hints[] = mb_strimwidth($reason, 0, 60, '…') . ' · ' . number_format(count($names)) . '개 대상';
          }
          $unsupItems[] = $line . ' — ' . implode(', ', $names);
      }
      $more = count($unsupItems) - count($hints);
      if ($more > 0) { $hints[] = '외 ' . number_format($more) . '종 (아래 접힘에 전체가 있습니다)'; }
      vg_alert([
          'type'  => 'warn',
          'title' => '일부 대상은 취약점 매칭이 수행되지 않습니다 — 0건은 "안전"이 아니라 "판정 불가"입니다',
          'hints' => $hints,
          'details' => [
              'summary' => '판정 불가 대상 ' . number_format($unsupTotal) . '개 · 사유 '
                         . number_format(count($unsupItems)) . '종 — 목록 보기',
              'items'   => $unsupItems,
          ],
      ]);
  endif; ?>

  <section class="action-queue" data-action-queue aria-labelledby="findingActionQueueTitle">
    <div class="action-queue__head">
      <strong id="findingActionQueueTitle">먼저 볼 작업</strong>
      <span class="why">— 최신 자산 스캔 기준 · 누르면 같은 모집단으로 필터됩니다</span>
    </div>
    <?php vg_kpi_strip([
        ['label' => 'High 이상', 'value' => number_format($actionCounts['high']), 'tone' => 'high',
         'href' => vg_qs(['sev' => 'HIGH+', 'fx' => null, 'st' => null, 'page' => 1]), 'selected' => $sev === 'HIGH+'],
        ['label' => '기한 초과', 'value' => number_format($actionCounts['overdue']), 'tone' => 'crit',
         'href' => vg_qs(['sev' => 'HIGH+', 'fx' => 'overdue', 'sort' => 'due', 'st' => null, 'page' => 1]), 'selected' => $fx === 'overdue'],
        ['label' => 'KEV 등재', 'value' => number_format($actionCounts['kev']), 'tone' => 'crit',
         'href' => vg_qs(['sev' => null, 'fx' => 'kev', 'st' => null, 'page' => 1]), 'selected' => $fx === 'kev'],
        ['label' => '외부 노출', 'value' => number_format($actionCounts['external']), 'tone' => 'high',
         'href' => vg_qs(['sev' => null, 'fx' => null, 'st' => 'EXTERNAL', 'page' => 1]), 'selected' => $st === 'EXTERNAL'],
        ['label' => '재시작 필요', 'value' => number_format($actionCounts['restart']), 'tone' => 'med',
         'href' => vg_qs(['sev' => null, 'fx' => 'restart', 'st' => null, 'page' => 1]), 'selected' => $fx === 'restart'],
    ], ['compact' => true]); ?>
  </section>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s):
      // 카드 크기·글자 크기는 CSS 가 전 등급에 똑같이 준다 — 그래서 자릿수가 많은 등급이 무조건
      //   커 보인다(실측: 'LOW 34184' 가 'CRITICAL 1' 보다 크게 읽혔다). 마크업에서 할 수 있는
      //   보정은 둘이다: (1) 천단위 구분으로 자릿수를 눈에 띄게 끊고(대시보드가 이미 '34,184' 로
      //   쓴다 — 같은 값이 화면마다 다르게 표기되지 않게 통일), (2) 0건인 등급은 등급색을 걷어
      //   중립(muted)으로 낮춘다. 0건은 "지금 볼 것이 없다" 는 뜻이라 색을 가져갈 이유가 없다.
      //   새 클래스(.kpi--zero 등)를 만들지 않는 이유: 색은 app.css 가 소유하고 지금 다른 작업이
      //   그 파일을 고치고 있다 — 이미 있는 tone-muted 로 같은 결과를 낸다.
      $zero = ((int) $counts[$s]) === 0;
    ?>
      <a href="<?= vg_h(vg_qs(['sev' => $sev === $s ? '' : $s, 'page' => 1])) ?>"
         class="kpi kpi--sm tone-<?= $zero ? 'muted' : vg_sev_tone($s) ?><?= $sev === $s ? ' is-selected' : '' ?>"
         title="<?= vg_h($s . ' ' . number_format((int) $counts[$s]) . '건' . ($sev === $s ? ' · 선택 해제' : ' 만 보기')) ?>">
        <b><?= number_format((int) $counts[$s]) ?></b><span><?= $s ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  // 단일 스캔 모드에선 scan_id 를 유지하고, 통합 모드에선 호스트 선택 드롭다운을 준다.
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['scan_id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  // KPI 카드로 고른 등급(sev)은 검색 폼 필드가 아니라, 폼 제출 시 사라지지 않도록 hidden 으로 함께 싣는다.
  if ($sev !== '') {
      $toolbar[] = ['type' => 'hidden', 'name' => 'sev', 'value' => $sev, 'reset' => true];
  }
  vg_toolbar(array_merge($toolbar, [
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
      // '전체 상태' 였던 것을 '노출 상태' 로 못박는다 — 바로 옆에 사람이 정하는 '조치 상태'가
      //   서기 때문에, 라벨이 둘 다 '상태' 면 어느 축인지 화면만 보고는 알 수 없다.
      ['type' => 'select', 'name' => 'st', 'empty_label' => '전체 노출 상태', 'selected' => $st,
          'options' => array_combine($stOptions, array_map('vg_status_label', $stOptions))],
      // 조치 상태 — 값 목록·라벨은 vg_finding_status_labels() 하나가 정본이다.
      ['type' => 'select', 'name' => 'fst', 'empty_label' => '전체 조치 상태', 'selected' => $fst,
          'options' => vg_finding_status_labels()],
      // 조치 가능성 — 벤더가 수정본을 안 낸 CVE 를 걸러 보거나, 그것만 모아 볼 수 있다.
      ['type' => 'select', 'name' => 'fx', 'empty_label' => '전체 조치 가능성', 'selected' => $fx,
          'options' => ['action' => '조치 가능', 'nofix' => '조치 불가(벤더 미수정)',
                        'restart' => '재시작·재부팅만 하면 됨', 'kev' => 'KEV 등재',
                        'overdue' => '기한 초과']],
      // 정렬은 표 머리글이 아니라 여기에 둔다 — vg_table 은 정렬 링크를 갖지 않는다(공용 표를
      //   이 화면 하나 때문에 바꾸지 않는다). 기한순은 최초 발견 시각을 되짚는 집계가 필요해
      //   기본값으로 두지 않는다.
      ['type' => 'select', 'name' => 'sort', 'empty_label' => '위험도순(기본)', 'selected' => $sort,
          'options' => ['due' => '조치 기한 임박순']],
  ]));

  // 컬럼 11개는 가로 스크롤을 만들어서, 정작 제일 중요한 "조치" 가 화면 밖으로 밀려났었다.
  // 값을 버리는 게 아니라 관련된 것끼리 한 칸에 쌓는다(패키지+버전, CVSS+EPSS+KEV).
  // 호스트 컬럼은 통합 모드에서만 — 단일 스캔 모드는 부제가 이미 호스트를 밝힌다.
  // 폭 배분: 목록 표는 table-layout:fixed 라(app.css 의 '목록 화면' 구역) 여기 적은 width 가
  //   그대로 지켜진다. 짧은 값(등급·상태·CVSS)은 내용 크기로 좁히고, 이름이 긴 주 식별자
  //   (호스트·CVE·패키지)에 폭을 몰아준다. 폭을 안 준 '근거' 가 남는 폭을 전부 갖는다.
  // 단위: **내용 크기가 고정된 열은 rem, 이름이 늘어나는 열은 %** 다.
  //   뱃지·점수는 화면이 좁아져도 안 줄어드는 고정 크기 덩어리라, % 로 주면 좁은 폭에서 칸보다
  //   커져 옆 열을 덮는다(cves.php 의 '심각도' 열이 같은 이유로 6.5rem 이다). 실제로 '위험도'
  //   8% 는 1440px 에서 'CVSS 9.8' 을 담지 못해 **점수가 화면에서 사라졌다.**
  //   반대로 rem 만 쓰면 넓은 화면에서 남는 폭이 전부 '근거' 로 몰리므로 이름 열은 % 로 둔다.
  //   합이 표 폭을 넘지 않게 유지한다 — 넘으면 폭 없는 '근거' 가 0 이 되고 표가 카드를 뚫는다
  //   (% 합 56.5% + 고정 19.5rem = 312px. 1060px 실측에서 근거 149px·행 높이 두 줄로 안정,
  //    가로 스크롤 없음).
  // 폭을 호스트(14.5→17%)와 조치(11.5→14%)로 옮겼다: 둘 다 **식별자** 열인데 잘리고 있었고
  //   (실측 'rollupchk.dep-rollup.example….', '1:1.22.1-3….'), 남는 폭을 전부 갖던 '근거' 는
  //   원래 두 줄 말줄임(clamp-2 + title)이라 좁아져도 잃는 정보가 없다. 식별자는 잘리면
  //   대조 자체가 불가능해진다 — 같은 폭이면 식별자에 준다.
  // 조치 상태·기한 두 칸이 늘면서 폭 예산을 다시 나눴다. 늘린 만큼은 **말줄임으로 잃는 정보가
  //   가장 적은 열**에서 가져온다: 근거(18→12.5%)는 원래 두 줄 말줄임 + title 이라 좁아져도
  //   전체 문장이 남고, 호스트·CVE·패키지 같은 식별자 열은 잘리면 대조 자체가 불가능해지므로
  //   1~2%p 만 줄였다(기존 주석의 원칙 그대로다).
  // 열 다이어트(2026-08): '근거' 열을 상세로 보냈다 — 판정 사유 문장과 판정 출처(match_source)는
  //   목록에서 "이게 뭔지·급한지·눌러 들어갈지" 를 정하는 데 쓰이지 않고, 이 표에서 유일하게
  //   여러 줄이 되는 칸이라 행 높이를 혼자 결정했다. 두 값 모두 finding_history.php 의
  //   '현재 상태' 카드(판정 근거 · 판정 출처)와 '스캔별 상태 타임라인'(회차별 근거)에 이미 있고,
  //   모든 행의 CVE 칸에 그리로 가는 '이 자산 판정 →' 링크가 있다.
  //   비운 폭(12.5%)은 전부 **식별자 열**로 돌린다 — 잘리면 대조 자체가 불가능해지는 값이라
  //   이 표에서 폭이 가장 아쉬운 곳이다(호스트 16→19 · CVE 15→17 · 패키지 10→14 · 조치 12→15.5).
  //   % 합(65.5%)과 고정폭(22rem) 총합은 이전과 같으므로 기존 실측 폭 예산이 그대로 유지된다.
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '19%', 'class' => 'col-id']];
  $headers = array_merge($headers, [
      // 뱃지 폭(CRITICAL 69px) + 칸 여백 32px = 101px → 6.5rem.
      ['label' => '등급',  'key' => 'severity',       'width' => '6.5rem', 'nowrap' => true],
      /* '노출 상태'·'조치 상태'·'기한' 세 열을 한 칸으로 합쳤다 — 셋 다 뱃지 하나짜리인데
       *   열을 따로 세우니 표가 10열이 되어 정작 '조치·올릴 버전' 이 눌렸다. 칸 안의 순서는
       *   vg_signal_slots() 의 축 순서(노출 → 조치)를 그대로 따르고 기한은 조치에 붙는다.
       *   합친 건 **표시뿐이고 쿼리는 그대로다** — 세 값 모두 원래 쿼리가 이미 들고 있던
       *   컬럼이라 SELECT·정렬·필터(st·fst·sort=due)는 한 글자도 바뀌지 않았다.
       *   vg_signal_slots() 네 칸을 행 안에 넣지 않은 이유: .signal-slots 는 min-width 18rem 이라
       *   폭이 고정된(table-layout:fixed) 이 표의 한 칸에 들어가면 표가 가로로 넘친다. */
      ['label' => '신호', 'key' => 'signals', 'width' => '9.5rem',
          'title' => '노출 상태(수집 결과) · 조치 상태와 남은 기한(사람이 정한 값)'],
      // CVE 는 nowrap 이 아니다 — 링크 뒤에 KEV·조치불가 표식이 붙어 한 줄에 안 들어간다.
      //   폭이 고정된 표에서 nowrap 이면 칸을 뚫고 나가 표가 가로로 넘친다. 대신 **식별자 자체가**
      //   쪼개지지 않게 셀에서 <code> 로 감싼다(app.css: td code 는 nowrap) — 예전엔 폭이 모자라
      //   'CVE-2023-' / '4911' 로 두 줄이 났다.
      // 폭 16% 는 실측값이다: 둘째 줄(KEV 뱃지 39px + '이 자산 판정 →' 92px = 135px)이 접히지
      //   않는 최소 폭(칸 여백 29px 포함 164px ≈ 15.5%)에 여유를 얹었다. 접히면 한 행이 세 줄이 된다.
      ['label' => 'CVE',   'key' => 'cve_id',         'width' => '17%'],
      ['label' => '패키지', 'key' => 'package_name',  'width' => '14%', 'class' => 'col-id'],
      // 점수 칸 — cves.php 의 같은 칸과 같은 모양·같은 정렬로 맞춘다(같은 뜻은 화면마다 같은 모양).
      //   6rem 은 둘째 줄 'EPSS 100.0%'(66px) + 칸 여백(29px) 기준이다.
      ['label' => 'CVSS',  'key' => 'risk',           'width' => '6rem', 'nowrap' => true,
          'align' => 'right', 'title' => 'CVSS 기본점수 · 아랫줄은 EPSS(30일 내 악용 확률)'],
      // 라벨에 '이 버전 이상' 을 못 담아 값 뒤에 '이상' 을 붙이던 것을 머리글로 올린다 —
      //   좁은 칸에서는 그 두 글자가 정작 버전 문자열을 밀어냈다.
      // col-fix: 이 칸에서만 버전 문자열의 줄바꿈을 허용한다(app.css '목록 화면' 구역).
      //   공용 .badge 는 nowrap 이라 rhel 모듈 버전이 12자에서 잘려 나갔는데, "무엇으로
      //   올려야 하는가" 가 이 열의 존재 이유라 잘리면 열 자체가 무의미해진다.
      ['label' => '조치 · 올릴 버전', 'key' => 'fix', 'width' => '15.5%', 'class' => 'col-fix',
          'title' => '이 버전 이상으로 올리면 해결됩니다'],
  ]);

  // 필터 초기화 CTA — vg_qs() 는 지금 $_GET 을 기준으로 넘겨받은 키만 비우므로, 단일 호스트
  //   모드(?host=N)·단일 스캔 모드(?scan_id=N)에서 눌러도 그 컨텍스트는 유지되고 필터만 지워진다
  //   (하드코딩된 '/findings.php' 였다면 호스트·스캔 컨텍스트까지 함께 날아갔다).
  // href 는 이중으로 안전하다: vg_qs() 자체가 모든 키·값을 urlencode() 하고(server/src/view/
  //   components.php 의 vg_qs 정의), 그 결과를 vg_empty() 가 다시 vg_h() 로 이스케이프해서
  //   출력한다(vg_empty 의 cta.href 렌더 라인 — title 과 동일한 규약). 그래서 호출부(여기)에서
  //   vg_h() 를 또 감싸면 '&' 가 '&amp;amp;' 로 이중 이스케이프된다 — 하면 안 된다.
  //   (같은 vg_qs() 를 KPI 카드처럼 직접 <a href=...> 를 만드는 코드에 쓸 땐, 그건 vg_empty() 를
  //   거치지 않으므로 그 호출부가 스스로 vg_h() 해야 한다 — 여기와는 다른 경로다.)
  //   tests/smoke.sh 가 임의 쿼리값 주입으로 이 전제를 회귀 검증한다.
  /* 표의 등급·노출 뱃지는 색으로 서열을 말하는데 그 색의 뜻이 화면에 없었다.
   *   어휘·톤은 각각 vg_sev_tone()·$scopeTone(노출 탭)이 소유한다 — 새 색을 만들지 않는다. */
  vg_legend(array_map(
      fn(string $s): array => ['label' => $s, 'tone' => vg_sev_tone($s), 'n' => (int) $counts[$s]],
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  ), ['inline' => true, 'caption' => '심각도']);

  $filterCta  = ['href' => vg_qs(['q' => '', 'sev' => '', 'st' => '', 'fx' => '', 'fst' => '', 'sort' => '', 'page' => 1]), 'label' => '필터 초기화'];
  $hasAnyFilter = $q !== '' || $sev !== '' || $st !== '' || $fx !== '' || $fst !== '' || $sort !== '';
  if ($scanId > 0 && !$scan) {
      // 단일 스캔 모드인데 그 스캔이 없는 경우(삭제됐거나 잘못된 id) — 필터 문제가 아니다.
      //   초기화 CTA 를 줘도 scan_id 는 그대로 유지돼(컨텍스트 보존이 이번 변경의 의도) 계속
      //   0건이므로, 전체 호스트 뷰로 보내는 별도 CTA 를 둔다.
      $emptySpec = [
          'icon'  => '📭',
          'title' => '스캔 #' . $scanId . ' 을(를) 찾을 수 없습니다.',
          'hint'  => '삭제됐거나 존재하지 않는 스캔입니다.',
          'cta'   => ['href' => '/findings.php', 'label' => '전체 호스트 보기'],
      ];
  } elseif (!$hostOptions) {
      // 필터 문제가 아니라 수집된 스캔 자체가 없는 경우 — "필터를 넓혀라" 는 오해를 준다.
      $emptySpec = [
          'icon'  => '📭',
          'title' => '아직 수집된 스캔이 없습니다.',
          'hint'  => '에이전트가 자산을 최소 한 번은 수집해야 이 화면에 판정이 뜹니다.',
      ];
  } elseif ($q !== '') {
      // $q 검색인데 0건이면 "필터를 넓혀라" 가 아니라 왜 안 나오는지를 알려준다 —
      //   vendor.php/packages.php 가 보여주는 패키지는 실제 설치 여부와 무관한 전역 데이터라,
      //   이 화면(호스트별 최신 스캔에서 매처가 실제로 잡은 판정)엔 없을 수 있다.
      $emptySpec = [
          'icon'  => '🔍',
          // title 은 vg_empty() 가 렌더링 시 vg_h() 로 이스케이프한다(cta.href 주석 참고 — 같은 함수).
          //   vg_trunc() 는 자체적으로 HTML/vg_h 를 반환하므로 여기서 같이 쓰면 이중 이스케이프로
          //   깨진다 — 그래서 순수 문자열 자르기(mb_strimwidth)만 쓴다. tests/smoke.sh 의
          //   "findings.php 검색어 XSS 이스케이프" 항목이 이 전제를 회귀 검증한다.
          'title' => "'" . mb_strimwidth($q, 0, 60, '…') . "' 는 이 화면(실제 스캔·매칭된 현재 판정)에는 없습니다.",
          'hint'  => '벤더 판정·영향 패키지 목록은 실제 설치 여부와 무관한 전역 데이터라 다를 수 있습니다. '
                   . '등급·상태·조치 가능성 필터도 확인해 보세요.',
          'cta'   => $filterCta,
      ];
  } elseif ($hasAnyFilter) {
      // 검색어 없이 등급·상태·조치 가능성만으로 0건 — KPI 카드 클릭으로 sev 가 걸린 경우
      //   특히 눈치채기 어려우므로 초기화 CTA 를 준다.
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '조건에 맞는 판정 결과가 없습니다.',
          'hint'  => '등급·상태·조치 가능성 필터를 넓혀 보세요.',
          'cta'   => $filterCta,
      ];
  } else {
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '조건에 맞는 판정 결과가 없습니다.',
          'hint'  => '검색어·등급·상태 필터를 넓혀 보세요.',
      ];
  }

  vg_table(
      $headers,
      $rows,
      [
          'empty' => $emptySpec,
          'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
          'cell' => [
              // 호스트는 이 표의 **주 식별자**다 — 어느 서버 얘긴지 모르면 나머지 값이 다 무의미하다.
              //   그런데 한 줄로 쓰면 칸 폭에 먹혀 'rollupchk.dep-rollup.example….' 로 끊겼다(실측).
              //   호스트 이름(첫 라벨)과 도메인을 두 줄로 나누면 같은 폭에서 보이는 글자 수가 두 배가
              //   되고, 이 표의 행은 이미 CVE·근거 칸 때문에 두 줄이라 행 높이도 안 는다.
              //   그래도 도메인이 길면 말줄임이 남으므로 전체 값은 title 로 남긴다(잘리는 열의 공통 규칙).
              'fqdn' => function ($r) {
                  $fqdn = (string) $r['fqdn'];
                  $dot  = strpos($fqdn, '.');
                  $head = $dot === false ? $fqdn : substr($fqdn, 0, $dot);
                  $rest = $dot === false ? '' : substr($fqdn, $dot);
                  return '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($fqdn) . '">'
                       . vg_h($head)
                       . ($rest === '' ? '' : '<div class="why">' . vg_h($rest) . '</div>')
                       . '</a>';
              },
              'severity'       => fn($r) => vg_sev_badge((string) $r['severity']),
              /* 신호 한 칸 — 노출(수집이 말하는 것) 윗줄, 조치와 기한(사람이 정하는 것) 아랫줄.
               *   값·톤·계산은 셋 다 원래 쓰던 헬퍼 그대로다(새로 세지 않는다).
               *   상태 라벨은 '로컬 세그먼트 노출' 처럼 길어 좁은 칸에선 말줄임에 먹히므로
               *   전체 문구를 title 로 남긴다(잘라야만 하는 값의 공통 규칙).
               *   조치 메모도 title 로만 준다 — 좁은 칸에 문장을 풀면 행 높이가 튄다. */
              'signals' => function ($r) use ($firstSeen, $policy) {
                  $exposure = '<span title="' . vg_h(vg_status_label($r['runtime_status'])) . '">'
                      . vg_status_badge($r['runtime_status']) . '</span>';

                  // 조치 상태 — 행이 없으면 미조치다(vg_finding_status_badge 가 null 을 OPEN 으로 눕힌다).
                  $note  = trim((string) ($r['finding_status_note'] ?? ''));
                  $fix   = vg_finding_status_badge($r['finding_status'] ?? null);
                  if ($note !== '') {
                      $fix = '<span title="' . vg_h(mb_strimwidth($note, 0, 120, '…')) . '">' . $fix . '</span>';
                  }

                  // 남은 일수 — 계산·표기는 vg_finding_due_cell() 하나가 갖는다(화면마다 다시 세지 않게).
                  $sla  = vg_finding_sla_days((bool) $r['in_kev'], (string) $r['severity'], $policy);
                  $seen = $firstSeen[vg_finding_status_key(
                      (int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                      (string) $r['cve_id'], (string) $r['package_name']
                  )] ?? null;
                  $due = vg_finding_due_cell(
                      $seen === null ? null : (int) $seen['days'], $sla,
                      $r['finding_status'] ?? null
                  );

                  return '<div>' . $exposure . '</div><div>' . $fix . ' ' . $due . '</div>';
              },
              // CVE — 링크 + KEV 뱃지(별도 컬럼이던 '✔' 를 여기로).
              // CVE 요약(summary)은 뺐다. 근거와 나란히 두면 긴 텍스트 컬럼이 둘이라
              // 표가 화면을 넘겨서 정작 제일 중요한 '조치' 가 밖으로 밀려난다.
              // 요약은 일반적인 CVE 설명이라 상세 페이지에 있고, 근거는 이 제품만의 판정 이유다.
              // 이 칸에 링크가 둘이다 — 둘의 대상이 다르므로 라벨로 구분한다.
              //   CVE-XXXX(=취약점 자체의 일반 설명, cve.php) / '이 자산 판정'(=이 호스트·패키지에서
              //   왜 그렇게 판정됐고 스캔마다 어땠는지, finding_history.php).
              //   진입로를 이 칸의 둘째 줄에 두는 이유: 행 높이는 '근거' 칸(clamp-2 = 두 줄)이
              //   결정하는데(아래 rationale 주석), CVE 칸은 보통 한 줄이라 여기 한 줄을 더해도
              //   행이 안 높아진다. '조치' 칸에 넣으면 조치 알약(clamp-2)이 이미 두 줄일 때 세 줄이 된다.
              'cve_id' => function ($r) {
                  // 식별자는 줄바꿈하면 안 된다 — 'CVE-2023-' / '4911' 로 쪼개지면 검색도 대조도
                  //   못 한다. <code> 는 app.css 에서 표 안 nowrap 이라(td code) 칸이 좁아도
                  //   하이픈에서 접히지 않는다. 칸 자체를 nowrap 으로 만들지 않는 건 뒤에 붙는
                  //   KEV·조치불가 표식이 잘려 사라지기 때문이다(cves.php 에 같은 기록이 있다).
                  // 두 줄 구조를 **마크업으로 고정**한다: 첫 줄은 식별자만, 둘째 줄에 표식과
                  //   진입로를 모은다. 예전처럼 식별자 옆에 뱃지를 흘려 두면 폭이 모자랄 때마다
                  //   뱃지가 다음 줄로 밀려 한 행이 세 줄이 됐다(KEV 행이 목록 맨 위를 채우므로
                  //   사실상 상단 전체가 세 줄이었다). 줄 수가 행마다 달라지지 않는 게 훑기에 낫다.
                  $html = '<div><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">'
                        . '<code>' . vg_h($r['cve_id']) . '</code></a></div>';
                  $marks = '';
                  if ($r['in_kev']) { $marks .= vg_badge('KEV', 'crit', 'CISA KEV 등재') . ' '; }
                  // 벤더가 수정본을 내지 않은 CVE — 패치로는 못 고친다(완화·격리·제거가 답).
                  // 뱃지 두 개가 겹쳐 시끄러워지는 걸 피하려고, 우선순위가 더 높은 KEV 만
                  // 뱃지로 두드러지게 하고 이건 평범한 텍스트(.why 톤)로 낮춘다 — 정보는 그대로.
                  if (!empty($r['no_fix'])) {
                      $marks .= '<span class="why">조치 불가</span> ';
                  }
                  $href = vg_finding_history_url(
                      (int) $r['host_id'], $r['container_id'] === null ? 0 : (int) $r['container_id'],
                      (string) $r['cve_id'], (string) $r['package_name']
                  );
                  $html .= '<div class="why">' . $marks . '<a href="' . vg_h($href) . '">이 자산 판정 →</a></div>';
                  return $html;
              },
              // 패키지 — 이름 + 설치 버전(아래줄).
              //   컨테이너 안의 취약점은 호스트 것과 조치 방법이 다르다(이미지 재빌드) → 구분해 보여준다.
              //   이미지는 버전 옆에 붙인다(칸을 새로 만들면 표가 다시 가로로 넘친다).
              'package_name' => function ($r) {
                  $name = vg_h((string) $r['package_name']);
                  $eco = vg_osv_ecosystem($r['package_os_id'] ?? null, $r['package_os_version'] ?? null);
                  if ($eco !== null) {
                      $name = '<a href="/package.php?name=' . urlencode((string) $r['package_name'])
                          . '&amp;eco=' . urlencode($eco) . '">' . $name . '</a>';
                  }
                  // col-id 열이라 넘치는 값은 말줄임으로 잘린다 — 이름·버전·이미지를 한 문장으로
                  //   모아 title 에 남긴다(호스트 칸과 같은 규칙).
                  $full = (string) $r['package_name'] . ' ' . (string) $r['installed_version']
                        . (!empty($r['container_cid']) ? ' · 컨테이너 ' . (string) $r['container_cid'] : '')
                        . (!empty($r['container_image']) ? ' · ' . (string) $r['container_image'] : '');
                  return '<span title="' . vg_h($full) . '">' . $name
                      . (!empty($r['container_cid']) ? ' ' . vg_badge('컨테이너 ' . $r['container_cid'], 'med') : '')
                      . '</span>'
                      . '<div class="why"><code>' . vg_h($r['installed_version']) . '</code>'
                      . (!empty($r['container_image']) ? ' · ' . vg_h((string) $r['container_image']) : '')
                      . '</div>';
              },
              // 위험도 — CVSS(얼마나 심한가) + EPSS(실제로 악용될 확률). 다른 걸 재므로 같이 본다.
              //   백분위("상위 N%")는 여기선 뺀다 — 좁은 칸에서 4줄로 접힌다. 상세 페이지에 있다.
              // 값 앞의 'CVSS' 다섯 글자를 뺀 이유: 이 칸에서 유일하게 안 잘려야 하는 건 **점수**인데,
              //   접두어가 폭을 먼저 먹어 정작 숫자가 잘려 나갔다(실측 'CVSS …' — 점수가 화면에서
              //   사라졌다). 무슨 숫자인지는 열 머리글('CVSS')이 말한다. EPSS 는 값이 둘째 줄이라
              //   무엇인지 알 수 없으므로 라벨을 남긴다.
              'risk' => function ($r) {
                  $cvss = $r['cvss'] !== null
                      ? '<strong>' . vg_h((string) $r['cvss']) . '</strong>'
                      : '<span class="why">–</span>';
                  $epss = $r['epss'] !== null && $r['epss'] !== ''
                      ? 'EPSS ' . vg_h(number_format((float) $r['epss'] * 100, 1)) . '%'
                      : 'EPSS –';
                  return $cvss . '<div class="why">' . $epss . '</div>';
              },
              // 설치 버전을 조치 칸에 다시 싣지 않는다(같은 행 '패키지' 칸에 이미 있다) — 한 칸에
              //   "설치 → 고침" 을 다 넣으니 알약이 세 줄이 되어 행 높이를 결정해 버렸다.
              // 조치 + 사람이 남긴 "미조치 사유" 표식. 사유 전문·승인자·승인일시는 이력 화면에 있다
              //   (좁은 칸에 사유 문장을 그대로 풀면 행 높이가 다시 근거 칸처럼 튄다 — title 로만 준다).
              //   예전엔 이 표식이 상세로 가는 링크였는데, 이제 CVE 칸의 '이 자산 판정 →' 가 모든 행에서
              //   같은 곳으로 간다 — 한 행에 같은 대상 링크가 둘이면 어느 쪽을 눌러야 하는지 헷갈린다.
              //   그래서 여기는 링크를 떼고 표식(뱃지)으로만 남긴다.
              // 값은 vg_fix_cell() 과 같지만 **모양은 이 표의 규칙**을 따른다. vg_fix_cell 의 알약
              //   (.pill)은 파란 배경 + 강조색 글자라, 링크가 아닌 '2.38-1ubuntu6 이상' 이 목록에서
              //   링크로 보였다(실측). 여기서는 중립 뱃지(tone-muted)로 낮추고, 이 칸에서 **진짜
              //   링크인 참조 URL 만** 링크색을 갖게 한다. 공용 헬퍼를 고치지 않는 이유: 같은 함수를
              //   폭이 다른 화면(host.php)이 함께 쓰고, 여기 필요한 건 이 표의 폭 규칙이라서다.
              'fix'       => function ($r) use ($notes) {
                  $fixed = (string) ($r['evidence_fixed_version'] ?? ($r['fixed_version'] ?? ''));
                  if ($fixed !== '') {
                      // 예전엔 12자에서 잘라 넣었다(vg_trunc) — rhel 모듈 버전
                      //   '1:1.22.1-3.module+el9.2.0+…' 이 '1:1.22.1-3….' 이 되어, 화면만 보고는
                      //   어느 버전으로 올려야 하는지 알 수 없었다. 자르는 대신 이 칸에서만
                      //   줄바꿈을 허용해(col-fix) 전체를 보인다. title 은 그대로 남긴다 —
                      //   줄바꿈된 값을 복사·대조할 때 원문 한 줄이 필요하다.
                      $html = '<span class="badge tone-muted" title="' . vg_h($fixed) . '">'
                            . vg_h($fixed) . '</span>';
                  } else {
                      // 참조 URL(벤더 어드바이저리·패치 링크)은 상세로 보냈다 — 목록의 이 칸이
                      //   답해야 하는 건 "어느 버전으로 올리나" 하나이고, 외부 링크는 그 답이
                      //   없을 때만 뜨는 곁가지였다. 같은 링크를 finding_history.php 의
                      //   '수정 버전'(vg_fix_cell 이 ref_urls_json 을 그대로 편다)과 cve.php 의
                      //   참조 목록이 이미 갖고 있고, 그 덕에 목록 쿼리에서 수 KB 짜리
                      //   ref_urls_json 을 안 실어 온다.
                      $html = '<span class="why">상세에서 확인</span>';
                  }
                  $note = $notes[vg_remediation_note_key(
                      (int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                      (string) $r['cve_id'], (string) $r['package_name']
                  )] ?? null;
                  if ($note !== null) {
                      $html .= ' ' . vg_badge('미조치 사유', 'info');
                  }
                  return $html;
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
