<?php
declare(strict_types=1);

/**
 * connectors/form.php — 데이터 소스 **추가·편집 모달**(폼 본문)만 갖는다.
 *   저장 처리는 src/connector_actions.php(action='save'), 폼을 채울 값은
 *   connectors/queries.php 의 vg_connectors_edit_target() 이 만든다.
 */

/**
 * @param array|null $edit   편집 대상(없으면 '추가' 모달). 있으면 모달이 자동으로 열린다.
 * @param array      $econn  $edit 의 connection_json 을 편 것
 * @param array      $esched $edit 의 schedule_json 을 편 것
 */
function vg_connectors_render_form(?array $edit, array $econn, array $esched, string $csrf): void
{
    // 추가·편집 폼은 목록 아래 늘 펼쳐두던 것 → 버튼 뒤 모달로.
    // ?edit=N 으로 들어오면(행의 [편집]) 값이 채워진 채 자동으로 열린다.
    vg_modal_open('connModal', $edit ? '데이터 소스 편집' : '데이터 소스 추가', '', $edit !== null);

    /* 타입 → 수집 방식·노출 필드. 근거는 src/feeds.php 의 카탈로그 하나다 — PHP 가 첫 화면을
     * 그리고(JS 없이도 맞다), 같은 표를 JSON 으로 넘겨 JS 가 타입 변경 때 다시 그린다.
     * 표를 JS 에 복붙하면 커넥터가 늘 때 한쪽만 고쳐진다(data-edit-generic 이 쓰는 것과 같은 수법). */
    $typeMeta = [];
    foreach (VG_CONNECTOR_TYPES as $tv => $m) {
        $tr = VG_TRANSPORTS[$m['transport']];
        $typeMeta[$tv] = [
            'transport' => $tr['label'], 'tone' => $tr['tone'], 'desc' => $m['desc'],
            'fields'    => $m['fields'], 'urlLabel' => $m['url_label'] ?? '',
        ];
    }
    $curType = (string) ($edit['connector_type'] ?? 'kev');
    if (!isset($typeMeta[$curType])) { $curType = 'kev'; }
    $curMeta = $typeMeta[$curType];
    // 이 타입이 안 읽는 필드는 아예 숨긴다 — 예전엔 전 타입에 다 띄우고 라벨의 괄호로 변명했다.
    $fieldOn = fn(string $f): string => in_array($f, $curMeta['fields'], true) ? '' : ' hidden';

    // 폼 위 한 줄 도식 — 이 모달이 무엇을 묻는 폼인지(주소·인증·매핑·주기) 필드보다 먼저 말한다.
    //   필드는 타입에 따라 숨겨졌다 나타나서, 처음 여는 사람은 "지금 뭘 채우는 중인지" 를 잃는다.
    vg_explain_flow([
        ['icon' => 'feed',    'label' => '엔드포인트'],
        ['icon' => 'shield',  'label' => '인증'],
        ['icon' => 'process', 'label' => '매핑'],
        ['icon' => 'clock',   'label' => '주기'],
    ], ['label' => '데이터 소스 설정 순서']);
    ?>
    <?php /* .setting-form + .field — 라벨과 입력이 한 칸(.45rem) 안에서 붙고 항목끼리는 1rem 으로
             벌어진다(host.php 자산등급 폼과 같은 규약). 두 가지를 지킨다:
               · 라벨은 <label> 그대로 두고 감싸는 div 에만 .field 를 준다 — connectors.js 가
                 #urlLabel 의 textContent 를 갈아치우므로 라벨이 입력을 품으면 그 순간 입력이 사라진다.
               · JS/PHP 가 hidden 속성으로 껐다 켜는 상자(#stdFields·#genericFields·[data-field]·
                 [data-schedule-field])에는 .field/.setting-form 을 주지 않는다 — app.css 에
                 [hidden] 규칙이 없어서 display 를 정하는 클래스가 붙는 순간 hidden 이 무력해진다. */ ?>
    <form id="connForm" method="post" class="setting-form"
          data-edit-generic="<?= ($edit['connector_type'] ?? '') === 'generic_api' ? vg_h(json_encode($econn)) : '' ?>"
          data-type-meta="<?= vg_h(json_encode($typeMeta, JSON_UNESCAPED_UNICODE)) ?>"
          data-role-labels="<?= vg_h(json_encode(VG_GENERIC_ROLE_LABELS, JSON_UNESCAPED_UNICODE)) ?>">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="<?= (int) ($edit['feed_connector_id'] ?? 0) ?>">
      <?php /* 짧은 입력(이름·종류)은 2열로 눕힌다 — 한 줄씩 쌓으면 모달이 세로로만 길어져
               스케줄·활성이 스크롤 아래로 밀렸다. 감싸는 상자는 hidden 으로 껐다 켜지 않는
               것만 고른다(.form-grid 는 display:grid 라, 토글되는 상자에 붙이면 hidden 이 무력해진다
               — 위 주석의 같은 함정). */ ?>
      <div class="form-grid">
        <div class="field">
          <label for="connName">이름</label>
          <input type="text" id="connName" name="name" value="<?= vg_h($edit['name'] ?? '') ?>" required>
        </div>
        <div class="field">
          <label for="connType">소스 종류</label>
          <select name="connector_type" id="connType">
            <?php foreach (VG_CONNECTOR_TYPES as $tv => $m): ?>
              <option value="<?= vg_h($tv) ?>" <?= $curType===$tv?'selected':'' ?>><?= vg_h($m['label']) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
      </div>
      <?php /* 수집 방식 — 이 커넥터가 데이터를 어떻게 가져오는가(역할이 아니다. 역할은 목록의 그룹 카드). */ ?>
      <div class="connmeta" id="connTransport">
        <?= vg_badge($curMeta['transport'], $curMeta['tone']) ?>
        <div class="sub" id="connTransportDesc"><?= vg_h($curMeta['desc']) ?></div>
      </div>
      <?php /* #stdFields 자신에는 .form-grid 를 못 준다(JS 가 이 상자를 hidden 으로 통째로 껐다 켠다).
               안쪽에 격자 상자를 하나 더 둔다 — connectors.js 는 std.querySelectorAll('[data-field]')
               로 후손을 찾으므로 한 겹이 늘어도 그대로 동작한다. URL 은 값이 길어 한 줄을 다 쓴다. */ ?>
      <div id="stdFields">
        <div class="form-grid">
          <div class="form-grid__full" data-field="url"<?= $fieldOn('url') ?>>
            <label id="urlLabel" for="connUrl"><?= vg_h($curMeta['urlLabel'] ?: 'URL') ?></label>
            <input type="text" id="connUrl" name="url" value="<?= vg_h($econn['url'] ?? '') ?>" placeholder="비우면 기본 주소를 씁니다">
          </div>
          <div class="form-grid__full" data-field="api_key"<?= $fieldOn('api_key') ?>>
            <label for="connApiKey">API Key</label>
            <input type="text" id="connApiKey" name="api_key" value="<?= vg_h($econn['api_key'] ?? '') ?>">
          </div>
          <div data-field="ecosystem"<?= $fieldOn('ecosystem') ?>>
            <label for="connEcosystem">Ecosystem</label>
            <input type="text" id="connEcosystem" name="ecosystem" value="<?= vg_h($econn['ecosystem'] ?? '') ?>" placeholder="예: Rocky Linux">
          </div>
          <div data-field="days"<?= $fieldOn('days') ?>>
            <label for="connDays">최근 N일</label>
            <input type="text" id="connDays" name="days" value="<?= vg_h((string) ($econn['days'] ?? '')) ?>" placeholder="7">
          </div>
        </div>
      </div>
      <?php /* #stdFields 와 같은 이유로 안쪽에 격자 상자를 둔다(이 상자도 JS 가 통째로 토글한다).
               긴 값(URL 템플릿·헤더·아이템 경로·필드 매핑)만 한 줄을 다 쓰고, 짧은 것은 2열. */ ?>
      <div id="genericFields" hidden>
       <div class="form-grid">
        <div class="field">
          <label for="gRole">역할</label>
          <select id="gRole">
            <?php foreach (VG_GENERIC_ROLE_LABELS as $rv => $rl): ?>
              <option value="<?= vg_h($rv) ?>"><?= vg_h($rl) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="alert alert--warn form-grid__full" id="gRoleNotice" hidden>
          <strong>기존 설정의 역할은 더 이상 지원하지 않습니다.</strong>
          <ul class="hint-list"><li>지원되는 역할을 다시 선택해야 저장할 수 있습니다.</li></ul>
        </div>

        <div class="field">
          <label for="gMethod">HTTP 메서드</label>
          <select id="gMethod">
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
        </div>

        <div class="field form-grid__full">
          <label for="gUrlTemplate">URL 템플릿</label>
          <input type="text" id="gUrlTemplate" placeholder="https://api.example.com/vulns?page={page}">
          <div class="sub">플레이스홀더: <code>{page}</code>(1부터) · <code>{offset}</code>(0부터) · <code>{today}</code> · <code>{days_ago_N}</code></div>
        </div>

        <div class="field form-grid__full">
          <label>인증 헤더</label>
          <div id="gHeaders" class="kvrows"></div>
          <div><button type="button" class="btn btn--sm btn--ghost" id="gHeaderAdd">+ 헤더 추가</button></div>
        </div>

        <div class="field">
          <label for="gPageType">페이징 타입</label>
          <select id="gPageType">
            <option value="none">없음</option>
            <option value="offset">offset</option>
          </select>
        </div>
        <div class="field">
          <label for="gPageSize">페이지 크기</label>
          <input type="text" id="gPageSize" placeholder="100">
        </div>
        <div class="field">
          <label for="gTotalPath">총 건수 경로 (선택)</label>
          <input type="text" id="gTotalPath" placeholder="meta.total">
        </div>

        <div class="field form-grid__full">
          <label for="gItemsPath">응답 아이템 경로</label>
          <input type="text" id="gItemsPath" placeholder="data.vulnerabilities">
          <div class="sub">응답 JSON 안에서 목록 배열의 dot-notation 경로. 최상위 배열이면 비워둔다.</div>
        </div>

        <div class="field form-grid__full">
          <label>필드 매핑 <span id="gRoleLabel" class="why"></span></label>
          <div id="gFieldMap" class="kvrows"></div>
          <div class="sub">응답 JSON의 dot-notation 경로를 입력합니다. * 표시는 필수입니다.</div>
        </div>
       </div>

        <input type="hidden" name="g_config_json" id="gConfigJson">
      </div>
      <?php $sm = $esched['mode'] ?? 'manual'; ?>
      <?php /* 스케줄은 항상 "방식 + 그 방식의 값 하나" 라 2열이 정확히 맞는다(나머지 둘은 hidden).
               격자 상자 자체는 토글되지 않으므로 여기엔 .form-grid 를 바로 줘도 된다. */ ?>
      <div class="form-grid">
        <div class="field">
          <label for="connSchedule">스케줄</label>
          <select name="schedule_mode" id="connSchedule">
            <?php foreach (['manual'=>'수동 (직접 실행)','interval'=>'주기 실행','daily'=>'매일 지정 시각','cron'=>'cron 표현식'] as $mv=>$ml): ?>
              <option value="<?= $mv ?>" <?= $sm===$mv?'selected':'' ?>><?= $ml ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div data-schedule-field="interval"<?= $sm === 'interval' ? '' : ' hidden' ?>>
          <label for="connInterval">주기(분)</label>
          <input type="text" id="connInterval" name="interval_minutes" value="<?= vg_h((string) ($esched['interval_minutes'] ?? '1440')) ?>">
        </div>
        <div data-schedule-field="daily"<?= $sm === 'daily' ? '' : ' hidden' ?>>
          <label for="connTime">시각 (HH:MM)</label>
          <input type="text" id="connTime" name="schedule_time" value="<?= vg_h((string) ($esched['time'] ?? '03:00')) ?>" placeholder="03:00">
        </div>
        <div data-schedule-field="cron"<?= $sm === 'cron' ? '' : ' hidden' ?>>
          <label for="connCron">cron (분 시 일 월 요일)</label>
          <input type="text" id="connCron" name="schedule_cron" value="<?= vg_h((string) ($esched['expr'] ?? '')) ?>" placeholder="0 3 * * *">
        </div>
      </div>
      <label class="inline">
        <input type="checkbox" name="enabled" value="1" <?= ($edit['enabled'] ?? 0) ? 'checked' : '' ?>> 활성
      </label>
      <?php if ($edit): ?>
        <div class="sub center"><a href="/connectors.php">+ 새 데이터 소스</a></div>
      <?php endif; ?>
      <pre id="vgPrev" class="out" hidden></pre>
      <?php vg_modal_foot($edit ? '저장' : '추가', ['extra' =>
          // "API 미리보기" 였는데 12종 중 절반은 API 가 아니다(정적 파일·gz/bz2 덤프·RSS).
          // 주작업(저장)은 아니지만 저장 전에 눌러 보라고 권하는 버튼이라, ghost 보다 분명한 btn--secondary.
          '<button type="button" id="vgPrevBtn" class="btn btn--secondary" data-loading="조회 중…" data-feed-preview>미리보기 (10건)</button>']); ?>
    </form>
  <?php vg_modal_close();
}
