<?php
declare(strict_types=1);

/**
 * assets/modal_grade.php — 자산 목록의 **등급 일괄 확정 입력창**(모달 본문)만 갖는다.
 *   저장 처리는 assets/confirm_post.php → vg_asset_grade_confirm() 이고, 여기엔 입력 폼뿐이다.
 *
 *   호출 위치가 중요하다: 이 모달은 **표를 감싼 폼 안**에서 그려야 한다. 네이티브 dialog 는
 *   렌더링만 top-layer 로 올라가고 DOM 상 폼 소속은 그대로라, 표의 host_ids[] 와 이 안의
 *   등급·근거가 한 번에 전송된다(밖에 두면 체크한 자산이 하나도 안 실려 간다).
 */

/** @param array $gradeTone 등급 뱃지와 같은 톤 표(화면이 소유한다 — 같은 값을 두 색으로 부르지 않는다). */
function vg_assets_render_grade_modal(array $gradeTone): void
{
    ?>
    <?php /* 확정 입력창. **폼 안**에 둔다 — 네이티브 dialog 는 렌더링만 top-layer 로 올라가고
             DOM 상 폼 소속은 그대로라, 표의 host_ids[] 와 이 안의 등급·근거가 한 번에 전송된다.
             (밖에 두면 체크한 자산이 하나도 안 실려 간다.) */ ?>
    <?php vg_modal_open('bulkGrade', '선택 자산 등급 일괄 확정'); ?>
      <p class="why" data-bulk-summary>선택한 자산이 없습니다.</p>

      <?php /* 등급 셋의 뜻은 문장이 아니라 세 칸으로 세운다 — 고르는 자리 바로 위에서
               "무엇을 고르는 것인지" 가 색과 함께 읽혀야 한다. 칸의 순서 자체가 승계 규칙
               (O < S < C — 오른쪽이 더 강한 보호)이고, 색은 등급 뱃지와 같은 톤을 쓴다.
               어휘는 assetgrade.php(VG_ASSET_GRADES)가 소유한다 — 여기서 다시 적지 않는다.
               두 번째 vg_explain_flow() 를 세우지 않는 건 도식은 화면당 하나라는 규칙 때문이다
               (docs/dev/ui-design-system.md) — 상단 흐름 도식이 이미 이 화면의 하나다. */ ?>
      <div class="cards">
        <?php foreach (['O' => '공개해도 되는 정보', 'S' => '제한적으로 다루는 정보',
                        'C' => '「정보공개법」 제9조 비공개 대상'] as $g => $note): ?>
          <div class="kpi kpi--sm tone-<?= vg_h($gradeTone[$g]) ?>">
            <b><?= vg_h($g) ?></b><span><?= vg_h(VG_ASSET_GRADES[$g]) ?></span>
            <span class="why"><?= vg_h($note) ?></span>
          </div>
        <?php endforeach; ?>
      </div>
      <p class="why">한 정보시스템에 여러 등급이 섞이면 오른쪽(더 강한 보호)을 승계합니다.</p>

      <label for="bulk-criticality">중요도</label>
      <select id="bulk-criticality" name="criticality">
        <option value="">변경 안 함</option>
        <?php foreach (VG_ASSET_CRITICALITY as $v => $label): ?>
          <option value="<?= vg_h($v) ?>"><?= vg_h($label) ?></option>
        <?php endforeach; ?>
      </select>

      <label for="bulk-grade">보안등급 (N2SF)</label>
      <select id="bulk-grade" name="grade" required>
        <option value="">선택</option>
        <?php foreach (VG_ASSET_GRADES as $v => $label): ?>
          <option value="<?= vg_h($v) ?>"><?= vg_h($label) ?></option>
        <?php endforeach; ?>
      </select>

      <label for="bulk-grade-reason">확정 근거</label>
      <input id="bulk-grade-reason" type="text" name="grade_reason" maxlength="255"
             placeholder="예: 「정보공개법」 제9조 제6호 해당 업무정보 보유">

      <?php /* 판정 기준은 산문이 아니라 정의목록으로 준다 — 등급 어휘는 assetgrade.php 가 소유하고
               (같은 문자열을 화면마다 다시 적지 않는다), 나머지는 이 폼이 실제로 하는 일이다. */ ?>
      <dl class="criteria">
        <?php /* 등급 어휘·기준은 바로 위 세 칸이 색과 함께 말한다 — 같은 말을 두 번 하지 않고,
                 여기엔 그 칸에 못 담는 것(누가 확정하는가)만 남긴다. */ ?>
        <dt>보안등급</dt>
        <dd>N2SF 등급 확정은 기관의 법적 처분이라 시스템이 대신하지 않습니다.</dd>
        <dt>중요도</dt>
        <dd>상 / 중 / 하 — 등급과 별개로 사람이 지정합니다. ‘변경 안 함’ 이면 지금 값을 그대로 둡니다.</dd>
        <dt>확정 범위</dt>
        <dd>지금 보고 있는 페이지에서 고른 자산만, 한 번에 500대까지. 자산마다 확정자·시각이 감사로그에 남습니다.</dd>
        <dt>구조화 검토 정보</dt>
        <dd>호스트마다 달라 일괄 입력하지 않습니다. 기존 정보는 재검토 필요 상태가 되며, 확정 후 각 자산 상세에서 제9조 해당 호, 업무·데이터 유형, 소유 부서, 공개 상태, 검토 문서와 재검토일을 다시 확인하세요.</dd>
      </dl>
      <?php vg_modal_foot('등급 확정', ['loading' => '확정 중…', 'cancel' => '취소']); ?>
    <?php vg_modal_close(); ?>
  <?php
}
