<?php
declare(strict_types=1);
/* 자산 설정 탭 — 수집 제어 · 자산 등급 · 자산 삭제. */ ?>
    <?php /* 수집 제어 카드는 host.php 가 히어로 직후 상단에서 이미 그린다(어느 탭이든 공통) —
             여기서 또 그리면 중복이다. 처리 결과 알림도 host.php 가 페이지 레벨에서 한 번만
             그린다(탭·assets 권한과 무관하게 늘 보인다) — 여기서 또 그리지 않는다. */ ?>
    <?php /* 자산 상세는 findings 권한만으로도 열린다(host.php: vg_require_menu_any('assets','findings')).
             등급 카드는 확정자·확정 근거 등 인사 정보를 담으므로, findings 만 있는 계정에는
             내리지 않는다 — 이 카드만의 역할 검사(전체 탭 인가 재설계는 범위 밖). */ ?>
    <?php /* 자산 삭제는 탭 맨 아래 카드 구석에 있어 화면 밖으로 밀려 안 보였다 —
             탭 상단 우측으로 올린다. 위험 톤(btn--danger)과 확인 대화상자(data-confirm)는
             그대로다. "목록·집계에서만 제외한다(수집 이력 보존)" 는 사실은 화면의 설명 줄이
             아니라 **확인 대화상자 문구**가 계속 갖는다 — 정작 읽어야 할 순간에 나온다. */ ?>
    <?php if (vg_has_role('admin', 'operator')): ?>
      <div class="manage-head">
        <form method="post" data-confirm="<?= vg_h((string)$host['fqdn']) ?> 자산을 삭제할까요? 수집 이력은 남고 목록·집계에서만 제외됩니다.">
          <input type="hidden" name="csrf" value="<?= vg_h($agentCsrf) ?>">
          <input type="hidden" name="action" value="host_delete">
          <input type="hidden" name="id" value="<?= (int)$host['host_id'] ?>">
          <button type="submit" class="btn btn--sm btn--danger">자산 삭제</button>
        </form>
      </div>
    <?php endif; ?>

    <?php if (vg_can('assets')): ?>
      <?php vg_host_render_grade($hostId, $host, $gradeReview, $agentCsrf, $approver, vg_has_role('admin'), $gradeSignals); ?>
      <?php vg_asset_grade_history_render($gradeSuggestionHistory); ?>
    <?php endif; ?>

