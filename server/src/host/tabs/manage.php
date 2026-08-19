<?php
declare(strict_types=1);
/* 자산 설정 탭 — 수집 제어 · 자산 등급 · 자산 삭제. */ ?>
    <?php /* 수집 제어 카드는 host.php 가 히어로 직후 상단에서 이미 그린다(어느 탭이든 공통) —
             여기서 또 그리면 중복이다. 그 카드가 없는 역할(등급만 확정하는 관리자)만
             처리 결과를 이 자리에서 알린다. */ ?>
    <?php if (!vg_can('assets')): ?>
      <?php vg_alert($agentMsg, 'ok'); vg_alert($agentErr); ?>
    <?php endif; ?>
    <?php /* 자산 상세는 findings 권한만으로도 열린다(host.php: vg_require_menu_any('assets','findings')).
             등급 카드는 확정자·확정 근거 등 인사 정보를 담으므로, findings 만 있는 계정에는
             내리지 않는다 — 이 카드만의 역할 검사(전체 탭 인가 재설계는 범위 밖). */ ?>
    <?php if (vg_can('assets')): ?>
      <?php vg_host_render_grade($hostId, $host, $gradeReview, $agentCsrf, $approver, vg_has_role('admin'), $gradeSignals); ?>
      <?php vg_asset_grade_history_render($gradeSuggestionHistory); ?>
    <?php endif; ?>

    <?php if (vg_has_role('admin', 'operator')): ?>
      <div class="card mt-lg">
        <strong>자산 관리</strong>
        <span class="why"> · 목록·집계에서만 제외합니다(수집 이력 보존)</span>
        <div class="card__body">
          <form method="post" class="actions" data-confirm="<?= vg_h((string)$host['fqdn']) ?> 자산을 삭제할까요? 수집 이력은 남고 목록·집계에서만 제외됩니다.">
            <input type="hidden" name="csrf" value="<?= vg_h($agentCsrf) ?>">
            <input type="hidden" name="action" value="host_delete">
            <input type="hidden" name="id" value="<?= (int)$host['host_id'] ?>">
            <button type="submit" class="btn btn--sm btn--danger">자산 삭제</button>
          </form>
        </div>
      </div>
    <?php endif; ?>
