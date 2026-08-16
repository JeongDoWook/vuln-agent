<?php
declare(strict_types=1);
/* 자산 설정 탭 — 수집 제어 · 자산 등급 · 자산 삭제. */ ?>
    <?php if (vg_can('assets')): ?>
      <?php /* 처리 결과(등급 확정 포함)는 이 카드 안에서 한 번만 알린다 — 두 군데서 그리면 중복된다. */ ?>
      <?php vg_host_render_agent_control($hostId, $host, $agentCsrf, $pendingCommands, $agentMsg, $agentErr); ?>
    <?php else: ?>
      <?php /* 수집 제어 카드가 없는 역할(등급만 확정하는 관리자)도 처리 결과는 봐야 한다. */ ?>
      <?php vg_alert($agentMsg, 'ok'); vg_alert($agentErr); ?>
    <?php endif; ?>
    <?php vg_host_render_grade($hostId, $host, $gradeReview, $agentCsrf, $approver, vg_has_role('admin'), $gradeSignals); ?>
    <?php vg_asset_grade_history_render($gradeSuggestionHistory); ?>

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
