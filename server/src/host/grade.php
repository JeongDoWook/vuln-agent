<?php
declare(strict_types=1);

/**
 * host/grade.php — 자산 등급 카드(중요도·N2SF C/S/O 를 사람이 확정하는 폼).
 *   등급 어휘·제안 계산은 src/assetgrade.php, 검토 정보 저장은 src/asset_grade_review.php 가
 *   갖는다 — 이 파일은 그 값을 화면으로 세우는 일만 한다.
 */

/**
 * 자산 등급 카드 — 중요도(상/중/하)와 N2SF 등급(C/S/O)을 **사람이 확정**하는 폼.
 *
 *   이 화면이 지키는 경계: 시스템 제안(grade_suggested)은 "참고" 자리에만 두고, 확정 입력의
 *   기본 선택으로 미리 채우지 않는다. 미리 채우면 사람이 그대로 저장하게 되어 사실상
 *   시스템이 등급을 정한 것이 된다. 등급 판정은 「정보공개법」 제9조 호 매핑에 따른 기관의
 *   법적 처분이므로 시스템이 대신할 수 없다.
 *
 *   $canEdit=false 면 읽기 전용으로 현재 값만 보여준다(확정은 관리자만).
 */
function vg_host_render_grade(int $hostId, array $host, array $review, string $csrf, ?string $approver, bool $canEdit, array $signals = []): void {
    $curGrade = (string) ($host['grade'] ?? '');
    $curCrit  = (string) ($host['criticality'] ?? '');
    $sugGrade = $host['grade_suggested'] ?? null;
    $sugReason = (string) ($host['grade_suggested_reason'] ?? '');
    ?>
    <section class="card mt-lg" aria-labelledby="asset-grade-title">
      <strong id="asset-grade-title">자산 등급</strong>
      <span class="why"> · N2SF 보안등급 <?= vg_h(vg_asset_grade_legend()) ?></span>
      <div class="card__body">
        <?php
        /* 여섯 항목(확정 등급·중요도·확정자·확정 시각·확정 근거·시스템 초안)을 2×3 정의목록으로
         *   세우던 자리다. 확정 전 자산에서는 여섯 칸 중 다섯이 '–' 라 빈 칸이 화면만 먹었다 —
         *   **사실을 지우는 게 아니라 한 줄로 접는다**: 확정된 자산은 확정 정보를, 미확정 자산은
         *   시스템 초안을 그 한 줄에 담는다. 아래 폼이 같은 값을 입력칸으로 다시 보여준다. */
        $gradeLine = [];
        if ($curGrade !== '') {
            $gradeLine[] = vg_asset_grade_badge($curGrade, false, (string) ($host['grade_reason'] ?? '')) . ' 확정';
            if ($curCrit !== '') { $gradeLine[] = '중요도 ' . vg_h(VG_ASSET_CRITICALITY[$curCrit] ?? $curCrit); }
            if ($approver !== null) { $gradeLine[] = vg_h($approver); }
            if (!empty($host['approved_at'])) { $gradeLine[] = vg_h((string) $host['approved_at']); }
            if (!empty($host['grade_reason'])) { $gradeLine[] = vg_trunc((string) $host['grade_reason'], 40); }
        } else {
            $gradeLine[] = '<strong>등급 미확정</strong>';
            if ($curCrit !== '') { $gradeLine[] = '중요도 ' . vg_h(VG_ASSET_CRITICALITY[$curCrit] ?? $curCrit); }
            $gradeLine[] = $sugGrade !== null
                ? '시스템 초안 ' . vg_asset_grade_badge((string) $sugGrade, true, $sugReason)
                : '시스템 초안 없음(근거 부족)';
        }
        ?>
        <p class="grade-summary"><?= implode(' · ', $gradeLine) ?></p>

        <?php /* 근거 문장을 배지 title(tooltip)에만 담으면 터치·키보드·Ctrl+F·복사·인쇄에서
                 사라진다 — 이 화면은 정보공개법 제9조 근거를 남기는 법적 증빙 화면이라 실질적
                 정보 손실이다. 배지는 요약으로 그대로 두고, 문장은 이미 이 파일이 쓰는 <details>
                 접기로 본문에 남긴다(접혀 있어도 펼치면 텍스트로 읽힌다). 목록의 정본은
                 assetgrade.php 의 상수다(분류표를 화면에 늘리지 않는다). */ ?>
        <?php if ($signals): ?>
          <div class="badge-set mt-lg">
            <?php foreach ($signals as $sig): ?>
              <?= vg_badge(($sig['grade'] !== null ? $sig['grade'] . ' · ' : '검토 · ') . $sig['label'], (string) $sig['tone']) ?>
            <?php endforeach; ?>
          </div>
          <details class="grade-review">
            <summary>시스템이 본 신호의 근거 (<?= count($signals) ?>건)</summary>
            <?php /* 한 줄에 **그대로 들어가는 사실 한 문장**만 세운다 — 등급 기호 + 근거(evidence).
                     evidence 는 이미 "업무 데이터 저장소 3건(etcd 외 2건)." 처럼 라벨과 건수를
                     제 안에 갖고 있어서 라벨을 앞에 한 번 더 붙이면 같은 말이 두 번 나온다.
                     예전엔 거기에 해설(note)까지 이어 붙이고 60자에서 vg_trunc 로 잘랐다 —
                     다섯 줄이 전부 '…' 로 끝나 정작 무슨 신호인지 안 읽혔다(사용자: "막 길게
                     설명하지 마. 아주 간략하게"). 해설은 지우지 않고 줄의 툴팁으로 내린다. */ ?>
            <ul class="why mt-lg">
              <?php foreach ($signals as $sig): ?>
                <?php
                $sigGrade = $sig['grade'] !== null ? (string) $sig['grade'] : '';
                $sigText  = rtrim((string) ($sig['evidence'] ?: $sig['label']), '.');
                /* 등급 신호 하나(외부 노출)는 evidence 가 이미 'O 외부노출 4개' 로 등급 기호를
                   달고 있다(그 문장이 그대로 tb_host.grade_suggested_reason 에 저장되기 때문).
                   앞에 기호를 한 번 더 붙이면 'O · O 외부노출 4개' 가 된다 — 겹치면 뗀다. */
                if ($sigGrade !== '' && strncmp($sigText, $sigGrade . ' ', strlen($sigGrade) + 1) === 0) {
                    $sigText = substr($sigText, strlen($sigGrade) + 1);
                }
                ?>
                <li<?= $sig['note'] !== '' ? ' title="' . vg_h((string) $sig['note']) . '"' : '' ?>><?=
                  vg_h(($sigGrade !== '' ? $sigGrade . ' · ' : '검토 · ') . $sigText) ?></li>
              <?php endforeach; ?>
            </ul>
          </details>
        <?php elseif ($host['grade_suggested'] ?? null): ?>
          <p class="why mt-lg">이전 관찰로 만든 초안 — 이번 수집의 근거 신호는 없음.</p>
        <?php endif; ?>

        <?php if ($canEdit): ?>
          <form class="setting-form mt-lg" method="post"
                data-confirm="이 자산의 등급을 확정할까요? 확정자와 시각이 감사로그에 기록됩니다.">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="host_set_grade">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <input type="hidden" name="review_version" value="<?= (int) ($review['review_version'] ?? 0) ?>">
            <input type="hidden" name="grade_version" value="<?= (int) ($host['grade_version'] ?? 0) ?>">

            <?php /* 확정 입력 두 칸은 셀렉트 하나씩이라 한 줄씩 쌓으면 오른쪽 절반이 늘 빈다.
                     수집 제어가 같은 이유로 두 칸 격자를 쓰고 있어 공용 헬퍼(.form-grid)로 맞춘다 —
                     이 화면 전용 격자를 새로 만들지 않는다. 좁은 화면에선 .form-grid 가 알아서 한 열로 떨어진다. */ ?>
            <div class="form-grid">
              <label class="field" for="asset-criticality">중요도
                <select id="asset-criticality" name="criticality">
                  <option value="">미지정</option>
                  <?php foreach (VG_ASSET_CRITICALITY as $v => $label): ?>
                    <option value="<?= vg_h($v) ?>"<?= $curCrit === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                  <?php endforeach; ?>
                </select>
              </label>

              <label class="field" for="asset-grade">보안등급 (N2SF)
                <select id="asset-grade" name="grade">
                  <option value="">미지정(확정 해제)</option>
                  <?php foreach (VG_ASSET_GRADES as $v => $label): ?>
                    <option value="<?= vg_h($v) ?>"<?= $curGrade === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                  <?php endforeach; ?>
                </select>
              </label>
            </div>

            <?php /* 확정 근거 아홉 칸(확정 근거·정보공개법 제9조 관련 구조화 검토 정보)은
                     이 화면에서 완전히 걷어냈다(사용자 확인) — 값은 tb_asset_grade_review·
                     tb_host.grade_reason 에 남아 있고 스키마도 그대로다, 이 폼만 안 보여준다.
                     제출 처리(agent_control.php host_set_grade)는 이 필드들이 $_POST 에
                     없을 때 기존 저장값을 그대로 유지하도록 처리돼 있다 — 등급만 바꿔도
                     예전 근거가 null 로 지워지지 않는다. */ ?>

            <?php /* 확정 버튼은 오른쪽 끝이다 — 폼의 마지막 조작이 왼쪽 구석에 서면 아홉 칸을
                     훑어 내려온 시선이 되돌아가야 한다(사용자 지적). */ ?>
            <div class="actions actions--end">
              <button type="submit" class="btn btn--sm btn--primary">등급 확정</button>
            </div>
          </form>
        <?php else: ?>
          <p class="why">등급 확정은 관리자만 할 수 있습니다.</p>
        <?php endif; ?>
      </div>
    </section>
    <?php
}
