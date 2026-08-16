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
    $missingReview = vg_asset_grade_review_missing($review);
    ?>
    <section class="card mt-lg" aria-labelledby="asset-grade-title">
      <strong id="asset-grade-title">자산 등급</strong>
      <span class="why"> · N2SF 보안등급 <?= vg_h(vg_asset_grade_legend()) ?></span>
      <div class="card__body">
        <?php /* 여섯 항목 모두 "이 자산 등급의 현재 사실" 이다 — 뒤에 산문 문단으로 매달지 않고
                 같은 정의목록 안에 둔다. 제안값은 여기서도 '제안' 꼬리표를 달아 확정과 갈라 둔다. */ ?>
        <dl class="fact-grid">
          <div><dt>확정 등급</dt><dd><?= vg_asset_grade_badge($curGrade !== '' ? $curGrade : null, false, (string) ($host['grade_reason'] ?? '')) ?></dd></div>
          <div><dt>중요도</dt><dd><?= $curCrit !== '' ? vg_h(VG_ASSET_CRITICALITY[$curCrit] ?? $curCrit) : '<span class="why">–</span>' ?></dd></div>
          <div><dt>확정자</dt><dd><?= $approver !== null ? vg_h($approver) : '<span class="why">–</span>' ?></dd></div>
          <div><dt>확정 시각</dt><dd><?= !empty($host['approved_at']) ? vg_h((string) $host['approved_at']) : '<span class="why">–</span>' ?></dd></div>
          <div><dt>확정 근거</dt><dd><?= $curGrade !== '' && !empty($host['grade_reason'])
              ? vg_h((string) $host['grade_reason'])
              : '<span class="why">–</span>' ?></dd></div>
          <div><dt>시스템 초안</dt><dd><?= $sugGrade !== null
              ? vg_asset_grade_badge((string) $sugGrade, true, $sugReason) . ' <span class="why">' . vg_h($sugReason) . '</span>'
              : '<span class="why">근거 부족 — 제안 없음</span>' ?></dd></div>
        </dl>

        <?php /* 제안 근거를 한 줄 문자열로만 두면 사람이 "무엇 때문에 S 인가"를 못 읽는다 —
                 등급을 만든 신호와, 등급을 만들지는 않지만 확정 회의에서 볼 신호를 갈라 보여준다.
                 목록의 정본은 assetgrade.php 의 상수다(화면에 분류표를 늘리지 않는다). */ ?>
        <?php if ($signals): ?>
          <p class="why mt-lg">시스템이 본 신호 — 이 근거들 때문에 위 초안이 나왔습니다. 확정은 사람이 합니다.</p>
          <div class="badge-set">
            <?php foreach ($signals as $sig): ?>
              <?= vg_badge(
                    ($sig['grade'] !== null ? $sig['grade'] . ' · ' : '검토 · ') . $sig['label'],
                    (string) $sig['tone'],
                    $sig['evidence'] . ' ' . $sig['note']
                  ) ?>
            <?php endforeach; ?>
          </div>
          <ul class="hint-list">
            <?php foreach ($signals as $sig): ?>
              <li><span class="why"><?= vg_h(($sig['grade'] !== null ? '[' . $sig['grade'] . ' 근거] ' : '[검토 신호] ')
                  . $sig['evidence'] . ' ' . $sig['note']) ?></span></li>
            <?php endforeach; ?>
          </ul>
        <?php elseif ($host['grade_suggested'] ?? null): ?>
          <p class="why mt-lg">이 스캔에서는 제안 근거 신호를 다시 읽지 못했습니다 — 위 초안은 이전 관찰 결과입니다.</p>
        <?php endif; ?>

        <p class="why mt-lg">정보공개법 제9조 해당 여부는 C/S/O 판단 근거 중 하나이며, 법률이 C/S/O 등급을 정의하는 것은 아닙니다.</p>
        <?php if ($canEdit && !empty($review['is_stale'])): ?>
          <p class="why">⚠ 일괄 등급 변경 뒤 구조화 검토 정보가 재확인되지 않았습니다. 현재 등급에 맞게 다시 검토해 저장하세요.</p>
        <?php elseif ($canEdit && vg_asset_grade_review_overdue($review)): ?>
          <p class="why">⚠ 다음 검토일이 지났습니다. 현재 등급과 구조화 검토 정보를 다시 확인하세요.</p>
        <?php elseif ($canEdit && $curGrade !== '' && $missingReview): ?>
          <p class="why">⚠ 검토 정보 누락: <?= vg_h(implode(', ', $missingReview)) ?></p>
        <?php endif; ?>
        <?php if ($canEdit): ?>
        <dl class="fact-grid">
          <div><dt>제9조 해당 호</dt><dd><?= vg_h(VG_ASSET_REVIEW_ARTICLE9_ITEMS[(string) ($review['article9_item'] ?? '')] ?? '–') ?></dd></div>
          <div><dt>조문·판단 참조</dt><dd><?= vg_h((string) ($review['article9_reference'] ?? '–')) ?></dd></div>
          <div><dt>업무 유형</dt><dd><?= vg_h((string) ($review['business_category'] ?? '–')) ?></dd></div>
          <div><dt>데이터 유형</dt><dd><?= vg_h((string) ($review['data_category'] ?? '–')) ?></dd></div>
          <div><dt>소유 부서</dt><dd><?= vg_h((string) ($review['owning_department'] ?? '–')) ?></dd></div>
          <div><dt>외부 공개 상태</dt><dd><?= vg_h(VG_ASSET_REVIEW_PUBLICATION_STATES[(string) ($review['external_publication_state'] ?? '')] ?? '–') ?></dd></div>
          <div><dt>검토 문서·티켓</dt><dd><?= vg_h((string) ($review['review_reference'] ?? '–')) ?></dd></div>
          <div><dt>다음 검토일</dt><dd><?= vg_h((string) ($review['next_review_date'] ?? '–')) ?></dd></div>
        </dl>
        <?php endif; ?>

        <?php if ($canEdit): ?>
          <form class="setting-form mt-lg" method="post"
                data-confirm="이 자산의 등급을 확정할까요? 확정자와 시각이 감사로그에 기록됩니다.">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="host_set_grade">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <input type="hidden" name="review_version" value="<?= (int) ($review['review_version'] ?? 0) ?>">
            <input type="hidden" name="grade_version" value="<?= (int) ($host['grade_version'] ?? 0) ?>">

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

            <label class="field" for="asset-grade-reason">확정 근거
              <input id="asset-grade-reason" type="text" name="grade_reason" maxlength="255"
                     placeholder="예: 「정보공개법」 제9조 제6호 해당 업무정보 보유"
                     value="<?= vg_h((string) ($host['grade_reason'] ?? '')) ?>">
            </label>

            <label class="field" for="asset-article9-item">정보공개법 제9조 해당 호
              <select id="asset-article9-item" name="article9_item">
                <option value="">미지정</option>
                <?php foreach (VG_ASSET_REVIEW_ARTICLE9_ITEMS as $v => $label): ?>
                  <option value="<?= vg_h((string) $v) ?>"<?= ($review['article9_item'] ?? null) === (string) $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label class="field" for="asset-article9-reference">조문·판단 참조
              <input id="asset-article9-reference" name="article9_reference" maxlength="255" value="<?= vg_h((string) ($review['article9_reference'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-business-category">업무 유형
              <input id="asset-business-category" name="business_category" maxlength="100" value="<?= vg_h((string) ($review['business_category'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-data-category">데이터 유형
              <input id="asset-data-category" name="data_category" maxlength="100" value="<?= vg_h((string) ($review['data_category'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-owning-department">소유 부서
              <input id="asset-owning-department" name="owning_department" maxlength="120" value="<?= vg_h((string) ($review['owning_department'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-publication-state">외부 공개 상태
              <select id="asset-publication-state" name="external_publication_state">
                <option value="">미지정</option>
                <?php foreach (VG_ASSET_REVIEW_PUBLICATION_STATES as $v => $label): ?>
                  <option value="<?= vg_h($v) ?>"<?= ($review['external_publication_state'] ?? null) === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label class="field" for="asset-review-reference">검토 문서·티켓 참조
              <input id="asset-review-reference" name="review_reference" maxlength="255" placeholder="예: SEC-1234, 보안검토 회의록 2026-03" value="<?= vg_h((string) ($review['review_reference'] ?? '')) ?>">
              <span class="why">문서 내용이 아니라 식별자나 위치만 남깁니다.</span>
            </label>
            <label class="field" for="asset-next-review-date">다음 검토일
              <input id="asset-next-review-date" type="date" name="next_review_date" value="<?= vg_h((string) ($review['next_review_date'] ?? '')) ?>">
            </label>

            <div class="actions">
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
