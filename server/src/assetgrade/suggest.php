<?php
declare(strict_types=1);

/**
 * assetgrade/suggest.php — 모은 신호로 **초안 등급을 제안**한다(판정층).
 *   이 파일이 지키는 경계: 확신이 없으면 제안하지 않고, **C 는 자동으로 제안하지 않는다**
 *   (「정보공개법」 제9조 해당 여부는 법적 판단이다). 확정은 confirm.php 한 곳만 한다.
 */

/**
 * 이 스캔의 수집 데이터만 보고 **초안 등급을 제안**한다. 확신이 없으면 제안하지 않는다.
 *
 * 우선순위: S 근거(로그·백업 / 데이터 저장소 / 인증·비밀) > 외부노출(O). 둘 다 해당하면
 *   보호수준이 높은 S 를 제안한다 — 외부에 열려 있다는 사실이 "공개해도 되는 정보"를
 *   뜻하지는 않기 때문이다. **C 는 자동으로 제안하지 않는다**(VG_ASSET_DATA_ROLES 주석 참고).
 *
 * source 는 이 제안을 **처음 뒷받침한** 근거의 종류다(우선순위대로 log_listener > process >
 *   external_exposure). 이력 기록이 "그 근거를 만든 수집 단계가 실제로 들어왔는가"를 판정해
 *   수집 누락과 근거 없음을 구분하는 데 쓴다 — 근거를 여러 개 모아도 판정에 필요한 단계는
 *   가장 먼저 성립한 근거의 단계다. 보조 신호(kind=review)는 source 를 만들지 않는다:
 *   그 신호만 있는 자산은 여전히 "근거 없음" 이지 "판정 불가" 가 아니다.
 *
 * @return array{grade:string,source:string,reason:string}|null 제안이 없으면 null
 */
function vg_asset_grade_suggest(PDO $pdo, int $scanId): ?array
{
    $signals = vg_asset_grade_signals($pdo, $scanId);

    $sEvidence = [];
    $sSource = null;
    $oEvidence = null;
    $review = [];
    foreach ($signals as $sig) {
        if ($sig['kind'] === 'review') { $review[] = $sig['evidence']; continue; }
        if ($sig['grade'] === 'S') {
            $sEvidence[] = $sig['evidence'];
            $sSource = $sSource ?? (string) $sig['source'];
        } elseif ($sig['grade'] === 'O') {
            $oEvidence = $sig['evidence'];
        }
    }

    if ($sEvidence) {
        // 보조 신호는 **맨 뒤**에 붙인다 — 255자 상한에 잘리더라도 등급을 만든 근거가 먼저 남는다.
        $sEvidence = array_merge($sEvidence, $review);
        if ($oEvidence !== null) { array_splice($sEvidence, 1, 0, [$oEvidence]); }
        array_unshift($sEvidence, 'S 초안(사람 확인 전 미확정).');
        return [
            'grade'  => 'S',
            'source' => (string) $sSource,
            'reason' => vg_asset_grade_reason($sEvidence),
        ];
    }

    if ($oEvidence !== null) {
        return [
            'grade'  => 'O',
            'source' => 'external_exposure',
            'reason' => vg_asset_grade_reason(
                array_merge([$oEvidence, '사람 확인 전에는 확정되지 않습니다.'], $review)
            ),
        ];
    }

    return null;   // 근거 없음 → 제안하지 않는다
}
