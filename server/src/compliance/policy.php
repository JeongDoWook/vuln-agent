<?php
declare(strict_types=1);

/**
 * compliance/policy.php — 판정 기준값·판정 어휘·통제 목록(SSOT).
 *   통제 4종의 판정 함수(patch/asset/secconfig/account)와 스냅샷이 전부 여기 값을 쓴다.
 *   여기서 갈라지면 화면과 증적의 기준이 갈라진다 — 그래서 한 파일이 소유한다.
 *
 *   ※ compliance.php 가 로드한다. 세션·인가·출력은 여기 두지 않는다(CLI 에서도 로드된다).
 */

require_once __DIR__ . '/../setting.php';    // vg_setting_int — 조직별 SLA·컷라인

// SLA 기준의 **폴백값**. 실제 판정은 tb_setting 의 값을 쓰고(조직마다 SLA 가 다르다),
//   설정 행이 없거나 설정 테이블을 못 읽으면 여기 값으로 지금과 동일하게 동작한다.
//   KEV 등재가 가장 급하고, 그다음 CRITICAL, HIGH 순.
const VG_COMPLIANCE_SLA_KEV_DAYS  = 15;
const VG_COMPLIANCE_SLA_CRIT_DAYS = 30;
const VG_COMPLIANCE_SLA_HIGH_DAYS = 60;

// 위반 건수 → 준수 상태 컷라인의 폴백값. 세 통제가 전부 같은 어휘를 쓴다(사용자가 한 화면에서
//   "몇 건부터 부분준수인가"를 매 통제마다 다시 배우지 않게).
const VG_COMPLIANCE_PARTIAL_MAX = 5;   // 1~5건 = 부분준수, 6건 이상 = 미준수

// first_seen 배치 쿼리가 되짚어볼 구간의 **여유일**. 실제 구간 = 가장 긴 SLA + 이 값.
//   절대 일수로 두지 않는 이유: SLA 를 늘려 놓고 구간이 그대로면 경과일이 구간 길이에서
//   잘려 위반이 아예 검출되지 않는다(= 허위 안심이 설정 실수로 재현된다).
//   여유를 두는 이유: 그보다 오래 지속된 발견은 어차피 이미 위반 확정이라 정확한 최초시각까지
//   알 필요가 없다(경계 밖에 실제 최초시각이 있어도, 경계 안에서 잡히는 first_seen 은 실제보다
//   항상 같거나 늦으므로 위반 판정이 과소평가되지 않는다).
const VG_COMPLIANCE_HISTORY_MARGIN_DAYS = 14;

/** 설정(tb_setting) + 폴백 상수로 조립한 판정 기준값 한 벌. 화면·스케줄러가 함께 쓴다. */
function vg_compliance_policy(): array {
    return [
        'kev'    => vg_setting_int('compliance.sla_kev_days',  VG_COMPLIANCE_SLA_KEV_DAYS),
        'crit'   => vg_setting_int('compliance.sla_crit_days', VG_COMPLIANCE_SLA_CRIT_DAYS),
        'high'   => vg_setting_int('compliance.sla_high_days', VG_COMPLIANCE_SLA_HIGH_DAYS),
        'partial_max' => vg_setting_int('compliance.partial_max', VG_COMPLIANCE_PARTIAL_MAX),
        'margin' => vg_setting_int('compliance.history_lookback_margin_days', VG_COMPLIANCE_HISTORY_MARGIN_DAYS),
    ];
}

/**
 * 자동판정 통제 정의(SSOT) — 화면 제목·스냅샷의 control_key·framework_ids 가 전부 여기서 온다.
 *   키는 DB 에 그대로 저장되므로 바꾸면 과거 스냅샷과 이어지지 않는다(추가만 한다).
 */
const VG_COMPLIANCE_CONTROLS = [
    'patch'   => ['label' => '패치관리',        'framework' => 'ISMS-P 2.10.8 / ISO 27001 A.8.8'],
    'asset'   => ['label' => '정보자산 식별',   'framework' => 'ISMS-P 1.2.1 / ISO 27001 A.5.9'],
    'secops'  => ['label' => '보안시스템 운영', 'framework' => 'ISMS-P 2.10.1'],
    // 계정 관리는 예전엔 VG_COMPLIANCE_MANUAL_CHECKLIST(사람이 심사) 였다. 계정 인벤토리
    //   (tb_host_account)가 제품 안에 생기면서 증적이 DB 에 있으니 자동판정으로 올렸다 —
    //   수동 체크리스트에는 증적이 제품 밖에 있는 항목만 남긴다.
    //   접근권한 검토(2.5.3)는 접속기록 점검 기능이 제거되면서 자동판정 근거(tb_activity_review)가
    //   없어져 다시 수동 체크리스트로 내렸다 — 근거가 없는 통제를 준수로 찍지 않는다.
    'account'        => ['label' => '계정 관리',      'framework' => 'ISMS-P 2.5.1 / ISO 27001 A.9.2'],
];

// 자동판정이 안 되는 통제 — 사람이 심사해야 하는 정책·승인이력류. 상태 판정 없이 항목명만.
//   2.5.1(계정 관리)은 여기서 뺐다 — tb_host_account 로 자동판정 통제가 됐다
//   (VG_COMPLIANCE_CONTROLS 의 account).
//   나머지는 증적이 제품 밖(정책 문서·검토 승인이력·대응 절차·복구 계획)에 있어 자동판정이 안 된다.
const VG_COMPLIANCE_MANUAL_CHECKLIST = [
    ['ismsp' => 'ISMS-P 1.1.1~1.1.6 관리체계 기반 마련', 'iso' => 'ISO 27001 A.5.1 정보보안 정책',
     'desc' => '정보보안 정책·관리체계 범위가 문서로 수립·승인되어 있는가'],
    ['ismsp' => 'ISMS-P 2.5.3 접근권한 검토', 'iso' => 'ISO 27001 A.9.2.5 사용자 접근권한 검토',
     'desc' => '접근권한을 주기적으로 검토하고 그 결과를 승인·보관하는가'],
    ['ismsp' => 'ISMS-P 2.11.1 사고 예방 및 대응체계 구축', 'iso' => 'ISO 27001 A.5.24~A.5.28 정보보안 사고 관리',
     'desc' => '침해사고 대응 절차·연락체계가 문서화되어 있는가'],
    ['ismsp' => 'ISMS-P 2.12.1 재해복구 체계 구축', 'iso' => 'ISO 27001 A.5.29~A.5.30 업무연속성 관리',
     'desc' => '백업·복구 절차가 수립되고 정기적으로 검증되는가'],
];

/**
 * 판정 결과 → ['label'=>..., 'tone'=>...]. 자동판정 통제가 공유하는 판정 어휘(SSOT).
 *   $unjudged = 위반이 없는데도 **판정 자체가 불가능한 대상**이 남아있는가.
 *   위반 0건이라고 무조건 "준수"로 쓰지 않는 이유: 볼 수 있는 근거가 모자라서 0건인 것을
 *   준수로 표기하면 심사 증빙에 허위 안심(false assurance)을 싣게 된다. 이 제품이 CCE 에서
 *   이미 지키는 원칙("NA 를 PASS 와 구분한다")을 컴플라이언스 판정에도 똑같이 적용한다.
 *   톤은 'med'(주의) — 'ok'(초록)와 색이 확실히 달라 준수로 오인되지 않는다.
 */
function vg_compliance_status(int $violations, bool $unjudged = false, int $partialMax = VG_COMPLIANCE_PARTIAL_MAX): array {
    if ($violations === 0) {
        return $unjudged ? ['label' => '판정 불가', 'tone' => 'med'] : ['label' => '준수', 'tone' => 'ok'];
    }
    if ($violations <= $partialMax) { return ['label' => '부분준수', 'tone' => 'high']; }
    return ['label' => '미준수', 'tone' => 'crit'];
}

/**
 * 상태 라벨 → 톤. 스냅샷은 라벨만 저장하므로(판정 어휘가 SSOT) 화면에서 톤을 되찾는다.
 *   판정 어휘가 4종(준수·판정 불가·부분준수·미준수)이라 (위반건수, 판정불가여부) 조합을
 *   전부 돌려 라벨이 맞는 것을 찾는다 — 톤 표를 따로 두면 SSOT 가 둘이 된다.
 */
function vg_compliance_tone_of(string $label): string {
    foreach ([[0, false], [0, true], [1, false], [PHP_INT_MAX, false]] as [$n, $na]) {
        $s = vg_compliance_status($n, $na, VG_COMPLIANCE_PARTIAL_MAX);
        if ($s['label'] === $label) { return $s['tone']; }
    }
    return 'muted';
}
