"""위험도 산정에 쓰이는 모든 상수·가중치·임계값·상태값을 한 곳에서 관리한다.

이 파일의 값을 바꾸면 위험점수/우선순위/신뢰도 계산 결과가 바뀌므로, 값을 바꿀 때는
`SCORING_VERSION`도 함께 올려서 어떤 규칙 버전으로 계산된 보고서인지 추적할 수 있게 한다.
"""

# 이 값을 바꾸면(가중치/임계값 변경) 반드시 함께 올릴 것 — 보고서에 그대로 노출된다.
SCORING_VERSION = 'risk-scoring-v2.0'
RULES_VERSION = 'vuln-agent-rules-2026.08'


# ---------------------------------------------------------------------------
# 도달가능성 (reachability)
# ---------------------------------------------------------------------------
# CONFIRMED_REACHABLE은 (1)영향 패키지/취약 코드 존재 (2)프로세스 실행·로드
# (3)네트워크/로컬 입력 경로 존재 (4)취약 기능 활성화 확인 (5)입력이 그 기능까지
# 전달된다는 근거 -- 이 5가지가 전부 있어야 부여한다. 현재 수집 파이프라인은
# (1)~(3)만 확인하고 (4)(5)를 확인할 방법이 없으므로, 이 상태는 정의만 해두고
# 실제로는 절대 부여하지 않는다(허위로 "확정 도달"이라 부르는 게 더 위험하다).
CONFIRMED_REACHABLE = 'CONFIRMED_REACHABLE'
POTENTIALLY_REACHABLE = 'POTENTIALLY_REACHABLE'
INSTALLED_ONLY = 'INSTALLED_ONLY'
REACHABILITY_UNKNOWN = 'UNKNOWN'

REACHABILITY_LABEL_KO = {
    CONFIRMED_REACHABLE: '확인된 도달 가능',
    POTENTIALLY_REACHABLE: '잠재적 도달 가능',
    INSTALLED_ONLY: '설치만 확인',
    REACHABILITY_UNKNOWN: '판정 불가(수집 불충분)',
}


# ---------------------------------------------------------------------------
# 우선순위 티어
# ---------------------------------------------------------------------------
TIER_P0 = 'P0'
TIER_P1 = 'P1'
TIER_P2 = 'P2'
TIER_P3 = 'P3'
TIER_REVIEW = 'REVIEW'

TIER_ORDER = {TIER_P0: 0, TIER_P1: 1, TIER_P2: 2, TIER_P3: 3, TIER_REVIEW: 4}

TIER_DUE_KO = {
    TIER_P0: '즉시~24시간',
    TIER_P1: '7일 이내',
    TIER_P2: '30일 이내',
    TIER_P3: '계획 조치',
    TIER_REVIEW: '담당자 검토 후 결정',
}

# P1로 인정하려면 POTENTIALLY_REACHABLE만으로는 부족하고, 영향(심각도/CVSS) 또는
# 실제 악용 가능성(EPSS)이 충분히 높아야 한다는 것을 코드로 강제하기 위한 임계값.
P1_MIN_CVSS = 7.0
P1_MIN_EPSS = 0.10  # 상위 10% 수준의 악용 확률
# INSTALLED_ONLY/UNKNOWN이라도 CRITICAL이면 완전히 무시하지 않고 P2로 끌어올린다.
P2_CRITICAL_ESCALATION_SEVERITIES = ('CRITICAL',)


# ---------------------------------------------------------------------------
# 데이터 검증 상태
# ---------------------------------------------------------------------------
VALIDATION_VALID = 'VALID'
VALIDATION_WARNING = 'WARNING'
VALIDATION_CONFLICT = 'CONFLICT'
VALIDATION_REVIEW_REQUIRED = 'REVIEW_REQUIRED'

CONFLICT_NO_FIX_WITH_FIXED_VERSION = 'NO_FIX_WITH_FIXED_VERSION'
CONFLICT_OS_FAMILY_MISMATCH = 'OS_FAMILY_MISMATCH'
CONFLICT_MISSING_CVE_EVIDENCE = 'MISSING_CVE_EVIDENCE'
CONFLICT_STALE_FEED = 'STALE_FEED'

CONFLICT_CODE_LABEL_KO = {
    CONFLICT_NO_FIX_WITH_FIXED_VERSION: '벤더 미수정 표시와 조치 버전이 동시에 존재함',
    CONFLICT_OS_FAMILY_MISMATCH: '컨테이너 OS 계열과 조치버전의 패키지 형식이 불일치함',
    CONFLICT_MISSING_CVE_EVIDENCE: 'CVE 설명(근거) 데이터 누락',
    CONFLICT_STALE_FEED: '취약점 근거 피드가 최신성 기준을 초과함',
}

# 충돌 코드별로 "무엇을 확인해서 어떻게 풀어야 하는지"를 담당자에게 알려준다.
CONFLICT_RESOLUTION_KO = {
    CONFLICT_NO_FIX_WITH_FIXED_VERSION: '벤더 트래커를 재확인해 no_fix 플래그와 조치버전 필드 중 어느 쪽이 최신 상태인지 재검증하십시오.',
    CONFLICT_OS_FAMILY_MISMATCH: '조치버전이 실제로 이 컨테이너의 배포판(OS)에 해당하는 값인지 재확인하십시오.',
    CONFLICT_MISSING_CVE_EVIDENCE: 'CVE 근거 피드(NVD·벤더 트래커)를 재수집한 뒤 재매칭하십시오. 이 사유가 다수라면 피드 수집/조인 로직 자체를 점검해야 합니다.',
    CONFLICT_STALE_FEED: '근거 피드를 최신 버전으로 갱신한 뒤 재판정하십시오.',
}

# 정상 분석 대상 중 이 비율 이상이 MISSING_CVE_EVIDENCE로 충돌 처리되면, 보고서 한정 문제가
# 아니라 피드 수집/조인 로직 자체의 운영 문제일 가능성이 높으므로 커버리지 경고로 승격한다.
MISSING_CVE_EVIDENCE_WARNING_RATIO = 0.3

# evidence.feed_updated_at이 이보다 오래되면 STALE_FEED 경고를 붙인다.
FEED_STALENESS_HOURS = 72

# rpm 계열 조치버전은 보통 `.el\d`/`.fc\d`/`.oe\d` 같은 배포판 태그를 포함하고,
# deb 계열은 `+deb`/`ubuntu`/`build`를 포함한다. 컨테이너 OS와 조치버전 표기가
# 서로 다른 계열이면 "다른 배포판 패키지의 조치버전을 잘못 안내"하는 사고일 수 있다.
RPM_VERSION_HINT_RE = r'\.(el|fc|oe)\d'
DEB_VERSION_HINT_RE = r'(\+deb|ubuntu|build\d)'


# ---------------------------------------------------------------------------
# 재시작 판정
# ---------------------------------------------------------------------------
RESTART_REQUIRED = 'RESTART_REQUIRED'
RESTART_CHECK_REQUIRED = 'RESTART_CHECK_REQUIRED'
RESTART_NOT_NEEDED = 'NOT_NEEDED'
RESTART_UNKNOWN = 'UNKNOWN'

RESTART_NOTE_KO = {
    RESTART_REQUIRED: (
        '재시작 필요: 이전 스캔에서 이미 교체된 라이브러리를 계속 사용 중인 프로세스가 확인되었습니다. '
        '프로세스 재시작(컨테이너라면 재배포)이 필요합니다.'
    ),
    RESTART_CHECK_REQUIRED: (
        '패치 후 취약 라이브러리를 로드한 프로세스가 남아 있는지 재스캔하여 재시작 필요 여부를 확인하십시오.'
    ),
    RESTART_NOT_NEEDED: '현재 설치만 되어 있고 로드된 프로세스가 없어 재시작이 필요하지 않을 가능성이 높습니다.',
    RESTART_UNKNOWN: '재시작 필요 여부를 판단할 근거가 부족합니다. 재스캔 후 재확인하십시오.',
}

# no_fix(벤더 미수정) 그룹은 "패치 후 재스캔"이라는 표현 자체가 성립하지 않으므로 별도 문구를 쓴다.
RESTART_NOTE_NO_FIX_KO = {
    RESTART_CHECK_REQUIRED: (
        '완화조치 적용 후에도 취약 라이브러리를 로드한 프로세스가 남아있을 수 있습니다. '
        '벤더 패치가 공개되면 업데이트 후 로드된 라이브러리 버전을 다시 확인하십시오.'
    ),
}


def restart_note_for(restart_status: str, no_fix: bool) -> str:
    if no_fix and restart_status in RESTART_NOTE_NO_FIX_KO:
        return RESTART_NOTE_NO_FIX_KO[restart_status]
    return RESTART_NOTE_KO[restart_status]


# "현재 스캔에서 재시작이 필요한 항목 0건"이 "패치해도 재시작 불필요"로 오독되는 것을 막기 위해
# 표지/통계 라벨을 세분화한다 — needs_restart/stale_lib로 실측된 것과, 조치 후 재확인이
# 필요한 그룹 수를 구분해서 보여준다.
RESTART_STAT_LABELS_KO = {
    'stale_lib_detected': '현재 stale library 발견(재시작 필요 확정)',
    'restart_check_groups': '패치·완화 후 재시작 검토 필요 그룹 수',
    'host_reboot_needed': '호스트 재부팅 필요(커널)',
}


# ---------------------------------------------------------------------------
# 조치 유형(action_type)
# ---------------------------------------------------------------------------
ACTION_PATCH_AVAILABLE = 'PATCH_AVAILABLE'
ACTION_NO_FIX_MITIGATION_REQUIRED = 'NO_FIX_MITIGATION_REQUIRED'
ACTION_REVIEW_REQUIRED = 'REVIEW_REQUIRED'
ACTION_APPLICABILITY_CHECK_REQUIRED = 'APPLICABILITY_CHECK_REQUIRED'

ACTION_LABEL_KO = {
    ACTION_PATCH_AVAILABLE: '패치 적용 가능',
    ACTION_NO_FIX_MITIGATION_REQUIRED: '완화 조치 필요(벤더 미수정)',
    ACTION_REVIEW_REQUIRED: '검토 필요',
    ACTION_APPLICABILITY_CHECK_REQUIRED: '적용성 확인 필요',
}

# action_type별로 검증 방법 문구를 달리한다 — no_fix 그룹에 "패치 후 CVE 미검출 확인"이라고
# 쓰면 성립하지 않는 조치를 검증하라는 것이 되므로(패치가 없다), 완화조치 관점의 검증으로 바꾼다.
VERIFICATION_METHOD_KO = {
    ACTION_PATCH_AVAILABLE: (
        '조치 적용 후 재스캔하여 아래 CVE가 더 이상 검출되지 않는지, 로드된 라이브러리 버전이 갱신됐는지 확인하십시오.'
    ),
    ACTION_NO_FIX_MITIGATION_REQUIRED: (
        '완화조치 적용 후 재스캔하여 노출 범위(exposure_scope)가 축소됐는지, 허용 IP 제한이 적용됐는지, '
        '취약 기능이 비활성화됐는지 확인하고, 벤더 패치가 새로 제공되는지 주기적으로 추적하십시오. '
        '완화조치만으로는 CVE 자체가 사라지지 않습니다.'
    ),
    ACTION_REVIEW_REQUIRED: '담당자가 벤더 트래커·패키지-OS 매핑을 재확인한 뒤 조치 여부를 결정하십시오.',
    ACTION_APPLICABILITY_CHECK_REQUIRED: (
        '취약 기능이 실제로 사용되는지와 공격 입력 경로가 존재하는지 확인한 뒤 조치 여부를 결정하십시오.'
    ),
}


# ---------------------------------------------------------------------------
# CCE 결과 정규화 (원본 tb_cce_finding.result는 PASS/FAIL/NA 그대로 유지하고,
# 보고서 분석 단계에서만 아래 5단계로 재분류한다)
# ---------------------------------------------------------------------------
CCE_PASS = 'PASS'
CCE_FAIL = 'FAIL'
CCE_NOT_APPLICABLE = 'NOT_APPLICABLE'
CCE_UNKNOWN = 'UNKNOWN'
CCE_REVIEW = 'REVIEW'

# rationale 텍스트 키워드 기반 분류. 순서가 중요하다(위에서부터 먼저 매치되는 것을 채택).
# "수집하지 못함/확인하지 못함" = 진짜 근거 부족 -> UNKNOWN
# "판정하지 않는다/검토가 필요/별도 검토" = 정책·업무 요건 확인 필요 -> REVIEW
# "필수 요건이 아니므로/정보성" = 진짜 해당없음 -> NOT_APPLICABLE
CCE_UNKNOWN_KEYWORDS = ['수집하지 못함', '확인하지 못함', '찾지 못함', '권한 부족']
CCE_REVIEW_KEYWORDS = ['판정하지 않는다', '검토가 필요', '별도 검토', '확인 필요']
CCE_NOT_APPLICABLE_KEYWORDS = ['필수 요건이 아니므로', '정보성']


# ---------------------------------------------------------------------------
# 위험점수 (threat / environment / impact) 가중치와 등급 구간
# ---------------------------------------------------------------------------
# threat_score: 이 환경에 존재하는 CVE들이 "위협 인텔리전스 관점"에서 얼마나
# 급한지(KEV/랜섬웨어/EPSS/CVSS) — 자산 정보와 무관하게 계산 가능.
THREAT_WEIGHTS = {
    'kev': 25,
    'ransomware': 10,
    'cvss_multiplier': 2.0,   # cvss(0~10) * multiplier
    'epss_multiplier': 15.0,  # epss(0~1) * multiplier
}
THREAT_SCORE_CAP = 100

# environment_score: 이 환경에서 얼마나 도달 가능한가(도달가능성 분포).
ENVIRONMENT_REACHABILITY_WEIGHTS = {
    CONFIRMED_REACHABLE: 100,
    POTENTIALLY_REACHABLE: 55,
    INSTALLED_ONLY: 15,
    REACHABILITY_UNKNOWN: 5,
}

# impact_score: 자산 중요도 반영. criticality가 없으면 "보수적 기본값"을 쓰고
# provisional=True로 표시한다(아래 2번 정책 참고, data_processing_services.py에서 사용).
CRITICALITY_IMPACT_SCORE = {
    'CRITICAL': 100,
    'HIGH': 80,
    'MEDIUM': 50,
    'LOW': 20,
}
# tb_host.criticality가 NULL일 때 쓰는 보수적 기본값(가장 급하지 않다고 가정하지 않고,
# 중간값보다 살짝 높게 잡아 과소평가를 피한다). provisional=True와 항상 함께 노출한다.
DEFAULT_PROVISIONAL_IMPACT_SCORE = 60
IMPACT_POLICY_NOTE_PROVISIONAL_KO = (
    f'자산 중요도가 미평가된 경우 보수적 기본값 MEDIUM({DEFAULT_PROVISIONAL_IMPACT_SCORE}점)을 적용했습니다.'
)

# 최종 overall_score = threat*W1 + environment*W2 + impact*W3 (가중 평균, 합 1.0)
OVERALL_SCORE_WEIGHTS = {
    'threat': 0.4,
    'environment': 0.35,
    'impact': 0.25,
}

# overall_score(0~100) -> risk_level 구간. 보고서에 그대로 노출한다.
RISK_LEVEL_THRESHOLDS = {
    'CRITICAL': 75,
    'HIGH': 45,
    'MEDIUM': 20,
    'LOW': 0,
}


def score_to_risk_level(score: float) -> str:
    if score >= RISK_LEVEL_THRESHOLDS['CRITICAL']:
        return 'CRITICAL'
    if score >= RISK_LEVEL_THRESHOLDS['HIGH']:
        return 'HIGH'
    if score >= RISK_LEVEL_THRESHOLDS['MEDIUM']:
        return 'MEDIUM'
    return 'LOW'


# ---------------------------------------------------------------------------
# 분석 신뢰도(confidence) 4개 지표 가중치
# ---------------------------------------------------------------------------
# analysis_confidence = collection_completeness를 기준으로, 아래 감점 사유가 있을 때마다 차감.
CONFIDENCE_PENALTIES = {
    'criticality_missing': 15,       # 자산 중요도 미확정
    'potentially_reachable_ratio': 20,  # POTENTIALLY_REACHABLE 비율에 비례해 최대 20점 감점
    'no_fix_contradiction': 10,      # no_fix+fixed_version 충돌이 하나라도 있으면
    'review_required_ratio': 25,     # REVIEW 비율에 비례해 최대 25점 감점
    'cce_unknown_ratio': 10,         # CCE UNKNOWN/REVIEW 비율에 비례해 최대 10점 감점
    'stale_feed': 10,                # 근거 피드가 최신성 기준을 넘겼으면
}

# 필수 수집 단계(이게 다 COMPLETE여야 collection_completeness=100%)
REQUIRED_COLLECTION_STAGES = (
    'packages', 'language_packages', 'runtime_processes', 'network_exposure', 'containers',
)


# ---------------------------------------------------------------------------
# finding 정렬용 연속 점수(순위 매기기 전용 — 티어 자체는 classify_priority_tier가 결정)
# ---------------------------------------------------------------------------
SEVERITY_WEIGHT = {'CRITICAL': 150, 'HIGH': 100, 'MEDIUM': 50, 'LOW': 0}
EXPOSURE_WEIGHT = {'EXTERNAL': 30, 'LOCAL': 15, 'FILTERED': 5, 'BOUND': 5}


def compute_priority_score(
    *,
    severity: str | None,
    cvss: float | None,
    epss: float | None,
    is_kev: bool,
    ransomware: bool,
    reachability: str,
    exposure_scope: str | None,
) -> float:
    score = SEVERITY_WEIGHT.get(severity, 0)
    score += EXPOSURE_WEIGHT.get(exposure_scope, 0)
    if is_kev:
        score += 1000
    if ransomware:
        score += 200
    score += float(cvss or 0) * 2
    score += float(epss or 0) * 100
    score += ENVIRONMENT_REACHABILITY_WEIGHTS.get(reachability, 0)
    return score


# 표지·보고서에 그대로 노출하는 티어 판정 기준 요약(사람이 읽는 설명 — 로직은 아래 함수가 실제 기준).
TIER_CRITERIA_KO = [
    (TIER_P0, 'KEV/랜섬웨어 등재 + 도달 가능(POTENTIALLY_REACHABLE 이상), 또는 확정 도달(CONFIRMED_REACHABLE) + 심각도 HIGH/CRITICAL'),
    (TIER_P1, 'POTENTIALLY_REACHABLE + 심각도 HIGH/CRITICAL + (CVSS ≥ 기준 또는 EPSS ≥ 기준, 자산 중요도에 따라 기준 조정)'),
    (TIER_P2, 'POTENTIALLY_REACHABLE이지만 P1 기준(CVSS/EPSS) 미달, 또는 INSTALLED_ONLY/UNKNOWN + 심각도 CRITICAL'),
    (TIER_P3, '설치만 확인되었거나 현재 실행 근거가 없는 나머지'),
    (TIER_REVIEW, '데이터 검증 충돌(CONFLICT) 또는 근거 부족(REVIEW_REQUIRED)'),
]


def _classify_with_reason(
    *,
    severity: str | None,
    cvss: float | None,
    epss: float | None,
    is_kev: bool,
    ransomware: bool,
    reachability: str,
    validation_status: str,
    criticality: str | None,
) -> tuple[str, str]:
    if validation_status in (VALIDATION_CONFLICT, VALIDATION_REVIEW_REQUIRED):
        return TIER_REVIEW, f'데이터 검증 상태가 {validation_status}이므로 우선순위를 매길 수 없어 REVIEW로 분류'

    cvss = cvss or 0.0
    epss = epss or 0.0
    high_impact_severity = severity in ('CRITICAL', 'HIGH')

    # 자산이 중요할수록(criticality) 같은 조건에서도 더 보수적으로(더 급하게) 판단한다.
    cvss_bar = P1_MIN_CVSS
    epss_bar = P1_MIN_EPSS
    if criticality in ('CRITICAL', 'HIGH'):
        cvss_bar -= 1.0
        epss_bar /= 2
    elif criticality == 'LOW':
        cvss_bar += 0.5

    if reachability == CONFIRMED_REACHABLE and high_impact_severity:
        return TIER_P0, f'확정 도달(CONFIRMED_REACHABLE) + 심각도 {severity} → P0'
    if (is_kev or ransomware) and reachability in (CONFIRMED_REACHABLE, POTENTIALLY_REACHABLE):
        reason = 'KEV 등재' if is_kev else '랜섬웨어 악용 확인'
        return TIER_P0, f'{reason} + 도달가능성 {reachability} → P0'

    if reachability == POTENTIALLY_REACHABLE and high_impact_severity and (cvss >= cvss_bar or epss >= epss_bar):
        basis = f'CVSS {cvss:.1f} ≥ 기준 {cvss_bar:.1f}' if cvss >= cvss_bar else f'EPSS {epss:.3f} ≥ 기준 {epss_bar:.3f}'
        return TIER_P1, f'POTENTIALLY_REACHABLE + 심각도 {severity} + {basis} → P1'

    if reachability == POTENTIALLY_REACHABLE:
        return TIER_P2, (
            f'POTENTIALLY_REACHABLE이지만 CVSS {cvss:.1f} < 기준 {cvss_bar:.1f}, '
            f'EPSS {epss:.3f} < 기준 {epss_bar:.3f} → P2'
        )
    if reachability in (INSTALLED_ONLY, REACHABILITY_UNKNOWN) and severity in P2_CRITICAL_ESCALATION_SEVERITIES:
        return TIER_P2, f'{reachability} + 심각도 {severity}(CRITICAL 예외 상향) → P2'

    return TIER_P3, f'{reachability} + 심각도 {severity} → 실행 근거 부족으로 P3'


def classify_priority_tier(
    *,
    severity: str | None,
    cvss: float | None,
    epss: float | None,
    is_kev: bool,
    ransomware: bool,
    reachability: str,
    validation_status: str,
    criticality: str | None,
) -> str:
    """결정론적 P0~P3/REVIEW 분류.

    POTENTIALLY_REACHABLE이라는 이유만으로 자동 P1을 주지 않는다 — 심각도/CVSS/EPSS로
    "영향이 충분히 확인됨"을 추가로 요구한다. validation_status가 CONFLICT/REVIEW_REQUIRED면
    다른 모든 조건을 무시하고 REVIEW로 보낸다(데이터가 못 미더운데 조치 우선순위를 매길 수 없다).
    """
    tier, _ = _classify_with_reason(
        severity=severity, cvss=cvss, epss=epss, is_kev=is_kev, ransomware=ransomware,
        reachability=reachability, validation_status=validation_status, criticality=criticality,
    )
    return tier


def explain_priority_tier(
    *,
    severity: str | None,
    cvss: float | None,
    epss: float | None,
    is_kev: bool,
    ransomware: bool,
    reachability: str,
    validation_status: str,
    criticality: str | None,
) -> tuple[str, str]:
    """classify_priority_tier와 동일한 규칙으로 (티어, 사람이 읽을 판정 근거 문장)을 함께 반환한다."""
    return _classify_with_reason(
        severity=severity, cvss=cvss, epss=epss, is_kev=is_kev, ransomware=ransomware,
        reachability=reachability, validation_status=validation_status, criticality=criticality,
    )
