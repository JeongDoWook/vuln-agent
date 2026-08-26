"""app/agent/risk_scoring.py 의 결정론적 로직에 대한 단위 테스트. LLM 호출 없음."""

from app.agent.risk_scoring import (
    classify_priority_tier,
    score_to_risk_level,
    TIER_P0,
    TIER_P1,
    TIER_P2,
    TIER_P3,
    TIER_REVIEW,
    CONFIRMED_REACHABLE,
    POTENTIALLY_REACHABLE,
    INSTALLED_ONLY,
    REACHABILITY_UNKNOWN,
    VALIDATION_VALID,
    VALIDATION_CONFLICT,
    VALIDATION_REVIEW_REQUIRED,
    RISK_LEVEL_THRESHOLDS,
)


def _tier(**overrides):
    base = dict(
        severity='HIGH', cvss=7.5, epss=0.05, is_kev=False, ransomware=False,
        reachability=POTENTIALLY_REACHABLE, validation_status=VALIDATION_VALID, criticality=None,
    )
    base.update(overrides)
    return classify_priority_tier(**base)


def test_potentially_reachable_is_not_automatically_p1():
    """요구사항 3: POTENTIALLY_REACHABLE이라는 이유만으로 P1이 되면 안 된다."""
    tier = _tier(severity='MEDIUM', cvss=5.0, epss=0.01)
    assert tier != TIER_P1
    assert tier == TIER_P2


def test_kev_with_reachable_path_is_p0():
    """요구사항 4: KEV와 확인된 도달 경로가 결합되면 P0."""
    assert _tier(is_kev=True, reachability=POTENTIALLY_REACHABLE) == TIER_P0
    assert _tier(is_kev=True, reachability=CONFIRMED_REACHABLE, severity='CRITICAL') == TIER_P0


def test_confirmed_reachable_high_severity_is_p0():
    assert _tier(reachability=CONFIRMED_REACHABLE, severity='CRITICAL', is_kev=False) == TIER_P0


def test_installed_only_is_p3():
    """요구사항 5: 설치만 확인된 항목은 P3."""
    assert _tier(reachability=INSTALLED_ONLY, severity='HIGH', cvss=8.0) == TIER_P3


def test_installed_only_critical_escalates_to_p2():
    assert _tier(reachability=INSTALLED_ONLY, severity='CRITICAL') == TIER_P2


def test_unknown_reachability_low_severity_is_p3():
    assert _tier(reachability=REACHABILITY_UNKNOWN, severity='MEDIUM') == TIER_P3


def test_validation_conflict_overrides_everything_to_review():
    assert _tier(validation_status=VALIDATION_CONFLICT, is_kev=True, reachability=CONFIRMED_REACHABLE) == TIER_REVIEW
    assert _tier(validation_status=VALIDATION_REVIEW_REQUIRED) == TIER_REVIEW


def test_p1_requires_impact_not_just_reachability():
    """HIGH 심각도 + POTENTIALLY_REACHABLE + 충분한 CVSS/EPSS 여야 P1."""
    assert _tier(severity='HIGH', cvss=8.0, epss=0.0, reachability=POTENTIALLY_REACHABLE) == TIER_P1
    # cvss도 낮고 epss도 낮으면 P1이 아니라 P2로 떨어져야 한다
    assert _tier(severity='HIGH', cvss=3.0, epss=0.0, reachability=POTENTIALLY_REACHABLE) == TIER_P2


def test_score_to_risk_level_thresholds():
    assert score_to_risk_level(RISK_LEVEL_THRESHOLDS['CRITICAL']) == 'CRITICAL'
    assert score_to_risk_level(RISK_LEVEL_THRESHOLDS['HIGH']) == 'HIGH'
    assert score_to_risk_level(RISK_LEVEL_THRESHOLDS['MEDIUM']) == 'MEDIUM'
    assert score_to_risk_level(0) == 'LOW'
