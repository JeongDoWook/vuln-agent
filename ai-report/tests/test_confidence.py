"""compute_confidence 단위 테스트. LLM/DB 호출 없음."""

from app.services.data_processing_services import compute_confidence
from app.agent.risk_scoring import REQUIRED_COLLECTION_STAGES, VALIDATION_VALID, POTENTIALLY_REACHABLE


def _complete_stages():
    return [{'stage_code': code, 'status': 'COMPLETE'} for code in REQUIRED_COLLECTION_STAGES]


def _findings(n=10):
    return [
        {'validation_status': VALIDATION_VALID, 'exploitability_status': POTENTIALLY_REACHABLE}
        for _ in range(n)
    ]


def test_full_collection_but_null_criticality_caps_confidence_below_100():
    """요구사항 1: 모든 수집 단계가 완료돼도 자산 중요도가 NULL이면 분석 신뢰도가 100%가 안 된다."""
    result = compute_confidence(
        collection_stage=_complete_stages(),
        findings=_findings(),
        cce_normalized_results=['PASS'] * 10,
        review_required_count=0,
        analyzed_count=10,
        host_criticality=None,
    )
    assert result['collection_completeness'] == 100
    assert result['analysis_confidence'] < 100


def test_full_collection_and_known_criticality_can_reach_100():
    result = compute_confidence(
        collection_stage=_complete_stages(),
        findings=_findings(),
        cce_normalized_results=['PASS'] * 10,
        review_required_count=0,
        analyzed_count=10,
        host_criticality='HIGH',
    )
    assert result['collection_completeness'] == 100
    assert result['analysis_confidence'] == 100


def test_incomplete_collection_lowers_completeness():
    stages = _complete_stages()[:-1]  # 한 단계 누락
    result = compute_confidence(
        collection_stage=stages,
        findings=_findings(),
        cce_normalized_results=['PASS'] * 10,
        review_required_count=0,
        analyzed_count=10,
        host_criticality='HIGH',
    )
    assert result['collection_completeness'] < 100
