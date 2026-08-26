"""요구사항 12: 기존 정상 보고서 생성 경로에 대한 회귀 테스트.

실제 host_id=3 데이터로 collect -> annotate -> validate -> group -> stats 까지
LLM 호출 없이 전 구간이 예외 없이 통과하고, 결과가 구조적으로 일관되는지 확인한다.
MySQL에 연결할 수 없는 환경에서는 스킵한다.
"""

import pytest

from app.database.mysql_session import MySQLSessionLocal
from app.services.data_processing_services import (
    collect_host_vulnerability_data,
    annotate_findings,
    select_candidate_findings,
    group_findings_for_remediation,
    compute_risk_grade_and_score,
    compute_confidence,
    compute_stats,
    normalize_cce_results,
)

HOST_UUID = '477b0ae1-8480-4cee-9994-7e30b73ced62'


def _load_data():
    db = MySQLSessionLocal()
    try:
        return collect_host_vulnerability_data(db, HOST_UUID)
    finally:
        db.close()


@pytest.fixture(scope='module')
def data():
    try:
        return _load_data()
    except Exception as exc:  # DB 연결 불가 등 환경 문제는 스킵
        pytest.skip(f'MySQL에 연결할 수 없어 회귀 테스트를 건너뜁니다: {exc}')


def test_full_deterministic_pipeline_runs_without_error(data):
    host_criticality = data['host'].get('criticality')
    container_by_id = {c['container_id']: c for c in data['container']}

    findings = annotate_findings(
        data['findings'], data['cve_by_id'], data['kev_by_id'],
        data['collection_stage'], data['evidence_by_finding_id'], container_by_id, host_criticality,
    )
    assert findings, '적어도 1건의 finding이 있어야 한다'
    for f in findings:
        assert f['priority_tier'] in ('P0', 'P1', 'P2', 'P3', 'REVIEW')
        assert f['exploitability_status'] in ('CONFIRMED_REACHABLE', 'POTENTIALLY_REACHABLE', 'INSTALLED_ONLY', 'UNKNOWN')
        assert f['validation_status'] in ('VALID', 'WARNING', 'CONFLICT', 'REVIEW_REQUIRED')

    candidates = select_candidate_findings(
        findings, data['cve_by_id'], data['kev_by_id'], data['evidence_by_finding_id'], container_by_id, max_total=80,
    )
    normal_groups, conflict_groups = group_findings_for_remediation(candidates, data['stale_lib'], max_groups=25)

    # 충돌/검토 그룹은 정상 그룹에 절대 섞이면 안 된다
    for g in normal_groups:
        assert g['validation_status'] == 'VALID'
    for g in conflict_groups:
        assert g['validation_status'] == 'CONFLICT'
        assert g['tier'] == 'REVIEW'

    risk = compute_risk_grade_and_score(findings, host_criticality)
    assert risk['risk_level'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    assert 0 <= risk['overall_score'] <= 100

    cce_normalized = normalize_cce_results(data['cce_finding'])
    confidence = compute_confidence(
        collection_stage=data['collection_stage'], findings=findings,
        cce_normalized_results=[c['normalized_result'] for c in cce_normalized],
        review_required_count=0, analyzed_count=len(normal_groups) + len(conflict_groups),
        host_criticality=host_criticality,
    )
    assert 0 <= confidence['analysis_confidence'] <= 100

    stats = compute_stats(findings, data['collection_stage'], cce_normalized, data['container'], data['evidence_by_finding_id'])
    # CCE 5개 카테고리 합이 전체와 일치해야 한다 (근거부족을 FAIL/NOT_APPLICABLE로 부풀리지 않았는지)
    cce_sum = (
        len(stats['cce_fail_items']) + len(stats['cce_not_applicable_items'])
        + len(stats['cce_unknown_items']) + len(stats['cce_review_items']) + stats['cce_pass_count']
    )
    assert cce_sum == stats['cce_total']

    # finding 수와 고유 CVE 수는 서로 달라야 한다(혼동 방지 확인)
    assert stats['total_findings'] != stats['unique_cve_count']
