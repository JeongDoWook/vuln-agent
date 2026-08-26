"""app/agent/report_qa.py 단위 테스트. LLM/DB 호출 없음."""

from app.agent.report_qa import run_report_qa


def _base_stats(**overrides):
    stats = dict(
        risk_level='HIGH', risk_level_thresholds={'HIGH': 45}, scoring_version='v1', overall_score=50,
        collection_completeness=100, analysis_confidence=90, matching_confidence=95, reachability_confidence=95,
        tier_distribution={'P0': 0, 'P1': 2, 'P2': 0, 'P3': 0, 'REVIEW': 0},
        total_group_count=2, total_findings=100, unique_cve_count=40,
    )
    stats.update(overrides)
    return stats


def _clean_group(**overrides):
    g = dict(
        package_name='openssl', container_label='vulnagent-db', tier='P1', max_score=100,
        no_fix=False, action_type='PATCH_AVAILABLE', validation_status='VALID',
        cve_refs=[{'cve_id': 'CVE-2026-1000'}],
        risk_summary='openssl 패키지에 취약점이 있습니다.',
        impact='영향이 있을 수 있습니다.',
        recommended_action='패치를 적용하십시오.',
    )
    g.update(overrides)
    return g


def _base_narrative():
    return {'executive_summary': '요약', 'overall_recommendation': '권고', 'conclusion': '결론'}


def test_clean_report_has_no_issues():
    issues = run_report_qa(
        host={}, stats=_base_stats(),
        remediation_groups=[_clean_group(), _clean_group(package_name='curl')],
        conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert issues == []


def test_p0_zero_but_p0_group_present_is_flagged():
    """요구사항 9: P0가 0건인데 P0 그룹이 본문에 있으면 검증 실패."""
    stats = _base_stats(tier_distribution={'P0': 0, 'P1': 0, 'P2': 0, 'P3': 0, 'REVIEW': 0}, total_group_count=1)
    issues = run_report_qa(
        host={}, stats=stats,
        remediation_groups=[_clean_group(tier='P0')],
        conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('P0=0' in i for i in issues)


def test_conflict_group_leaking_into_normal_groups_is_flagged():
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[_clean_group(validation_status='CONFLICT')],
        conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('검증 실패 그룹' in i for i in issues)


def test_stray_cve_mention_is_flagged():
    """요구사항 11: LLM 응답에 그룹 소속이 아닌 CVE가 언급되면 검증 실패."""
    group = _clean_group(
        cve_refs=[{'cve_id': 'CVE-2026-1000'}],
        risk_summary='이 문제는 CVE-2026-9999와 관련이 있습니다.',
    )
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('소속 아닌 CVE' in i for i in issues)


def test_forbidden_phrase_is_flagged():
    group = _clean_group(risk_summary='이 취약점은 실제로 악용됨이 확인되었습니다.')
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('금지 표현' in i for i in issues)


def test_no_fix_group_recommending_patch_is_flagged():
    group = _clean_group(
        no_fix=True, action_type='NO_FIX_MITIGATION_REQUIRED',
        recommended_action='제공된 패치를 적용하십시오. 업그레이드하십시오.',
    )
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('패치 권고' in i for i in issues)


def test_aggregate_count_mismatch_is_flagged():
    """요구사항 10: 본문·부록 집계가 일치하지 않으면 검증 실패."""
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=5),  # 실제로는 그룹 1개만 렌더링
        remediation_groups=[_clean_group()], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('집계 불일치' in i for i in issues)


def test_threat_actor_mention_without_cti_backing_is_flagged():
    """CTI(RAG) 근거(cti_snippets)가 없는데 위협 행위자를 언급하면 근거 없는 귀속으로 검증 실패."""
    group = _clean_group(risk_summary='이 취약점은 APT29가 과거 캠페인에서 악용한 것으로 알려져 있습니다.')
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('위협 행위자 언급' in i for i in issues)


def test_untranslated_english_group_text_is_flagged():
    """번역 실패로 영어 원문이 그대로 남으면(한글 비율이 낮으면) 검증 실패해야 한다."""
    group = _clean_group(
        risk_summary=(
            'This package has a critical vulnerability that could allow remote attackers '
            'to execute arbitrary code on the affected host under certain conditions.'
        ),
    )
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert any('번역 누락 의심' in i for i in issues)


def test_untranslated_english_narrative_is_flagged():
    narrative = {
        'executive_summary': (
            'This host has several high severity vulnerabilities that require immediate '
            'attention from the security operations team before the next maintenance window.'
        ),
        'overall_recommendation': '권고',
        'conclusion': '결론',
    }
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[_clean_group()], conflict_groups=[], review_groups=[], narrative=narrative,
    )
    assert any('번역 누락 의심' in i and '총평' in i for i in issues)


def test_korean_text_with_embedded_english_tokens_is_not_flagged():
    """정상 번역된 한글 문장에 CVE ID/패키지명 등 영문 토큰이 섞여도 오탐하면 안 된다."""
    group = _clean_group(
        risk_summary=(
            'openssl 패키지의 CVE-2026-1000 취약점은 공격자가 원격에서 임의 코드를 실행하게 '
            '할 수 있어 이 호스트의 데이터베이스 컨테이너에 심각한 영향을 줄 수 있습니다.'
        ),
    )
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert not any('번역 누락 의심' in i for i in issues)


def test_short_text_is_not_checked_for_translation():
    """너무 짧은 텍스트는 우연히 영문 토큰 비중이 높아도(예: 순수 CVE ID) 오탐 방지를 위해 검사 제외."""
    group = _clean_group(risk_summary='CVE-2026-1000 OpenSSL RCE')
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert not any('번역 누락 의심' in i for i in issues)


def test_threat_actor_mention_with_cti_backing_is_not_flagged():
    group = _clean_group(
        risk_summary='이 취약점은 APT29가 과거 캠페인에서 악용한 것으로 알려져 있습니다.',
        cti_snippets=[{'source': 'report_a.pdf', 'score': 0.8, 'text': 'APT29 exploited this exact CVE...'}],
    )
    issues = run_report_qa(
        host={}, stats=_base_stats(total_group_count=1),
        remediation_groups=[group], conflict_groups=[], review_groups=[], narrative=_base_narrative(),
    )
    assert not any('위협 행위자 언급' in i for i in issues)
