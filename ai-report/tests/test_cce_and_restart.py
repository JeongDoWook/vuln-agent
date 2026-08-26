"""CCE 정규화와 재시작 상태 판정 단위 테스트. LLM/DB 호출 없음."""

from app.services.data_processing_services import normalize_cce_results, _restart_status
from app.agent.risk_scoring import (
    CCE_UNKNOWN,
    CCE_FAIL,
    CCE_PASS,
    RESTART_REQUIRED,
    RESTART_CHECK_REQUIRED,
    RESTART_NOT_NEEDED,
)


def test_cce_insufficient_evidence_becomes_unknown():
    """요구사항 6: 근거 부족(수집하지 못함) CCE는 UNKNOWN으로 변환되고 FAIL/NOT_APPLICABLE로 집계되지 않는다."""
    rows = [
        {'code': 'X', 'title': 't', 'result': 'NA', 'rationale': '/etc/xinetd.conf 권한을 수집하지 못함(파일 없음 또는 권한 부족).'},
    ]
    normalized = normalize_cce_results(rows)
    assert normalized[0]['normalized_result'] == CCE_UNKNOWN


def test_cce_pass_and_fail_pass_through():
    rows = [
        {'code': 'A', 'result': 'PASS', 'rationale': 'ok'},
        {'code': 'B', 'result': 'FAIL', 'rationale': 'bad'},
    ]
    normalized = normalize_cce_results(rows)
    assert normalized[0]['normalized_result'] == CCE_PASS
    assert normalized[1]['normalized_result'] == CCE_FAIL


def test_stale_lib_forces_restart_required():
    """요구사항 7: stale library가 있으면 재시작 필요로 판정."""
    members = [{'needs_restart': 0, 'loaded': 0, 'package_name': 'glibc'}]
    assert _restart_status(members, stale_lib_packages=set()) != RESTART_REQUIRED
    assert _restart_status(members, stale_lib_packages={'glibc'}) == RESTART_REQUIRED


def test_needs_restart_flag_forces_restart_required():
    members = [{'needs_restart': 1, 'loaded': 1, 'package_name': 'openssl'}]
    assert _restart_status(members, stale_lib_packages=set()) == RESTART_REQUIRED


def test_loaded_without_restart_flag_needs_check():
    members = [{'needs_restart': 0, 'loaded': 1, 'package_name': 'curl'}]
    assert _restart_status(members, stale_lib_packages=set()) == RESTART_CHECK_REQUIRED


def test_not_loaded_is_not_needed():
    members = [{'needs_restart': 0, 'loaded': 0, 'package_name': 'foo'}]
    assert _restart_status(members, stale_lib_packages=set()) == RESTART_NOT_NEEDED
