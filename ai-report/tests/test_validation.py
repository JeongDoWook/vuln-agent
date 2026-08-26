"""app/agent/validation.py 단위 테스트. LLM/DB 호출 없음."""

from app.agent.validation import validate_finding
from app.agent.risk_scoring import (
    VALIDATION_CONFLICT,
    VALIDATION_VALID,
    CONFLICT_NO_FIX_WITH_FIXED_VERSION,
    CONFLICT_OS_FAMILY_MISMATCH,
)


def test_no_fix_with_fixed_version_is_conflict():
    """요구사항 2: no_fix=1과 fixed_version이 동시에 있으면 REVIEW(CONFLICT)로 분류."""
    finding = {'no_fix': 1, 'cve_summary': 'some summary'}
    status, codes = validate_finding(
        finding, fixed_version='1.2.3-4', container_os_id=None, container_manager=None,
        feed_updated_at=None,
    )
    assert status == VALIDATION_CONFLICT
    assert CONFLICT_NO_FIX_WITH_FIXED_VERSION in codes


def test_no_fix_without_fixed_version_is_not_conflict_for_that_reason():
    finding = {'no_fix': 1, 'cve_summary': 'some summary'}
    status, codes = validate_finding(
        finding, fixed_version=None, container_os_id=None, container_manager=None,
        feed_updated_at=None,
    )
    assert CONFLICT_NO_FIX_WITH_FIXED_VERSION not in codes
    assert status == VALIDATION_VALID


def test_os_family_mismatch_is_conflict():
    """요구사항 8: 컨테이너 OS에 맞지 않는 조치 버전 형식은 충돌로 분류."""
    finding = {'no_fix': 0, 'cve_summary': 'some summary'}
    # 데비안 컨테이너인데 rpm 계열(el9) 버전 표기가 조치버전으로 붙어있는 경우
    status, codes = validate_finding(
        finding,
        fixed_version='2.34-274.0.1.el9_8',
        container_os_id='debian',
        container_manager='dpkg',
        feed_updated_at=None,
    )
    assert status == VALIDATION_CONFLICT
    assert CONFLICT_OS_FAMILY_MISMATCH in codes


def test_matching_os_family_is_not_conflict():
    finding = {'no_fix': 0, 'cve_summary': 'some summary'}
    status, codes = validate_finding(
        finding,
        fixed_version='2.34-274.0.1.el9_8',
        container_os_id='rhel',
        container_manager='rpm',
        feed_updated_at=None,
    )
    assert CONFLICT_OS_FAMILY_MISMATCH not in codes
    assert status == VALIDATION_VALID


def test_missing_cve_summary_is_review_required():
    finding = {'no_fix': 0, 'cve_summary': None}
    status, codes = validate_finding(
        finding, fixed_version=None, container_os_id=None, container_manager=None,
        feed_updated_at=None,
    )
    assert status != VALIDATION_VALID
