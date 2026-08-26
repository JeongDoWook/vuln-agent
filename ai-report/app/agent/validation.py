"""조치 그룹을 만들기 전에 finding 단위로 데이터 정합성을 검증한다.

CONFLICT/REVIEW_REQUIRED로 판정된 finding은 정상 조치 그룹(P0~P3)에 절대 섞이지 않고
별도의 "데이터 충돌 및 검토 필요" 섹션으로 빠진다 — data_processing_services.py의
group_findings_for_remediation()에서 이 규칙을 적용한다.
"""

import re
from datetime import datetime, timezone
from typing import Any

from app.agent.risk_scoring import (
    VALIDATION_VALID,
    VALIDATION_WARNING,
    VALIDATION_CONFLICT,
    VALIDATION_REVIEW_REQUIRED,
    CONFLICT_NO_FIX_WITH_FIXED_VERSION,
    CONFLICT_OS_FAMILY_MISMATCH,
    CONFLICT_MISSING_CVE_EVIDENCE,
    CONFLICT_STALE_FEED,
    FEED_STALENESS_HOURS,
    RPM_VERSION_HINT_RE,
    DEB_VERSION_HINT_RE,
)


def _os_family(os_id: str | None, manager: str | None) -> str | None:
    if manager == 'rpm' or (os_id and os_id.lower() in ('rhel', 'centos', 'fedora', 'rocky', 'almalinux', 'oracle')):
        return 'rpm'
    if manager == 'dpkg' or (os_id and os_id.lower() in ('debian', 'ubuntu')):
        return 'deb'
    return None


def _version_family(version: str | None) -> str | None:
    if not version:
        return None
    if re.search(RPM_VERSION_HINT_RE, version):
        return 'rpm'
    if re.search(DEB_VERSION_HINT_RE, version):
        return 'deb'
    return None


def validate_finding(
    finding: dict[str, Any],
    *,
    fixed_version: str | None,
    container_os_id: str | None,
    container_manager: str | None,
    feed_updated_at: str | None,
    now: datetime | None = None,
) -> tuple[str, list[str]]:
    """finding 1건을 검증해 (validation_status, conflict_codes)를 반환한다.

    호스트 레벨(container_id=0) finding은 container_os_id/container_manager가
    None으로 들어오므로 OS 계열 불일치 검사는 자동으로 건너뛴다.
    """
    codes: list[str] = []

    if finding.get('no_fix') and fixed_version:
        codes.append(CONFLICT_NO_FIX_WITH_FIXED_VERSION)

    expected_family = _os_family(container_os_id, container_manager)
    actual_family = _version_family(fixed_version)
    if expected_family and actual_family and expected_family != actual_family:
        codes.append(CONFLICT_OS_FAMILY_MISMATCH)

    if not finding.get('cve_summary'):
        codes.append(CONFLICT_MISSING_CVE_EVIDENCE)

    if feed_updated_at:
        now = now or datetime.now(timezone.utc)
        try:
            feed_dt = datetime.fromisoformat(feed_updated_at)
            if feed_dt.tzinfo is None:
                feed_dt = feed_dt.replace(tzinfo=timezone.utc)
            age_hours = (now - feed_dt).total_seconds() / 3600
            if age_hours > FEED_STALENESS_HOURS:
                codes.append(CONFLICT_STALE_FEED)
        except ValueError:
            pass

    if CONFLICT_NO_FIX_WITH_FIXED_VERSION in codes or CONFLICT_OS_FAMILY_MISMATCH in codes:
        return VALIDATION_CONFLICT, codes
    if CONFLICT_MISSING_CVE_EVIDENCE in codes:
        return VALIDATION_REVIEW_REQUIRED, codes
    if CONFLICT_STALE_FEED in codes:
        return VALIDATION_WARNING, codes
    return VALIDATION_VALID, codes
