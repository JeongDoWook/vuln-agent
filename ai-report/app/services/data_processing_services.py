import re
from collections import Counter
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from app.repositories.mysql_repository import get_data
from app.queries.get_data import (
    tb_host_by_uuid,
    tb_scan,
    tb_scan_recent,
    tb_finding,
    tb_finding_evidence,
    tb_cve,
    tb_kev_catalog,
    tb_exposure,
    tb_process,
    tb_package,
    tb_container,
    tb_collection_stage,
    tb_package_dependency,
    tb_cce_finding,
    tb_pkg_change,
    tb_stale_lib,
)
from app.agent.validation import validate_finding
# app/agent/risk_scoring.py에 모든 가중치·임계값·상태값이 모여있다(단일 진실 공급원).
# 아래는 이 파일이 실제로 쓰는 것만 카테고리별로 나눠 가져온 것 — 전체 목록/의미는
# risk_scoring.py 자체의 섹션 주석을 참고.
from app.agent.risk_scoring import (
    SCORING_VERSION,
    # 도달가능성(reachability)
    CONFIRMED_REACHABLE,
    POTENTIALLY_REACHABLE,
    INSTALLED_ONLY,
    REACHABILITY_UNKNOWN,
    REACHABILITY_LABEL_KO,
    # 우선순위 티어
    TIER_ORDER,
    TIER_DUE_KO,
    compute_priority_score,
    explain_priority_tier,
    SEVERITY_WEIGHT,
    # 데이터 검증 상태 / 충돌 코드
    VALIDATION_VALID,
    VALIDATION_CONFLICT,
    VALIDATION_REVIEW_REQUIRED,
    CONFLICT_CODE_LABEL_KO,
    CONFLICT_RESOLUTION_KO,
    # 재시작 판정
    RESTART_REQUIRED,
    RESTART_CHECK_REQUIRED,
    RESTART_NOT_NEEDED,
    RESTART_UNKNOWN,
    restart_note_for,
    # 조치 유형(action_type)
    ACTION_PATCH_AVAILABLE,
    ACTION_NO_FIX_MITIGATION_REQUIRED,
    ACTION_REVIEW_REQUIRED,
    ACTION_APPLICABILITY_CHECK_REQUIRED,
    ACTION_LABEL_KO,
    VERIFICATION_METHOD_KO,
    # CCE 결과 정규화
    CCE_PASS,
    CCE_FAIL,
    CCE_NOT_APPLICABLE,
    CCE_UNKNOWN,
    CCE_REVIEW,
    CCE_UNKNOWN_KEYWORDS,
    CCE_REVIEW_KEYWORDS,
    CCE_NOT_APPLICABLE_KEYWORDS,
    # 위험점수(threat/environment/impact) 및 신뢰도
    THREAT_WEIGHTS,
    THREAT_SCORE_CAP,
    ENVIRONMENT_REACHABILITY_WEIGHTS,
    CRITICALITY_IMPACT_SCORE,
    DEFAULT_PROVISIONAL_IMPACT_SCORE,
    IMPACT_POLICY_NOTE_PROVISIONAL_KO,
    OVERALL_SCORE_WEIGHTS,
    RISK_LEVEL_THRESHOLDS,
    score_to_risk_level,
    CONFIDENCE_PENALTIES,
    REQUIRED_COLLECTION_STAGES,
)


REACHABILITY_PRIORITY_ORDER = [
    CONFIRMED_REACHABLE, POTENTIALLY_REACHABLE, REACHABILITY_UNKNOWN, INSTALLED_ONLY,
]

# 이 두 수집단계가 불완전하면 loaded/exposed 값을 신뢰할 수 없어 도달가능성을 UNKNOWN 처리한다.
_REACHABILITY_DEPENDENT_STAGES = {'runtime_processes', 'network_exposure'}


def _normalize_value(value: Any) -> Any:
    """SQLAlchemy가 돌려주는 Decimal/datetime/date를 JSON·Jinja2에서 그대로 쓸 수 있는 타입으로 바꾼다."""
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _normalize_rows(rows: list) -> list[dict[str, Any]]:
    """RowMapping 목록을 값이 정규화된 일반 dict 목록으로 바꾼다."""
    return [
        {key: _normalize_value(value) for key, value in dict(row).items()}
        for row in rows
    ]


def _fetch(db: Session, query: str, param: Any) -> list[dict[str, Any]]:
    """쿼리를 실행하고 정규화된 dict 목록으로 반환하는 공통 래퍼."""
    return _normalize_rows(get_data(db, query, param))


def _fetch_in(db: Session, query: str, values: list) -> list[dict[str, Any]]:
    """IN :param 절을 쓰는 쿼리. 빈 리스트를 넘기면 SQL 문법 오류가 나므로 스킵한다."""
    if not values:
        return []
    return _fetch(db, query, tuple(values))


def _container_label_map(container_rows: list[dict[str, Any]]) -> dict[int, str]:
    """container_id -> 사람이 읽을 라벨. container_id=0은 컨테이너가 아니라 호스트 자체를 뜻한다."""
    labels = {0: '호스트'}
    for c in container_rows:
        labels[c['container_id']] = c.get('name') or f"컨테이너#{c['container_id']}"
    return labels


def get_previous_scan_delta(
    db: Session,
    host_id: int,
    current_scan_id: int,
    current_scan: dict[str, Any],
    current_findings: list[dict[str, Any]],
    current_container: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """직전 스캔이 있으면 현재 스캔과의 차이를 계산한다. 없으면 None.

    container_id는 스캔마다 DELETE+INSERT로 재발급되어 같은 컨테이너라도 스캔 간에
    값이 달라지는 것을 실측으로 확인했다. 따라서 비교 키는 container_id가 아니라
    컨테이너 이름(또는 '호스트')을 사용한다.
    """

    recent_scans = _fetch(db, tb_scan_recent, host_id)
    prev = next((s for s in recent_scans if s['scan_id'] != current_scan_id), None)
    if prev is None:
        return None

    prev_findings = _fetch(db, tb_finding, prev['scan_id'])
    prev_container = _fetch(db, tb_container, prev['scan_id'])
    pkg_changes = _fetch(db, tb_pkg_change, current_scan_id)

    cur_labels = _container_label_map(current_container)
    prev_labels = _container_label_map(prev_container)

    cur_set = {
        (f['cve_id'], f['package_name'], cur_labels.get(f.get('container_id') or 0, f.get('container_id')))
        for f in current_findings if f.get('cve_id')
    }
    prev_set = {
        (f['cve_id'], f['package_name'], prev_labels.get(f.get('container_id') or 0, f.get('container_id')))
        for f in prev_findings if f.get('cve_id')
    }

    return {
        'previous_scan_id': prev['scan_id'],
        'previous_collected_at': prev['collected_at'],
        'new_finding_count': len(cur_set - prev_set),
        'resolved_finding_count': len(prev_set - cur_set),
        'total_finding_delta': len(current_findings) - len(prev_findings),
        'exposure_count_delta': (current_scan.get('exposure_count') or 0) - (prev.get('exposure_count') or 0),
        'package_changes': pkg_changes,
    }


def collect_host_vulnerability_data(db: Session, host_uuid: str) -> dict[str, Any]:
    """host_uuid로 특정 호스트의 최신 스캔 취약점 데이터를 전부 모은다."""

    host_rows = _fetch(db, tb_host_by_uuid, host_uuid)
    if not host_rows:
        raise ValueError(f'host_uuid={host_uuid}에 해당하는 호스트를 찾을 수 없습니다.')
    host = host_rows[0]
    host_id = host['host_id']

    scan_rows = _fetch(db, tb_scan, host_id)
    if not scan_rows:
        raise ValueError(f'host_id={host_id}에 대한 스캔 데이터가 없습니다.')
    scan = scan_rows[0]
    scan_id = scan['scan_id']

    collection_stage = _fetch(db, tb_collection_stage, scan_id)
    findings = _fetch(db, tb_finding, scan_id)
    exposure = _fetch(db, tb_exposure, scan_id)
    process = _fetch(db, tb_process, scan_id)
    package = _fetch(db, tb_package, scan_id)
    container = _fetch(db, tb_container, scan_id)
    package_dependency = _fetch(db, tb_package_dependency, scan_id)
    cce_finding = _fetch(db, tb_cce_finding, scan_id)
    stale_lib = _fetch(db, tb_stale_lib, scan_id)

    finding_ids = [f['finding_id'] for f in findings]
    evidence_rows = _fetch_in(db, tb_finding_evidence, finding_ids)
    evidence_by_finding_id = {row['finding_id']: row for row in evidence_rows}

    cve_ids = sorted({f['cve_id'] for f in findings if f.get('cve_id')})
    cve_rows = _fetch_in(db, tb_cve, cve_ids)
    cve_by_id = {row['cve_id']: row for row in cve_rows}

    kev_rows = _fetch_in(db, tb_kev_catalog, cve_ids)
    kev_by_id = {row['cve_id']: row for row in kev_rows}

    previous_scan_delta = get_previous_scan_delta(db, host_id, scan_id, scan, findings, container)

    return {
        'host': host,
        'scan': scan,
        'collection_stage': collection_stage,
        'findings': findings,
        'evidence_by_finding_id': evidence_by_finding_id,
        'cve_by_id': cve_by_id,
        'kev_by_id': kev_by_id,
        'exposure': exposure,
        'process': process,
        'package': package,
        'container': container,
        'package_dependency': package_dependency,
        'cce_finding': cce_finding,
        'stale_lib': stale_lib,
        'previous_scan_delta': previous_scan_delta,
    }


def _incomplete_reachability_stages(collection_stage: list[dict[str, Any]]) -> set[str]:
    """도달가능성 판정에 쓰이는 수집단계 중 MISSING/EMPTY인 것들의 코드 집합을 반환한다."""
    return {
        s['stage_code'] for s in collection_stage
        if s.get('stage_code') in _REACHABILITY_DEPENDENT_STAGES and s.get('status') in ('MISSING', 'EMPTY')
    }


def _exploitability_status(finding: dict[str, Any], incomplete_stages: set[str]) -> str:
    """실제 도달 가능성에 대해 우리가 가진 데이터로 주장할 수 있는 최대치.

    CONFIRMED_REACHABLE은 (1)영향 패키지 존재 (2)프로세스 로드 (3)입력 경로 존재
    (4)취약 기능 활성화 확인 (5)입력이 그 기능까지 전달된다는 근거 -- 이 다섯 가지가
    전부 있어야 부여한다. 이 파이프라인은 (4)(5)를 확인할 방법이 없으므로 이 상태는
    코드/스키마상 존재만 하고 실제로는 절대 부여하지 않는다 — 허위로 "확정 도달"이라
    부르는 게 더 위험하기 때문이다.

    관련 수집단계(runtime_processes/network_exposure)가 MISSING/EMPTY면 loaded/exposed
    값 자체를 신뢰할 수 없으므로 UNKNOWN으로 처리한다(예: exposed=0이 "실제로 노출 안
    됨"이 아니라 "노출 여부를 수집 못함"일 수 있다).
    """
    if incomplete_stages:
        return REACHABILITY_UNKNOWN
    if finding.get('loaded') and finding.get('exposed'):
        return POTENTIALLY_REACHABLE
    return INSTALLED_ONLY


def annotate_findings(
    findings: list[dict[str, Any]],
    cve_by_id: dict[str, dict[str, Any]],
    kev_by_id: dict[str, dict[str, Any]],
    collection_stage: list[dict[str, Any]],
    evidence_by_finding_id: dict[int, dict[str, Any]],
    container_by_id: dict[int, dict[str, Any]],
    host_criticality: str | None,
) -> list[dict[str, Any]]:
    """모든 finding에 도달가능성/데이터검증/우선순위 티어/정렬점수를 결정론적으로 부여한다.

    이 값들은 LLM 호출 없이 규칙만으로 계산되며, 심층 분석 대상(top-N)이 아니라 전체
    finding에 적용된다 — "3,386건 중 40건만 봤다"가 아니라 "전체를 다 분류했고, 그 중
    N건만 서술형으로 심층 분석했다"고 말할 수 있게 된다.
    """
    incomplete_stages = _incomplete_reachability_stages(collection_stage)

    for f in findings:
        cve = cve_by_id.get(f.get('cve_id'), {})
        kev = kev_by_id.get(f.get('cve_id'), {})
        is_kev = bool(f.get('in_kev')) or f.get('cve_id') in kev_by_id
        ransomware = bool(kev.get('ransomware'))
        reachability = _exploitability_status(f, incomplete_stages)

        container_id = f.get('container_id') or 0
        container_info = container_by_id.get(container_id, {})
        evidence = evidence_by_finding_id.get(f['finding_id'], {})

        f['cve_summary'] = cve.get('summary')
        f['_epss'] = cve.get('epss')
        f['is_kev'] = is_kev
        f['ransomware'] = ransomware
        f['exploitability_status'] = reachability

        validation_status, conflict_codes = validate_finding(
            f,
            fixed_version=evidence.get('fixed_version'),
            container_os_id=container_info.get('os_id') if container_id else None,
            container_manager=container_info.get('manager') if container_id else None,
            feed_updated_at=evidence.get('feed_updated_at'),
        )
        f['validation_status'] = validation_status
        f['conflict_codes'] = conflict_codes

        tier, tier_reason = explain_priority_tier(
            severity=f.get('severity'),
            cvss=f.get('cvss') or cve.get('cvss'),
            epss=cve.get('epss'),
            is_kev=is_kev,
            ransomware=ransomware,
            reachability=reachability,
            validation_status=validation_status,
            criticality=host_criticality,
        )
        f['priority_tier'] = tier
        f['tier_reason'] = tier_reason
        f['_score'] = compute_priority_score(
            severity=f.get('severity'),
            cvss=f.get('cvss') or cve.get('cvss'),
            epss=cve.get('epss'),
            is_kev=is_kev,
            ransomware=ransomware,
            reachability=reachability,
            exposure_scope=f.get('exposure_scope'),
        )

    return findings


def _enrich_candidate(
    finding: dict[str, Any],
    cve_by_id: dict[str, dict[str, Any]],
    kev_by_id: dict[str, dict[str, Any]],
    evidence_by_finding_id: dict[int, dict[str, Any]],
    container_by_id: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    """서술형 분석 대상으로 뽑힌 finding 1건에 CVE/KEV/증거/컨테이너 정보를 덧붙인다."""
    cve = cve_by_id.get(finding.get('cve_id'), {})
    kev = kev_by_id.get(finding.get('cve_id'), {})
    evidence = evidence_by_finding_id.get(finding['finding_id'], {})
    container_id = finding.get('container_id') or 0
    container_info = container_by_id.get(container_id, {})

    return {
        **finding,
        'cve_cwe': cve.get('cwe'),
        'epss': cve.get('epss'),
        'epss_percentile': cve.get('epss_percentile'),
        'kev_date_added': kev.get('date_added'),
        'kev_due_date': kev.get('due_date'),
        'kev_ransomware': kev.get('ransomware'),
        'fixed_version': evidence.get('fixed_version'),
        'source_package': evidence.get('source_package'),
        'container_label': (
            '호스트' if container_id == 0
            else container_info.get('name', f'컨테이너#{container_id}')
        ),
        'container_os_id': container_info.get('os_id'),
        'container_os_version': container_info.get('os_version'),
        'container_manager': container_info.get('manager'),
    }


def select_candidate_findings(
    findings: list[dict[str, Any]],
    cve_by_id: dict[str, dict[str, Any]],
    kev_by_id: dict[str, dict[str, Any]],
    evidence_by_finding_id: dict[int, dict[str, Any]],
    container_by_id: dict[int, dict[str, Any]],
    max_total: int = 80,
) -> list[dict[str, Any]]:
    """서술형 심층 분석 대상을 고른다. findings는 이미 annotate_findings()를 거친 상태여야 한다.

    P0는 전부, P1은 예산이 허용하는 한 전부, 남는 예산은 P2 상위 점수 순으로 채운다.
    REVIEW(데이터 검증 실패) 티어는 검증 순서상 항상 포함해서 별도 섹션에 낼 수 있게 하고,
    P3는 (통계로만 요약되고) 개별 서술 대상에서 제외한다.
    """
    by_tier: dict[str, list[dict[str, Any]]] = {'P0': [], 'P1': [], 'P2': [], 'P3': [], 'REVIEW': []}
    for f in findings:
        by_tier.setdefault(f['priority_tier'], []).append(f)
    for tier in by_tier:
        by_tier[tier].sort(key=lambda f: f['_score'], reverse=True)

    p0 = by_tier['P0']
    p1 = by_tier['P1'][: max(0, max_total - len(p0))]
    remaining_budget = max_total - len(p0) - len(p1)
    p2 = by_tier['P2'][: max(0, remaining_budget)]
    review = by_tier['REVIEW']  # 검증 실패 건은 예산과 무관하게 전부 검토 섹션 후보로 포함

    candidates = p0 + p1 + p2 + review
    return [
        _enrich_candidate(f, cve_by_id, kev_by_id, evidence_by_finding_id, container_by_id)
        for f in candidates
    ]


def _restart_status(members: list[dict[str, Any]], stale_lib_packages: set[str]) -> str:
    """그룹 멤버들의 needs_restart/loaded 값과 tb_stale_lib 조인 결과로 재시작 상태를 판정한다."""
    if any(m.get('needs_restart') for m in members):
        return RESTART_REQUIRED
    if any(m.get('package_name') in stale_lib_packages for m in members):
        return RESTART_REQUIRED
    loaded_values = [m.get('loaded') for m in members]
    if any(v is None for v in loaded_values):
        return RESTART_UNKNOWN
    if any(loaded_values):
        return RESTART_CHECK_REQUIRED
    return RESTART_NOT_NEEDED


def _normalize_package_family(source_package: str | None, fallback: str) -> str:
    """`glibc-2.34-231.0.1.el9_7.10.src.rpm` 같은 원시 파일명에서 패밀리명(`glibc`)만 뽑는다.

    원본 값은 그룹의 `source_packages` 필드에 그대로 보존한다(제목만 정규화, 근거는 원문 유지).
    """
    name = source_package or fallback
    match = re.match(r'^([A-Za-z0-9][A-Za-z0-9_.+-]*?)-\d', name)
    return match.group(1) if match else name


def _action_type(no_fix: bool, validation_status: str, reachability: str) -> str:
    """검증상태/도달가능성/패치유무로 담당자가 취해야 할 조치 유형을 결정한다.

    우선순위: 데이터 검증 실패(REVIEW_REQUIRED) > 도달가능성 판정 불가(APPLICABILITY_CHECK_REQUIRED)
    > 벤더 미수정(NO_FIX_MITIGATION_REQUIRED) > 기본값(PATCH_AVAILABLE).
    """
    if validation_status in (VALIDATION_CONFLICT, VALIDATION_REVIEW_REQUIRED):
        return ACTION_REVIEW_REQUIRED
    if reachability == REACHABILITY_UNKNOWN:
        return ACTION_APPLICABILITY_CHECK_REQUIRED
    if no_fix:
        return ACTION_NO_FIX_MITIGATION_REQUIRED
    return ACTION_PATCH_AVAILABLE


def _pick_group_reachability(members: list[dict[str, Any]]) -> str:
    """그룹 대표 도달가능성 = 멤버들 중 가장 강한(REACHABILITY_PRIORITY_ORDER 상위) 값."""
    present = {m['exploitability_status'] for m in members}
    for status in REACHABILITY_PRIORITY_ORDER:
        if status in present:
            return status
    return INSTALLED_ONLY


def group_findings_for_remediation(
    candidate_findings: list[dict[str, Any]],
    stale_lib: list[dict[str, Any]],
    max_groups: int = 25,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """같은 컨테이너·같은 소스패키지의 CVE들을 하나의 조치 단위로 묶는다.

    데이터 검증(CONFLICT/REVIEW_REQUIRED)에 걸린 finding이 하나라도 섞인 그룹은
    정상 조치 그룹에서 완전히 빼서 별도 리스트로 반환한다 — 담당자가 확신 없는
    권고를 정상 조치처럼 오인하지 않도록 하기 위함이다.

    Returns: (normal_groups, conflict_groups)
    """
    stale_lib_packages = {row['package_name'] for row in stale_lib}

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for f in candidate_findings:
        family = _normalize_package_family(f.get('source_package'), f['package_name'])
        key = (f['container_label'], family)
        groups.setdefault(key, []).append(f)

    normal_groups: list[dict[str, Any]] = []
    conflict_groups: list[dict[str, Any]] = []

    for (container_label, family), members in groups.items():
        has_conflict = any(
            m['validation_status'] in (VALIDATION_CONFLICT, VALIDATION_REVIEW_REQUIRED)
            for m in members
        )
        best_tier = min((m['priority_tier'] for m in members), key=lambda t: TIER_ORDER[t])
        max_score = max(m['_score'] for m in members)
        # 티어 판정 근거는 실제로 best_tier를 만들어낸(그 티어이면서 점수가 가장 높은) 멤버 기준으로 보여준다.
        tier_reason = max(
            (m for m in members if m['priority_tier'] == best_tier),
            key=lambda m: m['_score'],
        )['tier_reason']
        installed_versions = sorted({m.get('installed_version') for m in members if m.get('installed_version')})
        fixed_versions = sorted({m.get('fixed_version') for m in members if m.get('fixed_version')})
        no_fix = any(m.get('no_fix') for m in members)
        reachability = _pick_group_reachability(members)
        restart_status = _restart_status(members, stale_lib_packages)

        effective_validation = VALIDATION_CONFLICT if has_conflict else VALIDATION_VALID
        action_type = _action_type(no_fix, effective_validation, reachability)

        cve_refs = [
            {
                'cve_id': m['cve_id'],
                'severity': m.get('severity'),
                'cvss': m.get('cvss'),
                'epss': m.get('epss'),
                'epss_percentile': m.get('epss_percentile'),
                'is_kev': bool(m.get('is_kev')),
                'exploitability_status': m['exploitability_status'],
                'fixed_version': m.get('fixed_version'),
            }
            for m in members
        ]
        cve_refs.sort(key=lambda c: SEVERITY_WEIGHT.get(c['severity'], 0), reverse=True)

        conflict_codes = sorted({code for m in members for code in m.get('conflict_codes', [])})

        group = {
            'container_label': container_label,
            'package_name': family,
            'source_packages': sorted({m.get('source_package') or m['package_name'] for m in members}),
            'container_os': (
                f"{members[0].get('container_os_id') or ''} {members[0].get('container_os_version') or ''}".strip()
                or None
            ),
            'container_manager': members[0].get('container_manager'),
            'cwe_list': sorted({m.get('cve_cwe') for m in members if m.get('cve_cwe')}),
            'installed_versions': installed_versions,
            'fixed_versions': fixed_versions,
            'tier': 'REVIEW' if has_conflict else best_tier,
            'tier_reason': tier_reason,
            'due': TIER_DUE_KO['REVIEW' if has_conflict else best_tier],
            'max_score': max_score,
            'cve_refs': cve_refs,
            'cve_count': len(cve_refs),
            'no_fix': no_fix,
            'action_type': action_type,
            'action_type_label': ACTION_LABEL_KO[action_type],
            'verification_method': VERIFICATION_METHOD_KO[action_type],
            'reachability': reachability,
            'reachability_label': REACHABILITY_LABEL_KO[reachability],
            'restart_status': restart_status,
            'restart_note': restart_note_for(restart_status, no_fix),
            'validation_status': effective_validation,
            'conflict_codes': conflict_codes,
            'conflict_labels': [CONFLICT_CODE_LABEL_KO.get(c, c) for c in conflict_codes],
            'conflict_resolutions': [CONFLICT_RESOLUTION_KO.get(c, '') for c in conflict_codes],
            'representative_rationale': members[0].get('rationale'),
            # RAG 검색 질의문 구성용(CTI 벡터 검색은 영문 CVE 설명과의 의미 유사도가 가장 안정적).
            'cve_summary_excerpt': next((m.get('cve_summary') for m in members if m.get('cve_summary')), None),
        }

        if has_conflict:
            conflict_groups.append(group)
        else:
            normal_groups.append(group)

    normal_groups.sort(key=lambda g: (TIER_ORDER[g['tier']], -g['max_score']))
    conflict_groups.sort(key=lambda g: -g['max_score'])
    return normal_groups[:max_groups], conflict_groups


def compute_risk_grade_and_score(
    findings: list[dict[str, Any]],
    host_criticality: str | None,
) -> dict[str, Any]:
    """threat/environment/impact 3개 하위 점수를 가중합해 overall_score/risk_level을 계산한다.

    tb_host.criticality가 NULL이면(이 환경은 전 호스트가 NULL) impact_score에 보수적
    기본값을 쓰고 provisional=True로 표시한다 — "정책 1: 보수적 기본값 + provisional 플래그"를
    선택했다. 정책 2(재정규화)는 자산정보 유무에 따라 점수 스케일이 달라져 스캔 간 시계열
    비교가 어려워지고, 정책 3(범위 제공)은 현재의 단일 KPI 카드 UX와 맞지 않아 제외했다.
    (tests/test_risk_scoring.py 에 이 선택을 검증하는 테스트가 있다.)
    """
    # 심각도 HIGH/CRITICAL인 finding만 "신호"로 취급 — LOW 수천 건에 평균이 희석되는 것을 방지.
    signal = [f for f in findings if f.get('severity') in ('CRITICAL', 'HIGH')]
    n_signal = len(signal) or 1

    kev_ratio = sum(1 for f in signal if f.get('is_kev')) / n_signal
    ransomware_ratio = sum(1 for f in signal if f.get('ransomware')) / n_signal
    avg_cvss = sum(float(f.get('cvss') or 0) for f in signal) / n_signal
    avg_epss = sum(float(f.get('_epss') or 0) for f in signal) / n_signal

    threat_score = min(
        THREAT_SCORE_CAP,
        kev_ratio * 100 * 0.4
        + ransomware_ratio * 100 * 0.2
        + avg_cvss * THREAT_WEIGHTS['cvss_multiplier']
        + avg_epss * THREAT_WEIGHTS['epss_multiplier'],
    ) if signal else 0.0

    signal_reachability = Counter(f['exploitability_status'] for f in signal)
    if signal:
        environment_score = sum(
            ENVIRONMENT_REACHABILITY_WEIGHTS.get(f['exploitability_status'], 0) for f in signal
        ) / n_signal
    else:
        environment_score = 0.0

    if host_criticality:
        impact_score = CRITICALITY_IMPACT_SCORE.get(host_criticality, DEFAULT_PROVISIONAL_IMPACT_SCORE)
        provisional = False
        impact_policy_note = f'자산 중요도 {host_criticality} 기준으로 계산했습니다.'
    else:
        impact_score = DEFAULT_PROVISIONAL_IMPACT_SCORE
        provisional = True
        impact_policy_note = IMPACT_POLICY_NOTE_PROVISIONAL_KO

    overall_score = (
        threat_score * OVERALL_SCORE_WEIGHTS['threat']
        + environment_score * OVERALL_SCORE_WEIGHTS['environment']
        + impact_score * OVERALL_SCORE_WEIGHTS['impact']
    )
    risk_level = score_to_risk_level(overall_score)

    tier_counts = dict(Counter(f['priority_tier'] for f in findings))

    return {
        'threat_score': round(threat_score, 1),
        'environment_score': round(environment_score, 1),
        'impact_score': round(impact_score, 1),
        'overall_score': round(overall_score, 1),
        'risk_level': risk_level,
        'risk_level_thresholds': dict(RISK_LEVEL_THRESHOLDS),
        'scoring_version': SCORING_VERSION,
        'provisional': provisional,
        'tier_counts': tier_counts,
        # 아래는 threat/environment/impact가 "왜 그 값인지" 설명하기 위한 중간 계산값들.
        'threat_signal_count': len(signal),
        'threat_kev_count': sum(1 for f in signal if f.get('is_kev')),
        'threat_ransomware_count': sum(1 for f in signal if f.get('ransomware')),
        'threat_avg_cvss': round(avg_cvss, 1),
        'threat_avg_epss': round(avg_epss, 4),
        'environment_potentially_reachable_count': signal_reachability.get(POTENTIALLY_REACHABLE, 0),
        'environment_installed_only_count': signal_reachability.get(INSTALLED_ONLY, 0),
        'impact_policy_note': impact_policy_note,
    }


def compute_confidence(
    *,
    collection_stage: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    cce_normalized_results: list[str],
    review_required_count: int,
    analyzed_count: int,
    host_criticality: str | None,
) -> dict[str, Any]:
    """수집 완전성과 분석 신뢰도를 분리해서 계산한다.

    - collection_completeness: 필수 수집 단계 완료율
    - matching_confidence: VALID로 판정된 finding 비율(no_fix 모순/CVE 근거 누락/피드
      노후화가 있으면 VALID가 아니므로 자동으로 반영된다)
    - reachability_confidence: 도달가능성이 UNKNOWN이 아닌 finding 비율
    - analysis_confidence: 위 세 값의 최솟값에서, 세 값에 아직 반영 안 된 감점 요인
      (자산 중요도 미확정, LLM 검토 보류 비율, CCE 근거부족 비율)을 추가로 차감

    필수 수집 단계가 전부 COMPLETE여도 criticality가 NULL이면 analysis_confidence는
    100이 될 수 없다(criticality_missing 감점이 항상 들어가므로).
    """
    total_required = len(REQUIRED_COLLECTION_STAGES)
    complete = sum(
        1 for code in REQUIRED_COLLECTION_STAGES
        if any(s.get('stage_code') == code and s.get('status') == 'COMPLETE' for s in collection_stage)
    )
    collection_completeness = round(complete / total_required * 100)

    total = len(findings) or 1
    valid_count = sum(1 for f in findings if f.get('validation_status') == VALIDATION_VALID)
    matching_confidence = round(valid_count / total * 100)

    non_unknown = sum(1 for f in findings if f.get('exploitability_status') != REACHABILITY_UNKNOWN)
    reachability_confidence = round(non_unknown / total * 100)

    base = min(collection_completeness, matching_confidence, reachability_confidence)

    penalty = 0.0
    if host_criticality is None:
        penalty += CONFIDENCE_PENALTIES['criticality_missing']

    review_ratio = (review_required_count / analyzed_count) if analyzed_count else 0
    penalty += CONFIDENCE_PENALTIES['review_required_ratio'] * review_ratio

    cce_total = len(cce_normalized_results) or 1
    cce_soft_count = sum(1 for r in cce_normalized_results if r in (CCE_UNKNOWN, CCE_REVIEW))
    penalty += CONFIDENCE_PENALTIES['cce_unknown_ratio'] * (cce_soft_count / cce_total)

    analysis_confidence = max(0, round(base - penalty))

    return {
        'collection_completeness': collection_completeness,
        'matching_confidence': matching_confidence,
        'reachability_confidence': reachability_confidence,
        'analysis_confidence': analysis_confidence,
        'scoring_version': SCORING_VERSION,
    }


def normalize_cce_results(cce_finding: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """원본 tb_cce_finding.result(PASS/FAIL/NA)는 그대로 두고, rationale 키워드로
    PASS/FAIL/NOT_APPLICABLE/UNKNOWN/REVIEW 5단계 `normalized_result`를 별도로 붙인다."""
    normalized = []
    for c in cce_finding:
        result = c.get('result')
        rationale = c.get('rationale') or ''

        if result == 'PASS':
            norm = CCE_PASS
        elif result == 'FAIL':
            norm = CCE_FAIL
        elif any(kw in rationale for kw in CCE_UNKNOWN_KEYWORDS):
            norm = CCE_UNKNOWN
        elif any(kw in rationale for kw in CCE_REVIEW_KEYWORDS):
            norm = CCE_REVIEW
        elif any(kw in rationale for kw in CCE_NOT_APPLICABLE_KEYWORDS):
            norm = CCE_NOT_APPLICABLE
        else:
            # NA인데 어떤 키워드에도 안 걸리면, FAIL로 부풀리지 않기 위해 안전한 기본값으로 둔다.
            norm = CCE_NOT_APPLICABLE if result == 'NA' else CCE_REVIEW

        normalized.append({**c, 'normalized_result': norm})
    return normalized


def compute_stats(
    findings: list[dict[str, Any]],
    collection_stage: list[dict[str, Any]],
    cce_finding_normalized: list[dict[str, Any]],
    container: list[dict[str, Any]],
    evidence_by_finding_id: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    """findings는 annotate_findings()를 거친 전체 목록이어야 한다."""

    severity_dist = Counter(f.get('severity') for f in findings)
    exposure_dist = Counter(f.get('exposure_scope') or 'NONE' for f in findings)
    tier_dist = Counter(f.get('priority_tier') for f in findings)
    reachability_dist = Counter(f.get('exploitability_status') for f in findings)
    validation_dist = Counter(f.get('validation_status') for f in findings)

    no_fix_count = sum(1 for f in findings if f.get('no_fix'))
    no_fix_contradiction_count = sum(
        1 for f in findings
        if f.get('no_fix') and evidence_by_finding_id.get(f['finding_id'], {}).get('fixed_version')
    )
    needs_restart_count = sum(1 for f in findings if f.get('needs_restart'))

    package_counter = Counter(f.get('package_name') for f in findings)
    top_packages = package_counter.most_common(10)

    unique_cve_count = len({f['cve_id'] for f in findings if f.get('cve_id')})
    unique_package_count = len({f['package_name'] for f in findings if f.get('package_name')})

    coverage_warnings = [
        f"{stage['stage_code']} 단계 상태: {stage['status']}"
        for stage in collection_stage
        if stage.get('status') in ('MISSING', 'EMPTY')
    ]

    cce_by_norm = Counter(c['normalized_result'] for c in cce_finding_normalized)

    feed_dates = [
        v for v in (e.get('feed_updated_at') for e in evidence_by_finding_id.values()) if v
    ]

    return {
        'total_findings': len(findings),
        'unique_cve_count': unique_cve_count,
        'unique_package_count': unique_package_count,
        'severity_distribution': dict(severity_dist),
        'exposure_distribution': dict(exposure_dist),
        'tier_distribution': dict(tier_dist),
        'reachability_distribution': dict(reachability_dist),
        'validation_distribution': dict(validation_dist),
        'no_fix_count': no_fix_count,
        'no_fix_contradiction_count': no_fix_contradiction_count,
        'needs_restart_count': needs_restart_count,
        'top_packages': top_packages,
        'container_count': len(container),
        'coverage_warnings': coverage_warnings,
        'cce_fail_items': [c for c in cce_finding_normalized if c['normalized_result'] == CCE_FAIL],
        'cce_not_applicable_items': [c for c in cce_finding_normalized if c['normalized_result'] == CCE_NOT_APPLICABLE],
        'cce_unknown_items': [c for c in cce_finding_normalized if c['normalized_result'] == CCE_UNKNOWN],
        'cce_review_items': [c for c in cce_finding_normalized if c['normalized_result'] == CCE_REVIEW],
        'cce_pass_count': cce_by_norm.get(CCE_PASS, 0),
        'cce_total': len(cce_finding_normalized),
        'feed_oldest': min(feed_dates) if feed_dates else None,
        'feed_newest': max(feed_dates) if feed_dates else None,
    }
