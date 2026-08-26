"""PDF 렌더링 직전에 실행하는 보고서 자체 검증 게이트.

여기서 걸러지는 항목이 하나라도 있으면 PDF를 SUCCESS로 완료하지 않는다 — 사용자에게는
스택트레이스나 SQL 원문 없이 어떤 검증에 실패했는지만 알려준다(ReportQAError.message).

완전한 의미론적 검증(LLM이 입력에 없는 인과관계를 만들어냈는지 등)은 이 함수만으로는
불가능하다 — 여기서는 구조적으로 확인 가능한 것과, 정규식으로 저비용에 확인 가능한
"금지 표현" 위반만 다룬다. 나머지는 프롬프트 단의 제약(app/agent/prompts.py)이 1차 방어선이다.
"""

import re
from typing import Any


class ReportQAError(Exception):
    """보고서 자체 검증 실패. message는 내부 로그/문제 진단용으로만 안전하게 노출한다."""


# 도달가능성을 확정적 악용으로 과장하는 표현 — AI가 생성한 한글 텍스트에 있으면 안 됨.
_FORBIDDEN_PHRASES = [
    '확정적으로 악용', '실제로 악용됨', '즉시 원격 코드 실행', '직접 악용 가능',
    '외부에서 직접 악용', '악용이 확인되었', 'RCE가 가능합니다', '확실히 악용',
]

# RAG로 CTI 컨텍스트가 하나도 없는데 위협 행위자/APT를 언급하면 근거 없는 귀속(attribution)
# 환각일 가능성이 높다.
_THREAT_ACTOR_KEYWORDS = ['APT', '위협 행위자', '해킹 그룹', '랜섬웨어 조직']


def _extract_cve_ids(text: str) -> set[str]:
    return set(re.findall(r'CVE-\d{4}-\d+', text or ''))


# 번역이 정상적으로 됐다면 한글 문장 사이에 CVE ID/패키지명/버전 등 영문 토큰이 섞여
# 있는 정도라 한글:영문 알파벳 비율이 낮게 나오지 않는다. 이 비율이 낮으면 번역이
# 아예 안 됐거나(영어 원문 폴백) 중간에 잘렸을 가능성이 높다는 뜻이다.
_MIN_TEXT_LEN_FOR_HANGUL_CHECK = 40
_MIN_HANGUL_RATIO = 0.25


def _hangul_ratio(text: str) -> float | None:
    """text 중 한글:(한글+라틴alpha) 비율. 검사 대상이 아니면(너무 짧으면) None."""
    if not text or len(text) < _MIN_TEXT_LEN_FOR_HANGUL_CHECK:
        return None
    hangul = sum(1 for ch in text if '가' <= ch <= '힣')
    latin = sum(1 for ch in text if ch.isascii() and ch.isalpha())
    total = hangul + latin
    if total == 0:
        return None
    return hangul / total


def run_report_qa(
    *,
    host: dict[str, Any],
    stats: dict[str, Any],
    remediation_groups: list[dict[str, Any]],
    conflict_groups: list[dict[str, Any]],
    review_groups: list[dict[str, Any]],
    narrative: dict[str, Any],
) -> list[str]:
    """구조적으로 검증 가능한 항목을 검사해 위반 목록(빈 리스트면 통과)을 반환한다."""
    issues: list[str] = []

    # 1) 위험점수 산정 근거(구간/버전)가 빠지지 않았는지
    for key in ('risk_level', 'risk_level_thresholds', 'scoring_version', 'overall_score'):
        if stats.get(key) in (None, ''):
            issues.append(f'위험도 산정 근거 누락: stats.{key}')

    # 2) 수집완전성/분석신뢰도가 분리되어 둘 다 존재하는지 (혼용 방지)
    for key in ('collection_completeness', 'analysis_confidence', 'matching_confidence', 'reachability_confidence'):
        if stats.get(key) is None:
            issues.append(f'신뢰도 지표 누락: stats.{key}')

    # 3) P0=0인데 P0 등급 그룹(따라서 "24시간 이내" 문구)이 본문에 남아있는지
    p0_count = stats.get('tier_distribution', {}).get('P0', 0)
    if p0_count == 0:
        for g in remediation_groups:
            if g.get('tier') == 'P0':
                issues.append('P0=0인데 P0 등급 그룹이 본문에 존재함')

    # 4) no_fix=True인 정상 조치 그룹에 "패치"/"업데이트" 권고가 주된 조치로 들어갔는지
    for g in remediation_groups:
        if g.get('no_fix') and g.get('action_type') == 'NO_FIX_MITIGATION_REQUIRED':
            action_text = g.get('recommended_action') or ''
            if action_text and ('패치를 적용' in action_text or '업그레이드하십시오' in action_text) and '완화' not in action_text and '제한' not in action_text:
                issues.append(f"no_fix 그룹({g['package_name']}·{g['container_label']})에 패치 권고 텍스트가 주 조치로 포함됨")

    # 5) CONFLICT/REVIEW_REQUIRED 그룹이 정상 remediation_groups에 섞여있는지
    for g in remediation_groups:
        if g.get('validation_status') in ('CONFLICT', 'REVIEW_REQUIRED'):
            issues.append(f"검증 실패 그룹이 정상 조치 그룹에 포함됨: {g['package_name']}·{g['container_label']}")

    # 6) 그룹 카드 AI 텍스트에 그 그룹 소속이 아닌 CVE ID가 언급됐는지(가장 구체적인 환각 탐지)
    for g in remediation_groups:
        own_cves = {c['cve_id'] for c in g.get('cve_refs', [])}
        mentioned = _extract_cve_ids(
            (g.get('risk_summary') or '') + (g.get('impact') or '') + (g.get('recommended_action') or '')
        )
        stray = mentioned - own_cves
        if stray:
            issues.append(f"그룹({g['package_name']}·{g['container_label']}) 설명에 소속 아닌 CVE 언급: {sorted(stray)}")

    # 7) 금지 표현(확정적 악용 단정) 검사 — 그룹 설명 + 총평/권고/결론
    all_ai_text = ' '.join(
        [narrative.get('executive_summary') or '', narrative.get('overall_recommendation') or '', narrative.get('conclusion') or '']
        + [g.get('risk_summary') or '' for g in remediation_groups]
        + [g.get('impact') or '' for g in remediation_groups]
        + [g.get('recommended_action') or '' for g in remediation_groups]
    )
    for phrase in _FORBIDDEN_PHRASES:
        if phrase in all_ai_text:
            issues.append(f'금지 표현("{phrase}") 발견 — 도달가능성을 확정적 악용으로 과장')

    # 8) 표지/본문/부록 집계 일치 여부
    # total_group_count는 triage 시점(LLM 호출 전)의 (정상 그룹 + 충돌 그룹) 개수다.
    # LLM 분석 후에는 정상 그룹 중 일부가 review_groups로 옮겨갈 뿐 총합은 변하지 않아야 한다.
    total_groups_rendered = len(remediation_groups) + len(review_groups) + len(conflict_groups)
    if stats.get('total_group_count') is not None and total_groups_rendered != stats['total_group_count']:
        issues.append(
            f'집계 불일치: total_group_count={stats.get("total_group_count")} vs '
            f'렌더링된 그룹 수(정상+검토+충돌)={total_groups_rendered}'
        )

    # 9b) CTI 배경자료(cti_snippets)가 하나도 없는데 위협 행위자/APT 이름을 언급했는지
    #     (RAG로 실제로 뭔가 찾은 게 없으면 그 그룹 설명에 위협 행위자 귀속이 나올 근거가 없다)
    for g in remediation_groups:
        if g.get('cti_snippets'):
            continue
        combined_text = (g.get('risk_summary') or '') + (g.get('impact') or '')
        for kw in _THREAT_ACTOR_KEYWORDS:
            if kw in combined_text:
                issues.append(
                    f"그룹({g['package_name']}·{g['container_label']})에 CTI 근거 없이 "
                    f"위협 행위자 언급(\"{kw}\") 발견 — 근거 없는 귀속(attribution) 가능성"
                )
                break

    # 9c) 번역 누락/실패로 영어 원문이 그대로 남은 AI 텍스트가 있는지(app/agent/translate.py의
    #     영어 폴백이 조용히 보고서까지 올라오는 것을 막는 최종 안전망).
    text_fields_to_check: list[tuple[str, str]] = [
        ('총평(executive_summary)', narrative.get('executive_summary') or ''),
        ('종합 권고(overall_recommendation)', narrative.get('overall_recommendation') or ''),
        ('결론(conclusion)', narrative.get('conclusion') or ''),
    ]
    for g in remediation_groups:
        label = f"그룹({g.get('package_name')}·{g.get('container_label')})"
        text_fields_to_check.append((f'{label} 위험 요약', g.get('risk_summary') or ''))
        text_fields_to_check.append((f'{label} 영향', g.get('impact') or ''))
        text_fields_to_check.append((f'{label} 권고 조치', g.get('recommended_action') or ''))

    for field_label, text in text_fields_to_check:
        ratio = _hangul_ratio(text)
        if ratio is not None and ratio < _MIN_HANGUL_RATIO:
            issues.append(f'번역 누락 의심(한글 비율 {ratio:.0%}): {field_label}')

    # 9) finding 수 vs 고유 CVE 수 혼동(같은 값이면 의심 — 3천여 finding에 CVE도 똑같이 3천이면 이상)
    if (
        stats.get('total_findings')
        and stats.get('unique_cve_count')
        and stats['total_findings'] == stats['unique_cve_count']
        and stats['total_findings'] > 50
    ):
        issues.append('finding 수와 고유 CVE 수가 동일함 — 집계 로직 확인 필요')

    return issues
