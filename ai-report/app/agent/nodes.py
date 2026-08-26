"""LangGraph 파이프라인의 5개 노드(app/agent/graph.py에서 이 순서로 연결됨):

1. collect_data        MySQL에서 호스트의 최신 스캔 원본 데이터를 읽어온다.
2. triage_findings      전체 finding에 도달가능성/검증상태/우선순위 티어를 결정론적으로 부여하고
                        (LLM 미사용), 서술형 심층 분석 대상을 추려 조치 그룹으로 묶은 뒤 CTI를 붙인다.
3. analyze_risks        조치 그룹별로 LLM에게 영어로 위험 서술을 받고(cybersecurity 전문 모델),
                        translategemma로 한국어 번역까지 마친다.
4. synthesize_narrative 보고서 전체의 총평/권고/결론을 LLM으로 작성하고 번역한다.
5. render_pdf           보고서 자체 검증(report_qa)을 통과해야만 Jinja2+WeasyPrint로 PDF를 만든다.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from app.agent.llm_api import openai_api_llm, translate_llm
from app.agent.llm_json import call_llm_json
from app.agent.prompts import (
    GROUP_ANALYSIS_SYSTEM_PROMPT,
    REPORT_SYNTHESIS_SYSTEM_PROMPT,
    build_group_analysis_user_prompt,
    build_report_synthesis_user_prompt,
)
from app.agent.translate import translate_fields
from app.agent.rag import retrieve_cti_context
from app.agent.report_qa import run_report_qa, ReportQAError
from app.agent.risk_scoring import (
    TIER_ORDER,
    TIER_CRITERIA_KO,
    RESTART_REQUIRED,
    RESTART_CHECK_REQUIRED,
    CONFLICT_MISSING_CVE_EVIDENCE,
    MISSING_CVE_EVIDENCE_WARNING_RATIO,
)
from app.agent.state import VulnagentState
from app.config import settings
from app.database.mysql_session import MySQLSessionLocal
from app.schemas.report import ReportNarrative, GroupNarrativeList
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


GROUP_BATCH_SIZE = 8
MAX_CANDIDATE_FINDINGS = 80
MAX_GROUPS = 25
# 본문에 상세 카드로 보여줄 최대 조치 그룹 수(그 이상은 요약 표 + 기술 부록으로).
DETAIL_GROUP_LIMIT = 12
# CTI(위협 인텔리전스) RAG 검색 — 그룹당 상위 몇 건을, 유사도 몇 이상만 채택할지.
RAG_TOP_K = 3
RAG_SCORE_THRESHOLD = 0.5


def _attach_cti_context(remediation_groups: list[dict]) -> None:
    """조치 그룹마다 Qdrant CTI 컬렉션에서 관련 배경 맥락을 찾아 붙인다.

    Qdrant/임베딩 서버가 응답하지 않으면 retrieve_cti_context()가 빈 리스트를 반환하므로
    이 함수는 항상 안전하다(파이프라인을 멈추지 않는다).
    """
    for g in remediation_groups:
        query = ' '.join(filter(None, [
            g['package_name'],
            ' '.join(g.get('cwe_list') or []),
            g.get('cve_summary_excerpt'),
        ]))
        g['cti_snippets'] = retrieve_cti_context(query, top_k=RAG_TOP_K, score_threshold=RAG_SCORE_THRESHOLD)


_TEMPLATE_DIR = Path(__file__).parent / 'templates'
_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(['html']),
    trim_blocks=True,
    lstrip_blocks=True,
)


def collect_data(state: VulnagentState) -> dict:
    """host_uuid로 최신 스캔의 원본 데이터를 MySQL에서 읽어온다(1단계, LLM 미사용)."""
    db = MySQLSessionLocal()
    try:
        data = collect_host_vulnerability_data(db, state['host_uuid'])
    finally:
        db.close()

    return data


def triage_findings(state: VulnagentState) -> dict:
    """전체 finding 분류·조치 그룹화·위험점수/신뢰도 계산까지 마친다(2단계, LLM 미사용).

    이후 analyze_risks에서 LLM이 서술문을 붙일 remediation_groups/conflict_groups와,
    표지·부록에 쓰일 stats를 만든다.
    """
    host_criticality = state['host'].get('criticality')
    container_by_id = {c['container_id']: c for c in state['container']}

    findings = annotate_findings(
        state['findings'], state['cve_by_id'], state['kev_by_id'],
        state['collection_stage'], state['evidence_by_finding_id'],
        container_by_id, host_criticality,
    )

    candidate_findings = select_candidate_findings(
        findings=findings,
        cve_by_id=state['cve_by_id'],
        kev_by_id=state['kev_by_id'],
        evidence_by_finding_id=state['evidence_by_finding_id'],
        container_by_id=container_by_id,
        max_total=MAX_CANDIDATE_FINDINGS,
    )
    remediation_groups, conflict_groups = group_findings_for_remediation(
        candidate_findings, state['stale_lib'], max_groups=MAX_GROUPS,
    )
    _attach_cti_context(remediation_groups)

    risk = compute_risk_grade_and_score(findings, host_criticality)
    cce_normalized = normalize_cce_results(state['cce_finding'])

    stats = compute_stats(
        findings=findings,
        collection_stage=state['collection_stage'],
        cce_finding_normalized=cce_normalized,
        container=state['container'],
        evidence_by_finding_id=state['evidence_by_finding_id'],
    )
    stats.update(risk)
    confidence = compute_confidence(
        collection_stage=state['collection_stage'],
        findings=findings,
        cce_normalized_results=[c['normalized_result'] for c in cce_normalized],
        review_required_count=0,
        analyzed_count=len(remediation_groups) + len(conflict_groups),
        host_criticality=host_criticality,
    )
    stats.update(confidence)
    stats['analyzed_findings'] = len(candidate_findings)
    stats['total_group_count'] = len(remediation_groups) + len(conflict_groups)
    stats['previous_scan_delta'] = state.get('previous_scan_delta')

    # "재시작 필요 0건"이 "패치해도 재시작 불필요"로 오독되지 않도록 세분화한 값들.
    stats['restart_required_group_count'] = sum(1 for g in remediation_groups if g['restart_status'] == RESTART_REQUIRED)
    stats['restart_check_group_count'] = sum(1 for g in remediation_groups if g['restart_status'] == RESTART_CHECK_REQUIRED)

    # "도달가능성 판정 신뢰도 100%"가 "악용 확정 100%"로 오독되지 않도록, 우리가 절대
    # 확인하지 않는(할 수 없는) 항목을 명시적으로 0으로 노출한다.
    stats['confirmed_reachable_count'] = stats['reachability_distribution'].get('CONFIRMED_REACHABLE', 0)
    stats['vulnerable_feature_confirmed_count'] = 0
    stats['attacker_input_path_confirmed_count'] = 0

    # MISSING_CVE_EVIDENCE 비율이 높으면 보고서만의 문제가 아니라 피드 수집/조인 로직 문제일
    # 수 있으므로 데이터 품질 경고로 승격한다.
    total_groups = len(remediation_groups) + len(conflict_groups)
    missing_evidence_count = sum(
        1 for g in conflict_groups if CONFLICT_MISSING_CVE_EVIDENCE in g['conflict_codes']
    )
    if total_groups and (missing_evidence_count / total_groups) >= MISSING_CVE_EVIDENCE_WARNING_RATIO:
        stats['coverage_warnings'].append(
            f'CVE 근거 누락(MISSING_CVE_EVIDENCE) 충돌이 전체 조치 그룹의 '
            f'{round(missing_evidence_count / total_groups * 100)}%({missing_evidence_count}/{total_groups}건)를 '
            f'차지합니다 — 보고서 개별 오류가 아니라 CVE 근거 피드 수집·조인 로직 점검이 필요할 수 있습니다.'
        )

    return {
        'remediation_groups': remediation_groups,
        'conflict_groups': conflict_groups,
        'cce_normalized': cce_normalized,
        'stats': stats,
    }


def _batched(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def analyze_risks(state: VulnagentState) -> dict:
    """조치 그룹마다 LLM 서술(영어) + 번역(한국어)을 붙인다(3단계).

    GROUP_BATCH_SIZE개씩 묶어 한 번의 LLM 호출로 분석하지만, 번역은 그룹당 개별 호출로
    쪼갠다(app/agent/translate.py 참고 — 번역 응답이 잘려 일부만 영어로 남는 문제 방지).
    """
    remediation_groups = state['remediation_groups']
    review_groups: list[dict] = []

    for batch in _batched(remediation_groups, GROUP_BATCH_SIZE):
        try:
            result = call_llm_json(
                llm=openai_api_llm,
                system_prompt=GROUP_ANALYSIS_SYSTEM_PROMPT,
                user_prompt=build_group_analysis_user_prompt(batch),
                schema=GroupNarrativeList,
            )
        except Exception:
            # 배치 전체가 실패하면 이 배치의 그룹들은 전부 검토 대기로 보낸다
            for g in batch:
                g['tier'] = 'REVIEW'
                review_groups.append(g)
            continue

        narratives_by_index = {}
        seen_indices = set()
        for item in result.items:
            if item.index in seen_indices or not (1 <= item.index <= len(batch)):
                continue
            seen_indices.add(item.index)
            narratives_by_index[item.index] = item

        # 영어로 생성된 필드는 그룹 단위(3개 태그)로 개별 번역한다. 예전엔 배치 전체
        # (최대 8그룹 x 3필드 = 24태그)를 한 번의 translate_fields() 호출로 묶었는데,
        # CTI 인용이 붙어 필드가 길어지면 translategemma 응답이 max_tokens에서 잘려
        # 뒤쪽 그룹 태그가 통째로 누락 -> 영어 원문 폴백되는 사례가 있었다(보고서 일부만
        # 한글로 번역 안 되는 버그). 그룹당 호출을 쪼개면 한 그룹의 번역 실패가 다른
        # 그룹에 전염되지 않고, 각 호출의 응답 길이도 짧아져 잘릴 위험 자체가 줄어든다.
        for i, group in enumerate(batch, start=1):
            narrative = narratives_by_index.get(i)
            if narrative is None:
                # LLM이 이 그룹을 누락했거나 index가 어긋남 -> 신뢰할 수 없으므로 본문에서 제외
                group['tier'] = 'REVIEW'
                review_groups.append(group)
                continue

            translated = translate_fields(translate_llm, {
                'summary': narrative.risk_summary,
                'impact': narrative.impact,
                'action': narrative.recommended_action,
            })
            group['risk_summary'] = translated['summary']
            group['impact'] = translated['impact']
            group['recommended_action'] = f"{translated['action']} {group['restart_note']}"

    analyzed_groups = [g for g in remediation_groups if g.get('risk_summary')]
    analyzed_groups.sort(key=lambda g: (TIER_ORDER.get(g['tier'], 4), -g['max_score']))

    stats = dict(state['stats'])
    stats['analyzed_group_count'] = len(analyzed_groups)
    stats['review_required_count'] = len(review_groups)
    confidence = compute_confidence(
        collection_stage=state['collection_stage'],
        findings=state['findings'],
        cce_normalized_results=[c['normalized_result'] for c in state['cce_normalized']],
        review_required_count=len(review_groups),
        analyzed_count=len(remediation_groups) + len(state['conflict_groups']),
        host_criticality=state['host'].get('criticality'),
    )
    stats.update(confidence)

    return {
        'remediation_groups': analyzed_groups,
        'review_groups': review_groups,
        'stats': stats,
    }


def synthesize_narrative(state: VulnagentState) -> dict:
    """보고서 전체의 총평/권고/결론을 LLM으로 작성(영어)하고 번역한다(4단계)."""
    narrative_en = call_llm_json(
        llm=openai_api_llm,
        system_prompt=REPORT_SYNTHESIS_SYSTEM_PROMPT,
        user_prompt=build_report_synthesis_user_prompt(
            host=state['host'],
            scan=state['scan'],
            stats=state['stats'],
            remediation_groups=state['remediation_groups'],
            conflict_group_count=len(state['conflict_groups']),
        ),
        schema=ReportNarrative,
    )

    narrative = translate_fields(translate_llm, narrative_en.model_dump())

    return {'narrative': narrative}


def render_pdf(state: VulnagentState) -> dict:
    """보고서 자체 검증(report_qa)을 통과한 경우에만 PDF를 렌더링한다(5단계, 최종).

    검증에 하나라도 걸리면 ReportQAError를 던져 여기서 파이프라인이 멈춘다 — 상위
    Celery 태스크가 이를 잡아 잡 상태를 FAILED로 남기고, 문제 있는 PDF가 SUCCESS로
    사용자에게 노출되는 일은 없다.
    """
    issues = run_report_qa(
        host=state['host'],
        stats=state['stats'],
        remediation_groups=state['remediation_groups'],
        conflict_groups=state['conflict_groups'],
        review_groups=state['review_groups'],
        narrative=state['narrative'],
    )
    if issues:
        raise ReportQAError('보고서 자체 검증 실패: ' + '; '.join(issues))

    detail_groups = state['remediation_groups'][:DETAIL_GROUP_LIMIT]
    summary_groups = state['remediation_groups'][DETAIL_GROUP_LIMIT:]

    template = _env.get_template('report.html.jinja')
    html_content = template.render(
        host=state['host'],
        scan=state['scan'],
        stats=state['stats'],
        detail_groups=detail_groups,
        summary_groups=summary_groups,
        all_groups=state['remediation_groups'],
        conflict_groups=state['conflict_groups'],
        review_groups=state['review_groups'],
        narrative=state['narrative'],
        previous_scan_delta=state.get('previous_scan_delta'),
        generated_at=state['scan'].get('collected_at'),
        job_id=state['job_id'],
        tier_criteria=TIER_CRITERIA_KO,
    )

    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = reports_dir / f"job_{state['job_id']}.pdf"

    HTML(string=html_content, base_url=str(_TEMPLATE_DIR)).write_pdf(str(pdf_path))

    return {'pdf_path': str(pdf_path)}
