"""취약점 분석 파이프라인의 LangGraph 조립부. 각 노드가 실제로 무엇을 하는지는
app/agent/nodes.py 상단 모듈 docstring과 각 노드 함수의 docstring을 참고."""

from langgraph.graph import StateGraph, START, END

from app.agent.nodes import (
    collect_data,
    triage_findings,
    analyze_risks,
    synthesize_narrative,
    render_pdf,
)
from app.agent.state import VulnagentState


def _build_graph():
    graph = StateGraph(VulnagentState)

    graph.add_node('collect_data', collect_data)
    graph.add_node('triage_findings', triage_findings)
    graph.add_node('analyze_risks', analyze_risks)
    graph.add_node('synthesize_narrative', synthesize_narrative)
    graph.add_node('render_pdf', render_pdf)

    graph.add_edge(START, 'collect_data')
    graph.add_edge('collect_data', 'triage_findings')
    graph.add_edge('triage_findings', 'analyze_risks')
    graph.add_edge('analyze_risks', 'synthesize_narrative')
    graph.add_edge('synthesize_narrative', 'render_pdf')
    graph.add_edge('render_pdf', END)

    return graph.compile()


vuln_agent_graph = _build_graph()


def run_vuln_agent(host_uuid: str, job_id: int) -> str:
    """호스트 취약점 분석 파이프라인을 실행하고 생성된 PDF 경로를 반환한다."""
    result = vuln_agent_graph.invoke({
        'host_uuid': host_uuid,
        'job_id': job_id,
    })
    return result['pdf_path']
