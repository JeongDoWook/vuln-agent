from typing import Any, TypedDict


class VulnagentState(TypedDict, total=False):
    """LangGraph 파이프라인 상태.

    대화형(ReAct) 에이전트가 아니라 collect -> triage -> analyze ->
    synthesize -> render 로 이어지는 고정된 다단계 파이프라인이므로
    MessagesState 대신 일반 TypedDict를 사용한다.
    """

    # 입력
    host_uuid: str
    job_id: int

    # collect_data 노드에서 채워짐
    host: dict[str, Any]
    scan: dict[str, Any]
    collection_stage: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    evidence_by_finding_id: dict[int, dict[str, Any]]
    cve_by_id: dict[str, dict[str, Any]]
    kev_by_id: dict[str, dict[str, Any]]
    exposure: list[dict[str, Any]]
    process: list[dict[str, Any]]
    package: list[dict[str, Any]]
    container: list[dict[str, Any]]
    package_dependency: list[dict[str, Any]]
    cce_finding: list[dict[str, Any]]
    stale_lib: list[dict[str, Any]]
    previous_scan_delta: dict[str, Any] | None

    # triage_findings 노드에서 채워짐 (findings는 이 단계에서 티어/도달가능성/검증상태가 부여된다)
    remediation_groups: list[dict[str, Any]]
    conflict_groups: list[dict[str, Any]]
    cce_normalized: list[dict[str, Any]]
    stats: dict[str, Any]

    # analyze_risks / synthesize_narrative 노드에서 채워짐
    review_groups: list[dict[str, Any]]
    narrative: dict[str, Any]

    # render_pdf 노드에서 채워짐
    pdf_path: str
