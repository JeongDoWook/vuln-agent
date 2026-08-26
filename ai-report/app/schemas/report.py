from pydantic import BaseModel, Field


class GroupNarrative(BaseModel):
    """LLM이 하나의 조치 그룹(같은 컨테이너·같은 소스패키지)에 대해 작성하는 분석 문장.

    cve_id/package_name/우선순위 등 식별 정보는 LLM이 되돌려준 값을 신뢰하지 않고
    우리가 보낸 index로만 원본 그룹 데이터에 되붙인다 (배치 처리 중 항목이 뒤섞이는
    문제를 실측으로 확인했기 때문).
    """

    index: int = Field(description="Must exactly match the group number ([N]) given in the input")
    risk_summary: str = Field(description="Why this matters in this environment, grounded only in the given evidence (English)")
    impact: str = Field(description="Expected impact if exploited (English)")
    recommended_action: str = Field(description="Concrete remediation action (English)")


class GroupNarrativeList(BaseModel):
    items: list[GroupNarrative]


class ReportNarrative(BaseModel):
    """전체 리포트의 총평/권고/결론 (LLM 합성 결과)."""

    executive_summary: str = Field(description="Overall risk assessment summary for the host (English)")
    overall_recommendation: str = Field(description="Overall remediation strategy (English)")
    conclusion: str = Field(description="Closing conclusion (English)")
