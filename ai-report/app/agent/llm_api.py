from app.config import settings
from langchain_openai import ChatOpenAI


# 로컬 LLM(llama.cpp)이 응답 전 reasoning_content를 길게 생성하는 thinking 모델이라
# max_tokens를 넉넉히 주지 않으면 답변 본문이 나오기 전에 잘린다.
# 이 모델에는 영어로 위험 분석 콘텐츠를 작성하게 하고(사이버보안 전문 모델), 결과를
# translate_llm(translategemma)으로 한국어 번역한다.
oepnai_api_llm = ChatOpenAI(
    model=settings.model_name,
    api_key=settings.llm_api_key,
    base_url=settings.llm_base_url,
    max_tokens=8192,
    temperature=0.2,
    max_retries=2,
)

# 영→한 번역 전용 모델(translategemma, 8081 포트). 번역 작업이라 온도는 낮게 둔다.
# max_tokens=4096이던 시절엔 그룹 8개(최대 24개 태그)를 한 번에 번역하다 응답이 중간에
# 잘려 뒤쪽 태그가 누락 -> 영어 원문 폴백되는 문제가 있었다(app/agent/nodes.py에서 그룹당
# 개별 호출로 바꿔 배치 자체를 줄였지만, CTI 인용이 붙어 필드 하나가 길어지는 경우에도
# 여유를 두기 위해 상한도 같이 올린다).
translate_llm = ChatOpenAI(
    model=settings.translate_model_name,
    api_key=settings.translate_llm_api_key,
    base_url=settings.translate_llm_base_url,
    max_tokens=8192,
    temperature=0.1,
    max_retries=2,
)