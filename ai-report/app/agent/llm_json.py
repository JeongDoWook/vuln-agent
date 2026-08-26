import json
import re

from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import BaseModel, ValidationError


_JSON_BLOCK_RE = re.compile(r'\{.*\}|\[.*\]', re.DOTALL)


def _extract_json_text(text: str) -> str:
    """모델 응답에서 JSON으로 보이는 첫 블록을 추출한다.

    reasoning 모델이 코드펜스(```json ... ```)나 잡담을 함께 출력하는
    경우가 많아, 가장 바깥쪽 {} 또는 [] 블록만 골라낸다.
    """
    fenced = re.search(r'```(?:json)?\s*(.*?)```', text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text

    match = _JSON_BLOCK_RE.search(candidate)
    if not match:
        raise ValueError(f'응답에서 JSON 블록을 찾을 수 없습니다: {text[:500]!r}')
    return match.group(0)


def call_llm_json[T: BaseModel](
    llm: BaseChatModel,
    system_prompt: str,
    user_prompt: str,
    schema: type[T],
    max_retries: int = 2,
) -> T:
    """LLM을 호출해 JSON 형식으로 응답을 강제하고 Pydantic으로 검증한다.

    이 프로젝트의 로컬 llama.cpp 백엔드는 OpenAI tool-calling/json_mode를
    신뢰성 있게 지원하지 않는 것으로 확인되어, 프롬프트로 JSON 출력을
    강제하고 직접 파싱/검증하는 방식을 쓴다.
    """
    messages = [
        ('system', system_prompt),
        ('human', user_prompt),
    ]

    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        response = llm.invoke(messages)
        content = response.content if isinstance(response.content, str) else str(response.content)

        try:
            json_text = _extract_json_text(content)
            data = json.loads(json_text)
            return schema.model_validate(data)
        except (ValueError, json.JSONDecodeError, ValidationError) as exc:
            last_error = exc
            messages.append(('assistant', content))
            messages.append((
                'human',
                (
                    f'응답이 요구한 JSON 스키마와 맞지 않습니다: {exc}\n'
                    f'다른 설명 없이 스키마에 맞는 JSON만 다시 출력하세요.'
                ),
            ))

    raise RuntimeError(f'LLM JSON 응답 파싱에 {max_retries + 1}회 모두 실패했습니다: {last_error}')
