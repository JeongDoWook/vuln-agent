import logging
import re

from langchain_core.language_models.chat_models import BaseChatModel


logger = logging.getLogger(__name__)


TRANSLATE_INSTRUCTION = (
    "Translate the following tagged English text blocks into natural, professional Korean "
    "for a security report. Keep each [tag] marker exactly as-is at the start of its "
    "translated block, in the same order. Do not translate CVE IDs, package names, version "
    "strings, port numbers, or source file names (e.g. report.pdf). Output only the tagged "
    "translations, nothing else."
)

_TAG_BLOCK_RE = re.compile(r'\[([^\]\n]+)\]\s*(.*?)(?=\n\[[^\]\n]+\]|\Z)', re.DOTALL)


def _build_tagged_text(fields: dict[str, str]) -> str:
    return '\n'.join(f'[{tag}] {text}' for tag, text in fields.items())


def _build_translation_prompt(fields: dict[str, str]) -> str:
    # translategemma는 system 메시지 + 규칙 목록 형태의 프롬프트를 주면 번역 대신 텍스트에
    # 대한 설명/답변을 하려 드는 것을 실측으로 확인했다. 시스템 메시지 없이, 지시문과
    # 원문을 하나의 user 메시지로 합쳐 보내야 안정적으로 번역만 한다.
    return f"{TRANSLATE_INSTRUCTION}\n\n{_build_tagged_text(fields)}"


def _parse_tagged_text(text: str) -> dict[str, str]:
    return {tag.strip(): content.strip() for tag, content in _TAG_BLOCK_RE.findall(text)}


def translate_fields(
    llm: BaseChatModel,
    fields: dict[str, str],
    max_retries: int = 2,
) -> dict[str, str]:
    """{tag: 영어 텍스트} -> {tag: 한국어 텍스트}.

    번역이 끝까지 실패한 태그는(모델이 누락하는 등) 빈 문자열 대신 원문(영어)을 그대로
    돌려준다 — 보고서에서 그 항목이 통째로 비는 것보다는 영어 원문이라도 남는 게 낫다.
    단, 이 폴백이 조용히 일어나면 "왜 이 항목만 영어로 남았는지" 다음에 또 알 수 없으므로
    반드시 로그를 남긴다(app/agent/rag.py의 실패 로깅과 동일한 원칙).
    """
    if not fields:
        return {}

    messages = [
        ('human', _build_translation_prompt(fields)),
    ]

    parsed: dict[str, str] = {}
    for attempt in range(max_retries + 1):
        try:
            response = llm.invoke(messages)
        except Exception:
            # 번역 서버가 응답하지 않거나 오류를 반환하면(예: 아직 배포 전) 원문 영어를
            # 그대로 사용한다 — 번역 실패로 전체 파이프라인이 죽는 것보다 낫다.
            logger.warning(
                '번역 LLM 호출 실패(attempt=%d/%d), 원문 영어로 폴백: tags=%s',
                attempt + 1, max_retries + 1, list(fields), exc_info=True,
            )
            break

        content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_tagged_text(content)

        if all(parsed.get(tag) for tag in fields):
            break

        missing = [tag for tag in fields if not parsed.get(tag)]
        logger.warning(
            '번역 응답에 일부 태그 누락(attempt=%d/%d): missing=%s',
            attempt + 1, max_retries + 1, missing,
        )
        messages.append(('assistant', content))
        messages.append((
            'human',
            '일부 [tag] 항목이 누락되었습니다. 입력으로 주어진 모든 태그를 정확히 동일한 '
            '형식으로 다시 출력하세요.',
        ))

    still_missing = [tag for tag in fields if not parsed.get(tag)]
    if still_missing:
        logger.warning(
            '번역 재시도 소진, 다음 태그는 영어 원문으로 폴백됨: %s', still_missing,
        )

    return {tag: parsed.get(tag) or fields[tag] for tag in fields}
