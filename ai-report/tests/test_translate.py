"""app/agent/translate.py 단위 테스트. 실제 translategemma 호출 없음(mock).

핵심 회귀 대상: 응답이 잘리거나(max_tokens) 일부 태그가 누락됐을 때 그 태그만
영어 원문으로 폴백되고, 나머지 정상 태그는 번역 결과가 유지되는지.
"""

from unittest.mock import MagicMock

from app.agent.translate import translate_fields


def _llm_returning(*contents):
    llm = MagicMock()
    llm.invoke.side_effect = [MagicMock(content=c) for c in contents]
    return llm


def test_empty_fields_short_circuits_without_calling_llm():
    llm = MagicMock()
    assert translate_fields(llm, {}) == {}
    llm.invoke.assert_not_called()


def test_all_tags_translated_on_first_try():
    llm = _llm_returning('[a] 안녕\n[b] 반가워')
    result = translate_fields(llm, {'a': 'hello', 'b': 'nice to meet you'})
    assert result == {'a': '안녕', 'b': '반가워'}
    assert llm.invoke.call_count == 1


def test_missing_tag_falls_back_to_english_after_retries_exhausted():
    """긴 배치의 뒤쪽 태그가 응답에서 잘려나가는 상황을 재현: b 태그가 끝까지 안 옴."""
    llm = _llm_returning('[a] 안녕', '[a] 안녕', '[a] 안녕')
    result = translate_fields(llm, {'a': 'hello', 'b': 'goodbye'}, max_retries=2)
    assert result['a'] == '안녕'
    assert result['b'] == 'goodbye'  # 영어 원문 폴백
    assert llm.invoke.call_count == 3  # 최초 1회 + 재시도 2회


def test_missing_tag_recovers_on_retry():
    llm = _llm_returning('[a] 안녕', '[a] 안녕\n[b] 반가워')
    result = translate_fields(llm, {'a': 'hello', 'b': 'nice to meet you'}, max_retries=2)
    assert result == {'a': '안녕', 'b': '반가워'}
    assert llm.invoke.call_count == 2


def test_llm_exception_falls_back_to_english_for_all_tags():
    llm = MagicMock()
    llm.invoke.side_effect = ConnectionError('translate server unreachable')
    result = translate_fields(llm, {'a': 'hello', 'b': 'goodbye'})
    assert result == {'a': 'hello', 'b': 'goodbye'}


def test_per_field_granularity_isolates_one_bad_field_from_others():
    """nodes.py가 그룹당 3태그씩 개별 호출하는 구조를 검증: 한 그룹 실패가 다른 그룹에 전염 안 됨."""
    llm_group1 = _llm_returning('[summary] 요약1\n[impact] 영향1\n[action] 조치1')
    llm_group1.invoke = MagicMock(side_effect=llm_group1.invoke.side_effect)
    result1 = translate_fields(llm_group1, {'summary': 's1', 'impact': 'i1', 'action': 'a1'})
    assert result1 == {'summary': '요약1', 'impact': '영향1', 'action': '조치1'}

    llm_group2 = MagicMock()
    llm_group2.invoke.side_effect = ConnectionError('timeout on this call only')
    result2 = translate_fields(llm_group2, {'summary': 's2', 'impact': 'i2', 'action': 'a2'})
    assert result2 == {'summary': 's2', 'impact': 'i2', 'action': 'a2'}

    # group1의 결과는 group2 실패와 무관하게 이미 온전함
    assert result1 == {'summary': '요약1', 'impact': '영향1', 'action': '조치1'}
