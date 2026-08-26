"""app/agent/rag.py 단위 테스트. 실제 Qdrant/임베딩 서버 호출 없음(mock).

QdrantClient는 autospec으로 mock한다 — 예전에 실제로는 없는 `.search()`를 mock해서
테스트는 통과하지만 실서버에서는 AttributeError가 나는 버그가 있었다(qdrant-client
1.19.0부터 search()가 query_points()로 대체됨). autospec을 쓰면 실제 클래스에 없는
메서드/시그니처를 mock하려는 순간 테스트 자체가 실패해서 이런 종류의 버그를 잡아준다.
"""

from types import SimpleNamespace
from unittest.mock import create_autospec, patch

from qdrant_client import QdrantClient

from app.agent.rag import retrieve_cti_context


def _fake_hit(score, payload):
    return SimpleNamespace(score=score, payload=payload)


def _mock_qdrant_returning(hits):
    mock_client = create_autospec(QdrantClient, instance=True)
    mock_client.query_points.return_value = SimpleNamespace(points=hits)
    return mock_client


def test_empty_query_short_circuits_without_any_call():
    with patch('app.agent.rag._get_embeddings') as mock_emb, patch('app.agent.rag._get_qdrant') as mock_qdrant:
        result = retrieve_cti_context('')
        assert result == []
        mock_emb.assert_not_called()
        mock_qdrant.assert_not_called()


def test_backend_failure_returns_empty_list_not_exception():
    """요구사항: Qdrant/임베딩 서버가 죽어있어도 파이프라인이 죽지 않고 빈 리스트를 반환해야 한다."""
    with patch('app.agent.rag._get_embeddings') as mock_emb:
        mock_emb.return_value.embed_query.side_effect = ConnectionError('unreachable')
        result = retrieve_cti_context('openssl vulnerability')
    assert result == []


def test_well_formed_hits_are_parsed_correctly():
    hits = [
        _fake_hit(0.82, {'page_content': 'APT group X used a similar OpenSSL flaw...', 'metadata': {'filename': 'report_a.pdf'}}),
        _fake_hit(0.55, {'text': 'Generic mention of certificate validation issues.', 'filename': 'report_b.pdf'}),
    ]
    with patch('app.agent.rag._get_embeddings') as mock_emb, patch('app.agent.rag._get_qdrant') as mock_qdrant:
        mock_emb.return_value.embed_query.return_value = [0.1] * 1024
        mock_qdrant.return_value = _mock_qdrant_returning(hits)

        result = retrieve_cti_context('openssl certificate validation bypass', top_k=2)

    assert len(result) == 2
    assert result[0]['source'] == 'report_a.pdf'
    assert result[0]['score'] == 0.82
    assert 'APT group X' in result[0]['text']
    assert result[1]['source'] == 'report_b.pdf'


def test_hits_with_no_extractable_text_are_skipped():
    hits = [_fake_hit(0.9, {'metadata': {'filename': 'empty.pdf'}})]  # no page_content/text/content key
    with patch('app.agent.rag._get_embeddings') as mock_emb, patch('app.agent.rag._get_qdrant') as mock_qdrant:
        mock_emb.return_value.embed_query.return_value = [0.1] * 1024
        mock_qdrant.return_value = _mock_qdrant_returning(hits)
        result = retrieve_cti_context('query')
    assert result == []


def test_calls_the_real_query_points_method_with_correct_kwargs():
    """autospec이라 실제로 존재하지 않는 메서드/인자를 쓰면 여기서 바로 실패한다."""
    with patch('app.agent.rag._get_embeddings') as mock_emb, patch('app.agent.rag._get_qdrant') as mock_qdrant:
        mock_emb.return_value.embed_query.return_value = [0.1] * 1024
        mock_client = _mock_qdrant_returning([])
        mock_qdrant.return_value = mock_client

        retrieve_cti_context('query', top_k=5, score_threshold=0.4)

        mock_client.query_points.assert_called_once()
        _, kwargs = mock_client.query_points.call_args
        assert kwargs['collection_name']
        assert kwargs['limit'] == 5
        assert kwargs['score_threshold'] == 0.4
