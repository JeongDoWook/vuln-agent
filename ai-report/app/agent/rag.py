"""CTI(위협 인텔리전스) 벡터 검색으로 조치 그룹 분석에 배경 맥락을 보강한다.

Qdrant 컬렉션(기본값 Cyber-Threat-Intelligence)은 APT/위협 행위자 TTP 보고서를 청크
단위로 임베딩해 둔 것이다(`make_vectorDB.ipynb` 참고). 여기서 검색되는 내용은 "이 CVE가
실제로 악용됐다는 증거"가 아니라 "관련될 수 있는 배경 위협 인텔리전스"일 뿐이므로,
프롬프트(app/agent/prompts.py)에서도 그렇게만 쓰도록 강제한다 — RAG로 가져온 문서가
해당 CVE를 명시적으로 언급하지 않는 한, 특정 위협 행위자가 이 취약점을 악용했다고
단정하지 못하게 한다.

Qdrant나 임베딩 서버가 응답하지 않으면(예: 아직 배포 전, 일시 장애) 빈 리스트를 반환해
전체 파이프라인이 죽지 않도록 한다 — app/agent/translate.py의 방어적 설계와 동일하다.
"""

import logging
from typing import Any

from langchain_openai import OpenAIEmbeddings
from qdrant_client import QdrantClient

from app.config import settings


logger = logging.getLogger(__name__)


_embeddings: OpenAIEmbeddings | None = None
_qdrant: QdrantClient | None = None

# bge-m3 코사인 유사도 기준 이 값 미만은 "관련 없음"으로 보고 버린다. 실측 보정 전까지는
# 보수적으로 잡아, 애매한 결과를 억지로 끼워맞추는 것보다 아예 배경지식 없이 분석하는
# 쪽을 택한다.
DEFAULT_SCORE_THRESHOLD = 0.5
DEFAULT_TOP_K = 3
MAX_SNIPPET_CHARS = 600


def _get_embeddings() -> OpenAIEmbeddings:
    global _embeddings
    if _embeddings is None:
        _embeddings = OpenAIEmbeddings(
            model=settings.embedding_model_name,
            api_key=settings.embedding_api_key,
            base_url=settings.embedding_base_url,
        )
    return _embeddings


def _get_qdrant() -> QdrantClient:
    global _qdrant
    if _qdrant is None:
        _qdrant = QdrantClient(url=settings.qdrant_url, check_compatibility=False)
    return _qdrant


def _extract_text(payload: dict[str, Any]) -> str:
    return payload.get('page_content') or payload.get('text') or payload.get('content') or ''


def _extract_source(payload: dict[str, Any]) -> str:
    metadata = payload.get('metadata') or {}
    return metadata.get('filename') or payload.get('filename') or metadata.get('source') or 'unknown'


def retrieve_cti_context(
    query: str,
    top_k: int = DEFAULT_TOP_K,
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
) -> list[dict[str, Any]]:
    """query와 의미상 관련된 CTI 보고서 조각을 최대 top_k개 반환한다.

    Qdrant/임베딩 서버 장애, 컬렉션 부재 등 어떤 이유로든 실패하면 빈 리스트를 반환한다
    (RAG는 부가 기능이므로 실패해도 보고서 생성 자체는 계속돼야 한다).
    """
    if not query or not query.strip():
        return []

    try:
        vector = _get_embeddings().embed_query(query)
        # qdrant-client >=1.10에서 QdrantClient.search()가 제거되고 query_points()로
        # 대체됐다(1.19.0으로 실측 확인). 결과는 .points 안에 들어있다.
        hits = _get_qdrant().query_points(
            collection_name=settings.qdrant_collection_name,
            query=vector,
            limit=top_k,
            score_threshold=score_threshold,
            with_payload=True,
        ).points
    except Exception:
        # RAG는 부가 기능이라 실패해도 파이프라인을 죽이지 않지만, 조용히 묻히면 다음에
        # 또 못 찾을 수 있으니 최소한 로그는 남긴다.
        logger.warning('CTI RAG retrieval failed for query=%r', query[:80], exc_info=True)
        return []

    results = []
    for hit in hits:
        payload = hit.payload or {}
        text = _extract_text(payload)
        if not text:
            continue
        results.append({
            'text': text[:MAX_SNIPPET_CHARS],
            'source': _extract_source(payload),
            'score': round(float(hit.score), 3),
        })
    return results
