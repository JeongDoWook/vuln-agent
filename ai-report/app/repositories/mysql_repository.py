from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError


def get_data(db: Session, query: str, param: str | int | list) -> list:
    """query 내 :param을 param으로 바인딩해 실행한다. param이 리스트면 IN :param 절에 쓰인다
    (단, 빈 리스트는 SQL 문법 오류가 나므로 호출측(app/services/data_processing_services.py의
    _fetch_in)에서 미리 걸러야 한다)."""
    try:
        result = db.execute(
            text(query),
            {
                'param': param
            }
        )

        return result.mappings().all()

    except SQLAlchemyError as exc:
        raise RuntimeError(
            "Failed to read data from MySQL"
        ) from exc