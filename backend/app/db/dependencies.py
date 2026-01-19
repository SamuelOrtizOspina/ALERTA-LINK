"""
Dependencias de base de datos para FastAPI

Provee funciones generadoras para inyeccion de dependencias
en los endpoints de FastAPI.
"""

import logging
from typing import Generator, Optional

from sqlalchemy.orm import Session

from app.db.database import get_session_factory, is_db_available

logger = logging.getLogger(__name__)


def get_db() -> Generator[Session, None, None]:
    """
    Dependencia FastAPI para obtener sesion de BD.

    Uso en endpoint:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()

    Raises:
        RuntimeError si la BD no esta disponible
    """
    factory = get_session_factory()

    if factory is None:
        raise RuntimeError("Base de datos no configurada o no disponible")

    db = factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db_optional() -> Generator[Optional[Session], None, None]:
    """
    Dependencia FastAPI para obtener sesion de BD opcional.

    Retorna None si la BD no esta disponible, permitiendo
    que el endpoint use fallback (ej: JSONL).

    Uso en endpoint:
        @app.post("/ingest")
        def ingest(db: Optional[Session] = Depends(get_db_optional)):
            if db:
                # Usar PostgreSQL
                db.add(record)
            else:
                # Usar fallback JSONL
                save_to_jsonl(record)
    """
    if not is_db_available():
        logger.debug("BD no disponible, retornando None")
        yield None
        return

    factory = get_session_factory()

    if factory is None:
        yield None
        return

    db = factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
