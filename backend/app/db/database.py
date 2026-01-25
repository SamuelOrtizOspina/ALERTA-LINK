"""
Configuracion del engine SQLAlchemy y SessionLocal

Maneja la conexion a PostgreSQL con fallback seguro si
la base de datos no esta disponible.
"""

import logging
from typing import Optional
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError

from app.core.config import settings

logger = logging.getLogger(__name__)

# Engine global - se inicializa lazy
_engine = None
_SessionLocal = None
_db_available = None


def get_engine():
    """
    Obtiene o crea el engine de SQLAlchemy.

    Usa patron singleton para reutilizar la conexion.
    """
    global _engine

    if _engine is None:
        try:
            _engine = create_engine(
                settings.DATABASE_URL,
                pool_pre_ping=True,  # Verifica conexion antes de usar
                pool_size=5,
                max_overflow=10,
                pool_timeout=30,
                echo=settings.DEBUG,
            )
            logger.info("Engine SQLAlchemy creado exitosamente")
        except Exception as e:
            logger.error(f"Error creando engine: {e}")
            _engine = None

    return _engine


def get_session_factory():
    """
    Obtiene o crea el SessionLocal factory.
    """
    global _SessionLocal

    if _SessionLocal is None:
        eng = get_engine()
        if eng is not None:
            _SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=eng
            )

    return _SessionLocal


def check_db_connection() -> bool:
    """
    Verifica si la base de datos esta disponible.

    Returns:
        True si la conexion es exitosa, False en caso contrario
    """
    global _db_available

    eng = get_engine()
    if eng is None:
        _db_available = False
        return False

    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
            conn.commit()
        _db_available = True
        logger.info("Conexion a PostgreSQL verificada")
        return True
    except OperationalError as e:
        logger.warning(f"PostgreSQL no disponible: {e}")
        _db_available = False
        return False
    except Exception as e:
        logger.error(f"Error verificando conexion: {e}")
        _db_available = False
        return False


def is_db_available() -> bool:
    """
    Retorna el estado de disponibilidad de la BD.

    Usa cache para evitar verificaciones constantes.
    """
    global _db_available

    if _db_available is None:
        check_db_connection()

    return _db_available


def get_engine_status() -> dict:
    """
    Retorna informacion sobre el estado del engine.
    """
    eng = get_engine()
    available = is_db_available()

    return {
        "available": available,
        "url": settings.DATABASE_URL.split("@")[-1] if available else None,
        "pool_size": eng.pool.size() if eng and hasattr(eng, 'pool') else None,
    }


@contextmanager
def get_db_session():
    """
    Context manager para obtener una sesion de BD.

    Uso:
        with get_db_session() as db:
            db.query(Model).all()
    """
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Base de datos no disponible")

    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Aliases para compatibilidad
engine = property(lambda self: get_engine())
SessionLocal = get_session_factory()
