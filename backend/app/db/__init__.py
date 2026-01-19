"""
Capa de base de datos para ALERTA-LINK

Este modulo maneja la conexion a PostgreSQL y provee
dependencias para inyeccion en FastAPI.
"""

from app.db.database import engine, SessionLocal, get_engine_status
from app.db.dependencies import get_db, get_db_optional

__all__ = [
    "engine",
    "SessionLocal",
    "get_engine_status",
    "get_db",
    "get_db_optional",
]
