"""
Endpoint /health para verificar estado del servicio

Incluye verificacion de modelo ML y conexion a PostgreSQL.
"""

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings
from app.services.predictor import predictor
from app.services.whois_service import whois_service
from app.db.database import is_db_available, get_engine_status

router = APIRouter()


class DatabaseStatus(BaseModel):
    """Estado de la base de datos."""
    available: bool
    storage: str  # postgresql o jsonl


class HealthResponse(BaseModel):
    """Respuesta del endpoint de salud."""
    status: str
    version: str
    model_loaded: bool
    database: DatabaseStatus
    apis: dict


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Verifica el estado del servicio.

    Incluye:
    - Estado general del servicio
    - Version de la aplicacion
    - Estado del modelo ML
    - Estado de la base de datos
    - Estado de APIs externas

    Returns:
        Estado completo del servicio
    """
    db_available = is_db_available()

    # Verificar APIs configuradas
    api_status = settings.validate_api_keys()

    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        model_loaded=predictor.is_loaded(),
        database=DatabaseStatus(
            available=db_available,
            storage="postgresql" if db_available else "jsonl"
        ),
        apis={
            "tranco": api_status["tranco"]["configured"],
            "virustotal": api_status["virustotal"]["configured"]
        }
    )


@router.get("/health/db", tags=["Health"])
async def database_status():
    """
    Verifica el estado detallado de la base de datos.

    Returns:
        Informacion detallada de la conexion
    """
    status = get_engine_status()

    return {
        "status": "connected" if status["available"] else "disconnected",
        "engine": "postgresql" if status["available"] else "jsonl_fallback",
        "host": status.get("url"),
        "pool_size": status.get("pool_size")
    }


@router.get("/whois/{domain}", tags=["Tools"])
async def check_domain_age(domain: str):
    """
    Consulta la antiguedad de un dominio via WHOIS.

    Args:
        domain: Nombre del dominio a consultar (ej: example.com)

    Returns:
        Informacion de antiguedad del dominio
    """
    # Agregar schema si no tiene
    url = f"https://{domain}" if not domain.startswith("http") else domain

    result = whois_service.check_url(url)

    # Agregar interpretacion
    age_days = result.get("age_days")
    if age_days is not None:
        if age_days < 30:
            result["interpretation"] = "ALERTA: Dominio muy nuevo (< 30 dias). Alto riesgo de phishing."
            result["risk_indicator"] = "HIGH"
        elif age_days < 90:
            result["interpretation"] = "Dominio reciente (< 90 dias). Precaucion recomendada."
            result["risk_indicator"] = "MEDIUM"
        elif age_days < 365:
            result["interpretation"] = "Dominio con antiguedad moderada."
            result["risk_indicator"] = "LOW"
        else:
            years = round(age_days / 365, 1)
            result["interpretation"] = f"Dominio establecido ({years} años)."
            result["risk_indicator"] = "SAFE"
    else:
        result["interpretation"] = "No se pudo determinar la antiguedad del dominio."
        result["risk_indicator"] = "UNKNOWN"

    return result
