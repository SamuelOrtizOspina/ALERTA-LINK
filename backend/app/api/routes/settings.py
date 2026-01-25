"""
Endpoint /settings para configuracion del sistema
"""

import logging
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.config import settings
from app.schemas.analyze import ConnectionMode
from app.services.tranco_service import tranco_service
from app.services.virustotal_service import virustotal_service

logger = logging.getLogger(__name__)
router = APIRouter()


# Estado en memoria del modo (en produccion deberia persistirse)
_current_mode: ConnectionMode = ConnectionMode.AUTO


class ModeRequest(BaseModel):
    """Request para cambiar el modo de conexion."""
    mode: ConnectionMode = Field(..., description="Modo de conexion")
    sync_on_connect: bool = Field(default=True, description="Sincronizar al reconectar")


class ServiceStatus(BaseModel):
    """Estado de un servicio externo."""
    enabled: bool
    configured: bool
    message: str


class SettingsResponse(BaseModel):
    """Response con la configuracion actual."""
    app_name: str
    app_version: str
    connection_mode: ConnectionMode
    offline_fallback: bool
    services: dict[str, ServiceStatus]


class ModeResponse(BaseModel):
    """Response al cambiar el modo."""
    previous_mode: ConnectionMode
    current_mode: ConnectionMode
    message: str


@router.get("/settings", response_model=SettingsResponse, tags=["Settings"])
async def get_settings():
    """
    Obtiene la configuracion actual del sistema.

    Returns:
        Configuracion actual incluyendo modo y estado de servicios
    """
    global _current_mode

    # Estado de servicios
    tranco_status = ServiceStatus(
        enabled=tranco_service.enabled,
        configured=bool(settings.TRANCO_API_KEY),
        message="OK" if tranco_service.enabled else "API key no configurada"
    )

    vt_status = ServiceStatus(
        enabled=virustotal_service.enabled,
        configured=bool(settings.VIRUSTOTAL_API_KEY),
        message="OK" if virustotal_service.enabled else "API key no configurada"
    )

    return SettingsResponse(
        app_name=settings.APP_NAME,
        app_version=settings.APP_VERSION,
        connection_mode=_current_mode,
        offline_fallback=settings.OFFLINE_FALLBACK,
        services={
            "tranco": tranco_status,
            "virustotal": vt_status
        }
    )


@router.post("/settings/mode", response_model=ModeResponse, tags=["Settings"])
async def set_mode(request: ModeRequest):
    """
    Cambia el modo de conexion del sistema.

    - **mode**: auto, online, offline

    En modo offline, solo se usa ML local + heuristicas.
    En modo online, se usan APIs externas (Tranco, VirusTotal).
    En modo auto, se detecta automaticamente.
    """
    global _current_mode

    previous = _current_mode
    _current_mode = request.mode

    logger.info(f"Modo cambiado de {previous.value} a {_current_mode.value}")

    messages = {
        ConnectionMode.OFFLINE: "Modo offline activado. Solo se usara analisis local.",
        ConnectionMode.ONLINE: "Modo online activado. Se usaran APIs externas.",
        ConnectionMode.AUTO: "Modo automatico activado. Se detectara la conexion."
    }

    return ModeResponse(
        previous_mode=previous,
        current_mode=_current_mode,
        message=messages[_current_mode]
    )


@router.get("/settings/status", tags=["Settings"])
async def get_status():
    """
    Obtiene el estado de conectividad de todos los servicios.

    Util para la app movil para mostrar indicador de conexion.
    """
    return {
        "online": tranco_service.enabled or virustotal_service.enabled,
        "services": {
            "tranco": {
                "available": tranco_service.enabled,
                "last_check": None  # TODO: implementar health check
            },
            "virustotal": {
                "available": virustotal_service.enabled,
                "last_check": None
            },
            "database": {
                "available": False,  # TODO: verificar conexion BD
                "last_check": None
            }
        }
    }
