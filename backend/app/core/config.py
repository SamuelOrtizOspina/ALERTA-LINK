"""
Configuracion de la aplicacion ALERTA-LINK

Las credenciales sensibles se cargan desde variables de entorno (.env).
Ver .env.example para la plantilla de configuracion.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """
    Configuracion de la aplicacion.

    Los valores se cargan desde:
    1. Variables de entorno del sistema
    2. Archivo .env en la raiz del proyecto

    Las API keys NO deben tener valores por defecto para forzar
    su configuracion en el archivo .env
    """

    # App
    APP_NAME: str = "ALERTA-LINK"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Modo de conexion: auto, online, offline
    CONNECTION_MODE: str = "auto"
    OFFLINE_FALLBACK: bool = True  # Si falla online, usar offline

    # API
    API_PREFIX: str = "/api/v1"

    # Database - DEBE configurarse en .env para produccion
    # Si no esta configurado, usa fallback JSONL (aceptable para desarrollo)
    DATABASE_URL: str = ""

    # Security - OBLIGATORIO en produccion
    # Generar con: python -c "import secrets; print(secrets.token_urlsafe(32))"
    SECRET_KEY: str = ""

    # Model paths
    # En desarrollo: 4 niveles arriba (desarrollo/)
    # En Render: la carpeta backend es la raiz
    PROJECT_ROOT: Path = Path(__file__).parent.parent.parent.parent
    BACKEND_ROOT: Path = Path(__file__).parent.parent.parent

    # Ruta del modelo - se busca en ambas ubicaciones
    def get_model_path(self) -> Path:
        """Busca el modelo en backend/models (Render) o proyecto/models (local)"""
        backend_model = self.BACKEND_ROOT / "models" / "step1_baseline.pkl"
        if backend_model.exists():
            return backend_model
        return self.PROJECT_ROOT / "models" / "step1_baseline.pkl"

    # Mantener MODEL_PATH para compatibilidad (usa PROJECT_ROOT por defecto)
    MODEL_PATH: Path = PROJECT_ROOT / "models" / "step1_baseline.pkl"

    # Ingest fallback (si no hay DB)
    INGEST_FALLBACK_DIR: Path = PROJECT_ROOT / "datasets" / "ingested"

    # ---------------------------------------------------------------------
    # APIs Externas - Las keys se cargan desde .env
    # ---------------------------------------------------------------------

    # Tranco API (lista de dominios legitimos)
    # Registro: https://tranco-list.eu/
    TRANCO_API_KEY: str = ""  # Requerido en .env
    TRANCO_API_EMAIL: str = ""  # Requerido en .env
    TRANCO_RANK_THRESHOLD: int = 100000  # Top 100k = legitimo

    # VirusTotal API (verificacion de URLs maliciosas)
    # Registro: https://www.virustotal.com/gui/my-apikey
    VIRUSTOTAL_API_KEY: str = ""  # Requerido en .env
    VIRUSTOTAL_THRESHOLD: int = 3  # Minimo de detecciones para considerar malicioso
    VIRUSTOTAL_UNCERTAINTY_MIN: int = 30  # Score minimo para consultar VT
    VIRUSTOTAL_UNCERTAINTY_MAX: int = 70  # Score maximo para consultar VT

    # ---------------------------------------------------------------------
    # CORS - Separar multiples origenes con coma
    # SEGURIDAD: NO usar "*" en produccion
    # ---------------------------------------------------------------------
    CORS_ORIGINS: str = "https://samuelortizospina.me,https://api.samuelortizospina.me,http://localhost:8000,http://10.0.2.2:8000"

    @property
    def cors_origins_list(self) -> list:
        """Retorna CORS_ORIGINS como lista."""
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"  # Ignorar variables extra en .env

    def validate_api_keys(self) -> dict:
        """
        Valida que las API keys esten configuradas.
        Retorna un diccionario con el estado de cada servicio.
        """
        return {
            "tranco": {
                "configured": bool(self.TRANCO_API_KEY),
                "message": "OK" if self.TRANCO_API_KEY else "Falta TRANCO_API_KEY en .env"
            },
            "virustotal": {
                "configured": bool(self.VIRUSTOTAL_API_KEY),
                "message": "OK" if self.VIRUSTOTAL_API_KEY else "Falta VIRUSTOTAL_API_KEY en .env"
            }
        }

    def validate_security(self) -> dict:
        """
        Valida configuracion de seguridad critica.
        Retorna diccionario con estado y advertencias.
        """
        warnings = []
        is_production = not self.DEBUG

        # Verificar SECRET_KEY
        if not self.SECRET_KEY:
            if is_production:
                warnings.append("CRITICO: SECRET_KEY no configurada")
            else:
                warnings.append("WARNING: SECRET_KEY vacia (OK para desarrollo)")

        # Verificar CORS
        if "*" in self.CORS_ORIGINS:
            warnings.append("CRITICO: CORS permite cualquier origen (*)")

        return {
            "secure": len([w for w in warnings if "CRITICO" in w]) == 0,
            "warnings": warnings,
            "is_production": is_production
        }


settings = Settings()


# Mostrar advertencia si faltan API keys (solo en modo debug)
if settings.DEBUG:
    api_status = settings.validate_api_keys()
    for service, status in api_status.items():
        if not status["configured"]:
            print(f"[WARNING] {service}: {status['message']}")
