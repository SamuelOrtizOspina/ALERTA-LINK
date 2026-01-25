"""
ALERTA-LINK Backend API
Sistema de Analisis Forense Automatico para URLs sospechosas (phishing)

Universidad Manuela Beltran - Ingenieria de Software 2025
Autores: Cristia Salazar, Samuel Ortiz Ospina, Juan Stiven Castro
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.api.routes import health, analyze, ingest, report, settings as settings_routes
from app.services.predictor import predictor

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configurar Rate Limiter
# Limites: 30 requests/minuto por IP para /analyze, 100/minuto general
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle del servidor - carga modelo al iniciar."""
    logger.info("="*60)
    logger.info(f"Iniciando {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("="*60)

    # Cargar modelo ML
    if predictor.load_model():
        logger.info("Modelo ML cargado exitosamente")
    else:
        logger.warning("Modelo ML no disponible - usando solo heuristicas")

    yield

    logger.info("Cerrando servidor...")


# Crear aplicacion FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    description="""
## ALERTA-LINK API

Sistema de Analisis Forense Automatico para detectar URLs de phishing/smishing.

### Endpoints principales:

* **GET /health** - Estado del servicio
* **POST /analyze** - Analizar una URL sospechosa
* **POST /ingest** - Ingestar URL al dataset
* **POST /report** - Reportar URL desde la app movil
* **GET /settings** - Obtener configuracion actual
* **POST /settings/mode** - Cambiar modo (online/offline/auto)
* **GET /settings/status** - Estado de conectividad

### Score de riesgo:
- **0-30**: Bajo riesgo (verde)
- **31-70**: Riesgo medio (amarillo)
- **71-100**: Alto riesgo (rojo)
    """,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configurar Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configurar CORS para app movil
# SEGURIDAD: Usar lista de origenes permitidos, no "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# Registrar rutas
app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(ingest.router)
app.include_router(report.router)
app.include_router(settings_routes.router)


@app.get("/", include_in_schema=False)
async def root():
    """Redirige a documentacion."""
    return {
        "message": f"Bienvenido a {settings.APP_NAME}",
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
