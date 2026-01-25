"""
Schemas para el endpoint /analyze
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ConnectionMode(str, Enum):
    AUTO = "auto"
    ONLINE = "online"
    OFFLINE = "offline"


class ModelType(str, Enum):
    """Tipo de modelo para el analisis."""
    ML = "ml"
    HEURISTIC = "heuristic"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CrawlStatus(str, Enum):
    SKIPPED = "SKIPPED"
    OK = "OK"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class AnalyzeOptions(BaseModel):
    """Opciones para el analisis."""
    enable_crawler: bool = Field(default=False, description="Habilitar crawler de la URL")
    timeout_seconds: int = Field(default=20, ge=1, le=60, description="Timeout en segundos")
    max_redirects: int = Field(default=5, ge=0, le=10, description="Maximo de redirects")


class AnalyzeRequest(BaseModel):
    """Request para analizar una URL."""
    url: str = Field(..., min_length=10, max_length=2048, description="URL a analizar")
    mode: ConnectionMode = Field(default=ConnectionMode.ONLINE, description="Modo de conexion")
    model: ModelType = Field(default=ModelType.ML, description="Tipo de modelo: ml o heuristic")
    options: Optional[AnalyzeOptions] = Field(default=None, description="Opciones de analisis")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com/login",
                "mode": "online",
                "model": "ml",
                "options": {
                    "enable_crawler": False,
                    "timeout_seconds": 20,
                    "max_redirects": 5
                }
            }
        }


class Signal(BaseModel):
    """Una senal de riesgo detectada."""
    id: str = Field(..., description="Identificador de la senal")
    severity: Severity = Field(..., description="Severidad de la senal")
    weight: int = Field(..., ge=-100, le=100, description="Peso en el score (negativo=bonificacion)")
    evidence: Dict[str, Any] = Field(default={}, description="Evidencia")
    explanation: str = Field(..., description="Explicacion en espanol")


class CrawlResult(BaseModel):
    """Resultado del crawling (opcional)."""
    enabled: bool = False
    status: CrawlStatus = CrawlStatus.SKIPPED
    final_url: Optional[str] = None
    redirect_chain: List[str] = []
    html_fingerprint: Optional[str] = None
    evidence: Dict[str, Any] = {}


class Timestamps(BaseModel):
    """Timestamps del analisis."""
    requested_at: datetime
    completed_at: datetime
    duration_ms: int


class ApisConsulted(BaseModel):
    """APIs consultadas durante el analisis."""
    tranco: bool = Field(default=False, description="Si se consulto Tranco")
    virustotal: bool = Field(default=False, description="Si se consulto VirusTotal")
    database: bool = Field(default=False, description="Si se consulto la BD")


class AnalyzeResponse(BaseModel):
    """Response del analisis de URL."""
    url: str = Field(..., description="URL original")
    normalized_url: str = Field(..., description="URL normalizada")
    score: int = Field(..., ge=0, le=100, description="Score de riesgo 0-100")
    risk_level: RiskLevel = Field(..., description="Nivel de riesgo")
    model_used: ModelType = Field(..., description="Modelo usado: ml o heuristic")
    mode_used: ConnectionMode = Field(..., description="Modo de conexion usado")
    apis_consulted: ApisConsulted = Field(default_factory=ApisConsulted, description="APIs consultadas")
    signals: List[Signal] = Field(default=[], description="Senales detectadas")
    recommendations: List[str] = Field(default=[], description="Recomendaciones")
    crawl: CrawlResult = Field(default_factory=CrawlResult, description="Resultado del crawl")
    timestamps: Timestamps = Field(..., description="Timestamps")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://paypa1-secure.xyz/login",
                "normalized_url": "https://paypa1-secure.xyz/login",
                "score": 85,
                "risk_level": "HIGH",
                "model_used": "ml",
                "mode_used": "online",
                "signals": [
                    {
                        "id": "SUSPICIOUS_DOMAIN",
                        "severity": "HIGH",
                        "weight": 30,
                        "evidence": {"domain": "paypa1-secure.xyz"},
                        "explanation": "El dominio contiene palabras sospechosas que imitan a PayPal"
                    }
                ],
                "recommendations": [
                    "No ingrese sus credenciales en este sitio",
                    "Verifique la URL oficial de PayPal"
                ],
                "crawl": {
                    "enabled": False,
                    "status": "SKIPPED"
                },
                "timestamps": {
                    "requested_at": "2026-01-01T12:00:00Z",
                    "completed_at": "2026-01-01T12:00:00Z",
                    "duration_ms": 150
                }
            }
        }
