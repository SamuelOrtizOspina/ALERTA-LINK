"""
Schemas para el endpoint /ingest
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum


class IngestSource(str, Enum):
    MANUAL = "manual"
    FEED = "feed"
    USER = "user"
    API = "api"


class IngestRequest(BaseModel):
    """Request para ingestar una URL."""
    url: str = Field(..., min_length=10, max_length=2048, description="URL a ingestar")
    label: Optional[int] = Field(None, ge=0, le=1, description="Label (0=legitimo, 1=malicioso)")
    source: IngestSource = Field(default=IngestSource.MANUAL, description="Fuente del dato")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Metadatos adicionales")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example-phishing.xyz/login",
                "label": 1,
                "source": "manual",
                "metadata": {
                    "reporter": "security_team",
                    "confidence": "high"
                }
            }
        }


class IngestResponse(BaseModel):
    """Response de ingestion."""
    status: str = Field(..., description="Estado de la operacion")
    id: str = Field(..., description="ID del registro creado")
    stored: bool = Field(..., description="Si se guardo exitosamente")
    url_hash: Optional[str] = Field(None, description="Hash de la URL")
    message: Optional[str] = Field(None, description="Mensaje adicional")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "received",
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "stored": True,
                "url_hash": "a1b2c3d4...",
                "message": "URL ingestada exitosamente"
            }
        }
