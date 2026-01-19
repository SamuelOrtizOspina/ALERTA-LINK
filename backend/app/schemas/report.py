"""
Schemas para el endpoint /report
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from enum import Enum


class ReportLabel(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    SCAM = "scam"
    UNKNOWN = "unknown"


class ReportRequest(BaseModel):
    """Request para reportar una URL."""
    url: str = Field(..., min_length=10, max_length=2048, description="URL a reportar")
    label: ReportLabel = Field(..., description="Tipo de amenaza reportada")
    comment: Optional[str] = Field(None, max_length=500, description="Comentario opcional")
    contact: Optional[str] = Field(None, max_length=100, description="Contacto opcional")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://suspicious-site.xyz/verify",
                "label": "phishing",
                "comment": "Recibi este enlace por SMS, parece phishing de banco",
                "contact": None
            }
        }


class ReportResponse(BaseModel):
    """Response de reporte."""
    status: str = Field(..., description="Estado del reporte")
    report_id: str = Field(..., description="ID del reporte")
    message: str = Field(..., description="Mensaje de confirmacion")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "received",
                "report_id": "rpt_550e8400-e29b-41d4-a716-446655440000",
                "message": "Gracias. Tu reporte fue registrado."
            }
        }
