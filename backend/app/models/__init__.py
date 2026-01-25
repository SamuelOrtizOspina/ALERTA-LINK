"""
Modelos SQLAlchemy para ALERTA-LINK

Este modulo exporta todos los modelos de base de datos.
"""

from app.models.base import Base
from app.models.ingested_url import IngestedUrl
from app.models.report import Report
from app.models.analysis_result import AnalysisResult

__all__ = [
    "Base",
    "IngestedUrl",
    "Report",
    "AnalysisResult",
]
