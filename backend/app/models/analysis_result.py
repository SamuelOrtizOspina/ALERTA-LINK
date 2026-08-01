"""
Modelo SQLAlchemy para resultados de analisis

Tabla: analysis_results
Proposito: Almacenar historico de analisis de URLs para consulta y estadisticas
"""

import uuid
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, Text, Integer, Boolean, DateTime, Index, Numeric
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.models.base import Base


class AnalysisResult(Base):
    """
    Modelo para resultados de analisis de URLs.

    Almacena el historico de analisis realizados, incluyendo
    scores, senales detectadas y APIs consultadas.

    Attributes:
        id: UUID unico del analisis
        url_normalized: URL analizada (normalizada)
        url_hash: Hash SHA256 para busquedas rapidas
        score: Puntuacion de riesgo (0-100)
        risk_level: Nivel de riesgo (LOW, MEDIUM, HIGH)
        signals: Lista de senales detectadas (JSONB)
        ml_score: Score del modelo ML
        heuristic_score: Score de heuristicas
        tranco_verified: Si se verifico con Tranco
        tranco_rank: Ranking en Tranco (si aplica)
        virustotal_checked: Si se consulto VirusTotal
        virustotal_detections: Detecciones de VT
        mode_used: Modo usado (online, offline, auto)
        duration_ms: Duracion del analisis en ms
        created_at: Fecha del analisis
    """

    __tablename__ = "analysis_results"

    # Columnas principales
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url_normalized = Column(Text, nullable=False)
    url_hash = Column(Text, nullable=True, index=True)

    # Resultados del analisis
    score = Column(Integer, nullable=False)  # 0-100
    risk_level = Column(Text, nullable=False)  # LOW, MEDIUM, HIGH
    signals = Column(JSONB, nullable=True)  # Lista de senales

    # Scores individuales
    ml_score = Column(Integer, nullable=True)
    heuristic_score = Column(Integer, nullable=True)

    # Estado de APIs externas
    tranco_verified = Column(Boolean, default=False)
    tranco_rank = Column(Integer, nullable=True)
    virustotal_checked = Column(Boolean, default=False)
    virustotal_detections = Column(Integer, nullable=True)

    # Metadatos
    mode_used = Column(Text, default="auto")  # online, offline, auto
    duration_ms = Column(Integer, nullable=True)

    # Columnas presentes en database/schema.sql que faltaban en el ORM.
    # Sin ellas, cualquier intento de escribirlas lanzaba TypeError y el
    # analisis nunca llegaba a persistirse.
    model_used = Column(Text, nullable=True)  # ml | heuristic
    probability = Column(Numeric(5, 4), nullable=True)
    recommendations = Column(JSONB, nullable=True)

    # Dimension de URLs: el trigger fill_url_dimension la completa sola,
    # se declara para poder consultarla desde el ORM.
    url_id = Column(UUID(as_uuid=True), nullable=True)

    # Resultado del crawler opcional
    crawl_enabled = Column(Boolean, default=False)
    crawl_status = Column(Text, default="SKIPPED")  # SKIPPED | OK | TIMEOUT | ERROR
    crawl_final_url = Column(Text, nullable=True)
    crawl_redirect_chain = Column(JSONB, nullable=True)
    crawl_html_fingerprint = Column(Text, nullable=True)
    crawl_evidence = Column(JSONB, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Indices
    __table_args__ = (
        Index('idx_analysis_created_at', created_at.desc()),
        Index('idx_analysis_score', score),
        Index('idx_analysis_risk_level', risk_level),
    )

    def __repr__(self) -> str:
        return f"<AnalysisResult(id={self.id}, score={self.score}, risk={self.risk_level})>"

    @staticmethod
    def hash_url(url: str) -> str:
        """Genera hash SHA256 de una URL."""
        return hashlib.sha256(url.encode('utf-8')).hexdigest()

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normaliza una URL."""
        normalized = url.lower().strip()
        if normalized.endswith('/') and normalized.count('/') > 3:
            normalized = normalized.rstrip('/')
        return normalized

    @classmethod
    def create(
        cls,
        url: str,
        score: int,
        risk_level: str,
        signals: Optional[List[Dict]] = None,
        ml_score: Optional[int] = None,
        heuristic_score: Optional[int] = None,
        tranco_verified: bool = False,
        tranco_rank: Optional[int] = None,
        virustotal_checked: bool = False,
        virustotal_detections: Optional[int] = None,
        model_used: Optional[str] = None,
        mode_used: str = "auto",
        duration_ms: Optional[int] = None,
        probability: Optional[float] = None,
        recommendations: Optional[List[str]] = None,
        crawl: Optional[Dict[str, Any]] = None
    ) -> "AnalysisResult":
        """
        Crea una nueva instancia de AnalysisResult.

        Args:
            url: URL analizada
            score: Puntuacion de riesgo (0-100)
            risk_level: Nivel de riesgo
            signals: Lista de senales detectadas
            ml_score: Score del modelo ML
            heuristic_score: Score de heuristicas
            tranco_verified: Si se verifico con Tranco
            tranco_rank: Ranking en Tranco
            virustotal_checked: Si se consulto VirusTotal
            virustotal_detections: Detecciones de VT
            mode_used: Modo usado
            duration_ms: Duracion en ms

        Returns:
            Nueva instancia de AnalysisResult
        """
        normalized = cls.normalize_url(url)
        return cls(
            url_normalized=normalized,
            url_hash=cls.hash_url(normalized),
            score=score,
            risk_level=risk_level,
            signals=signals,
            ml_score=ml_score,
            heuristic_score=heuristic_score,
            tranco_verified=tranco_verified,
            tranco_rank=tranco_rank,
            virustotal_checked=virustotal_checked,
            virustotal_detections=virustotal_detections,
            model_used=model_used,
            mode_used=mode_used,
            duration_ms=duration_ms,
            probability=probability,
            recommendations=recommendations,
            crawl_enabled=bool(crawl and crawl.get("enabled")),
            crawl_status=(crawl or {}).get("status", "SKIPPED"),
            crawl_final_url=(crawl or {}).get("final_url"),
            crawl_redirect_chain=(crawl or {}).get("redirect_chain"),
            crawl_html_fingerprint=(crawl or {}).get("html_fingerprint"),
            crawl_evidence=(crawl or {}).get("evidence"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el modelo a diccionario."""
        return {
            "id": str(self.id),
            "url": self.url_normalized,
            "score": self.score,
            "risk_level": self.risk_level,
            "signals": self.signals or [],
            "ml_score": self.ml_score,
            "heuristic_score": self.heuristic_score,
            "apis": {
                "tranco": {
                    "verified": self.tranco_verified,
                    "rank": self.tranco_rank
                },
                "virustotal": {
                    "checked": self.virustotal_checked,
                    "detections": self.virustotal_detections
                }
            },
            "mode_used": self.mode_used,
            "duration_ms": self.duration_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
