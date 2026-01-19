"""
Modelo SQLAlchemy para reportes de usuarios

Tabla: reports
Proposito: Almacenar reportes de URLs sospechosas enviados desde la app movil
"""

import uuid
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import Column, Text, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import Base


class Report(Base):
    """
    Modelo para reportes de usuarios.

    Almacena URLs reportadas como sospechosas por usuarios
    de la aplicacion movil.

    Attributes:
        id: UUID unico del reporte (prefijo rpt_)
        url_normalized: URL normalizada
        url_hash: Hash SHA256 para deduplicacion
        label: Tipo de amenaza (phishing, malware, scam, unknown)
        comment: Comentario del usuario
        contact: Contacto opcional del reportante
        source: Origen del reporte (mobile_app, web, api)
        created_at: Fecha de creacion
    """

    __tablename__ = "reports"

    # Columnas
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url_normalized = Column(Text, nullable=False)
    url_hash = Column(Text, nullable=True, index=True)
    label = Column(Text, nullable=False)  # phishing, malware, scam, unknown
    comment = Column(Text, nullable=True)
    contact = Column(Text, nullable=True)
    source = Column(Text, default="mobile_app")
    created_at = Column(DateTime, default=datetime.utcnow)

    # Indices adicionales
    __table_args__ = (
        Index('idx_reports_created_at', created_at.desc()),
        Index('idx_reports_label', label),
    )

    def __repr__(self) -> str:
        return f"<Report(id={self.id}, label={self.label}, url={self.url_normalized[:50]}...)>"

    @staticmethod
    def hash_url(url: str) -> str:
        """Genera hash SHA256 de una URL."""
        return hashlib.sha256(url.encode('utf-8')).hexdigest()

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normaliza una URL para comparacion consistente."""
        normalized = url.lower().strip()
        if normalized.endswith('/') and normalized.count('/') > 3:
            normalized = normalized.rstrip('/')
        return normalized

    @classmethod
    def create(
        cls,
        url: str,
        label: str,
        comment: Optional[str] = None,
        contact: Optional[str] = None,
        source: str = "mobile_app"
    ) -> "Report":
        """
        Crea una nueva instancia de Report.

        Args:
            url: URL reportada
            label: Tipo de amenaza
            comment: Comentario del usuario
            contact: Contacto del reportante
            source: Origen del reporte

        Returns:
            Nueva instancia de Report
        """
        normalized = cls.normalize_url(url)
        return cls(
            url_normalized=normalized,
            url_hash=cls.hash_url(normalized),
            label=label,
            comment=comment,
            contact=contact,
            source=source
        )

    def get_report_id(self) -> str:
        """Retorna el ID con prefijo rpt_."""
        return f"rpt_{self.id}"

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el modelo a diccionario."""
        return {
            "report_id": self.get_report_id(),
            "url": self.url_normalized,
            "url_hash": self.url_hash[:16] if self.url_hash else None,
            "label": self.label,
            "comment": self.comment,
            "contact": self.contact,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
