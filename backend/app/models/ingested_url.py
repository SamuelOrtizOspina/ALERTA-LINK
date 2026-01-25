"""
Modelo SQLAlchemy para URLs ingresadas

Tabla: ingested_urls
Proposito: Almacenar URLs enviadas para entrenamiento del modelo ML
"""

import uuid
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import Column, Text, Integer, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.models.base import Base


class IngestedUrl(Base):
    """
    Modelo para URLs ingresadas al sistema.

    Almacena URLs reportadas por feeds, usuarios o APIs externas
    para su uso en entrenamiento del modelo ML.

    Attributes:
        id: UUID unico del registro
        url_normalized: URL normalizada (lowercase, sin trailing slash)
        url_hash: Hash SHA256 de la URL para deduplicacion
        label: Etiqueta (0=legitimo, 1=malicioso, None=sin etiquetar)
        source: Origen del dato (manual, feed, user, api)
        raw_payload: Datos adicionales en formato JSON
        created_at: Fecha de creacion
    """

    __tablename__ = "ingested_urls"

    # Columnas
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url_normalized = Column(Text, nullable=False)
    url_hash = Column(Text, nullable=True, index=True)
    label = Column(Integer, nullable=True)  # 0=legitimo, 1=malicioso
    source = Column(Text, default="manual")
    raw_payload = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Indices adicionales
    __table_args__ = (
        Index('idx_ingested_created_at', created_at.desc()),
        Index('idx_ingested_label', label),
    )

    def __repr__(self) -> str:
        return f"<IngestedUrl(id={self.id}, url={self.url_normalized[:50]}..., label={self.label})>"

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
        label: Optional[int] = None,
        source: str = "manual",
        metadata: Optional[Dict[str, Any]] = None
    ) -> "IngestedUrl":
        """
        Crea una nueva instancia de IngestedUrl.

        Args:
            url: URL a ingestar
            label: Etiqueta (0=legitimo, 1=malicioso)
            source: Origen del dato
            metadata: Metadatos adicionales

        Returns:
            Nueva instancia de IngestedUrl
        """
        normalized = cls.normalize_url(url)
        return cls(
            url_normalized=normalized,
            url_hash=cls.hash_url(normalized),
            label=label,
            source=source,
            raw_payload=metadata
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el modelo a diccionario."""
        return {
            "id": str(self.id),
            "url": self.url_normalized,
            "url_hash": self.url_hash[:16] if self.url_hash else None,
            "label": self.label,
            "source": self.source,
            "metadata": self.raw_payload,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
