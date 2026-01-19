"""
Endpoint /ingest para ingestar URLs al dataset

Guarda en PostgreSQL si esta disponible, sino usa JSONL como fallback.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import validate_and_normalize_url
from app.schemas.ingest import IngestRequest, IngestResponse
from app.db.dependencies import get_db_optional
from app.models import IngestedUrl

logger = logging.getLogger(__name__)
router = APIRouter()


def save_to_jsonl(data: dict, filepath: Path):
    """Guarda un registro en formato JSONL (fallback)."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(json.dumps(data, ensure_ascii=False, default=str) + '\n')


@router.post("/ingest", response_model=IngestResponse, tags=["Ingest"])
async def ingest_url(
    request: IngestRequest,
    db: Optional[Session] = Depends(get_db_optional)
):
    """
    Ingesta una URL al dataset para futuro entrenamiento.

    - **url**: URL a ingestar (requerido)
    - **label**: Etiqueta 0=legitimo, 1=malicioso (opcional)
    - **source**: Fuente del dato (manual, feed, user, api)
    - **metadata**: Metadatos adicionales (opcional)

    Returns:
        ID del registro creado y estado
    """
    # Validar URL (proteccion SSRF)
    normalized_url, error = validate_and_normalize_url(request.url)
    if error:
        raise HTTPException(status_code=400, detail=f"URL invalida: {error}")

    try:
        if db is not None:
            # Usar PostgreSQL
            ingested = IngestedUrl.create(
                url=normalized_url,
                label=request.label,
                source=request.source.value,
                metadata=request.metadata
            )
            db.add(ingested)
            db.flush()  # Para obtener el ID generado

            record_id = str(ingested.id)
            url_hash = ingested.url_hash
            storage = "postgresql"

            logger.info(f"URL ingestada en PostgreSQL: {normalized_url[:50]}... (id={record_id})")
        else:
            # Fallback a JSONL
            ingested = IngestedUrl.create(
                url=normalized_url,
                label=request.label,
                source=request.source.value,
                metadata=request.metadata
            )

            record = {
                'id': str(ingested.id),
                'url': request.url,
                'url_normalized': ingested.url_normalized,
                'url_hash': ingested.url_hash,
                'label': request.label,
                'source': request.source.value,
                'metadata': request.metadata or {},
                'created_at': datetime.now().isoformat()
            }

            filepath = settings.INGEST_FALLBACK_DIR / "ingested_urls.jsonl"
            save_to_jsonl(record, filepath)

            record_id = str(ingested.id)
            url_hash = ingested.url_hash
            storage = "jsonl"

            logger.info(f"URL ingestada en JSONL (fallback): {normalized_url[:50]}... (id={record_id})")

        return IngestResponse(
            status="received",
            id=record_id,
            stored=True,
            url_hash=url_hash[:16] + "...",
            message=f"URL ingestada exitosamente ({storage})"
        )

    except Exception as e:
        logger.error(f"Error ingestando URL: {e}")
        raise HTTPException(status_code=500, detail="Error guardando URL")
