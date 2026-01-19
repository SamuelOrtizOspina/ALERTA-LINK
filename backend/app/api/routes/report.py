"""
Endpoint /report para reportar URLs sospechosas

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
from app.schemas.report import ReportRequest, ReportResponse
from app.db.dependencies import get_db_optional
from app.models import Report

logger = logging.getLogger(__name__)
router = APIRouter()


def save_report_to_jsonl(data: dict, filepath: Path):
    """Guarda un reporte en formato JSONL (fallback)."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(json.dumps(data, ensure_ascii=False, default=str) + '\n')


@router.post("/report", response_model=ReportResponse, tags=["Report"])
async def report_url(
    request: ReportRequest,
    db: Optional[Session] = Depends(get_db_optional)
):
    """
    Reporta una URL sospechosa desde la app movil.

    - **url**: URL a reportar (requerido)
    - **label**: Tipo de amenaza (phishing, malware, scam, unknown)
    - **comment**: Comentario opcional del usuario
    - **contact**: Contacto opcional del usuario

    Returns:
        ID del reporte y mensaje de confirmacion
    """
    # Validar URL (proteccion SSRF)
    normalized_url, error = validate_and_normalize_url(request.url)
    if error:
        raise HTTPException(status_code=400, detail=f"URL invalida: {error}")

    try:
        if db is not None:
            # Usar PostgreSQL
            report = Report.create(
                url=normalized_url,
                label=request.label.value,
                comment=request.comment,
                contact=request.contact,
                source="mobile_app"
            )
            db.add(report)
            db.flush()  # Para obtener el ID generado

            report_id = report.get_report_id()
            storage = "postgresql"

            logger.info(f"Reporte guardado en PostgreSQL: {normalized_url[:50]}... (id={report_id})")
        else:
            # Fallback a JSONL
            report = Report.create(
                url=normalized_url,
                label=request.label.value,
                comment=request.comment,
                contact=request.contact,
                source="mobile_app"
            )

            report_record = {
                'id': report.get_report_id(),
                'url': request.url,
                'url_normalized': report.url_normalized,
                'url_hash': report.url_hash,
                'label': request.label.value,
                'comment': request.comment,
                'contact': request.contact,
                'source': 'mobile_app',
                'created_at': datetime.now().isoformat()
            }

            filepath = settings.INGEST_FALLBACK_DIR / "user_reports.jsonl"
            save_report_to_jsonl(report_record, filepath)

            report_id = report.get_report_id()
            storage = "jsonl"

            logger.info(f"Reporte guardado en JSONL (fallback): {normalized_url[:50]}... (id={report_id})")

        return ReportResponse(
            status="received",
            report_id=report_id,
            message=f"Gracias. Tu reporte fue registrado ({storage})."
        )

    except Exception as e:
        logger.error(f"Error guardando reporte: {e}")
        raise HTTPException(status_code=500, detail="Error guardando reporte")
