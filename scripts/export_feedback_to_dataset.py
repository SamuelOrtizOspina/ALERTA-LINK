#!/usr/bin/env python3
"""
export_feedback_to_dataset.py - Cierra el ciclo de mejora continua (Fase 4)

Toma las URLs que llegaron por el canal de reporte voluntario (RF-10) y las
convierte en filas de entrenamiento con las mismas 24 features del dataset,
para que puedan incorporarse al proximo reentrenamiento.

POR QUE NO SE USAN LOS ANALISIS
-------------------------------
La tabla analysis_results guarda lo que el sistema *predijo* (score y
risk_level), no la verdad. Entrenar con eso seria realimentar al modelo con
sus propios aciertos y errores, degradandolo progresivamente. Solo se
exporta aquello que tiene una etiqueta de origen humano:

  - reports         : el usuario afirma que el enlace es fraudulento -> label 1
  - ingested_urls   : URLs cargadas con etiqueta explicita (0 o 1)

REVISION MANUAL OBLIGATORIA
---------------------------
Un reporte de usuario es una sospecha, no una verdad verificada. Por eso la
salida va a un archivo aparte marcado como pendiente de revision, y NUNCA se
mezcla automaticamente con datasets/splits/. El flujo previsto es:

  1. python scripts/export_feedback_to_dataset.py
  2. revisar a mano datasets/feedback/pendiente_revision.csv
  3. mover las filas validadas al dataset maestro
  4. python scripts/rebuild_splits.py && python scripts/train_model_v3.py

Funciona con PostgreSQL y, si no hay base de datos configurada, con el
respaldo JSONL que usa el backend.

Uso:
    python scripts/export_feedback_to_dataset.py
"""

import csv
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR / "backend"))

from app.services.feature_extractor import extract_features, BASE_FEATURE_NAMES  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

SALIDA_DIR = BASE_DIR / "datasets" / "feedback"
JSONL_DIR = BASE_DIR / "datasets" / "ingested"

# Etiqueta que corresponde a cada tipo de reporte del RF-10.
# 'unknown' se descarta: el usuario mismo declara no estar seguro.
LABEL_POR_TIPO = {"phishing": 1, "malware": 1, "scam": 1}


def leer_de_postgres() -> List[Dict]:
    """Lee reportes y URLs etiquetadas desde PostgreSQL, si esta disponible."""
    try:
        from app.db.database import is_db_available, get_session_factory
    except ImportError:
        return []

    if not is_db_available():
        logger.info("  PostgreSQL no disponible")
        return []

    factory = get_session_factory()
    if factory is None:
        return []

    from app.models import Report, IngestedUrl

    registros = []
    sesion = factory()
    try:
        for r in sesion.query(Report).all():
            label = LABEL_POR_TIPO.get((r.label or "").lower())
            if label is not None:
                registros.append(
                    {"url": r.url_normalized, "label": label, "origen": f"report:{r.label}"}
                )

        for i in sesion.query(IngestedUrl).all():
            if i.label in (0, 1):
                registros.append(
                    {"url": i.url_normalized, "label": i.label, "origen": f"ingest:{i.source}"}
                )
    finally:
        sesion.close()

    logger.info(f"  PostgreSQL: {len(registros)} filas etiquetadas")
    return registros


def leer_de_jsonl() -> List[Dict]:
    """Respaldo: lee los JSONL que escribe el backend cuando no hay BD."""
    registros = []

    archivo_reportes = JSONL_DIR / "user_reports.jsonl"
    if archivo_reportes.exists():
        with open(archivo_reportes, encoding="utf-8") as f:
            for linea in f:
                try:
                    d = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                label = LABEL_POR_TIPO.get(str(d.get("label", "")).lower())
                url = d.get("url_normalized") or d.get("url")
                if label is not None and url:
                    registros.append(
                        {"url": url, "label": label, "origen": f"report:{d.get('label')}"}
                    )

    archivo_ingest = JSONL_DIR / "ingested_urls.jsonl"
    if archivo_ingest.exists():
        with open(archivo_ingest, encoding="utf-8") as f:
            for linea in f:
                try:
                    d = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                url = d.get("url_normalized") or d.get("url")
                if d.get("label") in (0, 1) and url:
                    registros.append(
                        {"url": url, "label": d["label"], "origen": f"ingest:{d.get('source', 'na')}"}
                    )

    logger.info(f"  JSONL: {len(registros)} filas etiquetadas")
    return registros


def urls_ya_en_dataset() -> set:
    """URLs presentes en los splits, para no duplicar."""
    conocidas = set()
    splits = BASE_DIR / "datasets" / "splits"
    for nombre in ("train.csv", "val.csv", "test.csv"):
        ruta = splits / nombre
        if not ruta.exists():
            continue
        try:
            with open(ruta, encoding="utf-8", errors="replace") as f:
                for fila in csv.DictReader(f):
                    if fila.get("url"):
                        conocidas.add(fila["url"].strip())
        except OSError:
            logger.warning(f"  No se pudo leer {nombre} (posible cuarentena del antivirus)")
    return conocidas


def main() -> None:
    logger.info("=" * 66)
    logger.info("EXPORTACION DE RETROALIMENTACION AL DATASET (Fase 4)")
    logger.info("=" * 66)

    logger.info("")
    logger.info("Leyendo fuentes etiquetadas por humanos...")
    registros = leer_de_postgres() or leer_de_jsonl()

    if not registros:
        logger.info("")
        logger.info("No hay reportes etiquetados todavia. Nada que exportar.")
        logger.info("Se llenara a medida que los usuarios usen el boton de")
        logger.info("reporte voluntario de la app (RF-10).")
        return

    # Deduplicar por URL y descartar lo que ya esta en el dataset
    conocidas = urls_ya_en_dataset()
    vistas = set()
    nuevos = []
    for r in registros:
        url = r["url"].strip()
        if url in vistas or url in conocidas:
            continue
        vistas.add(url)
        nuevos.append(r)

    logger.info("")
    logger.info(f"  candidatas unicas : {len(vistas)}")
    logger.info(f"  ya en el dataset  : {len(registros) - len(nuevos)}")
    logger.info(f"  nuevas a exportar : {len(nuevos)}")

    if not nuevos:
        logger.info("\nTodas las URLs reportadas ya estan en el dataset.")
        return

    # Extraer las mismas features del dataset de entrenamiento
    logger.info("")
    logger.info("Extrayendo features...")
    filas = []
    for r in nuevos:
        try:
            features = extract_features(r["url"])
        except Exception as e:
            logger.warning(f"  omitida {r['url'][:50]}: {e}")
            continue
        # Las features de Tranco requieren red; se dejan neutras y se
        # completaran al reconstruir el dataset maestro.
        features.setdefault("in_tranco", 0)
        features.setdefault("tranco_rank", 0)
        features.setdefault("brand_impersonation", 0)
        fila = {c: features.get(c, 0) for c in BASE_FEATURE_NAMES}
        fila["url"] = r["url"]
        fila["label"] = r["label"]
        fila["origen"] = r["origen"]
        fila["revisado"] = 0  # debe validarse a mano antes de entrenar
        filas.append(fila)

    SALIDA_DIR.mkdir(parents=True, exist_ok=True)
    salida = SALIDA_DIR / "pendiente_revision.csv"
    columnas = BASE_FEATURE_NAMES + ["url", "label", "origen", "revisado"]

    with open(salida, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=columnas)
        escritor.writeheader()
        escritor.writerows(filas)

    logger.info("")
    logger.info("=" * 66)
    logger.info(f"{len(filas)} filas escritas en:")
    logger.info(f"  {salida}")
    logger.info("=" * 66)
    logger.info("")
    logger.info("IMPORTANTE: estas URLs provienen de sospechas de usuarios y")
    logger.info("NO se han verificado. Revise el archivo y marque revisado=1")
    logger.info("en las filas correctas antes de incorporarlas al dataset")
    logger.info("maestro y reentrenar.")


if __name__ == "__main__":
    main()
