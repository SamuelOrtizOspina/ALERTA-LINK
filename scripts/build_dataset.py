#!/usr/bin/env python3
"""
build_dataset.py - Construye el dataset maestro unificado para ALERTA-LINK

Este script:
1. Lee datos de PhiUSIIL (dataset academico con labels 0/1)
2. Lee datos de Phishing.Database (URLs de phishing, label=1)
3. Lee datos de URLhaus (URLs de malware, label=1)
4. Normaliza, deduplica y genera splits train/val/test

Uso:
    python scripts/build_dataset.py

Salida:
    datasets/processed/dataset_master.csv
    datasets/splits/train.csv
    datasets/splits/val.csv
    datasets/splits/test.csv
"""

import os
import sys
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional

import pandas as pd
from sklearn.model_selection import train_test_split

# Configuracion de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rutas del proyecto
PROJECT_ROOT = Path(__file__).parent.parent
DATOS_MALOS = PROJECT_ROOT / "Datos_Malos"
BUENOS_DATOS = PROJECT_ROOT / "Buenos_Datos"
DATOS_YA_ENTRENADOS = PROJECT_ROOT / "datos_ya_entrenados_pushing"
DATASETS_DIR = PROJECT_ROOT / "datasets"
PROCESSED_DIR = DATASETS_DIR / "processed"
SPLITS_DIR = DATASETS_DIR / "splits"

# Configuracion
RANDOM_STATE = 42
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15


def normalize_url(url: str) -> str:
    """Normaliza una URL: lowercase, sin trailing slash."""
    if not url:
        return ""
    url = url.strip().lower()
    if url.endswith('/'):
        url = url[:-1]
    return url


def hash_url(url: str) -> str:
    """Genera hash SHA256 de la URL normalizada."""
    return hashlib.sha256(url.encode('utf-8')).hexdigest()


def is_valid_url(url: str) -> bool:
    """Valida que la URL tenga formato correcto."""
    if not url or len(url) < 10:
        return False
    try:
        result = urlparse(url)
        return result.scheme in ('http', 'https') and bool(result.netloc)
    except Exception:
        return False


def load_phiusiil() -> pd.DataFrame:
    """Carga el dataset PhiUSIIL (academico con labels)."""
    csv_path = DATOS_YA_ENTRENADOS / "PhiUSIIL_Phishing_URL_Dataset.csv"

    if not csv_path.exists():
        logger.warning(f"PhiUSIIL no encontrado en {csv_path}")
        return pd.DataFrame()

    logger.info(f"Cargando PhiUSIIL desde {csv_path}")

    try:
        df = pd.read_csv(csv_path, low_memory=False)
        logger.info(f"PhiUSIIL: {len(df)} filas cargadas")

        # Buscar columna de URL
        url_col = None
        for col in ['URL', 'url', 'Url']:
            if col in df.columns:
                url_col = col
                break

        if url_col is None:
            logger.error("No se encontro columna URL en PhiUSIIL")
            return pd.DataFrame()

        # Buscar columna de label
        label_col = None
        for col in ['label', 'Label', 'LABEL']:
            if col in df.columns:
                label_col = col
                break

        if label_col is None:
            logger.error("No se encontro columna label en PhiUSIIL")
            return pd.DataFrame()

        # Crear dataframe normalizado
        result = pd.DataFrame({
            'url': df[url_col].astype(str),
            'label': df[label_col].astype(int),
            'source': 'phiusiil',
            'threat_type': df[label_col].apply(lambda x: 'phishing' if x == 1 else 'legitimate')
        })

        logger.info(f"PhiUSIIL procesado: {len(result)} URLs")
        logger.info(f"  - Legitimas (0): {len(result[result['label'] == 0])}")
        logger.info(f"  - Maliciosas (1): {len(result[result['label'] == 1])}")

        return result

    except Exception as e:
        logger.error(f"Error cargando PhiUSIIL: {e}")
        return pd.DataFrame()


def load_phishing_database() -> pd.DataFrame:
    """Carga URLs de Phishing.Database (todas son phishing, label=1)."""
    txt_path = BUENOS_DATOS / "Phishing.Database-master" / "phishing-links-ACTIVE.txt"

    if not txt_path.exists():
        logger.warning(f"Phishing.Database no encontrado en {txt_path}")
        return pd.DataFrame()

    logger.info(f"Cargando Phishing.Database desde {txt_path}")

    try:
        urls = []
        with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    urls.append(url)

        if not urls:
            logger.warning("No se encontraron URLs en Phishing.Database")
            return pd.DataFrame()

        result = pd.DataFrame({
            'url': urls,
            'label': 1,
            'source': 'phishing_database',
            'threat_type': 'phishing'
        })

        logger.info(f"Phishing.Database: {len(result)} URLs cargadas")
        return result

    except Exception as e:
        logger.error(f"Error cargando Phishing.Database: {e}")
        return pd.DataFrame()


def load_urlhaus() -> pd.DataFrame:
    """Carga URLs de URLhaus (malware, label=1)."""
    # Intentar cargar CSV
    csv_path = DATOS_MALOS / "otro_datos"
    json_path = DATOS_MALOS / "datos_jison"

    urls = []

    # Cargar CSV
    if csv_path.exists():
        logger.info(f"Cargando URLhaus CSV desde {csv_path}")
        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extraer URL del CSV (formato: id,dateadded,url,...)
                        parts = line.split(',')
                        if len(parts) >= 3:
                            url = parts[2].strip('"')
                            if url.startswith('http'):
                                urls.append(url)
        except Exception as e:
            logger.error(f"Error cargando URLhaus CSV: {e}")

    # Cargar JSON (formato: dict con IDs como keys, cada value es lista con objetos)
    if json_path.exists():
        logger.info(f"Cargando URLhaus JSON desde {json_path}")
        try:
            with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)

            # Formato: {"3748722": [{"url": "http://...", ...}], ...}
            if isinstance(data, dict):
                for key, items in data.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict) and 'url' in item:
                                urls.append(item['url'])
                    elif isinstance(items, dict) and 'url' in items:
                        urls.append(items['url'])

            logger.info(f"URLhaus JSON: {len(urls)} URLs extraidas")

        except json.JSONDecodeError as e:
            logger.error(f"Error parseando URLhaus JSON: {e}")
        except Exception as e:
            logger.error(f"Error cargando URLhaus JSON: {e}")

    if not urls:
        logger.warning("No se encontraron URLs en URLhaus")
        return pd.DataFrame()

    result = pd.DataFrame({
        'url': urls,
        'label': 1,
        'source': 'urlhaus',
        'threat_type': 'malware'
    })

    logger.info(f"URLhaus: {len(result)} URLs cargadas")
    return result


def build_master_dataset() -> pd.DataFrame:
    """Construye el dataset maestro unificando todas las fuentes."""
    logger.info("="*60)
    logger.info("Construyendo dataset maestro ALERTA-LINK")
    logger.info("="*60)

    # Cargar todas las fuentes
    dfs = []

    df_phiusiil = load_phiusiil()
    if not df_phiusiil.empty:
        dfs.append(df_phiusiil)

    df_phishing_db = load_phishing_database()
    if not df_phishing_db.empty:
        dfs.append(df_phishing_db)

    df_urlhaus = load_urlhaus()
    if not df_urlhaus.empty:
        dfs.append(df_urlhaus)

    if not dfs:
        logger.error("No se cargaron datos de ninguna fuente")
        return pd.DataFrame()

    # Concatenar todos los dataframes
    logger.info("Concatenando fuentes...")
    master = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total URLs antes de limpieza: {len(master)}")

    # Normalizar URLs
    logger.info("Normalizando URLs...")
    master['url_normalized'] = master['url'].apply(normalize_url)

    # Filtrar URLs invalidas
    logger.info("Filtrando URLs invalidas...")
    valid_mask = master['url_normalized'].apply(is_valid_url)
    invalid_count = (~valid_mask).sum()
    master = master[valid_mask].copy()
    logger.info(f"URLs invalidas eliminadas: {invalid_count}")

    # Generar hash para deduplicacion
    logger.info("Generando hashes...")
    master['url_hash'] = master['url_normalized'].apply(hash_url)

    # Deduplicar (mantener primera ocurrencia, priorizando maliciosas)
    logger.info("Deduplicando...")
    # Ordenar para que maliciosos (label=1) aparezcan primero
    master = master.sort_values('label', ascending=False)
    before_dedup = len(master)
    master = master.drop_duplicates(subset='url_hash', keep='first')
    after_dedup = len(master)
    logger.info(f"Duplicados eliminados: {before_dedup - after_dedup}")

    # Agregar timestamp
    master['created_at'] = datetime.now().isoformat()

    # Ordenar columnas
    master = master[['url', 'url_normalized', 'url_hash', 'label',
                     'source', 'threat_type', 'created_at']]

    logger.info("="*60)
    logger.info("ESTADISTICAS DEL DATASET MAESTRO")
    logger.info("="*60)
    logger.info(f"Total URLs: {len(master)}")
    logger.info(f"URLs legitimas (0): {len(master[master['label'] == 0])}")
    logger.info(f"URLs maliciosas (1): {len(master[master['label'] == 1])}")
    logger.info(f"Balance: {len(master[master['label'] == 0]) / len(master) * 100:.1f}% legitimas")
    logger.info("Por fuente:")
    for source, count in master['source'].value_counts().items():
        logger.info(f"  - {source}: {count}")

    return master


def create_splits(master: pd.DataFrame) -> tuple:
    """Crea splits estratificados train/val/test."""
    logger.info("Creando splits estratificados...")

    # Primer split: train vs (val+test)
    train_df, temp_df = train_test_split(
        master,
        test_size=(VAL_RATIO + TEST_RATIO),
        stratify=master['label'],
        random_state=RANDOM_STATE
    )

    # Segundo split: val vs test
    relative_test_size = TEST_RATIO / (VAL_RATIO + TEST_RATIO)
    val_df, test_df = train_test_split(
        temp_df,
        test_size=relative_test_size,
        stratify=temp_df['label'],
        random_state=RANDOM_STATE
    )

    # Agregar columna split
    train_df = train_df.copy()
    train_df['split'] = 'train'

    val_df = val_df.copy()
    val_df['split'] = 'val'

    test_df = test_df.copy()
    test_df['split'] = 'test'

    logger.info(f"Train: {len(train_df)} ({len(train_df)/len(master)*100:.1f}%)")
    logger.info(f"Val: {len(val_df)} ({len(val_df)/len(master)*100:.1f}%)")
    logger.info(f"Test: {len(test_df)} ({len(test_df)/len(master)*100:.1f}%)")

    return train_df, val_df, test_df


def main():
    """Funcion principal."""
    logger.info("Iniciando construccion del dataset...")

    # Crear directorios si no existen
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)

    # Construir dataset maestro
    master = build_master_dataset()

    if master.empty:
        logger.error("No se pudo construir el dataset maestro")
        sys.exit(1)

    # Crear splits
    train_df, val_df, test_df = create_splits(master)

    # Agregar split al maestro
    master_with_split = pd.concat([train_df, val_df, test_df], ignore_index=True)

    # Guardar archivos
    logger.info("Guardando archivos...")

    master_path = PROCESSED_DIR / "dataset_master.csv"
    master_with_split.to_csv(master_path, index=False)
    logger.info(f"Guardado: {master_path}")

    train_path = SPLITS_DIR / "train.csv"
    train_df.to_csv(train_path, index=False)
    logger.info(f"Guardado: {train_path}")

    val_path = SPLITS_DIR / "val.csv"
    val_df.to_csv(val_path, index=False)
    logger.info(f"Guardado: {val_path}")

    test_path = SPLITS_DIR / "test.csv"
    test_df.to_csv(test_path, index=False)
    logger.info(f"Guardado: {test_path}")

    # Guardar estadisticas
    stats = {
        'total_urls': len(master),
        'legitimate_count': int(len(master[master['label'] == 0])),
        'malicious_count': int(len(master[master['label'] == 1])),
        'sources': master['source'].value_counts().to_dict(),
        'splits': {
            'train': len(train_df),
            'val': len(val_df),
            'test': len(test_df)
        },
        'created_at': datetime.now().isoformat(),
        'random_state': RANDOM_STATE
    }

    stats_path = PROCESSED_DIR / "dataset_stats.json"
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)
    logger.info(f"Estadisticas guardadas: {stats_path}")

    logger.info("="*60)
    logger.info("DATASET CONSTRUIDO EXITOSAMENTE")
    logger.info("="*60)


if __name__ == "__main__":
    main()
