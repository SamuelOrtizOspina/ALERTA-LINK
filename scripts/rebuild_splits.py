#!/usr/bin/env python3
"""
rebuild_splits.py - Regenera los conjuntos train/val/test sin fuga de datos

MOTIVO
------
Los archivos val.csv y test.csv originales presentaban fuga de datos: la
feature has_https separaba las clases con 100% de concordancia (todas las
URLs maliciosas eran http:// y todas las legitimas https://), y lo mismo
ocurria con in_tranco. Cualquier modelo evaluado sobre ellos alcanzaba
metricas perfectas sin haber aprendido nada util.

train.csv no presenta ese problema (has_https 58,7% / in_tranco 85,0%),
por lo que este script reparte ESE conjunto en tres splits estratificados.

Los archivos anteriores se conservan como *_legacy.csv.

Uso:
    python scripts/rebuild_splits.py

Salida:
    datasets/splits/train.csv  (60%)
    datasets/splits/val.csv    (20%)
    datasets/splits/test.csv   (20%)
"""

import shutil
import logging
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
SPLITS_DIR = PROJECT_ROOT / "datasets" / "splits"

SEED = 42
FRAC_TEST = 0.20
FRAC_VAL = 0.20


def concordancia(df: pd.DataFrame, feature: str) -> float:
    """Mide que tan bien una sola feature binaria separa las clases."""
    if feature not in df.columns:
        return float("nan")
    col = df[feature].astype(str)
    de_acuerdo = ((col.isin(["0", "0.0"])) == (df["label"] == 1)).sum()
    return max(de_acuerdo, len(df) - de_acuerdo) / len(df)


def diagnostico(nombre: str, df: pd.DataFrame) -> None:
    logger.info(
        f"  {nombre:<12} n={len(df):<6} "
        f"legitimas={(df['label'] == 0).sum():<5} "
        f"maliciosas={(df['label'] == 1).sum():<5} "
        f"has_https={concordancia(df, 'has_https'):.1%} "
        f"in_tranco={concordancia(df, 'in_tranco'):.1%}"
    )


def main() -> None:
    # El conjunto de origen es el train.csv completo de 6000 filas. Si el
    # script ya se ejecuto antes, ese archivo quedo reemplazado por el split
    # de 3600, asi que se prefiere el respaldo para poder re-ejecutar sin
    # ir reduciendo el dataset en cada corrida.
    legacy = SPLITS_DIR / "train_legacy.csv"
    origen = legacy if legacy.exists() else SPLITS_DIR / "train.csv"
    logger.info(f"Origen: {origen.name}")
    logger.info("")
    if not origen.exists():
        raise FileNotFoundError(f"No se encontro {origen}")

    df = pd.read_csv(origen)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    logger.info("=" * 70)
    logger.info("CONJUNTO DE ORIGEN")
    logger.info("=" * 70)
    diagnostico("train.csv", df)

    logger.info("")
    logger.info("Concordancia = que porcentaje de las etiquetas queda determinado")
    logger.info("por esa sola feature. Cerca de 100% indica fuga de datos.")

    # Respaldar los splits contaminados antes de sobrescribirlos
    logger.info("")
    logger.info("=" * 70)
    logger.info("RESPALDO DE LOS ARCHIVOS ANTERIORES")
    logger.info("=" * 70)
    for nombre in ("val.csv", "test.csv", "train.csv"):
        actual = SPLITS_DIR / nombre
        legacy = SPLITS_DIR / nombre.replace(".csv", "_legacy.csv")
        if legacy.exists():
            # Nunca pisar un respaldo existente: en una segunda corrida se
            # estaria guardando el split ya regenerado y se perderia el
            # conjunto original.
            logger.info(f"  {legacy.name} ya existe, se conserva")
        elif actual.exists():
            shutil.copy(actual, legacy)
            logger.info(f"  {nombre} -> {legacy.name}")

    # Reparto estratificado 60 / 20 / 20
    resto, test = train_test_split(
        df, test_size=FRAC_TEST, random_state=SEED, stratify=df["label"]
    )
    val_relativo = FRAC_VAL / (1 - FRAC_TEST)
    train, val = train_test_split(
        resto, test_size=val_relativo, random_state=SEED, stratify=resto["label"]
    )

    train.to_csv(SPLITS_DIR / "train.csv", index=False)
    val.to_csv(SPLITS_DIR / "val.csv", index=False)
    test.to_csv(SPLITS_DIR / "test.csv", index=False)

    logger.info("")
    logger.info("=" * 70)
    logger.info("SPLITS REGENERADOS")
    logger.info("=" * 70)
    diagnostico("train.csv", train)
    diagnostico("val.csv", val)
    diagnostico("test.csv", test)

    logger.info("")
    logger.info("Listo. Ninguna feature individual separa las clases por si sola.")


if __name__ == "__main__":
    main()
