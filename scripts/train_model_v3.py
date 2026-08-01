#!/usr/bin/env python3
"""
train_model_v3.py - Reentrena el modelo ML sobre los splits sin fuga de datos

MOTIVO
------
1. El modelo anterior (step1_baseline.pkl) fue serializado con scikit-learn
   1.8.0 y no carga en el entorno actual (1.9.0): "No module named '_loss'".
2. Los conjuntos val.csv y test.csv anteriores tenian fuga de datos, por lo
   que las metricas reportadas (100% en cinco algoritmos) no eran validas.

Este script entrena sobre los splits regenerados por rebuild_splits.py y
evalua sobre un test que el modelo nunca vio.

Se entrenan DOS variantes para poder comparar honestamente:
  - COMPLETA:  las 24 features
  - SIN FUGA:  se excluyen in_tranco y tranco_rank, que siguen mostrando
               85% de concordancia con la etiqueta

El backend selecciona las features por nombre, asi que ambas variantes son
compatibles con app/services/predictor.py sin cambios.

Uso:
    python scripts/train_model_v3.py

Salida:
    models/step1_baseline.pkl   (modelo elegido, nombre que espera el backend)
    models/best_model.pkl       (mismo contenido)
    El hash SHA256 que debe copiarse en predictor.py
"""

import pickle
import hashlib
import logging
from pathlib import Path
from typing import List, Tuple

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
SPLITS_DIR = PROJECT_ROOT / "datasets" / "splits"
MODELS_DIR = PROJECT_ROOT / "models"
BACKEND_MODELS_DIR = PROJECT_ROOT / "backend" / "models"

SEED = 42

TODAS_LAS_FEATURES = [
    'url_length', 'domain_length', 'path_length', 'num_digits',
    'num_hyphens', 'num_dots', 'num_subdomains', 'entropy',
    'has_https', 'has_port', 'has_at_symbol', 'contains_ip',
    'has_punycode', 'shortener_detected', 'paste_service_detected',
    'has_suspicious_words', 'tld_risk', 'excessive_subdomains',
    'digit_ratio', 'num_params', 'special_chars',
    'in_tranco', 'tranco_rank', 'brand_impersonation'
]

# Features que en el dataset actual siguen correlacionando demasiado con la
# etiqueta (85%). Se excluyen en la variante "sin fuga".
FEATURES_CON_FUGA = ['in_tranco', 'tranco_rank']


def construir_modelos() -> dict:
    return {
        'LogisticRegression': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', LogisticRegression(C=0.5, max_iter=1000, random_state=SEED))
        ]),
        'RandomForest': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(
                n_estimators=100, max_depth=10, min_samples_split=5,
                random_state=SEED, n_jobs=-1
            ))
        ]),
        'GradientBoosting': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', GradientBoostingClassifier(
                n_estimators=100, max_depth=5, learning_rate=0.1,
                random_state=SEED
            ))
        ]),
    }


def entrenar_variante(nombre_variante: str, features: List[str],
                      train: pd.DataFrame, val: pd.DataFrame,
                      test: pd.DataFrame) -> Tuple[str, Pipeline, dict]:
    """Entrena los tres algoritmos y devuelve el mejor segun F1 en validacion."""
    logger.info("")
    logger.info("=" * 72)
    logger.info(f"VARIANTE: {nombre_variante}  ({len(features)} features)")
    logger.info("=" * 72)

    X_train, y_train = train[features], train['label']
    X_val, y_val = val[features], val['label']
    X_test, y_test = test[features], test['label']

    logger.info(f"{'Modelo':<22}{'CV(5) acc':>12}{'Val F1':>10}{'Test acc':>11}")
    logger.info("-" * 72)

    mejor_nombre, mejor_pipeline, mejor_f1 = None, None, -1.0
    resultados = {}

    for nombre, pipeline in construir_modelos().items():
        cv = cross_val_score(pipeline, X_train, y_train, cv=5, scoring='accuracy')
        pipeline.fit(X_train, y_train)

        f1_val = f1_score(y_val, pipeline.predict(X_val))
        acc_test = accuracy_score(y_test, pipeline.predict(X_test))
        resultados[nombre] = {'cv': cv.mean(), 'val_f1': f1_val, 'test_acc': acc_test}

        logger.info(
            f"{nombre:<22}{cv.mean():>11.1%}{f1_val:>10.3f}{acc_test:>11.1%}"
        )

        # La seleccion se hace con validacion, nunca con test
        if f1_val > mejor_f1:
            mejor_f1, mejor_nombre, mejor_pipeline = f1_val, nombre, pipeline

    logger.info("")
    logger.info(f"Mejor por F1 en validacion: {mejor_nombre}")

    # Evaluacion final sobre test
    y_pred = mejor_pipeline.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    metricas = {
        'variante': nombre_variante,
        'modelo': mejor_nombre,
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred, zero_division=0),
        'recall': recall_score(y_test, y_pred, zero_division=0),
        'f1': f1_score(y_test, y_pred, zero_division=0),
        'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
    }

    logger.info("")
    logger.info(f"--- Test ({len(test)} URLs que el modelo nunca vio) ---")
    logger.info(f"  Accuracy   {metricas['accuracy']:.1%}")
    logger.info(f"  Precision  {metricas['precision']:.1%}")
    logger.info(f"  Recall     {metricas['recall']:.1%}")
    logger.info(f"  F1         {metricas['f1']:.3f}")
    logger.info("")
    logger.info("                  Predicho legitima   Predicho maliciosa")
    logger.info(f"  Real legitima         {tn:6d}              {fp:6d}")
    logger.info(f"  Real maliciosa        {fn:6d}              {tp:6d}")
    logger.info("")
    logger.info(classification_report(
        y_test, y_pred, target_names=['Legitimo', 'Phishing'], zero_division=0
    ))

    if hasattr(mejor_pipeline.named_steps['classifier'], 'feature_importances_'):
        importancias = sorted(
            zip(features, mejor_pipeline.named_steps['classifier'].feature_importances_),
            key=lambda x: -x[1]
        )
        logger.info("  Features mas influyentes:")
        for nombre_f, peso in importancias[:8]:
            logger.info(f"    {nombre_f:<26}{peso:.3f}")

    return mejor_nombre, mejor_pipeline, metricas


def guardar(pipeline: Pipeline, features: List[str], info: dict) -> str:
    """Guarda el modelo y devuelve su hash SHA256."""
    contenido = {
        'pipeline': pipeline,
        'feature_names': features,
        'info': info,
    }

    destinos = [MODELS_DIR / "step1_baseline.pkl", MODELS_DIR / "best_model.pkl"]
    if BACKEND_MODELS_DIR.exists():
        destinos.append(BACKEND_MODELS_DIR / "step1_baseline.pkl")

    for destino in destinos:
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(destino, 'wb') as f:
            pickle.dump(contenido, f)
        logger.info(f"  guardado: {destino}")

    with open(destinos[0], 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def main() -> None:
    train = pd.read_csv(SPLITS_DIR / "train.csv")
    val = pd.read_csv(SPLITS_DIR / "val.csv")
    test = pd.read_csv(SPLITS_DIR / "test.csv")

    logger.info("=" * 72)
    logger.info("REENTRENAMIENTO SOBRE SPLITS SIN FUGA")
    logger.info("=" * 72)
    logger.info(f"  train {len(train)}   val {len(val)}   test {len(test)}")

    sin_fuga = [f for f in TODAS_LAS_FEATURES if f not in FEATURES_CON_FUGA]

    _, pipe_completa, met_completa = entrenar_variante(
        "COMPLETA (incluye in_tranco)", TODAS_LAS_FEATURES, train, val, test
    )
    _, pipe_sin_fuga, met_sin_fuga = entrenar_variante(
        "SIN FUGA (excluye in_tranco)", sin_fuga, train, val, test
    )

    logger.info("")
    logger.info("=" * 72)
    logger.info("COMPARACION")
    logger.info("=" * 72)
    logger.info(f"{'Variante':<32}{'Modelo':<20}{'Accuracy':>10}{'F1':>8}")
    for m in (met_completa, met_sin_fuga):
        logger.info(f"{m['variante']:<32}{m['modelo']:<20}{m['accuracy']:>9.1%}{m['f1']:>8.3f}")

    # Se despliega la variante sin fuga: es la defendible metodologicamente
    logger.info("")
    logger.info("=" * 72)
    logger.info("GUARDANDO LA VARIANTE SIN FUGA")
    logger.info("=" * 72)
    nuevo_hash = guardar(pipe_sin_fuga, sin_fuga, met_sin_fuga)

    logger.info("")
    logger.info("=" * 72)
    logger.info("SIGUIENTE PASO OBLIGATORIO")
    logger.info("=" * 72)
    logger.info("Copiar este hash en backend/app/services/predictor.py")
    logger.info("(constante AUTHORIZED_MODEL_HASH) o el modelo sera rechazado:")
    logger.info("")
    logger.info(f'    AUTHORIZED_MODEL_HASH = "{nuevo_hash}"')
    logger.info("")


if __name__ == "__main__":
    main()
