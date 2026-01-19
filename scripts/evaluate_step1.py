#!/usr/bin/env python3
"""
evaluate_step1.py - Evalua el modelo baseline en los sets de validacion y test

Este script:
1. Carga el modelo entrenado
2. Evalua en validation y test sets
3. Genera metricas y confusion matrix
4. Guarda reporte de evaluacion

Uso:
    python scripts/evaluate_step1.py

Salida:
    reports/step1_metrics.json
"""

import os
import sys
import json
import pickle
import logging
from pathlib import Path
from datetime import datetime

import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    precision_recall_curve, average_precision_score
)

# Configuracion de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rutas
PROJECT_ROOT = Path(__file__).parent.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"
SPLITS_DIR = DATASETS_DIR / "splits"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Importar extractor de features del script de entrenamiento
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from train_step1 import extract_features_batch


def load_model():
    """Carga el modelo entrenado."""
    model_path = MODELS_DIR / "step1_baseline.pkl"

    if not model_path.exists():
        logger.error(f"No se encontro el modelo en {model_path}")
        logger.error("Ejecuta primero: python scripts/train_step1.py")
        sys.exit(1)

    logger.info(f"Cargando modelo desde {model_path}")
    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)

    return model_data


def load_evaluation_data(split: str) -> pd.DataFrame:
    """Carga datos de validacion o test."""
    data_path = SPLITS_DIR / f"{split}.csv"

    if not data_path.exists():
        logger.error(f"No se encontro {data_path}")
        sys.exit(1)

    logger.info(f"Cargando {split} set desde {data_path}")
    df = pd.read_csv(data_path)

    logger.info(f"  - Total: {len(df)}")
    logger.info(f"  - Legitimas (0): {len(df[df['label'] == 0])}")
    logger.info(f"  - Maliciosas (1): {len(df[df['label'] == 1])}")

    return df


def evaluate_model(pipeline, X: pd.DataFrame, y: pd.Series, split_name: str) -> dict:
    """Evalua el modelo y retorna metricas."""
    logger.info(f"Evaluando en {split_name}...")

    # Predicciones
    y_pred = pipeline.predict(X)
    y_proba = pipeline.predict_proba(X)[:, 1]

    # Metricas
    metrics = {
        'accuracy': float(accuracy_score(y, y_pred)),
        'precision': float(precision_score(y, y_pred)),
        'recall': float(recall_score(y, y_pred)),
        'f1_score': float(f1_score(y, y_pred)),
        'roc_auc': float(roc_auc_score(y, y_proba)),
        'average_precision': float(average_precision_score(y, y_proba)),
        'samples': int(len(y))
    }

    # Confusion matrix
    cm = confusion_matrix(y, y_pred)
    metrics['confusion_matrix'] = {
        'true_negative': int(cm[0, 0]),
        'false_positive': int(cm[0, 1]),
        'false_negative': int(cm[1, 0]),
        'true_positive': int(cm[1, 1])
    }

    # Classification report
    report = classification_report(y, y_pred, output_dict=True)
    metrics['classification_report'] = report

    # Log resultados
    logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
    logger.info(f"  Precision: {metrics['precision']:.4f}")
    logger.info(f"  Recall: {metrics['recall']:.4f}")
    logger.info(f"  F1-Score: {metrics['f1_score']:.4f}")
    logger.info(f"  ROC-AUC: {metrics['roc_auc']:.4f}")
    logger.info(f"  Confusion Matrix:")
    logger.info(f"    TN={cm[0,0]} FP={cm[0,1]}")
    logger.info(f"    FN={cm[1,0]} TP={cm[1,1]}")

    return metrics


def calculate_risk_thresholds(pipeline, X: pd.DataFrame, y: pd.Series) -> dict:
    """Calcula umbrales optimos para niveles de riesgo."""
    y_proba = pipeline.predict_proba(X)[:, 1]

    # Convertir probabilidades a scores 0-100
    scores = y_proba * 100

    # Calcular precision/recall en diferentes thresholds
    thresholds = {}

    for threshold in [30, 50, 70]:
        y_pred = (scores >= threshold).astype(int)

        # Solo calcular si hay predicciones positivas
        if y_pred.sum() > 0:
            prec = precision_score(y, y_pred, zero_division=0)
            rec = recall_score(y, y_pred, zero_division=0)
            thresholds[f"threshold_{threshold}"] = {
                'precision': float(prec),
                'recall': float(rec),
                'predicted_positive': int(y_pred.sum())
            }

    return thresholds


def save_report(metrics: dict):
    """Guarda el reporte de evaluacion."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    report_path = REPORTS_DIR / "step1_metrics.json"
    with open(report_path, 'w') as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Reporte guardado en {report_path}")


def main():
    """Funcion principal."""
    logger.info("="*60)
    logger.info("EVALUACION STEP 1 - BASELINE")
    logger.info("="*60)

    # Cargar modelo
    model_data = load_model()
    pipeline = model_data['pipeline']
    feature_names = model_data['feature_names']

    logger.info(f"Modelo cargado, version: {model_data.get('version', 'unknown')}")
    logger.info(f"Features: {len(feature_names)}")

    # Evaluar en validation set
    val_df = load_evaluation_data('val')
    X_val = extract_features_batch(val_df['url'])
    y_val = val_df['label']
    val_metrics = evaluate_model(pipeline, X_val, y_val, 'validation')

    # Evaluar en test set
    test_df = load_evaluation_data('test')
    X_test = extract_features_batch(test_df['url'])
    y_test = test_df['label']
    test_metrics = evaluate_model(pipeline, X_test, y_test, 'test')

    # Calcular thresholds en validation
    thresholds = calculate_risk_thresholds(pipeline, X_val, y_val)

    # Compilar reporte completo
    report = {
        'model': {
            'name': 'step1_baseline',
            'type': 'LogisticRegression',
            'version': model_data.get('version', '1.0.0'),
            'created_at': model_data.get('created_at', 'unknown'),
            'features_count': len(feature_names),
            'features': feature_names
        },
        'validation': val_metrics,
        'test': test_metrics,
        'risk_thresholds': thresholds,
        'evaluated_at': datetime.now().isoformat()
    }

    # Guardar reporte
    save_report(report)

    # Resumen final
    logger.info("="*60)
    logger.info("RESUMEN DE EVALUACION")
    logger.info("="*60)
    logger.info(f"Validation F1: {val_metrics['f1_score']:.4f}")
    logger.info(f"Test F1: {test_metrics['f1_score']:.4f}")
    logger.info(f"Test Precision: {test_metrics['precision']:.4f}")
    logger.info(f"Test Recall: {test_metrics['recall']:.4f}")

    # Verificar objetivos
    logger.info("")
    logger.info("Verificacion de objetivos (scoring_config.json):")

    target_precision = 0.85
    target_recall = 0.80
    target_f1 = 0.82

    prec_ok = "OK" if test_metrics['precision'] >= target_precision else "FALTA"
    rec_ok = "OK" if test_metrics['recall'] >= target_recall else "FALTA"
    f1_ok = "OK" if test_metrics['f1_score'] >= target_f1 else "FALTA"

    logger.info(f"  Precision >= {target_precision}: {test_metrics['precision']:.4f} [{prec_ok}]")
    logger.info(f"  Recall >= {target_recall}: {test_metrics['recall']:.4f} [{rec_ok}]")
    logger.info(f"  F1 >= {target_f1}: {test_metrics['f1_score']:.4f} [{f1_ok}]")

    logger.info("="*60)
    logger.info("EVALUACION COMPLETADA")
    logger.info("="*60)


if __name__ == "__main__":
    main()
