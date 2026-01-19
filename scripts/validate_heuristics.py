#!/usr/bin/env python3
"""
validate_heuristics.py - Valida el motor heurístico contra el dataset

Este script:
1. Carga el dataset de URLs (buenos/malos)
2. Aplica las reglas heurísticas a cada URL
3. Calcula métricas de rendimiento
4. Sugiere ajustes a los pesos

Uso:
    python scripts/validate_heuristics.py

Salida:
    reports/heuristics_validation.json
"""

import os
import sys
import json
import re
import math
import logging
from pathlib import Path
from datetime import datetime
from collections import Counter
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Tuple, Any

import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
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
REPORTS_DIR = PROJECT_ROOT / "reports"

# ============================================================================
# REGLAS HEURISTICAS (mismo código que en Dart para consistencia)
# ============================================================================

# Pesos de señales
WEIGHTS = {
    'IP_AS_HOST': 25,
    'PUNYCODE_DETECTED': 20,
    'TYPOSQUATTING': 25,
    'BRAND_IMPERSONATION': 30,
    'URL_SHORTENER': 15,
    'SUSPICIOUS_WORDS': 5,  # x cantidad
    'RISKY_TLD': 10,
    'EXCESSIVE_SUBDOMAINS': 10,
    'AT_SYMBOL': 15,
    'HIGH_ENTROPY': 10,
    'NO_HTTPS': 5,
    'LONG_URL': 5,
    'HIGH_DIGIT_RATIO': 5,
    'MANY_HYPHENS': 5,
    'NON_STANDARD_PORT': 5,
}

# Umbrales
THRESHOLDS = {
    'low': 0,
    'medium': 31,
    'high': 71,
}

# Palabras sospechosas
SUSPICIOUS_WORDS = [
    'login', 'signin', 'sign-in', 'log-in',
    'verify', 'verificar', 'confirmar', 'confirm',
    'update', 'actualizar', 'upgrade',
    'secure', 'seguro', 'security', 'seguridad',
    'suspend', 'suspender', 'suspended',
    'expire', 'expired', 'vence', 'vencido',
    'urgent', 'urgente', 'immediately', 'inmediato',
    'password', 'contraseña', 'clave',
    'account', 'cuenta', 'usuario',
    'bank', 'banco', 'banking',
    'payment', 'pago', 'pay',
    'free', 'gratis', 'regalo', 'gift',
    'winner', 'ganador', 'premio',
    'click', 'clic', 'validate', 'validar',
]

# URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
    'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
    'cutt.ly', 'shorte.st', 'bc.vc', 'j.mp',
]

# TLDs de riesgo
RISKY_TLDS = [
    'xyz', 'top', 'club', 'online', 'site',
    'website', 'space', 'tech', 'info', 'biz',
    'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'ws',
]

# Marcas objetivo
TARGETED_BRANDS = [
    'bancolombia', 'davivienda', 'bbva', 'nequi', 'daviplata',
    'paypal', 'netflix', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'instagram', 'whatsapp',
]

# Dominios oficiales
OFFICIAL_DOMAINS = [
    'bancolombia.com', 'davivienda.com', 'bbva.com.co',
    'paypal.com', 'netflix.com', 'amazon.com',
    'apple.com', 'microsoft.com', 'google.com',
    'facebook.com', 'instagram.com', 'whatsapp.com',
]

# Typosquatting
TYPOSQUATTING_PATTERNS = [
    {'pattern': 'paypa1', 'brand': 'PayPal'},
    {'pattern': 'paypai', 'brand': 'PayPal'},
    {'pattern': 'netfiix', 'brand': 'Netflix'},
    {'pattern': 'netf1ix', 'brand': 'Netflix'},
    {'pattern': 'arnazon', 'brand': 'Amazon'},
    {'pattern': 'amaz0n', 'brand': 'Amazon'},
    {'pattern': 'g00gle', 'brand': 'Google'},
    {'pattern': 'faceb00k', 'brand': 'Facebook'},
    {'pattern': 'rnicrosoft', 'brand': 'Microsoft'},
]


def calculate_entropy(text: str) -> float:
    """Calcula entropía de Shannon."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            freq = count / length
            entropy -= freq * math.log2(freq)
    return entropy


def is_ip_address(host: str) -> bool:
    """Verifica si el host es una IP."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, host.split(':')[0]))


def analyze_url_heuristic(url: str) -> Tuple[int, List[Dict]]:
    """
    Analiza una URL usando heurísticas.

    Returns:
        Tuple[int, List[Dict]]: (score, lista de señales)
    """
    signals = []

    try:
        url_lower = url.lower().strip()
        parsed = urlparse(url_lower)
        domain = parsed.netloc
        path = parsed.path
        scheme = parsed.scheme

        # Extraer TLD y subdominios
        domain_parts = domain.split('.')
        tld = domain_parts[-1] if domain_parts else ''
        subdomain_count = len(domain_parts) - 2 if len(domain_parts) > 2 else 0

        # === VERIFICACIONES ===

        # 1. Sin HTTPS
        if scheme == 'http':
            signals.append({'id': 'NO_HTTPS', 'weight': WEIGHTS['NO_HTTPS']})

        # 2. IP como host
        if is_ip_address(domain):
            signals.append({'id': 'IP_AS_HOST', 'weight': WEIGHTS['IP_AS_HOST']})

        # 3. Punycode
        if 'xn--' in domain:
            signals.append({'id': 'PUNYCODE_DETECTED', 'weight': WEIGHTS['PUNYCODE_DETECTED']})

        # 4. Subdominios excesivos
        if subdomain_count > 3:
            signals.append({'id': 'EXCESSIVE_SUBDOMAINS', 'weight': WEIGHTS['EXCESSIVE_SUBDOMAINS']})

        # 5. Símbolo @
        if '@' in url:
            signals.append({'id': 'AT_SYMBOL', 'weight': WEIGHTS['AT_SYMBOL']})

        # 6. URL muy larga
        if len(url) > 100:
            signals.append({'id': 'LONG_URL', 'weight': WEIGHTS['LONG_URL']})

        # 7. Alto ratio de dígitos
        digit_count = sum(c.isdigit() for c in url)
        digit_ratio = digit_count / len(url) if len(url) > 0 else 0
        if digit_ratio > 0.3:
            signals.append({'id': 'HIGH_DIGIT_RATIO', 'weight': WEIGHTS['HIGH_DIGIT_RATIO']})

        # 8. Muchos guiones
        hyphen_count = domain.count('-')
        if hyphen_count > 3:
            signals.append({'id': 'MANY_HYPHENS', 'weight': WEIGHTS['MANY_HYPHENS']})

        # 9. Alta entropía
        entropy = calculate_entropy(domain)
        if entropy > 4.0:
            signals.append({'id': 'HIGH_ENTROPY', 'weight': WEIGHTS['HIGH_ENTROPY']})

        # 10. URL shortener
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                signals.append({'id': 'URL_SHORTENER', 'weight': WEIGHTS['URL_SHORTENER']})
                break

        # 11. TLD riesgoso
        if tld in RISKY_TLDS:
            signals.append({'id': 'RISKY_TLD', 'weight': WEIGHTS['RISKY_TLD']})

        # 12. Palabras sospechosas
        suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)
        if suspicious_count > 0:
            weight = min(WEIGHTS['SUSPICIOUS_WORDS'] * suspicious_count, 25)
            signals.append({'id': 'SUSPICIOUS_WORDS', 'weight': weight, 'count': suspicious_count})

        # 13. Typosquatting
        for pattern in TYPOSQUATTING_PATTERNS:
            if pattern['pattern'] in domain:
                signals.append({'id': 'TYPOSQUATTING', 'weight': WEIGHTS['TYPOSQUATTING']})
                break

        # 14. Impersonación de marca
        for brand in TARGETED_BRANDS:
            if brand in domain:
                is_official = any(domain.endswith(d) for d in OFFICIAL_DOMAINS)
                if not is_official:
                    signals.append({'id': 'BRAND_IMPERSONATION', 'weight': WEIGHTS['BRAND_IMPERSONATION']})
                    break

    except Exception as e:
        logger.warning(f"Error analizando {url}: {e}")

    # Calcular score total
    score = sum(s['weight'] for s in signals)
    score = min(score, 100)  # Máximo 100

    return score, signals


def predict_label(score: int, threshold: int = 50) -> int:
    """Predice label basado en score."""
    return 1 if score >= threshold else 0


def evaluate_on_dataset(df: pd.DataFrame, threshold: int = 50) -> Dict:
    """Evalúa las heurísticas en un dataset."""
    logger.info(f"Evaluando {len(df)} URLs con threshold={threshold}...")

    scores = []
    predictions = []
    signal_counts = Counter()

    for url in df['url']:
        score, signals = analyze_url_heuristic(str(url))
        scores.append(score)
        predictions.append(predict_label(score, threshold))

        for signal in signals:
            signal_counts[signal['id']] += 1

    y_true = df['label'].values
    y_pred = np.array(predictions)

    # Métricas
    metrics = {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, zero_division=0)),
        'f1_score': float(f1_score(y_true, y_pred, zero_division=0)),
    }

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    metrics['confusion_matrix'] = {
        'true_negative': int(cm[0, 0]),
        'false_positive': int(cm[0, 1]),
        'false_negative': int(cm[1, 0]),
        'true_positive': int(cm[1, 1]),
    }

    # Distribución de scores
    metrics['score_distribution'] = {
        'mean': float(np.mean(scores)),
        'median': float(np.median(scores)),
        'std': float(np.std(scores)),
        'min': int(np.min(scores)),
        'max': int(np.max(scores)),
    }

    # Señales más frecuentes
    metrics['signal_frequency'] = dict(signal_counts.most_common(15))

    return metrics


def find_optimal_threshold(df: pd.DataFrame) -> Tuple[int, Dict]:
    """Encuentra el threshold óptimo para maximizar F1."""
    best_threshold = 50
    best_f1 = 0
    best_metrics = {}

    for threshold in range(20, 81, 5):
        metrics = evaluate_on_dataset(df, threshold)
        if metrics['f1_score'] > best_f1:
            best_f1 = metrics['f1_score']
            best_threshold = threshold
            best_metrics = metrics

    return best_threshold, best_metrics


def main():
    """Función principal."""
    logger.info("="*60)
    logger.info("VALIDACIÓN DE REGLAS HEURÍSTICAS")
    logger.info("="*60)

    # Cargar datos
    test_path = SPLITS_DIR / "test.csv"
    if not test_path.exists():
        # Intentar con dataset procesado
        test_path = DATASETS_DIR / "processed" / "dataset_master.csv"

    if not test_path.exists():
        logger.error("No se encontró dataset. Ejecuta primero build_dataset.py")
        sys.exit(1)

    logger.info(f"Cargando datos desde {test_path}")
    df = pd.read_csv(test_path)

    # Tomar muestra si es muy grande
    if len(df) > 50000:
        logger.info(f"Dataset muy grande ({len(df)}), tomando muestra de 50000")
        df = df.sample(n=50000, random_state=42)

    logger.info(f"URLs a evaluar: {len(df)}")
    logger.info(f"Distribución: {df['label'].value_counts().to_dict()}")

    # Evaluar con threshold por defecto
    logger.info("\n--- Evaluación con threshold=50 ---")
    metrics_50 = evaluate_on_dataset(df, threshold=50)

    logger.info(f"Accuracy: {metrics_50['accuracy']:.4f}")
    logger.info(f"Precision: {metrics_50['precision']:.4f}")
    logger.info(f"Recall: {metrics_50['recall']:.4f}")
    logger.info(f"F1-Score: {metrics_50['f1_score']:.4f}")

    # Encontrar threshold óptimo
    logger.info("\n--- Buscando threshold óptimo ---")
    optimal_threshold, optimal_metrics = find_optimal_threshold(df)

    logger.info(f"Threshold óptimo: {optimal_threshold}")
    logger.info(f"F1-Score óptimo: {optimal_metrics['f1_score']:.4f}")

    # Evaluar con diferentes thresholds
    threshold_results = {}
    for threshold in [30, 40, 50, 60, 70]:
        metrics = evaluate_on_dataset(df, threshold)
        threshold_results[threshold] = {
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'f1_score': metrics['f1_score'],
        }

    # Compilar reporte
    report = {
        'dataset': {
            'path': str(test_path),
            'total_urls': len(df),
            'legitimate': int((df['label'] == 0).sum()),
            'malicious': int((df['label'] == 1).sum()),
        },
        'current_weights': WEIGHTS,
        'thresholds': THRESHOLDS,
        'evaluation_threshold_50': metrics_50,
        'optimal_threshold': optimal_threshold,
        'optimal_metrics': optimal_metrics,
        'threshold_comparison': threshold_results,
        'signal_frequency': metrics_50['signal_frequency'],
        'evaluated_at': datetime.now().isoformat(),
    }

    # Sugerencias de ajuste
    suggestions = []

    if metrics_50['recall'] < 0.80:
        suggestions.append("Recall bajo: considerar reducir el threshold o aumentar pesos de señales")

    if metrics_50['precision'] < 0.80:
        suggestions.append("Precision baja: considerar aumentar el threshold o reducir falsos positivos")

    if optimal_threshold != 50:
        suggestions.append(f"El threshold óptimo ({optimal_threshold}) difiere del actual (50)")

    report['suggestions'] = suggestions

    # Guardar reporte
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / "heuristics_validation.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    logger.info(f"\nReporte guardado en {report_path}")

    # Resumen final
    logger.info("\n" + "="*60)
    logger.info("RESUMEN")
    logger.info("="*60)
    logger.info(f"F1-Score con threshold 50: {metrics_50['f1_score']:.4f}")
    logger.info(f"Threshold óptimo: {optimal_threshold} (F1={optimal_metrics['f1_score']:.4f})")
    logger.info(f"Top 5 señales más frecuentes:")
    for signal, count in list(metrics_50['signal_frequency'].items())[:5]:
        logger.info(f"  - {signal}: {count}")

    if suggestions:
        logger.info("\nSugerencias:")
        for s in suggestions:
            logger.info(f"  - {s}")


if __name__ == "__main__":
    main()
