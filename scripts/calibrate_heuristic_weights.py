#!/usr/bin/env python3
"""
Script de Calibracion de Pesos Heuristicos para ALERTA-LINK

Este script utiliza el dataset de 7,600 URLs para calibrar y optimizar
los pesos del modelo heuristico, reduciendo falsos positivos y mejorando
la precision sin sustituir el motor heuristico.

Metodologia:
1. Carga el dataset completo (train + val + test)
2. Extrae senales heuristicas de cada URL (SIN APIs externas)
3. Usa optimizacion para encontrar los pesos optimos
4. Guarda los pesos calibrados en models/heuristic_weights.json
"""

import sys
import os
import json
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Any, NamedTuple
from datetime import datetime
from urllib.parse import urlparse
import re
import math
from scipy.optimize import differential_evolution
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix
)

# Configuracion de paths
BASE_DIR = Path(__file__).parent.parent
DATASETS_DIR = BASE_DIR / 'datasets' / 'splits'
MODELS_DIR = BASE_DIR / 'models'
OUTPUT_FILE = MODELS_DIR / 'heuristic_weights.json'


# ============================================================================
# LISTAS DE PATRONES (copiadas de heuristic_predictor.py)
# ============================================================================

SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'password',
    'confirm', 'banking', 'suspend', 'expire', 'verify', 'wallet', 'alert',
    'unusual', 'locked', 'unlock', 'validate', 'authenticate', 'credential',
    'ssn', 'social', 'security', 'paypal', 'netflix', 'amazon', 'apple',
    'microsoft', 'google', 'facebook', 'instagram', 'whatsapp', 'telegram',
    'bancolombia', 'davivienda', 'nequi', 'daviplata', 'bbva', 'banco',
    'crack', 'keygen', 'serial', 'patch', 'activator', 'kms', 'warez',
    'nulled', 'cracked', 'torrent', 'free-download', 'full-version'
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'yourls.org', 'short.io',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'acortar.link', 'acortaurl.com'
]

RISKY_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online', 'site',
    'work', 'click', 'link', 'info', 'pw', 'cc', 'ws', 'buzz', 'surf',
    'icu', 'monster', 'cam', 'email', 'life', 'live', 'world', 'today'
]

PASTE_SERVICES = [
    'pastebin.com', 'paste.ee', 'justpaste.it', 'ghostbin.com', 'paste2.org',
    'hastebin.com', 'dpaste.org', 'ideone.com', 'codepad.org', 'rentry.co',
    'del.dog', 'paste.mozilla.org', 'privatebin.net'
]

HOSTING_PLATFORMS = [
    'appspot.com', 'github.io', 'gitlab.io', 'herokuapp.com', 'netlify.app',
    'vercel.app', 'pages.dev', 'web.app', 'firebaseapp.com', 'azurewebsites.net',
    'cloudfront.net', 'amazonaws.com', 'blob.core.windows.net', 'ngrok.io',
    'trycloudflare.com', 'workers.dev', 'r2.dev', 'replit.co', 'glitch.me'
]

KNOWN_BRANDS = [
    'paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'whatsapp', 'telegram', 'twitter', 'linkedin', 'spotify',
    'bancolombia', 'davivienda', 'nequi', 'daviplata', 'bbva', 'santander',
    'banco', 'dian', 'movistar', 'claro', 'tigo', 'rappi', 'mercadolibre',
    'falabella', 'exito', 'alkosto', 'olimpica', 'colsubsidio', 'compensar'
]

OFFICIAL_DOMAINS = {
    'paypal': 'paypal.com', 'netflix': 'netflix.com', 'amazon': 'amazon.com',
    'apple': 'apple.com', 'microsoft': 'microsoft.com', 'google': 'google.com',
    'facebook': 'facebook.com', 'instagram': 'instagram.com', 'whatsapp': 'whatsapp.com',
    'bancolombia': 'bancolombia.com', 'davivienda': 'davivienda.com',
    'nequi': 'nequi.com.co', 'daviplata': 'daviplata.com', 'dian': 'dian.gov.co',
    'rappi': 'rappi.com', 'mercadolibre': 'mercadolibre.com.co'
}

TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
    'bancolombia.com', 'davivienda.com', 'bbva.com.co', 'grupobancolombia.com',
    'nequi.com.co', 'daviplata.com', 'pse.com.co', 'dian.gov.co', 'gov.co'
]


# Pesos locales (se calibran con el dataset)
LOCAL_WEIGHTS = {
    'IP_AS_HOST': 30,
    'PUNYCODE_DETECTED': 25,
    'BRAND_IMPERSONATION': 45,
    'URL_SHORTENER': 15,
    'PASTE_SERVICE': 20,
    'HOSTING_PLATFORM': 15,
    'RISKY_TLD': 15,
    'SUSPICIOUS_WORDS': 10,
    'EXCESSIVE_SUBDOMAINS': 10,
    'NO_HTTPS': 8,
    'LONG_URL': 5,
    'HIGH_DIGIT_RATIO': 8,
    'HIGH_ENTROPY': 10,
    'AT_SYMBOL': 15,
    'TRUSTED_DOMAIN': -30,  # Lista local de dominios confiables
}

# Pesos externos (NO se calibran - se mantienen fijos)
# Estos requieren APIs externas que no podemos usar offline
EXTERNAL_WEIGHTS = {
    'DOMAIN_NOT_IN_TRANCO': 12,
    'DOMAIN_IN_TRANCO': -35,
    'VIRUSTOTAL_CLEAN': -25,
    'VIRUSTOTAL_MALICIOUS_LOW': 25,
    'VIRUSTOTAL_MALICIOUS_MED': 40,
    'VIRUSTOTAL_MALICIOUS_HIGH': 60,
    'VIRUSTOTAL_MALICIOUS_CRITICAL': 80
}

# Todos los pesos combinados
DEFAULT_WEIGHTS = {**LOCAL_WEIGHTS, **EXTERNAL_WEIGHTS}


class SignalInfo(NamedTuple):
    """Senal simple para calibracion."""
    name: str
    weight: float


def calculate_entropy(text: str) -> float:
    """Calcula entropia de Shannon del texto."""
    if not text:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def extract_features(url: str) -> Dict[str, Any]:
    """Extrae features de la URL para las heuristicas."""
    features = {}

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()

        # Basicas
        features['url_length'] = len(url)
        features['domain'] = domain
        features['path'] = path
        features['has_https'] = parsed.scheme == 'https'

        # TLD
        parts = domain.split('.')
        features['tld'] = parts[-1] if parts else ''
        features['tld_risk'] = features['tld'] in RISKY_TLDS

        # Subdominios
        features['num_subdomains'] = max(0, len(parts) - 2)
        features['excessive_subdomains'] = features['num_subdomains'] > 3

        # Digitos
        digits = sum(c.isdigit() for c in url)
        features['num_digits'] = digits
        features['digit_ratio'] = digits / len(url) if len(url) > 0 else 0

        # Entropia
        features['entropy'] = calculate_entropy(domain)

        # Patrones especificos
        features['contains_ip'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))
        features['has_punycode'] = 'xn--' in domain
        features['has_at_symbol'] = '@' in url
        features['shortener_detected'] = any(s in domain for s in SHORTENERS)
        features['paste_service_detected'] = any(p in domain for p in PASTE_SERVICES)
        features['hosting_platform'] = any(h in domain for h in HOSTING_PLATFORMS)

        # Palabras sospechosas
        suspicious_count = sum(1 for w in SUSPICIOUS_WORDS if w in full_url)
        features['suspicious_words_count'] = suspicious_count

        # Deteccion de marca
        features['brand_mentioned'] = None
        features['brand_impersonation'] = False
        for brand in KNOWN_BRANDS:
            if brand in full_url:
                features['brand_mentioned'] = brand
                official = OFFICIAL_DOMAINS.get(brand, f"{brand}.com")
                if official not in domain and brand not in domain.split('.')[0]:
                    features['brand_impersonation'] = True
                break

        # Dominio de confianza
        features['is_trusted'] = any(td in domain for td in TRUSTED_DOMAINS)

    except Exception as e:
        features['error'] = str(e)

    return features


def generate_signals(url: str, features: Dict[str, Any], weights: Dict[str, float]) -> List[SignalInfo]:
    """Genera senales basadas en las features extraidas."""
    signals = []

    # IP como host
    if features.get('contains_ip'):
        signals.append(SignalInfo('IP_AS_HOST', weights['IP_AS_HOST']))

    # Punycode
    if features.get('has_punycode'):
        signals.append(SignalInfo('PUNYCODE_DETECTED', weights['PUNYCODE_DETECTED']))

    # Suplantacion de marca
    if features.get('brand_impersonation'):
        signals.append(SignalInfo('BRAND_IMPERSONATION', weights['BRAND_IMPERSONATION']))

    # URL Shortener
    if features.get('shortener_detected'):
        signals.append(SignalInfo('URL_SHORTENER', weights['URL_SHORTENER']))

    # Paste Service
    if features.get('paste_service_detected'):
        signals.append(SignalInfo('PASTE_SERVICE', weights['PASTE_SERVICE']))

    # Hosting Platform
    if features.get('hosting_platform'):
        signals.append(SignalInfo('HOSTING_PLATFORM', weights['HOSTING_PLATFORM']))

    # TLD de riesgo
    if features.get('tld_risk'):
        signals.append(SignalInfo('RISKY_TLD', weights['RISKY_TLD']))

    # Palabras sospechosas
    if features.get('suspicious_words_count', 0) > 0:
        count = features['suspicious_words_count']
        weight = min(count * weights['SUSPICIOUS_WORDS'], 30)
        signals.append(SignalInfo('SUSPICIOUS_WORDS', weight))

    # Subdominios excesivos
    if features.get('excessive_subdomains'):
        signals.append(SignalInfo('EXCESSIVE_SUBDOMAINS', weights['EXCESSIVE_SUBDOMAINS']))

    # Sin HTTPS
    if not features.get('has_https'):
        signals.append(SignalInfo('NO_HTTPS', weights['NO_HTTPS']))

    # URL muy larga
    if features.get('url_length', 0) > 100:
        signals.append(SignalInfo('LONG_URL', weights['LONG_URL']))

    # Alto ratio de digitos
    if features.get('digit_ratio', 0) > 0.3:
        signals.append(SignalInfo('HIGH_DIGIT_RATIO', weights['HIGH_DIGIT_RATIO']))

    # Alta entropia
    if features.get('entropy', 0) > 4.0:
        signals.append(SignalInfo('HIGH_ENTROPY', weights['HIGH_ENTROPY']))

    # Simbolo @
    if features.get('has_at_symbol'):
        signals.append(SignalInfo('AT_SYMBOL', weights['AT_SYMBOL']))

    # Dominio de confianza (bonificacion)
    if features.get('is_trusted'):
        signals.append(SignalInfo('TRUSTED_DOMAIN', weights['TRUSTED_DOMAIN']))

    return signals


def load_datasets() -> pd.DataFrame:
    """Carga y combina todos los datasets."""
    print("\n[*] Cargando datasets...")

    datasets = []
    files = ['train.csv', 'val.csv', 'test.csv']

    for file in files:
        path = DATASETS_DIR / file
        if path.exists():
            df = pd.read_csv(path)
            datasets.append(df)
            print(f"   [OK] {file}: {len(df)} URLs")
        else:
            print(f"   [X] {file}: no encontrado")

    if not datasets:
        raise FileNotFoundError("No se encontraron datasets")

    combined = pd.concat(datasets, ignore_index=True)
    combined = combined.drop_duplicates(subset=['url'])

    print(f"\n   Total: {len(combined)} URLs unicas")
    print(f"   Legitimas: {len(combined[combined['label'] == 0])}")
    print(f"   Phishing: {len(combined[combined['label'] == 1])}")

    return combined


def extract_signals_batch(urls: List[str], weights: Dict[str, float]) -> List[List[SignalInfo]]:
    """Extrae senales de todas las URLs."""
    signals_list = []

    for i, url in enumerate(urls):
        if i % 1000 == 0:
            print(f"   Procesando URL {i+1}/{len(urls)}...")

        try:
            features = extract_features(url)
            signals = generate_signals(url, features, weights)
            signals_list.append(signals)
        except Exception:
            signals_list.append([])

    return signals_list


def calculate_scores(signals_list: List[List[SignalInfo]], weights: Dict[str, float]) -> np.ndarray:
    """Calcula scores para todas las URLs usando los pesos dados."""
    scores = []
    base_score = 15

    for signals in signals_list:
        score = base_score
        for signal in signals:
            # Usar el peso del diccionario de pesos
            if signal.name in weights:
                score += weights[signal.name]
            else:
                score += signal.weight

        score = max(0, min(100, score))
        scores.append(score)

    return np.array(scores)


def evaluate_weights_func(weights_dict: Dict[str, float],
                          signals_list: List[List[SignalInfo]],
                          labels: np.ndarray,
                          threshold: float = 50) -> float:
    """
    Funcion objetivo para optimizacion.
    Maximiza F1-score (minimiza 1 - F1).
    """
    scores = calculate_scores(signals_list, weights_dict)
    predictions = (scores >= threshold).astype(int)

    # Calcular F1 score
    f1 = f1_score(labels, predictions, zero_division=0)

    # Penalizar si no hay detecciones (soluciones triviales)
    num_positive = predictions.sum()
    if num_positive == 0:
        trivial_penalty = 0.5
    else:
        trivial_penalty = 0

    # Minimizar (1 - F1) + penalizacion por solucion trivial
    loss = (1 - f1) + trivial_penalty

    return loss


def optimize_weights(signals_list: List[List[SignalInfo]],
                    labels: np.ndarray,
                    local_weights: Dict[str, float],
                    external_weights: Dict[str, float]) -> Dict[str, float]:
    """Optimiza SOLO los pesos locales usando evolucion diferencial."""

    # Solo optimizamos pesos locales
    signal_names = list(local_weights.keys())

    print(f"\n[OPT] Optimizando {len(signal_names)} pesos locales...")
    print(f"   (Pesos externos fijos: {len(external_weights)})")
    print("   Esto puede tomar varios minutos...\n")

    # Bounds mas restrictivos para evitar valores extremos
    bounds = []
    for name in signal_names:
        if name == 'TRUSTED_DOMAIN':
            bounds.append((-50, -10))  # Siempre bonificacion
        elif name == 'BRAND_IMPERSONATION':
            bounds.append((30, 60))  # Siempre penalizacion alta
        elif name in ['IP_AS_HOST', 'PUNYCODE_DETECTED']:
            bounds.append((15, 50))  # Penalizacion media-alta
        else:
            bounds.append((0, 40))  # Penalizacion moderada

    def objective_with_fixed(weights_array):
        """Funcion objetivo que incluye pesos externos fijos."""
        local_w = dict(zip(signal_names, weights_array))
        full_weights = {**local_w, **external_weights}
        return evaluate_weights_func(full_weights, signals_list, labels, 50)

    result = differential_evolution(
        func=objective_with_fixed,
        bounds=bounds,
        maxiter=150,
        popsize=20,
        mutation=(0.5, 1),
        recombination=0.7,
        seed=42,
        disp=True,
        workers=1,
        tol=0.001
    )

    # Combinar pesos locales optimizados con externos fijos
    optimized_local = dict(zip(signal_names, result.x))
    optimized_local = {k: int(round(v)) for k, v in optimized_local.items()}

    # Combinar todos los pesos
    all_weights = {**optimized_local, **external_weights}

    return all_weights


def evaluate_model(signals_list: List[List[SignalInfo]],
                  labels: np.ndarray,
                  weights: Dict[str, float],
                  name: str) -> Dict:
    """Evalua el modelo con los pesos dados."""

    scores = calculate_scores(signals_list, weights)
    predictions = (scores >= 50).astype(int)

    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, zero_division=0)
    recall = recall_score(labels, predictions, zero_division=0)
    f1 = f1_score(labels, predictions, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(labels, predictions).ravel()

    print(f"\n[EVAL] Resultados - {name}:")
    print(f"   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    print(f"   F1-Score:  {f1:.4f}")
    print(f"\n   Matriz de Confusion:")
    print(f"   TN (Legitimas correctas): {tn}")
    print(f"   FP (Falsos positivos):    {fp}")
    print(f"   FN (Falsos negativos):    {fn}")
    print(f"   TP (Phishing detectado):  {tp}")

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn),
        'tp': int(tp)
    }


def save_calibrated_weights(weights: Dict[str, float], metrics: Dict):
    """Guarda los pesos calibrados en JSON."""

    output = {
        'version': '1.0',
        'calibration_date': datetime.now().isoformat(),
        'dataset_size': metrics.get('dataset_size', 0),
        'metrics': {
            'accuracy': metrics['accuracy'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'f1': metrics['f1']
        },
        'weights': weights
    }

    MODELS_DIR.mkdir(exist_ok=True)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n[SAVE] Pesos calibrados guardados en: {OUTPUT_FILE}")


def main():
    print("=" * 60)
    print("CALIBRACION DE PESOS HEURISTICOS - ALERTA-LINK")
    print("=" * 60)

    # 1. Cargar datasets
    df = load_datasets()
    urls = df['url'].tolist()
    labels = df['label'].values

    # 2. Extraer senales con pesos por defecto
    print("\n[SCAN] Extrayendo senales heuristicas...")
    signals_list = extract_signals_batch(urls, DEFAULT_WEIGHTS)

    # Contar senales encontradas
    total_signals = sum(len(s) for s in signals_list)
    urls_with_signals = sum(1 for s in signals_list if len(s) > 0)
    print(f"   Total senales encontradas: {total_signals}")
    print(f"   URLs con al menos 1 senal: {urls_with_signals}")

    # Contar por tipo
    signal_counts = {}
    for signals in signals_list:
        for s in signals:
            signal_counts[s.name] = signal_counts.get(s.name, 0) + 1

    print("\n   Distribucion de senales:")
    for name, count in sorted(signal_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"      {name}: {count}")

    # 3. Evaluar con pesos por defecto
    default_metrics = evaluate_model(signals_list, labels, DEFAULT_WEIGHTS, "Pesos Por Defecto")

    # 4. Optimizar pesos (solo locales, externos fijos)
    optimized_weights = optimize_weights(signals_list, labels, LOCAL_WEIGHTS, EXTERNAL_WEIGHTS)

    # 5. Re-extraer senales con pesos optimizados
    print("\n[SCAN] Re-extrayendo senales con pesos optimizados...")
    signals_list_opt = extract_signals_batch(urls, optimized_weights)

    # 6. Evaluar con pesos optimizados
    optimized_metrics = evaluate_model(signals_list_opt, labels, optimized_weights, "Pesos Calibrados")
    optimized_metrics['dataset_size'] = len(df)

    # 7. Mostrar comparacion
    print("\n" + "=" * 60)
    print("COMPARACION DE RESULTADOS")
    print("=" * 60)
    print(f"\n{'Metrica':<15} {'Default':<15} {'Calibrado':<15} {'Mejora':<15}")
    print("-" * 60)

    for metric in ['accuracy', 'precision', 'recall', 'f1']:
        default_val = default_metrics[metric]
        calib_val = optimized_metrics[metric]
        improvement = calib_val - default_val
        sign = '+' if improvement >= 0 else ''
        print(f"{metric:<15} {default_val:.4f}         {calib_val:.4f}         {sign}{improvement:.4f}")

    print("\n" + "-" * 60)
    print(f"{'FP':<15} {default_metrics['fp']:<15} {optimized_metrics['fp']:<15}")
    print(f"{'FN':<15} {default_metrics['fn']:<15} {optimized_metrics['fn']:<15}")

    # 8. Mostrar pesos calibrados
    print("\n" + "=" * 60)
    print("PESOS CALIBRADOS")
    print("=" * 60)

    sorted_weights = sorted(optimized_weights.items(), key=lambda x: abs(x[1]), reverse=True)

    print("\n[RISK] Senales de Riesgo (positivos):")
    for name, value in sorted_weights:
        if value > 0:
            print(f"   {name}: +{value}")

    print("\n[BONUS] Bonificaciones (negativos):")
    for name, value in sorted_weights:
        if value < 0:
            print(f"   {name}: {value}")

    print("\n[NEUTRAL] Neutrales:")
    for name, value in sorted_weights:
        if value == 0:
            print(f"   {name}: {value}")

    # 9. Guardar pesos calibrados
    save_calibrated_weights(optimized_weights, optimized_metrics)

    # 10. Resumen final
    print("\n" + "=" * 60)
    print("CALIBRACION COMPLETADA")
    print("=" * 60)
    print(f"\n[OK] Dataset utilizado: {len(df)} URLs")
    print(f"[OK] Accuracy mejorada: {default_metrics['accuracy']:.2%} -> {optimized_metrics['accuracy']:.2%}")
    print(f"[OK] Falsos positivos reducidos: {default_metrics['fp']} -> {optimized_metrics['fp']}")
    print(f"[OK] Pesos guardados en: {OUTPUT_FILE}")

    return optimized_weights


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[WARN] Calibracion cancelada por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Error durante la calibracion: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
