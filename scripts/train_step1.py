#!/usr/bin/env python3
"""
train_step1.py - Entrena el modelo baseline LogisticRegression para ALERTA-LINK

Este script:
1. Carga el dataset de entrenamiento
2. Extrae features de las URLs
3. Entrena un modelo LogisticRegression
4. Guarda el modelo y el vectorizador

Uso:
    python scripts/train_step1.py

Salida:
    models/step1_baseline.pkl
"""

import os
import sys
import json
import pickle
import logging
import re
import math
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from collections import Counter

import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

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
DETECTION_CONFIG = PROJECT_ROOT / "detection" / "config"

# Palabras sospechosas para deteccion (sincronizado con feature_extractor.py)
SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'bank',
    'free', 'gift', 'password', 'confirm', 'suspend', 'unusual', 'expire',
    'urgent', 'immediately', 'click', 'validate', 'authenticate', 'credential',
    'paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    # Software pirata/crackeado (vectores de malware)
    'crack', 'keygen', 'serial', 'patch', 'activator', 'loader', 'kms',
    'pirate', 'warez', 'nulled', 'cracked', 'torrent', 'download-free',
    'full-version', 'license-key', 'product-key', 'activation', 'bypass'
]

# URL shorteners conocidos (lista ampliada)
SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'yourls.org', 'rebrand.ly',
    # Agregados para mejor deteccion
    'kutt.it', 'tinyplease.com', 'shorturl.at', 'tiny.cc', 'bc.vc', 'j.mp',
    'v.gd', 'x.co', 'u.to', 'cutt.ly', 'rb.gy', 'clck.ru', 'shorturl.asia',
    'tinu.be', 'hyperurl.co', 'urlz.fr', 'link.zip', 'short.io', 'soo.gd',
    'clickmeter.com', 's.id', 'rotf.lol', 'surl.li', 'shortcm.li'
]

# Servicios de paste (vectores comunes de distribucion de malware)
PASTE_SERVICES = [
    'pastebin.com', 'paste.ee', 'pastecode.io', 'dpaste.org', 'paste.mozilla.org',
    'hastebin.com', 'ghostbin.com', 'paste2.org', 'pastebin.pl', 'paste.rs',
    'rentry.co', 'rentry.org', 'privatebin.net', 'controlc.com', 'justpaste.it'
]

# TLDs de alto riesgo
RISKY_TLDS = [
    'xyz', 'top', 'club', 'online', 'site', 'website', 'space', 'tech',
    'info', 'biz', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'ws'
]

# Dominios legitimos conocidos (simulacion de Tranco para entrenamiento offline)
KNOWN_LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
    'youtube.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com',
    'spotify.com', 'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
    'whatsapp.com', 'paypal.com', 'ebay.com', 'walmart.com', 'target.com',
    'bestbuy.com', 'homedepot.com', 'lowes.com', 'costco.com', 'chase.com',
    'bankofamerica.com', 'wellsfargo.com', 'citi.com', 'usbank.com', 'capitalone.com',
    'discover.com', 'americanexpress.com', 'dropbox.com', 'box.com', 'zoom.us',
    'slack.com', 'notion.so', 'trello.com', 'asana.com', 'nytimes.com',
    'washingtonpost.com', 'bbc.com', 'cnn.com', 'reuters.com', 'bloomberg.com',
    'forbes.com', 'wsj.com', 'economist.com', 'theguardian.com', 'npr.org',
    'pbs.org', 'nasa.gov', 'nih.gov', 'cdc.gov', 'fda.gov', 'irs.gov',
    'harvard.edu', 'stanford.edu', 'mit.edu', 'yale.edu', 'princeton.edu',
    'outlook.com', 'office.com', 'onedrive.com', 'azure.com', 'aws.amazon.com',
    'npmjs.com', 'pypi.org', 'rubygems.org', 'heroku.com', 'vercel.com', 'netlify.com'
]

# Marcas conocidas para detectar suplantacion
KNOWN_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
    'instagram', 'whatsapp', 'twitter', 'linkedin', 'dropbox', 'spotify',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'capitalone',
    'ebay', 'walmart', 'adobe', 'zoom', 'slack', 'github'
]

# Dominios oficiales de las marcas
OFFICIAL_DOMAINS = {
    'paypal': 'paypal.com', 'amazon': 'amazon.com', 'apple': 'apple.com',
    'microsoft': 'microsoft.com', 'google': 'google.com', 'facebook': 'facebook.com',
    'netflix': 'netflix.com', 'instagram': 'instagram.com', 'whatsapp': 'whatsapp.com',
    'twitter': 'twitter.com', 'linkedin': 'linkedin.com', 'dropbox': 'dropbox.com',
    'spotify': 'spotify.com', 'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com', 'ebay': 'ebay.com', 'walmart': 'walmart.com',
    'adobe': 'adobe.com', 'zoom': 'zoom.us', 'slack': 'slack.com', 'github': 'github.com'
}


def calculate_entropy(text: str) -> float:
    """Calcula la entropia de Shannon de un texto."""
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


def extract_features(url: str) -> dict:
    """Extrae features de una URL para el modelo."""
    features = {}

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        # Features lexicas
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_hyphens'] = url.count('-')
        features['num_dots'] = url.count('.')
        features['num_subdomains'] = max(0, domain.count('.') - 1) if domain else 0

        # Entropia
        features['entropy'] = calculate_entropy(url)

        # Features binarias
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_port'] = 1 if ':' in domain.split('.')[-1] else 0
        features['has_at_symbol'] = 1 if '@' in url else 0

        # IP como host
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_without_port = domain.split(':')[0]
        features['contains_ip'] = 1 if re.match(ip_pattern, domain_without_port) else 0

        # Punycode
        features['has_punycode'] = 1 if 'xn--' in domain else 0

        # URL shortener
        features['shortener_detected'] = 1 if any(s in domain for s in SHORTENERS) else 0

        # Servicio de paste (vector de distribucion de malware)
        features['paste_service_detected'] = 1 if any(p in domain for p in PASTE_SERVICES) else 0

        # Palabras sospechosas
        url_lower = url.lower()
        suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)
        features['has_suspicious_words'] = min(suspicious_count, 5)  # Cap at 5

        # TLD de riesgo
        tld = domain.split('.')[-1] if domain else ''
        features['tld_risk'] = 1 if tld in RISKY_TLDS else 0

        # Subdominios excesivos
        features['excessive_subdomains'] = 1 if features['num_subdomains'] > 3 else 0

        # Ratio de digitos
        features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0

        # Query params
        features['num_params'] = len(parse_qs(query)) if query else 0

        # Caracteres especiales
        special_chars = sum(1 for c in url if c in '!#$%&*+=?^_`{|}~')
        features['special_chars'] = special_chars

        # === Features de Tranco (simuladas para entrenamiento offline) ===

        # Verificar si el dominio es legitimo conocido
        domain_clean = domain
        if domain_clean.startswith('www.'):
            domain_clean = domain_clean[4:]

        # in_tranco: 1 si el dominio es conocido como legitimo
        features['in_tranco'] = 1 if any(
            domain_clean == d or domain_clean.endswith('.' + d)
            for d in KNOWN_LEGITIMATE_DOMAINS
        ) else 0

        # tranco_rank: score normalizado (1.0 para sitios muy conocidos)
        features['tranco_rank'] = 0.9 if features['in_tranco'] else 0.0

        # brand_impersonation: detectar si menciona una marca pero no es el dominio oficial
        features['brand_impersonation'] = 0
        url_lower = url.lower()
        for brand, official in OFFICIAL_DOMAINS.items():
            if brand in url_lower:
                # Menciona la marca
                if official not in domain_clean and domain_clean != official:
                    # Pero NO es el dominio oficial
                    features['brand_impersonation'] = 1
                    break

    except Exception as e:
        logger.warning(f"Error extrayendo features de {url}: {e}")
        # Valores por defecto
        for key in ['url_length', 'domain_length', 'path_length', 'num_digits',
                    'num_hyphens', 'num_dots', 'num_subdomains', 'entropy',
                    'has_https', 'has_port', 'has_at_symbol', 'contains_ip',
                    'has_punycode', 'shortener_detected', 'paste_service_detected',
                    'has_suspicious_words', 'tld_risk', 'excessive_subdomains',
                    'digit_ratio', 'num_params', 'special_chars',
                    'in_tranco', 'tranco_rank', 'brand_impersonation']:
            features[key] = 0

    return features


def load_training_data() -> tuple:
    """Carga los datos de entrenamiento."""
    train_path = SPLITS_DIR / "train.csv"

    if not train_path.exists():
        logger.error(f"No se encontro {train_path}")
        logger.error("Ejecuta primero: python scripts/build_dataset.py")
        sys.exit(1)

    logger.info(f"Cargando datos de entrenamiento desde {train_path}")
    df = pd.read_csv(train_path)

    logger.info(f"Filas cargadas: {len(df)}")
    logger.info(f"Distribucion de clases:")
    logger.info(f"  - Legitimas (0): {len(df[df['label'] == 0])}")
    logger.info(f"  - Maliciosas (1): {len(df[df['label'] == 1])}")

    return df


def extract_features_batch(urls: pd.Series) -> pd.DataFrame:
    """Extrae features de un batch de URLs."""
    logger.info(f"Extrayendo features de {len(urls)} URLs...")

    features_list = []
    for i, url in enumerate(urls):
        if i % 10000 == 0:
            logger.info(f"  Procesando {i}/{len(urls)}...")
        features_list.append(extract_features(str(url)))

    return pd.DataFrame(features_list)


def train_model(X: pd.DataFrame, y: pd.Series) -> Pipeline:
    """Entrena el modelo LogisticRegression."""
    logger.info("Entrenando modelo LogisticRegression...")

    # Pipeline con normalizacion + modelo
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=42,
            n_jobs=-1,
            verbose=1
        ))
    ])

    pipeline.fit(X, y)

    # Log de coeficientes
    classifier = pipeline.named_steps['classifier']
    feature_names = X.columns.tolist()
    coefs = classifier.coef_[0]

    logger.info("Top 10 features por importancia:")
    sorted_idx = np.argsort(np.abs(coefs))[::-1]
    for i in sorted_idx[:10]:
        logger.info(f"  {feature_names[i]}: {coefs[i]:.4f}")

    return pipeline


def save_model(pipeline: Pipeline, feature_names: list):
    """Guarda el modelo entrenado."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    model_data = {
        'pipeline': pipeline,
        'feature_names': feature_names,
        'created_at': datetime.now().isoformat(),
        'version': '1.0.0'
    }

    model_path = MODELS_DIR / "step1_baseline.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)

    logger.info(f"Modelo guardado en {model_path}")


def main():
    """Funcion principal."""
    logger.info("="*60)
    logger.info("ENTRENAMIENTO STEP 1 - BASELINE")
    logger.info("="*60)

    # Cargar datos
    train_df = load_training_data()

    # Extraer features
    X = extract_features_batch(train_df['url'])
    y = train_df['label']

    logger.info(f"Shape de features: {X.shape}")
    logger.info(f"Features: {X.columns.tolist()}")

    # Entrenar modelo
    pipeline = train_model(X, y)

    # Guardar modelo
    save_model(pipeline, X.columns.tolist())

    # Calcular accuracy en training (para referencia)
    train_pred = pipeline.predict(X)
    train_accuracy = (train_pred == y).mean()
    logger.info(f"Training accuracy: {train_accuracy:.4f}")

    logger.info("="*60)
    logger.info("ENTRENAMIENTO COMPLETADO")
    logger.info("="*60)
    logger.info("Siguiente paso: python scripts/evaluate_step1.py")


if __name__ == "__main__":
    main()
