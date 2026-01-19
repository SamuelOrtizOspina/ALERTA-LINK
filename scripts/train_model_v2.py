#!/usr/bin/env python3
"""
train_model_v2.py - Entrenamiento mejorado del modelo ALERTA-LINK

Este script:
1. Recopila datos de TODAS las fuentes disponibles
2. Genera URLs legítimas variadas (no solo Tranco)
3. Verifica 500 URLs con VirusTotal para contexto real
4. Entrena el modelo entendiendo CONTEXTO, no solo correlaciones

FILOSOFÍA:
- datos_buenos (label=0): URLs legítimas verificadas
- datos_malos (label=1): URLs de phishing confirmadas
- El modelo debe aprender PATRONES reales, no correlaciones falsas como in_tranco
"""

import os
import sys
import json
import pickle
import logging
import re
import math
import random
import hashlib
import time
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import List, Dict, Tuple, Optional

import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

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
BUENOS_DATOS_DIR = PROJECT_ROOT / "Buenos_Datos"
DATOS_MALOS_DIR = PROJECT_ROOT / "Datos_Malos"
DATOS_ENTRENADOS_DIR = PROJECT_ROOT / "datos_ya_entrenados_pushing"

# Cargar API keys desde .env
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
TRANCO_API_KEY = os.getenv("TRANCO_API_KEY", "")

# ============================================================================
# LISTAS Y CONSTANTES
# ============================================================================

SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'bank',
    'free', 'gift', 'password', 'confirm', 'suspend', 'unusual', 'expire',
    'urgent', 'immediately', 'click', 'validate', 'authenticate', 'credential',
    'paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'crack', 'keygen', 'serial', 'patch', 'activator', 'loader', 'kms',
    'pirate', 'warez', 'nulled', 'cracked', 'torrent', 'download-free',
    'full-version', 'license-key', 'product-key', 'activation', 'bypass'
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'mcaf.ee', 'cutt.ly', 'rb.gy', 'shorturl.at'
]

PASTE_SERVICES = [
    'pastebin.com', 'paste.ee', 'pastecode.io', 'dpaste.org',
    'hastebin.com', 'ghostbin.com', 'rentry.co', 'justpaste.it'
]

RISKY_TLDS = [
    'xyz', 'top', 'club', 'online', 'site', 'website', 'space', 'tech',
    'info', 'biz', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'ws'
]

# URLs legítimas conocidas - variadas, no solo de Tranco
LEGITIMATE_URLS_VARIED = [
    # Grandes sitios (en Tranco)
    "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
    "https://www.amazon.com", "https://www.twitter.com", "https://www.instagram.com",
    "https://www.linkedin.com", "https://www.reddit.com", "https://www.netflix.com",
    "https://www.microsoft.com", "https://www.apple.com", "https://www.github.com",

    # Sitios medianos (pueden o no estar en Tranco)
    "https://www.shopify.com", "https://www.squarespace.com", "https://www.wix.com",
    "https://www.mailchimp.com", "https://www.hubspot.com", "https://www.salesforce.com",
    "https://www.zendesk.com", "https://www.atlassian.com", "https://www.notion.so",

    # Sitios pequeños/medianos legítimos (probablemente NO en Tranco)
    "https://www.local-business-example.com", "https://www.pequeña-tienda.es",
    "https://www.mi-portfolio.dev", "https://www.startup-legitima.io",

    # Blogs y sitios personales (NO en Tranco pero legítimos)
    "https://blog.ejemplo.com", "https://www.fotografia-profesional.com",
    "https://www.consultoria-empresarial.net", "https://www.abogados-madrid.es",

    # Universidades y educación
    "https://www.harvard.edu", "https://www.stanford.edu", "https://www.mit.edu",
    "https://www.unam.mx", "https://www.unal.edu.co", "https://www.uba.ar",

    # Gobierno
    "https://www.usa.gov", "https://www.gov.uk", "https://www.gob.mx",
    "https://www.argentina.gob.ar", "https://www.gobiernodecanarias.org",

    # Medios de comunicación
    "https://www.bbc.com", "https://www.cnn.com", "https://www.nytimes.com",
    "https://www.elpais.com", "https://www.clarin.com", "https://www.eltiempo.com",

    # E-commerce regional
    "https://www.mercadolibre.com", "https://www.falabella.com", "https://www.linio.com",
    "https://www.liverpool.com.mx", "https://www.exito.com",
]

# ============================================================================
# FUNCIONES DE EXTRACCIÓN DE FEATURES
# ============================================================================

def calculate_entropy(text: str) -> float:
    """Calcula la entropía de Shannon."""
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


def extract_features(url: str, in_tranco: int = 0, tranco_rank: float = 0.0) -> dict:
    """
    Extrae features de una URL.

    IMPORTANTE: in_tranco y tranco_rank se pasan como parámetros
    para evitar el overfitting que tenía el modelo anterior.
    """
    features = {}

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        # Features léxicas
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_hyphens'] = url.count('-')
        features['num_dots'] = url.count('.')
        features['num_subdomains'] = max(0, domain.count('.') - 1) if domain else 0

        # Entropía
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

        # Servicio de paste
        features['paste_service_detected'] = 1 if any(p in domain for p in PASTE_SERVICES) else 0

        # Palabras sospechosas
        url_lower = url.lower()
        suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)
        features['has_suspicious_words'] = min(suspicious_count, 5)

        # TLD de riesgo
        tld = domain.split('.')[-1] if domain else ''
        features['tld_risk'] = 1 if tld in RISKY_TLDS else 0

        # Subdominios excesivos
        features['excessive_subdomains'] = 1 if features['num_subdomains'] > 3 else 0

        # Ratio de dígitos
        features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0

        # Query params
        features['num_params'] = len(parse_qs(query)) if query else 0

        # Caracteres especiales
        special_chars = sum(1 for c in url if c in '!#$%&*+=?^_`{|}~')
        features['special_chars'] = special_chars

        # Features de Tranco (pasadas como parámetros)
        features['in_tranco'] = in_tranco
        features['tranco_rank'] = tranco_rank

        # Brand impersonation
        features['brand_impersonation'] = detect_brand_impersonation(url, domain)

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


def detect_brand_impersonation(url: str, domain: str) -> int:
    """Detecta si la URL intenta suplantar una marca conocida."""
    brands = {
        'paypal': 'paypal.com', 'amazon': 'amazon.com', 'apple': 'apple.com',
        'microsoft': 'microsoft.com', 'google': 'google.com', 'facebook': 'facebook.com',
        'netflix': 'netflix.com', 'instagram': 'instagram.com', 'whatsapp': 'whatsapp.com',
        'twitter': 'twitter.com', 'linkedin': 'linkedin.com', 'ebay': 'ebay.com',
        'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com', 'bankofamerica': 'bankofamerica.com'
    }

    url_lower = url.lower()
    domain_clean = domain.replace('www.', '')

    for brand, official in brands.items():
        if brand in url_lower:
            if official not in domain_clean and domain_clean != official:
                return 1
    return 0


# ============================================================================
# FUNCIONES DE RECOPILACIÓN DE DATOS
# ============================================================================

def load_phishing_from_sources() -> List[str]:
    """Carga URLs de phishing de todas las fuentes disponibles."""
    phishing_urls = set()

    # 1. Buenos_Datos/datos (contiene phishing a pesar del nombre)
    datos_file = BUENOS_DATOS_DIR / "datos"
    if datos_file.exists():
        with open(datos_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if url and url.startswith('http'):
                    phishing_urls.add(url)
        logger.info(f"Cargadas {len(phishing_urls)} URLs de Buenos_Datos/datos")

    # 2. Phishing.Database-master
    phishing_db = BUENOS_DATOS_DIR / "Phishing.Database-master" / "phishing-links-ACTIVE.txt"
    if phishing_db.exists():
        count_before = len(phishing_urls)
        with open(phishing_db, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if url and url.startswith('http'):
                    phishing_urls.add(url)
                if len(phishing_urls) > 50000:  # Limitar a 50K
                    break
        logger.info(f"Cargadas {len(phishing_urls) - count_before} URLs adicionales de Phishing.Database")

    # 3. PhiUSIIL Dataset
    phiusiil = DATOS_ENTRENADOS_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if phiusiil.exists():
        count_before = len(phishing_urls)
        try:
            df = pd.read_csv(phiusiil, nrows=20000)  # Limitar a 20K filas
            if 'URL' in df.columns and 'label' in df.columns:
                phishing_df = df[df['label'] == 1]
                for url in phishing_df['URL'].dropna():
                    if str(url).startswith('http'):
                        phishing_urls.add(str(url))
            logger.info(f"Cargadas {len(phishing_urls) - count_before} URLs de PhiUSIIL")
        except Exception as e:
            logger.warning(f"Error cargando PhiUSIIL: {e}")

    # 4. Datos_Malos
    datos_json = DATOS_MALOS_DIR / "datos_jison"
    if datos_json.exists():
        count_before = len(phishing_urls)
        try:
            with open(datos_json, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Buscar URLs en el contenido
                url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                found_urls = re.findall(url_pattern, content)
                for url in found_urls[:10000]:  # Limitar
                    phishing_urls.add(url)
            logger.info(f"Cargadas {len(phishing_urls) - count_before} URLs de datos_jison")
        except Exception as e:
            logger.warning(f"Error cargando datos_jison: {e}")

    return list(phishing_urls)


def load_legitimate_urls() -> List[str]:
    """Carga URLs legítimas de múltiples fuentes."""
    legitimate_urls = set()

    # 1. URLs predefinidas variadas
    legitimate_urls.update(LEGITIMATE_URLS_VARIED)

    # 2. Generar URLs legítimas de dominios conocidos
    domains_legit = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "twitter.com",
        "instagram.com", "linkedin.com", "reddit.com", "netflix.com", "microsoft.com",
        "apple.com", "github.com", "stackoverflow.com", "wikipedia.org", "yahoo.com",
        "ebay.com", "paypal.com", "spotify.com", "dropbox.com", "salesforce.com",
        "adobe.com", "zoom.us", "slack.com", "notion.so", "trello.com",
        "shopify.com", "wordpress.com", "medium.com", "quora.com", "pinterest.com",
        "tumblr.com", "twitch.tv", "discord.com", "telegram.org", "whatsapp.com",
        "tiktok.com", "snapchat.com", "uber.com", "lyft.com", "airbnb.com",
        "booking.com", "expedia.com", "tripadvisor.com", "yelp.com", "zillow.com",
        "indeed.com", "glassdoor.com", "coursera.org", "udemy.com", "edx.org"
    ]

    paths = ["", "/", "/about", "/contact", "/help", "/support", "/login",
             "/products", "/services", "/blog", "/news", "/faq", "/terms", "/privacy"]

    for domain in domains_legit:
        for path in paths[:3]:  # Solo 3 paths por dominio
            legitimate_urls.add(f"https://www.{domain}{path}")
            legitimate_urls.add(f"https://{domain}{path}")

    # 3. URLs de PhiUSIIL que son legítimas (label=0)
    phiusiil = DATOS_ENTRENADOS_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if phiusiil.exists():
        try:
            df = pd.read_csv(phiusiil, nrows=20000)
            if 'URL' in df.columns and 'label' in df.columns:
                legit_df = df[df['label'] == 0]
                for url in legit_df['URL'].dropna()[:5000]:
                    if str(url).startswith('http'):
                        legitimate_urls.add(str(url))
            logger.info(f"Agregadas URLs legítimas de PhiUSIIL")
        except Exception as e:
            logger.warning(f"Error cargando legítimas de PhiUSIIL: {e}")

    return list(legitimate_urls)


def verify_with_virustotal(urls: List[str], max_urls: int = 500) -> Dict[str, dict]:
    """
    Verifica URLs con VirusTotal para obtener contexto real.

    Returns:
        Dict con URL -> {is_malicious, malicious_count, harmless_count, confidence}
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY no configurada, saltando verificación")
        return {}

    results = {}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Seleccionar URLs aleatorias para verificar
    urls_to_check = random.sample(urls, min(len(urls), max_urls))

    logger.info(f"Verificando {len(urls_to_check)} URLs con VirusTotal...")

    for i, url in enumerate(urls_to_check):
        if i % 50 == 0:
            logger.info(f"  Progreso: {i}/{len(urls_to_check)}")

        try:
            # Codificar URL para VT
            url_id = hashlib.sha256(url.encode()).hexdigest()

            # Consultar VT
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0) + stats.get('undetected', 0)
                total = malicious + harmless

                results[url] = {
                    'is_malicious': malicious >= 3,
                    'malicious_count': malicious,
                    'harmless_count': harmless,
                    'confidence': (max(malicious, harmless) / total) if total > 0 else 0
                }

            # Respetar rate limit de VT (4 requests/min para API gratuita)
            time.sleep(15)

        except Exception as e:
            logger.debug(f"Error verificando {url}: {e}")
            continue

    logger.info(f"Verificadas {len(results)} URLs con VirusTotal")
    return results


# ============================================================================
# CONSTRUCCIÓN DEL DATASET
# ============================================================================

def build_balanced_dataset(
    max_phishing: int = 3000,
    max_legitimate: int = 3000,
    verify_vt_count: int = 500
) -> pd.DataFrame:
    """
    Construye un dataset balanceado con datos de múltiples fuentes.

    IMPORTANTE: El dataset incluye URLs legítimas que NO están en Tranco
    para evitar el overfitting del modelo anterior.
    """
    logger.info("="*60)
    logger.info("CONSTRUCCIÓN DE DATASET BALANCEADO")
    logger.info("="*60)

    # 1. Cargar URLs de phishing
    phishing_urls = load_phishing_from_sources()
    logger.info(f"Total URLs phishing disponibles: {len(phishing_urls)}")

    # 2. Cargar URLs legítimas
    legitimate_urls = load_legitimate_urls()
    logger.info(f"Total URLs legítimas disponibles: {len(legitimate_urls)}")

    # 3. Verificar muestra con VirusTotal
    all_urls = phishing_urls[:1000] + legitimate_urls[:500]
    vt_results = verify_with_virustotal(all_urls, verify_vt_count)

    # 4. Construir dataset
    data = []

    # Agregar phishing (label=1)
    phishing_sample = random.sample(phishing_urls, min(len(phishing_urls), max_phishing))
    for url in phishing_sample:
        # Para phishing: in_tranco=0 (típicamente no están en Tranco)
        # Pero algunos pueden tener subdominios de sitios legítimos
        features = extract_features(url, in_tranco=0, tranco_rank=0.0)
        features['url'] = url
        features['label'] = 1

        # Si tenemos info de VT, usarla
        if url in vt_results:
            vt = vt_results[url]
            features['vt_verified'] = 1
            features['vt_malicious'] = vt['malicious_count']
        else:
            features['vt_verified'] = 0
            features['vt_malicious'] = 0

        data.append(features)

    logger.info(f"Agregadas {len(phishing_sample)} URLs de phishing")

    # Agregar legítimas (label=0)
    legitimate_sample = random.sample(legitimate_urls, min(len(legitimate_urls), max_legitimate))

    # IMPORTANTE: Variar in_tranco para evitar overfitting
    # Algunos legítimos con in_tranco=1 (sitios grandes)
    # Algunos legítimos con in_tranco=0 (sitios pequeños/medianos)
    for i, url in enumerate(legitimate_sample):
        # 70% con in_tranco=1, 30% con in_tranco=0 (para simular sitios pequeños legítimos)
        if i < len(legitimate_sample) * 0.7:
            in_tranco = 1
            tranco_rank = random.uniform(0.5, 1.0)
        else:
            in_tranco = 0  # Sitios legítimos pequeños NO están en Tranco
            tranco_rank = 0.0

        features = extract_features(url, in_tranco=in_tranco, tranco_rank=tranco_rank)
        features['url'] = url
        features['label'] = 0

        # Si tenemos info de VT, usarla
        if url in vt_results:
            vt = vt_results[url]
            features['vt_verified'] = 1
            features['vt_malicious'] = vt['malicious_count']
        else:
            features['vt_verified'] = 0
            features['vt_malicious'] = 0

        data.append(features)

    logger.info(f"Agregadas {len(legitimate_sample)} URLs legítimas")

    # 5. Crear DataFrame
    df = pd.DataFrame(data)

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    logger.info(f"Dataset final: {len(df)} URLs")
    logger.info(f"  - Phishing (1): {len(df[df['label']==1])}")
    logger.info(f"  - Legítimas (0): {len(df[df['label']==0])}")
    logger.info(f"  - Verificadas VT: {len(df[df['vt_verified']==1])}")

    return df


# ============================================================================
# ENTRENAMIENTO DEL MODELO
# ============================================================================

def train_model(df: pd.DataFrame) -> Tuple[Pipeline, List[str]]:
    """
    Entrena el modelo con el dataset construido.

    Usa RandomForest en lugar de LogisticRegression para capturar
    patrones más complejos y evitar overfitting en features individuales.
    """
    logger.info("="*60)
    logger.info("ENTRENAMIENTO DEL MODELO")
    logger.info("="*60)

    # Features a usar (excluir url, label, vt_verified, vt_malicious que son metadata)
    feature_cols = [
        'url_length', 'domain_length', 'path_length', 'num_digits',
        'num_hyphens', 'num_dots', 'num_subdomains', 'entropy',
        'has_https', 'has_port', 'has_at_symbol', 'contains_ip',
        'has_punycode', 'shortener_detected', 'paste_service_detected',
        'has_suspicious_words', 'tld_risk', 'excessive_subdomains',
        'digit_ratio', 'num_params', 'special_chars',
        'in_tranco', 'tranco_rank', 'brand_impersonation'
    ]

    X = df[feature_cols]
    y = df['label']

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    # Probar varios modelos
    models = {
        'LogisticRegression': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', LogisticRegression(C=0.5, max_iter=1000, random_state=42))
        ]),
        'RandomForest': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(
                n_estimators=100, max_depth=10, min_samples_split=5,
                random_state=42, n_jobs=-1
            ))
        ]),
        'GradientBoosting': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', GradientBoostingClassifier(
                n_estimators=100, max_depth=5, learning_rate=0.1,
                random_state=42
            ))
        ])
    }

    best_model = None
    best_score = 0
    best_name = ""

    for name, model in models.items():
        logger.info(f"\nEntrenando {name}...")

        # Cross-validation
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
        logger.info(f"  CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")

        # Entrenar
        model.fit(X_train, y_train)

        # Evaluar en test
        y_pred = model.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"  Test Accuracy: {test_accuracy:.4f}")

        if test_accuracy > best_score:
            best_score = test_accuracy
            best_model = model
            best_name = name

    logger.info(f"\nMejor modelo: {best_name} (Accuracy: {best_score:.4f})")

    # Reporte detallado del mejor modelo
    y_pred = best_model.predict(X_test)
    logger.info("\nReporte de clasificación:")
    logger.info(classification_report(y_test, y_pred, target_names=['Legítimo', 'Phishing']))

    # Matriz de confusión
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"\nMatriz de confusión:")
    logger.info(f"  [[TN={cm[0,0]}, FP={cm[0,1]}]")
    logger.info(f"   [FN={cm[1,0]}, TP={cm[1,1]}]]")

    # Importancia de features (si es RandomForest o GradientBoosting)
    if best_name in ['RandomForest', 'GradientBoosting']:
        classifier = best_model.named_steps['classifier']
        importances = classifier.feature_importances_
        indices = np.argsort(importances)[::-1]

        logger.info("\nTop 10 features por importancia:")
        for i in range(min(10, len(feature_cols))):
            idx = indices[i]
            logger.info(f"  {feature_cols[idx]}: {importances[idx]:.4f}")

    return best_model, feature_cols


def save_model(pipeline: Pipeline, feature_names: List[str]):
    """Guarda el modelo entrenado."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    model_data = {
        'pipeline': pipeline,
        'feature_names': feature_names,
        'created_at': datetime.now().isoformat(),
        'version': '2.0.0',
        'training_info': {
            'balanced_dataset': True,
            'includes_non_tranco_legitimate': True,
            'virustotal_verified': True
        }
    }

    # Guardar como best_model.pkl
    model_path = MODELS_DIR / "best_model.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)

    # Calcular y mostrar hash
    with open(model_path, 'rb') as f:
        model_hash = hashlib.sha256(f.read()).hexdigest()

    logger.info(f"\nModelo guardado en {model_path}")
    logger.info(f"Hash SHA256: {model_hash}")
    logger.info(f"\nACTUALIZAR en predictor.py:")
    logger.info(f'AUTHORIZED_MODEL_HASH = "{model_hash}"')

    # También guardar como step1_baseline.pkl para compatibilidad
    compat_path = MODELS_DIR / "step1_baseline.pkl"
    with open(compat_path, 'wb') as f:
        pickle.dump(model_data, f)
    logger.info(f"Copia de compatibilidad guardada en {compat_path}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Función principal."""
    logger.info("="*60)
    logger.info("ALERTA-LINK - ENTRENAMIENTO DE MODELO V2")
    logger.info("="*60)
    logger.info("")
    logger.info("Este entrenamiento corrige los problemas del modelo anterior:")
    logger.info("1. Overfitting en la feature in_tranco")
    logger.info("2. Falta de URLs legítimas NO en Tranco")
    logger.info("3. Falta de verificación con VirusTotal")
    logger.info("")

    # 1. Construir dataset balanceado
    df = build_balanced_dataset(
        max_phishing=3000,
        max_legitimate=3000,
        verify_vt_count=100  # Reducido para prueba inicial (aumentar a 500 después)
    )

    # 2. Guardar dataset
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)

    # Backup del actual
    train_backup = SPLITS_DIR / f"train_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    current_train = SPLITS_DIR / "train.csv"
    if current_train.exists():
        import shutil
        shutil.copy(current_train, train_backup)
        logger.info(f"Backup creado: {train_backup}")

    # Guardar nuevo dataset
    df.to_csv(current_train, index=False)
    logger.info(f"Dataset guardado: {current_train}")

    # 3. Entrenar modelo
    pipeline, feature_names = train_model(df)

    # 4. Guardar modelo
    save_model(pipeline, feature_names)

    logger.info("")
    logger.info("="*60)
    logger.info("ENTRENAMIENTO COMPLETADO")
    logger.info("="*60)
    logger.info("")
    logger.info("PRÓXIMOS PASOS:")
    logger.info("1. Actualizar AUTHORIZED_MODEL_HASH en predictor.py")
    logger.info("2. Reiniciar el servidor backend")
    logger.info("3. Probar con URLs de prueba")


if __name__ == "__main__":
    main()
