#!/usr/bin/env python3
"""
Test de integracion completa con Tranco API
"""

import pickle
import pandas as pd
import requests
import time
import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
from functools import lru_cache

# ========== CONFIGURACION ==========
# Obtener API key de variable de entorno
import os
TRANCO_API_KEY = os.environ.get('TRANCO_API_KEY', 'tu-api-key-aqui')
TRANCO_BASE_URL = 'https://tranco-list.eu/api'

# Listas actualizadas
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
    'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'yourls.org', 'rebrand.ly',
    'kutt.it', 'tinyplease.com', 'shorturl.at', 'tiny.cc', 'bc.vc', 'j.mp',
    'v.gd', 'x.co', 'u.to', 'cutt.ly', 'rb.gy', 'clck.ru', 'shorturl.asia'
]

PASTE_SERVICES = [
    'pastebin.com', 'paste.ee', 'pastecode.io', 'dpaste.org', 'hastebin.com',
    'ghostbin.com', 'rentry.co', 'rentry.org', 'privatebin.net', 'justpaste.it'
]

RISKY_TLDS = [
    'xyz', 'top', 'club', 'online', 'site', 'website', 'space', 'tech',
    'info', 'biz', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'ws'
]

OFFICIAL_DOMAINS = {
    'paypal': 'paypal.com', 'amazon': 'amazon.com', 'apple': 'apple.com',
    'microsoft': 'microsoft.com', 'google': 'google.com', 'facebook': 'facebook.com',
    'netflix': 'netflix.com', 'instagram': 'instagram.com'
}


# ========== FUNCIONES ==========
def calculate_entropy(text):
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in counter.values() if c > 0)


@lru_cache(maxsize=100)
def get_tranco_rank(domain):
    try:
        time.sleep(1.1)  # Rate limit
        r = requests.get(f'{TRANCO_BASE_URL}/ranks/domain/{domain}', timeout=10)
        if r.status_code == 200:
            ranks = r.json().get('ranks', [])
            if ranks:
                return ranks[0].get('rank')
    except Exception as e:
        print(f"    [Tranco Error: {e}]")
    return None


def extract_features_full(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # Features basicas
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_hyphens'] = url.count('-')
    features['num_dots'] = url.count('.')
    features['num_subdomains'] = max(0, domain.count('.') - 1)
    features['entropy'] = calculate_entropy(url)
    features['has_https'] = 1 if parsed.scheme == 'https' else 0
    features['has_port'] = 1 if ':' in domain.split('.')[-1] else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['contains_ip'] = 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain.split(':')[0]) else 0
    features['has_punycode'] = 1 if 'xn--' in domain else 0
    features['shortener_detected'] = 1 if any(s in domain for s in SHORTENERS) else 0
    features['paste_service_detected'] = 1 if any(p in domain for p in PASTE_SERVICES) else 0

    url_lower = url.lower()
    features['has_suspicious_words'] = min(sum(1 for w in SUSPICIOUS_WORDS if w in url_lower), 5)

    tld = domain.split('.')[-1] if domain else ''
    features['tld_risk'] = 1 if tld in RISKY_TLDS else 0
    features['excessive_subdomains'] = 1 if features['num_subdomains'] > 3 else 0
    features['digit_ratio'] = features['num_digits'] / len(url) if url else 0
    features['num_params'] = len(parse_qs(query)) if query else 0
    features['special_chars'] = sum(1 for c in url if c in '!#$%&*+=?^_`{|}~')

    # Features de Tranco (ONLINE)
    domain_clean = domain[4:] if domain.startswith('www.') else domain
    rank = get_tranco_rank(domain_clean)

    if rank:
        features['in_tranco'] = 1
        features['tranco_rank'] = max(0, 1 - (rank / 1000000))
    else:
        # Intentar dominio padre
        parts = domain_clean.split('.')
        if len(parts) > 2:
            parent = '.'.join(parts[-2:])
            rank = get_tranco_rank(parent)
            if rank:
                features['in_tranco'] = 1
                features['tranco_rank'] = max(0, 1 - (rank / 1000000))
            else:
                features['in_tranco'] = 0
                features['tranco_rank'] = 0
        else:
            features['in_tranco'] = 0
            features['tranco_rank'] = 0

    # Suplantacion de marca
    features['brand_impersonation'] = 0
    for brand, official in OFFICIAL_DOMAINS.items():
        if brand in url_lower:
            if official not in domain_clean and domain_clean != official:
                features['brand_impersonation'] = 1
                break

    return features


def main():
    # Cargar modelo
    with open('models/step1_baseline.pkl', 'rb') as f:
        model_data = pickle.load(f)
    pipeline = model_data['pipeline']
    feature_names = model_data['feature_names']

    # URLs de prueba
    test_urls = [
        ('https://www.google.com', 'Legitimo - Google'),
        ('https://www.paypal.com/login', 'Legitimo - PayPal'),
        ('https://pastebin.com/cpdmr6HZ', 'Sospechoso - Pastebin'),
        ('https://secure-paypal-verify.xyz/login', 'Phishing - Suplanta PayPal'),
        ('https://kutt.it/kms-activator', 'Phishing - Shortener + KMS'),
        ('https://amazon-gift-free.top/claim', 'Phishing - Suplanta Amazon'),
    ]

    print('=' * 70)
    print('PRUEBA COMPLETA DEL SISTEMA CON TRANCO API')
    print('=' * 70)

    for url, descripcion in test_urls:
        print(f'\nURL: {url}')
        print(f'Esperado: {descripcion}')

        features = extract_features_full(url)
        X = pd.DataFrame([features])[feature_names]
        prob = pipeline.predict_proba(X)[0, 1]
        score = int(prob * 100)

        if score <= 30:
            risk = 'BAJO'
        elif score <= 70:
            risk = 'MEDIO'
        else:
            risk = 'ALTO'

        print(f'  Score: {score}/100 - Riesgo: {risk}')
        print(f'  in_tranco: {features["in_tranco"]} | tranco_rank: {features["tranco_rank"]:.3f}')
        print(f'  brand_impersonation: {features["brand_impersonation"]} | paste_service: {features["paste_service_detected"]}')
        print(f'  shortener: {features["shortener_detected"]} | tld_risk: {features["tld_risk"]}')

    print('\n' + '=' * 70)
    print('PRUEBA COMPLETADA')
    print('=' * 70)


if __name__ == '__main__':
    main()
