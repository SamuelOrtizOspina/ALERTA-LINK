"""
Extractor de features para URLs - Usado por el predictor
"""

import re
import math
import logging
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


# Palabras sospechosas
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

# URL shorteners (lista ampliada)
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

# Plataformas de hosting donde cualquiera puede subir contenido
# Aunque el dominio sea confiable, el contenido puede ser malicioso
HOSTING_PLATFORMS = [
    'appspot.com',      # Google App Engine
    'github.io',        # GitHub Pages
    'githubusercontent.com',  # GitHub raw content
    'netlify.app',      # Netlify
    'vercel.app',       # Vercel
    'herokuapp.com',    # Heroku
    'firebaseapp.com',  # Firebase
    'web.app',          # Firebase
    'pages.dev',        # Cloudflare Pages
    'workers.dev',      # Cloudflare Workers
    'azurewebsites.net',# Azure
    'cloudfront.net',   # AWS CloudFront
    's3.amazonaws.com', # AWS S3
    'blogspot.com',     # Blogger
    'wordpress.com',    # WordPress
    'wixsite.com',      # Wix
    'weebly.com',       # Weebly
    'squarespace.com',  # Squarespace
    'glitch.me',        # Glitch
    'repl.co',          # Replit
    'surge.sh',         # Surge
    'render.com',       # Render
    'fly.dev',          # Fly.io
    'deno.dev',         # Deno Deploy
]

# TLDs de riesgo
RISKY_TLDS = [
    'xyz', 'top', 'club', 'online', 'site', 'website', 'space', 'tech',
    'info', 'biz', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'ws'
]

# Marcas conocidas que son frecuentemente suplantadas en phishing
KNOWN_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
    'instagram', 'whatsapp', 'twitter', 'linkedin', 'dropbox', 'spotify',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'capitalone',
    'americanexpress', 'visa', 'mastercard', 'ebay', 'walmart', 'target',
    'bestbuy', 'costco', 'homedepot', 'adobe', 'zoom', 'slack', 'github',
    'youtube', 'tiktok', 'reddit', 'twitch', 'discord', 'telegram'
]

# Dominios oficiales de las marcas conocidas (para validar con Tranco)
OFFICIAL_DOMAINS = {
    'paypal': 'paypal.com',
    'amazon': 'amazon.com',
    'apple': 'apple.com',
    'microsoft': 'microsoft.com',
    'google': 'google.com',
    'facebook': 'facebook.com',
    'netflix': 'netflix.com',
    'instagram': 'instagram.com',
    'whatsapp': 'whatsapp.com',
    'twitter': 'twitter.com',
    'linkedin': 'linkedin.com',
    'dropbox': 'dropbox.com',
    'spotify': 'spotify.com',
    'chase': 'chase.com',
    'wellsfargo': 'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com',
    'ebay': 'ebay.com',
    'walmart': 'walmart.com',
    'adobe': 'adobe.com',
    'zoom': 'zoom.us',
    'slack': 'slack.com',
    'github': 'github.com',
    'youtube': 'youtube.com',
    'tiktok': 'tiktok.com',
    'reddit': 'reddit.com',
    'twitch': 'twitch.tv',
    'discord': 'discord.com',
    'telegram': 'telegram.org'
}

# Dominios de confianza conocidos (Top 100 global - fallback cuando Tranco no esta disponible)
# Estos son sitios verificados como legitimos que no deben recibir puntuacion de phishing
TRUSTED_DOMAINS = {
    # Redes sociales y video
    'youtube.com': 1,
    'facebook.com': 2,
    'twitter.com': 3,
    'instagram.com': 4,
    'tiktok.com': 5,
    'linkedin.com': 6,
    'reddit.com': 7,
    'pinterest.com': 8,
    'twitch.tv': 9,
    'discord.com': 10,
    # Buscadores y tecnologia
    'google.com': 11,
    'bing.com': 12,
    'yahoo.com': 13,
    'duckduckgo.com': 14,
    # Comercio
    'amazon.com': 15,
    'ebay.com': 16,
    'walmart.com': 17,
    'aliexpress.com': 18,
    'mercadolibre.com': 19,
    # Servicios
    'microsoft.com': 20,
    'apple.com': 21,
    'netflix.com': 22,
    'spotify.com': 23,
    'paypal.com': 24,
    'dropbox.com': 25,
    'github.com': 26,
    'stackoverflow.com': 27,
    'zoom.us': 28,
    'slack.com': 29,
    # Noticias y medios
    'wikipedia.org': 30,
    'bbc.com': 31,
    'cnn.com': 32,
    'nytimes.com': 33,
    # Comunicacion
    'whatsapp.com': 34,
    'telegram.org': 35,
    'messenger.com': 36,
    # Correo
    'gmail.com': 37,
    'outlook.com': 38,
    'live.com': 39,
    'hotmail.com': 40,
}


def is_trusted_domain(url: str) -> Tuple[bool, int]:
    """
    Verifica si el dominio esta en la lista de sitios de confianza.
    Fallback para cuando Tranco no esta disponible.

    Returns:
        Tuple[bool, int]: (es_confiable, rank_aproximado)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remover www
        if domain.startswith('www.'):
            domain = domain[4:]

        # Verificar dominio exacto
        if domain in TRUSTED_DOMAINS:
            return True, TRUSTED_DOMAINS[domain]

        # Verificar subdominios (ej: m.youtube.com, music.youtube.com)
        for trusted, rank in TRUSTED_DOMAINS.items():
            if domain.endswith('.' + trusted):
                return True, rank

        return False, 0
    except Exception:
        return False, 0


def calculate_entropy(text: str) -> float:
    """Calcula entropia de Shannon."""
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


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extrae features de una URL.

    Returns:
        Dict con todas las features necesarias para el modelo
    """
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

        # URL shortener - verificar que el dominio SEA el shortener, no que lo contenga
        # Ejemplo: "bit.ly" debe detectarse, pero "microsoft.com" no (contiene "t.co")
        features['shortener_detected'] = 1 if any(
            domain == s or domain.endswith('.' + s) for s in SHORTENERS
        ) else 0

        # Servicio de paste (vector de distribucion de malware)
        features['paste_service_detected'] = 1 if any(
            domain == p or domain.endswith('.' + p) for p in PASTE_SERVICES
        ) else 0

        # Palabras sospechosas - pero NO si es el dominio oficial de la marca
        url_lower = url.lower()
        # Extraer dominio base (sin www.)
        domain_base = domain.replace('www.', '').split('.')[0] if domain else ''

        # Contar palabras sospechosas, excluyendo la marca si es su dominio oficial
        suspicious_count = 0
        for word in SUSPICIOUS_WORDS:
            if word in url_lower:
                # Si la palabra es una marca conocida, verificar si es el dominio oficial
                if word in KNOWN_BRANDS:
                    official = OFFICIAL_DOMAINS.get(word, f"{word}.com")
                    # Si el dominio actual ES el oficial, no contar como sospechoso
                    if domain == official or domain == f"www.{official}":
                        continue
                suspicious_count += 1
        features['has_suspicious_words'] = min(suspicious_count, 5)

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

    except Exception:
        # Valores por defecto en caso de error
        for key in ['url_length', 'domain_length', 'path_length', 'num_digits',
                    'num_hyphens', 'num_dots', 'num_subdomains', 'entropy',
                    'has_https', 'has_port', 'has_at_symbol', 'contains_ip',
                    'has_punycode', 'shortener_detected', 'paste_service_detected',
                    'has_suspicious_words', 'tld_risk', 'excessive_subdomains',
                    'digit_ratio', 'num_params', 'special_chars']:
            features[key] = 0

    return features


# Features base sin Tranco (para modelo ML)
BASE_FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'num_digits',
    'num_hyphens', 'num_dots', 'num_subdomains', 'entropy',
    'has_https', 'has_port', 'has_at_symbol', 'contains_ip',
    'has_punycode', 'shortener_detected', 'paste_service_detected',
    'has_suspicious_words', 'tld_risk', 'excessive_subdomains',
    'digit_ratio', 'num_params', 'special_chars',
    'in_tranco', 'tranco_rank', 'brand_impersonation'
]


def extract_features_with_tranco(url: str, tranco_service=None) -> Dict[str, Any]:
    """
    Extrae features de una URL incluyendo verificacion con Tranco API.

    Args:
        url: URL a analizar
        tranco_service: Instancia del servicio de Tranco (opcional)

    Returns:
        Dict con todas las features, incluyendo las de Tranco
    """
    # Primero extraer features basicas
    features = extract_features(url)

    # Inicializar features de Tranco
    features['in_tranco'] = 0
    features['tranco_rank'] = 0
    features['brand_impersonation'] = 0

    if tranco_service is None:
        return features

    try:
        # Verificar si el dominio esta en Tranco
        in_tranco, rank = tranco_service.check_url(url)

        if in_tranco and rank is not None:
            features['in_tranco'] = 1
            # Normalizar rank: 1-1000 = 1.0, 1000-10000 = 0.8, etc.
            features['tranco_rank'] = max(0, 1 - (rank / 1000000))
        else:
            features['in_tranco'] = 0
            features['tranco_rank'] = 0

        # Detectar suplantacion de marca
        # Si la URL menciona una marca conocida pero NO es el dominio oficial
        url_lower = url.lower()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remover www
        if domain.startswith('www.'):
            domain = domain[4:]

        for brand, official_domain in OFFICIAL_DOMAINS.items():
            if brand in url_lower:
                # La URL menciona la marca
                if official_domain not in domain and domain != official_domain:
                    # Pero NO es el dominio oficial - posible suplantacion
                    features['brand_impersonation'] = 1
                    logger.debug(f"Posible suplantacion de {brand}: {domain}")
                    break

    except Exception as e:
        logger.error(f"Error en verificacion Tranco: {e}")

    return features


def get_brand_mentioned(url: str) -> Optional[str]:
    """
    Detecta si la URL menciona alguna marca conocida.

    Returns:
        Nombre de la marca mencionada o None
    """
    url_lower = url.lower()

    for brand in KNOWN_BRANDS:
        if brand in url_lower:
            return brand

    return None


def is_official_domain(url: str, brand: str) -> bool:
    """
    Verifica si la URL corresponde al dominio oficial de una marca.

    Args:
        url: URL a verificar
        brand: Nombre de la marca

    Returns:
        True si es el dominio oficial
    """
    if brand not in OFFICIAL_DOMAINS:
        return False

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if domain.startswith('www.'):
            domain = domain[4:]

        official = OFFICIAL_DOMAINS[brand]

        # Verificar si el dominio termina con el dominio oficial
        # Esto permite subdominios legitimos como mail.google.com
        return domain == official or domain.endswith('.' + official)

    except Exception:
        return False
