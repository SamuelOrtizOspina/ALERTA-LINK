#!/usr/bin/env python3
"""
build_training_dataset.py - Construye dataset de entrenamiento robusto

Combina:
- URLs legitimas de sitios conocidos
- URLs de phishing reales de Phishing.Database
"""

import os
import random
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
PHISHING_DATA = PROJECT_ROOT / "Buenos_Datos" / "Phishing.Database-master"
OUTPUT_FILE = PROJECT_ROOT / "datasets" / "splits" / "train.csv"

# URLs legitimas conocidas (expandidas)
LEGITIMATE_URLS = [
    # Buscadores
    "https://www.google.com", "https://www.google.com/search?q=test",
    "https://www.bing.com", "https://www.bing.com/search?q=test",
    "https://duckduckgo.com", "https://www.yahoo.com",

    # Redes sociales
    "https://www.facebook.com", "https://www.facebook.com/login",
    "https://www.instagram.com", "https://www.instagram.com/accounts/login",
    "https://twitter.com", "https://twitter.com/login",
    "https://www.linkedin.com", "https://www.linkedin.com/login",
    "https://www.reddit.com", "https://www.tiktok.com",
    "https://www.pinterest.com", "https://www.snapchat.com",

    # Streaming
    "https://www.netflix.com", "https://www.netflix.com/login",
    "https://www.spotify.com", "https://accounts.spotify.com/login",
    "https://www.youtube.com", "https://www.twitch.tv",
    "https://www.hulu.com", "https://www.disneyplus.com",
    "https://www.hbomax.com", "https://www.primevideo.com",

    # E-commerce
    "https://www.amazon.com", "https://www.amazon.com/ap/signin",
    "https://www.ebay.com", "https://signin.ebay.com",
    "https://www.walmart.com", "https://www.target.com",
    "https://www.bestbuy.com", "https://www.costco.com",
    "https://www.etsy.com", "https://www.aliexpress.com",

    # Finanzas
    "https://www.paypal.com", "https://www.paypal.com/signin",
    "https://www.chase.com", "https://secure.chase.com",
    "https://www.bankofamerica.com", "https://www.wellsfargo.com",
    "https://www.citi.com", "https://www.capitalone.com",
    "https://www.americanexpress.com", "https://www.discover.com",
    "https://www.usbank.com", "https://www.pnc.com",
    "https://www.venmo.com", "https://cash.app",

    # Tecnologia
    "https://www.microsoft.com", "https://login.microsoftonline.com",
    "https://www.apple.com", "https://appleid.apple.com",
    "https://www.google.com/accounts", "https://accounts.google.com",
    "https://www.github.com", "https://github.com/login",
    "https://www.gitlab.com", "https://bitbucket.org",
    "https://www.dropbox.com", "https://www.box.com",
    "https://www.zoom.us", "https://zoom.us/signin",
    "https://slack.com", "https://app.slack.com",

    # Correo
    "https://mail.google.com", "https://outlook.live.com",
    "https://mail.yahoo.com", "https://www.protonmail.com",
    "https://www.icloud.com/mail",

    # Noticias
    "https://www.nytimes.com", "https://www.washingtonpost.com",
    "https://www.bbc.com", "https://www.cnn.com",
    "https://www.reuters.com", "https://www.bloomberg.com",
    "https://www.theguardian.com", "https://www.forbes.com",

    # Gobierno/Educacion
    "https://www.usa.gov", "https://www.irs.gov",
    "https://www.ssa.gov", "https://www.cdc.gov",
    "https://www.harvard.edu", "https://www.stanford.edu",
    "https://www.mit.edu", "https://www.berkeley.edu",

    # Servicios
    "https://www.uber.com", "https://www.lyft.com",
    "https://www.airbnb.com", "https://www.booking.com",
    "https://www.expedia.com", "https://www.tripadvisor.com",
    "https://www.doordash.com", "https://www.grubhub.com",

    # Desarrollo
    "https://stackoverflow.com", "https://www.npmjs.com",
    "https://pypi.org", "https://docs.python.org",
    "https://developer.mozilla.org", "https://www.w3schools.com",
    "https://www.heroku.com", "https://vercel.com",
    "https://www.netlify.com", "https://aws.amazon.com",
    "https://cloud.google.com", "https://azure.microsoft.com",
]


def load_phishing_urls(max_urls: int = 5000) -> list:
    """Carga URLs de phishing reales."""
    phishing_urls = []

    # Archivos de phishing
    phishing_files = [
        PHISHING_DATA / "phishing-links-ACTIVE.txt",
        PHISHING_DATA / "phishing-domains-ACTIVE.txt",
    ]

    for filepath in phishing_files:
        if filepath.exists():
            logger.info(f"Cargando {filepath.name}...")
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    url = line.strip()
                    if url and len(url) > 10:
                        # Asegurar que tenga protocolo
                        if not url.startswith(('http://', 'https://', 'ftp://')):
                            url = 'http://' + url
                        phishing_urls.append(url)

                        if len(phishing_urls) >= max_urls * 2:
                            break

            if len(phishing_urls) >= max_urls * 2:
                break

    # Mezclar y seleccionar
    random.shuffle(phishing_urls)
    selected = phishing_urls[:max_urls]

    logger.info(f"URLs de phishing seleccionadas: {len(selected)}")
    return selected


def build_dataset():
    """Construye el dataset de entrenamiento."""
    logger.info("="*60)
    logger.info("CONSTRUCCION DE DATASET DE ENTRENAMIENTO")
    logger.info("="*60)

    # URLs legitimas
    legitimate = LEGITIMATE_URLS.copy()
    logger.info(f"URLs legitimas base: {len(legitimate)}")

    # Agregar variaciones de URLs legitimas
    variations = []
    for url in legitimate[:50]:
        # Variaciones con paths comunes
        if 'login' not in url:
            variations.append(url + "/login")
        if 'account' not in url:
            variations.append(url + "/account")
        variations.append(url + "/help")
        variations.append(url + "/about")

    legitimate.extend(variations)
    logger.info(f"URLs legitimas con variaciones: {len(legitimate)}")

    # URLs de phishing reales
    num_phishing = len(legitimate)  # Balancear clases
    phishing = load_phishing_urls(max_urls=num_phishing)

    # Construir dataset
    logger.info("Construyendo dataset final...")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("url,label\n")

        # Escribir legitimas (label=0)
        for url in legitimate:
            # Escapar comas en URLs
            url_clean = url.replace('"', '""')
            f.write(f'"{url_clean}",0\n')

        # Escribir phishing (label=1)
        for url in phishing:
            url_clean = url.replace('"', '""')
            f.write(f'"{url_clean}",1\n')

    total = len(legitimate) + len(phishing)
    logger.info(f"Dataset guardado en {OUTPUT_FILE}")
    logger.info(f"Total URLs: {total}")
    logger.info(f"  - Legitimas: {len(legitimate)} ({len(legitimate)/total*100:.1f}%)")
    logger.info(f"  - Phishing: {len(phishing)} ({len(phishing)/total*100:.1f}%)")

    return total


if __name__ == "__main__":
    build_dataset()
