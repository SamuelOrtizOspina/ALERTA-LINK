#!/usr/bin/env python3
"""
Construye un dataset grande de entrenamiento con verificacion de VirusTotal

Este script:
1. Recopila URLs de phishing de la base de datos local
2. Verifica una muestra con VirusTotal para confirmar
3. Recopila URLs legitimas de fuentes conocidas
4. Genera un dataset balanceado para entrenamiento
"""

import sys
import random
import time
import csv
from pathlib import Path
from datetime import datetime

# Agregar backend al path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.services.feature_extractor import extract_features
from app.services.virustotal_service import virustotal_service

# Rutas
PROJECT_ROOT = Path(__file__).parent.parent
PHISHING_DB = PROJECT_ROOT / "Buenos_Datos" / "Phishing.Database-master"
OUTPUT_DIR = PROJECT_ROOT / "datasets" / "splits"


def load_phishing_urls(limit: int = 2000) -> list:
    """Carga URLs de phishing de la base de datos local."""
    urls = []

    # Cargar de phishing-links-ACTIVE.txt
    links_file = PHISHING_DB / "phishing-links-ACTIVE.txt"
    if links_file.exists():
        print(f"Cargando URLs de {links_file.name}...")
        with open(links_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if url and url.startswith('http'):
                    urls.append(url)
                if len(urls) >= limit * 3:  # Cargar extra para filtrar
                    break

    # Mezclar y tomar muestra
    random.shuffle(urls)

    # Filtrar URLs validas y diversas
    filtered = []
    seen_domains = set()

    for url in urls:
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.lower()
            # Evitar muchas URLs del mismo dominio
            if domain not in seen_domains:
                filtered.append(url)
                seen_domains.add(domain)
            if len(filtered) >= limit:
                break
        except:
            continue

    print(f"URLs de phishing cargadas: {len(filtered)}")
    return filtered


def load_legitimate_urls(limit: int = 2000) -> list:
    """Genera URLs legitimas de sitios conocidos."""

    # Dominios legitimos populares (Tranco Top 100)
    top_domains = [
        "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
        "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
        "github.com", "stackoverflow.com", "wikipedia.org", "reddit.com", "twitch.tv",
        "spotify.com", "dropbox.com", "salesforce.com", "adobe.com", "zoom.us",
        "slack.com", "notion.so", "figma.com", "canva.com", "shopify.com",
        "wordpress.com", "blogger.com", "medium.com", "tumblr.com", "pinterest.com",
        "whatsapp.com", "telegram.org", "discord.com", "skype.com", "teams.microsoft.com",
        "gmail.com", "outlook.com", "yahoo.com", "protonmail.com", "icloud.com",
        "paypal.com", "stripe.com", "square.com", "venmo.com", "wise.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "usbank.com",
        "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "bloomberg.com",
        "espn.com", "nba.com", "nfl.com", "mlb.com", "fifa.com",
        "imdb.com", "rottentomatoes.com", "metacritic.com", "gamespot.com", "ign.com",
        "ebay.com", "etsy.com", "aliexpress.com", "walmart.com", "target.com",
        "bestbuy.com", "homedepot.com", "lowes.com", "costco.com", "ikea.com",
        "airbnb.com", "booking.com", "expedia.com", "tripadvisor.com", "kayak.com",
        "uber.com", "lyft.com", "doordash.com", "grubhub.com", "instacart.com",
        "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "duolingo.com",
        "trello.com", "asana.com", "monday.com", "jira.atlassian.com", "basecamp.com",
        "aws.amazon.com", "cloud.google.com", "azure.microsoft.com", "heroku.com", "digitalocean.com",
        "cloudflare.com", "godaddy.com", "namecheap.com", "squarespace.com", "wix.com"
    ]

    # Paths comunes
    paths = [
        "", "/", "/login", "/signup", "/about", "/contact", "/help", "/support",
        "/products", "/services", "/pricing", "/blog", "/news", "/careers",
        "/terms", "/privacy", "/faq", "/docs", "/api", "/download"
    ]

    urls = []
    for domain in top_domains:
        for path in random.sample(paths, min(5, len(paths))):
            url = f"https://www.{domain}{path}"
            urls.append(url)
            if len(urls) >= limit:
                break
        if len(urls) >= limit:
            break

    # Agregar variaciones
    while len(urls) < limit:
        domain = random.choice(top_domains)
        path = random.choice(paths)
        url = f"https://{domain}{path}"
        if url not in urls:
            urls.append(url)

    random.shuffle(urls)
    print(f"URLs legitimas generadas: {len(urls[:limit])}")
    return urls[:limit]


def verify_sample_with_virustotal(urls: list, sample_size: int = 20) -> dict:
    """
    Verifica una muestra de URLs con VirusTotal.
    Retorna estadisticas de verificacion.
    """
    if not virustotal_service.enabled:
        print("VirusTotal no disponible, saltando verificacion")
        return {"verified": 0, "confirmed": 0, "false_positives": 0}

    print(f"\nVerificando {sample_size} URLs con VirusTotal...")
    print("(Esto puede tomar varios minutos por los rate limits)")

    sample = random.sample(urls, min(sample_size, len(urls)))
    stats = {"verified": 0, "confirmed": 0, "false_positives": 0, "errors": 0}

    for i, url in enumerate(sample):
        print(f"  [{i+1}/{sample_size}] Verificando: {url[:50]}...")

        try:
            result = virustotal_service.check_url(url, wait_for_analysis=False)

            if result.analyzed:
                stats["verified"] += 1
                if result.is_malicious or result.malicious_count > 0:
                    stats["confirmed"] += 1
                    print(f"    -> CONFIRMADO malicioso ({result.malicious_count} motores)")
                else:
                    stats["false_positives"] += 1
                    print(f"    -> Posible falso positivo (0 detecciones)")
            else:
                stats["errors"] += 1
                print(f"    -> No se pudo verificar")

        except Exception as e:
            stats["errors"] += 1
            print(f"    -> Error: {e}")

        # Rate limit: esperar entre requests
        time.sleep(16)

    return stats


def extract_all_features(urls: list, label: int) -> list:
    """Extrae features de todas las URLs."""
    data = []
    total = len(urls)

    for i, url in enumerate(urls):
        if (i + 1) % 100 == 0:
            print(f"  Procesando {i+1}/{total}...")

        try:
            features = extract_features(url)
            features['url'] = url
            features['label'] = label
            # Agregar features de Tranco con valores por defecto
            features['in_tranco'] = 1 if label == 0 else 0
            features['tranco_rank'] = 0.8 if label == 0 else 0
            features['brand_impersonation'] = 0
            data.append(features)
        except Exception as e:
            print(f"  Error procesando {url}: {e}")
            continue

    return data


def save_dataset(data: list, output_path: Path):
    """Guarda el dataset en formato CSV."""
    if not data:
        print("No hay datos para guardar")
        return

    # Obtener todas las columnas
    fieldnames = list(data[0].keys())

    # Asegurar que 'url' y 'label' estan al principio
    for col in ['label', 'url']:
        if col in fieldnames:
            fieldnames.remove(col)
            fieldnames.insert(0, col)

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    print(f"Dataset guardado en: {output_path}")
    print(f"Total de registros: {len(data)}")


def main():
    print("=" * 80)
    print("CONSTRUCCION DE DATASET GRANDE CON VERIFICACION VIRUSTOTAL")
    print("=" * 80)
    print(f"Fecha: {datetime.now().isoformat()}")

    # Configuracion
    PHISHING_COUNT = 2000
    LEGITIMATE_COUNT = 2000
    VT_SAMPLE_SIZE = 15  # Verificar 15 URLs con VT (por rate limit)

    # 1. Cargar URLs de phishing
    print("\n[1/5] Cargando URLs de phishing...")
    phishing_urls = load_phishing_urls(PHISHING_COUNT)

    # 2. Verificar muestra con VirusTotal
    print("\n[2/5] Verificando muestra con VirusTotal...")
    vt_stats = verify_sample_with_virustotal(phishing_urls, VT_SAMPLE_SIZE)

    print(f"\nEstadisticas de verificacion VirusTotal:")
    print(f"  - Verificadas: {vt_stats['verified']}")
    print(f"  - Confirmadas maliciosas: {vt_stats['confirmed']}")
    print(f"  - Posibles falsos positivos: {vt_stats['false_positives']}")

    if vt_stats['verified'] > 0:
        accuracy = vt_stats['confirmed'] / vt_stats['verified'] * 100
        print(f"  - Precision estimada: {accuracy:.1f}%")

    # 3. Cargar URLs legitimas
    print("\n[3/5] Generando URLs legitimas...")
    legitimate_urls = load_legitimate_urls(LEGITIMATE_COUNT)

    # 4. Extraer features
    print("\n[4/5] Extrayendo features...")
    print("  Procesando URLs de phishing...")
    phishing_data = extract_all_features(phishing_urls, label=1)

    print("  Procesando URLs legitimas...")
    legitimate_data = extract_all_features(legitimate_urls, label=0)

    # 5. Combinar y guardar
    print("\n[5/5] Guardando dataset...")
    all_data = phishing_data + legitimate_data
    random.shuffle(all_data)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / "train.csv"

    # Backup del dataset anterior
    if output_path.exists():
        backup_path = OUTPUT_DIR / f"train_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        output_path.rename(backup_path)
        print(f"Backup creado: {backup_path.name}")

    save_dataset(all_data, output_path)

    # Resumen
    print("\n" + "=" * 80)
    print("RESUMEN")
    print("=" * 80)
    print(f"URLs de phishing: {len(phishing_data)}")
    print(f"URLs legitimas: {len(legitimate_data)}")
    print(f"Total: {len(all_data)}")
    print(f"Dataset guardado en: {output_path}")

    if vt_stats['verified'] > 0:
        print(f"\nVerificacion VirusTotal: {vt_stats['confirmed']}/{vt_stats['verified']} confirmadas")

    print("\nSiguiente paso: ejecutar scripts/train_step1.py para reentrenar el modelo")


if __name__ == '__main__':
    main()
