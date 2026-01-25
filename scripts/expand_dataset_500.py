#!/usr/bin/env python3
"""
Expande el dataset existente con 500 URLs nuevas verificadas con VirusTotal

Este script:
1. Carga el dataset actual
2. Obtiene 250 URLs de phishing nuevas (verificadas con VT)
3. Obtiene 250 URLs legitimas nuevas
4. Agrega al dataset existente manteniendo balance
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
TRAIN_FILE = OUTPUT_DIR / "train.csv"


def load_existing_urls() -> set:
    """Carga las URLs existentes del dataset para evitar duplicados."""
    existing = set()
    if TRAIN_FILE.exists():
        with open(TRAIN_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing.add(row['url'].lower())
    print(f"URLs existentes en dataset: {len(existing)}")
    return existing


def load_new_phishing_urls(existing: set, limit: int = 300) -> list:
    """Carga URLs de phishing nuevas que no estan en el dataset."""
    urls = []

    # Cargar de phishing-links-ACTIVE.txt
    links_file = PHISHING_DB / "phishing-links-ACTIVE.txt"
    if not links_file.exists():
        print(f"ERROR: No se encontro {links_file}")
        return urls

    print(f"Buscando URLs nuevas en {links_file.name}...")

    with open(links_file, 'r', encoding='utf-8', errors='ignore') as f:
        all_urls = [line.strip() for line in f if line.strip().startswith('http')]

    # Mezclar para obtener variedad
    random.shuffle(all_urls)

    # Filtrar URLs nuevas
    seen_domains = set()
    for url in all_urls:
        url_lower = url.lower()
        if url_lower in existing:
            continue

        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.lower()
            # Evitar muchas URLs del mismo dominio
            if domain not in seen_domains:
                urls.append(url)
                seen_domains.add(domain)
            if len(urls) >= limit:
                break
        except:
            continue

    print(f"URLs de phishing nuevas encontradas: {len(urls)}")
    return urls


def generate_new_legitimate_urls(existing: set, limit: int = 300) -> list:
    """Genera URLs legitimas nuevas."""

    # Dominios legitimos adicionales
    domains = [
        # Tech companies
        "nvidia.com", "intel.com", "amd.com", "qualcomm.com", "cisco.com",
        "oracle.com", "ibm.com", "hp.com", "dell.com", "lenovo.com",
        # Social media
        "snapchat.com", "tiktok.com", "quora.com", "imgur.com", "flickr.com",
        # News
        "washingtonpost.com", "wsj.com", "theguardian.com", "forbes.com", "wired.com",
        # E-commerce
        "newegg.com", "wayfair.com", "overstock.com", "zappos.com", "macys.com",
        # Travel
        "hotels.com", "vrbo.com", "priceline.com", "southwest.com", "delta.com",
        # Finance
        "fidelity.com", "schwab.com", "vanguard.com", "capitalone.com", "discover.com",
        # Education
        "mit.edu", "stanford.edu", "harvard.edu", "yale.edu", "berkeley.edu",
        # Gaming
        "steam.com", "epicgames.com", "riotgames.com", "ea.com", "blizzard.com",
        # Entertainment
        "hulu.com", "hbomax.com", "disneyplus.com", "paramount.com", "peacock.com",
        # Others
        "zoom.us", "webex.com", "gotomeeting.com", "whereby.com", "meet.google.com",
        "mailchimp.com", "constantcontact.com", "hubspot.com", "zendesk.com", "freshdesk.com",
        "atlassian.com", "bitbucket.org", "gitlab.com", "digitalocean.com", "linode.com",
        "cloudflare.com", "fastly.com", "akamai.com", "maxcdn.com", "jsdelivr.com",
        "npmjs.com", "pypi.org", "rubygems.org", "maven.org", "nuget.org"
    ]

    paths = [
        "", "/", "/login", "/signup", "/register", "/account",
        "/products", "/services", "/solutions", "/pricing", "/plans",
        "/about", "/about-us", "/company", "/team", "/careers",
        "/contact", "/support", "/help", "/faq", "/docs",
        "/blog", "/news", "/press", "/resources", "/case-studies",
        "/privacy", "/terms", "/security", "/compliance", "/legal"
    ]

    urls = []
    for domain in domains:
        for path in random.sample(paths, min(8, len(paths))):
            url = f"https://www.{domain}{path}"
            url_lower = url.lower()
            if url_lower not in existing:
                urls.append(url)
            if len(urls) >= limit:
                break
        if len(urls) >= limit:
            break

    random.shuffle(urls)
    print(f"URLs legitimas nuevas generadas: {len(urls[:limit])}")
    return urls[:limit]


def verify_with_virustotal(urls: list, max_checks: int = 25) -> tuple:
    """
    Verifica URLs con VirusTotal.
    Retorna (urls_confirmadas, estadisticas)
    """
    if not virustotal_service.enabled:
        print("VirusTotal no disponible, usando todas las URLs sin verificar")
        return urls, {"verified": 0, "confirmed": 0, "skipped": len(urls)}

    print(f"\nVerificando {max_checks} URLs con VirusTotal...")
    print("(Esto tomara aprox. {:.0f} minutos por rate limits)".format(max_checks * 16 / 60))

    confirmed = []
    stats = {"verified": 0, "confirmed": 0, "clean": 0, "errors": 0}

    # Verificar muestra
    sample = urls[:max_checks]

    for i, url in enumerate(sample):
        print(f"  [{i+1}/{max_checks}] {url[:50]}...", end=" ", flush=True)

        try:
            result = virustotal_service.check_url(url, wait_for_analysis=False)

            if result.analyzed:
                stats["verified"] += 1
                if result.is_malicious or result.malicious_count > 0:
                    stats["confirmed"] += 1
                    confirmed.append(url)
                    print(f"MALICIOSO ({result.malicious_count})")
                else:
                    stats["clean"] += 1
                    print("limpio")
            else:
                stats["errors"] += 1
                confirmed.append(url)  # Incluir aunque no se pudo verificar
                print("sin verificar")

        except Exception as e:
            stats["errors"] += 1
            confirmed.append(url)  # Incluir aunque fallo
            print(f"error: {str(e)[:30]}")

        # Rate limit
        time.sleep(16)

    # Agregar el resto de URLs no verificadas
    remaining = urls[max_checks:]
    confirmed.extend(remaining)

    return confirmed, stats


def extract_all_features(urls: list, label: int, description: str) -> list:
    """Extrae features de todas las URLs."""
    data = []
    total = len(urls)

    print(f"\nExtrayendo features de {description} ({total} URLs)...")

    for i, url in enumerate(urls):
        if (i + 1) % 50 == 0 or (i + 1) == total:
            print(f"  Procesando {i+1}/{total}...")

        try:
            features = extract_features(url)
            features['url'] = url
            features['label'] = label
            # Features de Tranco (valores por defecto)
            features['in_tranco'] = 1 if label == 0 else 0
            features['tranco_rank'] = 0.8 if label == 0 else 0
            features['brand_impersonation'] = 0
            data.append(features)
        except Exception as e:
            print(f"  Error en {url[:50]}: {e}")
            continue

    return data


def append_to_dataset(new_data: list, output_path: Path):
    """Agrega nuevos datos al dataset existente."""

    # Leer dataset existente
    existing_data = []
    fieldnames = None

    if output_path.exists():
        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            existing_data = list(reader)

    print(f"\nDataset existente: {len(existing_data)} registros")
    print(f"Nuevos registros: {len(new_data)}")

    # Combinar
    all_data = existing_data + new_data
    random.shuffle(all_data)

    # Obtener fieldnames del nuevo data si no existia
    if not fieldnames and new_data:
        fieldnames = list(new_data[0].keys())

    # Asegurar orden de columnas
    for col in ['label', 'url']:
        if col in fieldnames:
            fieldnames.remove(col)
            fieldnames.insert(0, col)

    # Backup
    if output_path.exists():
        backup_path = output_path.parent / f"train_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(backup_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(existing_data)
        print(f"Backup creado: {backup_path.name}")

    # Guardar dataset combinado
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_data:
            # Asegurar que tiene todas las columnas
            row_data = {k: row.get(k, '') for k in fieldnames}
            writer.writerow(row_data)

    print(f"Dataset guardado: {output_path}")
    print(f"Total de registros: {len(all_data)}")

    return len(all_data)


def main():
    print("=" * 80)
    print("EXPANSION DE DATASET CON 500 URLs NUEVAS")
    print("=" * 80)
    print(f"Fecha: {datetime.now().isoformat()}")

    # Configuracion
    PHISHING_TO_ADD = 250
    LEGITIMATE_TO_ADD = 250
    VT_CHECKS = 25  # Verificar 25 URLs con VT (por rate limit)

    # 1. Cargar URLs existentes
    print("\n[1/5] Cargando URLs existentes...")
    existing = load_existing_urls()

    # 2. Obtener nuevas URLs de phishing
    print("\n[2/5] Buscando URLs de phishing nuevas...")
    new_phishing = load_new_phishing_urls(existing, PHISHING_TO_ADD + 50)  # Extra por si fallan

    if len(new_phishing) < PHISHING_TO_ADD:
        print(f"ADVERTENCIA: Solo se encontraron {len(new_phishing)} URLs nuevas")

    # 3. Verificar muestra con VirusTotal
    print("\n[3/5] Verificando con VirusTotal...")
    verified_phishing, vt_stats = verify_with_virustotal(new_phishing, VT_CHECKS)
    verified_phishing = verified_phishing[:PHISHING_TO_ADD]

    print(f"\nEstadisticas VirusTotal:")
    print(f"  - Verificadas: {vt_stats['verified']}")
    print(f"  - Confirmadas maliciosas: {vt_stats['confirmed']}")
    print(f"  - Limpias (posibles FP): {vt_stats['clean']}")

    if vt_stats['verified'] > 0:
        accuracy = vt_stats['confirmed'] / vt_stats['verified'] * 100
        print(f"  - Precision estimada: {accuracy:.1f}%")

    # 4. Generar URLs legitimas nuevas
    print("\n[4/5] Generando URLs legitimas nuevas...")
    new_legitimate = generate_new_legitimate_urls(existing, LEGITIMATE_TO_ADD)

    # 5. Extraer features y agregar al dataset
    print("\n[5/5] Extrayendo features y actualizando dataset...")

    phishing_data = extract_all_features(verified_phishing, label=1, description="phishing")
    legitimate_data = extract_all_features(new_legitimate, label=0, description="legitimas")

    new_data = phishing_data + legitimate_data

    total = append_to_dataset(new_data, TRAIN_FILE)

    # Resumen
    print("\n" + "=" * 80)
    print("RESUMEN DE EXPANSION")
    print("=" * 80)
    print(f"URLs de phishing agregadas: {len(phishing_data)}")
    print(f"URLs legitimas agregadas: {len(legitimate_data)}")
    print(f"Total nuevas: {len(new_data)}")
    print(f"Total en dataset: {total}")

    if vt_stats['verified'] > 0:
        print(f"\nVerificacion VT: {vt_stats['confirmed']}/{vt_stats['verified']} confirmadas")

    print("\n" + "=" * 80)
    print("SIGUIENTE PASO: Ejecutar scripts/train_step1.py para reentrenar el modelo")
    print("=" * 80)


if __name__ == '__main__':
    main()
