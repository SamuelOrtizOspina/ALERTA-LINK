#!/usr/bin/env python3
"""
Script para obtener datos de entrenamiento desde VirusTotal

Este script:
1. Verifica URLs contra VirusTotal
2. Guarda las URLs maliciosas confirmadas para entrenamiento
3. Permite enriquecer el dataset existente

Uso:
    python scripts/fetch_virustotal_data.py --verify  # Verificar URLs de prueba
    python scripts/fetch_virustotal_data.py --enrich  # Enriquecer dataset existente
"""

import sys
import time
import csv
import argparse
from pathlib import Path
from datetime import datetime

# Agregar backend al path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.services.virustotal_service import virustotal_service
from app.services.feature_extractor import extract_features


def verify_sample_urls():
    """Verifica un conjunto de URLs de prueba contra VirusTotal."""

    # URLs de prueba conocidas (mezcla de legitimas y sospechosas)
    test_urls = [
        # Sospechosas/Maliciosas
        "https://pastebin.com/cpdmr6HZ",
        "https://bit.ly/free-gift-card",
        "http://192.168.1.1/login.php",

        # Legitimas
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
    ]

    print("=" * 80)
    print("VERIFICACION DE URLs CON VIRUSTOTAL")
    print("=" * 80)

    if not virustotal_service.enabled:
        print("ERROR: API de VirusTotal no configurada")
        return

    results = []

    for url in test_urls:
        print(f"\nVerificando: {url}")

        result = virustotal_service.check_url(url, wait_for_analysis=False)

        if result.analyzed:
            status = "MALICIOSO" if result.is_malicious else "SEGURO"
            print(f"  Estado: {status}")
            print(f"  Maliciosos: {result.malicious_count}/{result.total_engines}")
            print(f"  Sospechosos: {result.suspicious_count}")
            print(f"  Seguros: {result.harmless_count}")

            if result.threat_names:
                print(f"  Amenazas: {', '.join(result.threat_names[:3])}")

            results.append({
                'url': url,
                'is_malicious': result.is_malicious,
                'malicious_count': result.malicious_count,
                'total_engines': result.total_engines,
                'threats': ','.join(result.threat_names[:3])
            })
        else:
            print(f"  Error: {result.error or 'No analizado'}")

        # Esperar entre requests (rate limit)
        time.sleep(16)

    # Guardar resultados
    output_path = Path(__file__).parent.parent / "datasets" / "virustotal_results.csv"
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['url', 'is_malicious', 'malicious_count', 'total_engines', 'threats'])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResultados guardados en: {output_path}")


def enrich_dataset():
    """Enriquece el dataset existente verificando URLs con VirusTotal."""

    dataset_path = Path(__file__).parent.parent / "datasets" / "splits" / "train.csv"

    if not dataset_path.exists():
        print(f"ERROR: Dataset no encontrado en {dataset_path}")
        return

    print("=" * 80)
    print("ENRIQUECIENDO DATASET CON VIRUSTOTAL")
    print("=" * 80)

    if not virustotal_service.enabled:
        print("ERROR: API de VirusTotal no configurada")
        return

    # Leer dataset existente
    urls_to_verify = []
    with open(dataset_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Solo verificar las que estan marcadas como maliciosas (label=1)
            if row.get('label') == '1':
                urls_to_verify.append(row['url'])

    print(f"URLs maliciosas en dataset: {len(urls_to_verify)}")
    print(f"Verificando muestra de 10 URLs (por rate limit)...")

    # Solo verificar una muestra pequena (rate limit de API gratuita)
    sample = urls_to_verify[:10]
    verified = []
    false_positives = []

    for url in sample:
        print(f"\nVerificando: {url[:50]}...")

        result = virustotal_service.check_url(url, wait_for_analysis=False)

        if result.analyzed:
            if result.is_malicious:
                print(f"  CONFIRMADO malicioso ({result.malicious_count} motores)")
                verified.append(url)
            else:
                print(f"  Posible falso positivo (solo {result.malicious_count} detecciones)")
                if result.malicious_count == 0:
                    false_positives.append(url)
        else:
            print(f"  No se pudo verificar: {result.error}")

        time.sleep(16)

    print("\n" + "=" * 80)
    print("RESUMEN")
    print("=" * 80)
    print(f"Verificadas: {len(sample)}")
    print(f"Confirmadas maliciosas: {len(verified)}")
    print(f"Posibles falsos positivos: {len(false_positives)}")

    if false_positives:
        print("\nURLs que podrian ser falsos positivos:")
        for url in false_positives:
            print(f"  - {url}")


def fetch_malicious_urls():
    """
    Intenta obtener URLs maliciosas de VirusTotal.

    NOTA: Requiere API premium para busquedas avanzadas.
    Con API gratuita, solo verificamos URLs existentes.
    """

    print("=" * 80)
    print("OBTENIENDO URLs MALICIOSAS DE VIRUSTOTAL")
    print("=" * 80)

    if not virustotal_service.enabled:
        print("ERROR: API de VirusTotal no configurada")
        return

    print("\nNOTA: La busqueda de URLs requiere API premium de VirusTotal.")
    print("Con la API gratuita, usa --verify o --enrich para verificar URLs conocidas.")

    # Intentar busqueda (probablemente falle con API gratuita)
    urls = virustotal_service.get_malicious_urls(limit=10)

    if urls:
        print(f"\nURLs maliciosas encontradas: {len(urls)}")
        for url in urls[:5]:
            print(f"  - {url}")

        # Guardar URLs
        output_path = Path(__file__).parent.parent / "datasets" / "vt_malicious_urls.txt"
        with open(output_path, 'w', encoding='utf-8') as f:
            for url in urls:
                f.write(url + '\n')

        print(f"\nURLs guardadas en: {output_path}")
    else:
        print("\nNo se pudieron obtener URLs (probablemente necesitas API premium).")
        print("Alternativas:")
        print("  1. Usa --verify para verificar URLs de prueba")
        print("  2. Usa --enrich para verificar tu dataset existente")
        print("  3. Agrega URLs manualmente al archivo datasets/Buenos_Datos/malicious_urls.txt")


def add_verified_urls_to_training():
    """Agrega URLs verificadas por VT al dataset de entrenamiento."""

    vt_results_path = Path(__file__).parent.parent / "datasets" / "virustotal_results.csv"
    train_path = Path(__file__).parent.parent / "datasets" / "splits" / "train.csv"

    if not vt_results_path.exists():
        print("Primero ejecuta --verify para obtener resultados de VirusTotal")
        return

    print("=" * 80)
    print("AGREGANDO URLs VERIFICADAS AL DATASET")
    print("=" * 80)

    # Leer resultados de VT
    new_malicious = []
    with open(vt_results_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['is_malicious'] == 'True':
                new_malicious.append(row['url'])

    if not new_malicious:
        print("No hay URLs maliciosas confirmadas para agregar")
        return

    print(f"URLs maliciosas confirmadas por VT: {len(new_malicious)}")

    # Leer URLs existentes en el dataset
    existing_urls = set()
    rows = []
    with open(train_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            existing_urls.add(row['url'])
            rows.append(row)

    # Agregar nuevas URLs
    added = 0
    for url in new_malicious:
        if url not in existing_urls:
            features = extract_features(url)
            features['url'] = url
            features['label'] = 1
            features['in_tranco'] = 0
            features['tranco_rank'] = 0
            features['brand_impersonation'] = 0
            rows.append(features)
            added += 1

    if added > 0:
        # Guardar dataset actualizado
        with open(train_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"Agregadas {added} URLs nuevas al dataset")
        print(f"Total URLs en dataset: {len(rows)}")
    else:
        print("No hay URLs nuevas para agregar (ya existen en el dataset)")


def main():
    parser = argparse.ArgumentParser(description='Obtener datos de VirusTotal para entrenamiento')
    parser.add_argument('--verify', action='store_true', help='Verificar URLs de prueba')
    parser.add_argument('--enrich', action='store_true', help='Enriquecer dataset existente')
    parser.add_argument('--fetch', action='store_true', help='Intentar obtener URLs maliciosas (requiere API premium)')
    parser.add_argument('--add', action='store_true', help='Agregar URLs verificadas al dataset de entrenamiento')

    args = parser.parse_args()

    if args.verify:
        verify_sample_urls()
    elif args.enrich:
        enrich_dataset()
    elif args.fetch:
        fetch_malicious_urls()
    elif args.add:
        add_verified_urls_to_training()
    else:
        parser.print_help()
        print("\nEjemplos:")
        print("  python scripts/fetch_virustotal_data.py --verify  # Verificar URLs de prueba")
        print("  python scripts/fetch_virustotal_data.py --enrich  # Verificar URLs del dataset")
        print("  python scripts/fetch_virustotal_data.py --add     # Agregar verificadas al training")


if __name__ == '__main__':
    main()
