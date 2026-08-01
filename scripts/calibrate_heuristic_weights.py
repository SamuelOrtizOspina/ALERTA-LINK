#!/usr/bin/env python3
"""
calibrate_heuristic_weights.py - Calibra los pesos del motor heuristico

A DIFERENCIA de la version anterior, este script NO tiene una copia propia
de la logica heuristica: importa el motor real del backend
(app.services.heuristic_predictor) y extrae con el las senales de cada URL.
La version anterior duplicaba extract_features/generate_signals con solo 15
senales (sin TYPOSQUATTING ni DOMAIN_NOT_IN_TRANCO) y con el matching por
substring ya corregido en el motor, por lo que optimizaba pesos para un
motor distinto al de produccion.

Metodologia:
1. Carga train.csv + val.csv (NUNCA test.csv, que queda reservado para
   medir sobre datos que el optimizador no vio).
2. Ejecuta el motor real en modo offline sobre cada URL y registra que
   senales se activaron. Las activaciones no dependen de los pesos, asi
   que una sola pasada basta.
3. Busca con evolucion diferencial (SciPy) los pesos locales que maximizan
   F1, con el umbral de produccion: maliciosa si score > 30 (MEDIUM/HIGH).
4. Guarda los pesos en models/ y en backend/models/ (la ruta que el motor
   lee realmente).

Uso:
    python scripts/calibrate_heuristic_weights.py

Salida:
    models/heuristic_weights.json
    backend/models/heuristic_weights.json
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.optimize import differential_evolution

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR / "backend"))

from app.services.heuristic_predictor import heuristic_predictor, DEFAULT_WEIGHTS  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

SPLITS_DIR = BASE_DIR / "datasets" / "splits"
DESTINOS = [
    BASE_DIR / "models" / "heuristic_weights.json",
    BASE_DIR / "backend" / "models" / "heuristic_weights.json",
]

# Umbral de produccion: el sistema trata MEDIUM y HIGH como maliciosa
UMBRAL = 30
SEED = 42

# Senales que pueden activarse en modo offline y cuyos pesos se optimizan.
# Las senales de APIs externas (Tranco online, VirusTotal, WHOIS) no se
# activan sin red, asi que sus pesos se conservan tal cual.
SENALES_LOCALES = [
    'IP_AS_HOST', 'PUNYCODE_DETECTED', 'BRAND_IMPERSONATION', 'TYPOSQUATTING',
    'URL_SHORTENER', 'PASTE_SERVICE', 'HOSTING_PLATFORM', 'RISKY_TLD',
    'SUSPICIOUS_WORDS', 'EXCESSIVE_SUBDOMAINS', 'NO_HTTPS', 'LONG_URL',
    'HIGH_DIGIT_RATIO', 'HIGH_ENTROPY', 'AT_SYMBOL', 'DOMAIN_NOT_IN_TRANCO',
    'TRUSTED_DOMAIN',
]

# Limites por senal, con criterio experto:
# - TRUSTED_DOMAIN debe ser siempre bonificacion.
# - Suplantacion de marca y typosquatting deben ser siempre graves.
def limites_para(nombre: str) -> Tuple[float, float]:
    if nombre == 'TRUSTED_DOMAIN':
        return (-50, -10)
    if nombre in ('BRAND_IMPERSONATION', 'TYPOSQUATTING'):
        return (30, 60)
    if nombre in ('IP_AS_HOST', 'PUNYCODE_DETECTED'):
        return (15, 50)
    return (0, 40)


def cargar_urls() -> Tuple[List[str], np.ndarray]:
    """Carga train+val. test.csv queda fuera deliberadamente."""
    frames = []
    for nombre in ("train.csv", "val.csv"):
        ruta = SPLITS_DIR / nombre
        df = pd.read_csv(ruta)
        frames.append(df[["url", "label"]])
        logger.info(f"  {nombre}: {len(df)} URLs")
    combinado = pd.concat(frames, ignore_index=True).drop_duplicates(subset=["url"])
    logger.info(f"  total unicas: {len(combinado)}")
    return combinado["url"].tolist(), combinado["label"].to_numpy()


def extraer_activaciones(urls: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    """
    Ejecuta el motor real (offline) sobre cada URL.

    Devuelve:
        A:  matriz [n_urls x n_senales] con 1 si la senal se activo
        sw: vector [n_urls] con el conteo de palabras sospechosas
            (su peso efectivo en el motor es min(conteo * peso, 30))
    """
    n = len(urls)
    k = len(SENALES_LOCALES)
    indice = {s: i for i, s in enumerate(SENALES_LOCALES)}
    A = np.zeros((n, k), dtype=np.float64)
    sw = np.zeros(n, dtype=np.float64)

    for fila, url in enumerate(urls):
        try:
            _, _, _, senales = heuristic_predictor.predict(
                url, use_tranco=False, use_virustotal=False, use_whois=False
            )
        except Exception:
            continue
        for s in senales:
            col = indice.get(s.id)
            if col is None:
                continue
            A[fila, col] = 1.0
            if s.id == 'SUSPICIOUS_WORDS':
                sw[fila] = float(s.evidence.get('count', 1))
        if (fila + 1) % 1000 == 0:
            logger.info(f"  {fila + 1}/{n} URLs procesadas")

    return A, sw


def puntuar(A: np.ndarray, sw: np.ndarray, pesos: np.ndarray, idx_sw: int) -> np.ndarray:
    """Replica la aritmetica del motor: suma de pesos, tope de
    SUSPICIOUS_WORDS en 30 y recorte final a [0, 100]."""
    contrib = A @ pesos
    # Sustituir la contribucion lineal de SUSPICIOUS_WORDS por la real
    contrib -= A[:, idx_sw] * pesos[idx_sw]
    contrib += np.minimum(sw * pesos[idx_sw], 30.0) * A[:, idx_sw]
    return np.clip(contrib, 0.0, 100.0)


def metricas(scores: np.ndarray, labels: np.ndarray) -> Dict[str, float]:
    pred = scores > UMBRAL
    real = labels == 1
    tp = int(np.sum(pred & real))
    tn = int(np.sum(~pred & ~real))
    fp = int(np.sum(pred & ~real))
    fn = int(np.sum(~pred & real))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "accuracy": (tp + tn) / len(labels),
        "precision": prec, "recall": rec, "f1": f1,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


def main() -> None:
    logger.info("=" * 64)
    logger.info("CALIBRACION DE PESOS - usando el motor real del backend")
    logger.info("=" * 64)

    urls, labels = cargar_urls()

    logger.info("")
    logger.info("[SCAN] Extrayendo senales con heuristic_predictor (offline)...")
    A, sw = extraer_activaciones(urls)
    idx_sw = SENALES_LOCALES.index('SUSPICIOUS_WORDS')

    activaciones = A.sum(axis=0).astype(int)
    logger.info("")
    logger.info("  Activaciones por senal:")
    for nombre, cuenta in sorted(zip(SENALES_LOCALES, activaciones), key=lambda x: -x[1]):
        if cuenta:
            logger.info(f"    {nombre:<26}{cuenta:>6}")

    # Linea base: pesos actuales del motor
    pesos_actuales = np.array(
        [heuristic_predictor.weights.get(s, DEFAULT_WEIGHTS.get(s, 0)) for s in SENALES_LOCALES],
        dtype=np.float64,
    )
    base = metricas(puntuar(A, sw, pesos_actuales, idx_sw), labels)
    logger.info("")
    logger.info(f"  Linea base (pesos actuales): accuracy {base['accuracy']:.1%}  f1 {base['f1']:.3f}")

    # Optimizacion
    logger.info("")
    logger.info("[OPT] Evolucion diferencial (esto toma unos minutos)...")
    limites = [limites_para(s) for s in SENALES_LOCALES]

    def objetivo(w: np.ndarray) -> float:
        return -metricas(puntuar(A, sw, w, idx_sw), labels)["f1"]

    resultado = differential_evolution(
        objetivo, bounds=limites, maxiter=200, popsize=24,
        mutation=(0.5, 1.0), recombination=0.7, seed=SEED, tol=1e-4,
        polish=True, disp=False,
    )
    pesos_nuevos = np.rint(resultado.x)
    calibrado = metricas(puntuar(A, sw, pesos_nuevos, idx_sw), labels)

    logger.info("")
    logger.info(f"{'Metrica':<12}{'Actual':>10}{'Calibrado':>12}")
    for m in ("accuracy", "precision", "recall", "f1"):
        logger.info(f"{m:<12}{base[m]:>10.3f}{calibrado[m]:>12.3f}")
    logger.info(f"{'FP':<12}{base['fp']:>10}{calibrado['fp']:>12}")
    logger.info(f"{'FN':<12}{base['fn']:>10}{calibrado['fn']:>12}")

    # Combinar con los pesos externos, que se conservan
    pesos_finales = dict(DEFAULT_WEIGHTS)
    pesos_finales.update(heuristic_predictor.weights)
    pesos_finales.update({s: int(v) for s, v in zip(SENALES_LOCALES, pesos_nuevos)})

    logger.info("")
    logger.info("  Pesos calibrados (locales):")
    for s, v in sorted(zip(SENALES_LOCALES, pesos_nuevos), key=lambda x: -abs(x[1])):
        logger.info(f"    {s:<26}{int(v):>5}")

    salida = {
        "version": "2.0",
        "calibration_date": datetime.now().isoformat(),
        "engine": "app.services.heuristic_predictor (motor real)",
        "dataset_size": len(urls),
        "threshold": UMBRAL,
        "metrics": {m: calibrado[m] for m in ("accuracy", "precision", "recall", "f1")},
        "weights": pesos_finales,
    }
    for destino in DESTINOS:
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(destino, "w", encoding="utf-8") as f:
            json.dump(salida, f, indent=2, ensure_ascii=False)
        logger.info(f"\n[SAVE] {destino}")

    logger.info("")
    logger.info("Reiniciar el backend para que el motor cargue los pesos nuevos.")
    logger.info("Medir sobre test.csv con: python scripts/evaluate_offline.py test.csv")


if __name__ == "__main__":
    main()
