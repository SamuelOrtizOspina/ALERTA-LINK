#!/usr/bin/env python3
"""
evaluate_offline.py - Evalua el motor heuristico en modo offline puro

Replica la metodologia del Capitulo IV: sin Tranco, sin WHOIS y sin
VirusTotal, de modo que el resultado depende unicamente de las reglas
locales y de los pesos de models/heuristic_weights.json.

Se considera prediccion "maliciosa" cuando el score supera 30, es decir
los niveles MEDIUM y HIGH.

Uso:
    python scripts/evaluate_offline.py            # usa test.csv
    python scripts/evaluate_offline.py train.csv  # otro split
"""

import sys
import csv
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.services.heuristic_predictor import heuristic_predictor  # noqa: E402

CSV = ROOT / "datasets" / "splits" / (sys.argv[1] if len(sys.argv) > 1 else "test.csv")

filas = []
with open(CSV, "r", encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        url = (row.get("url") or "").strip()
        label = (row.get("label") or "").strip()
        if url and label in ("0", "1"):
            filas.append((url, int(label)))

print(f"URLs cargadas: {len(filas)}")
print(f"  legitimas (0): {sum(1 for _, l in filas if l == 0)}")
print(f"  maliciosas (1): {sum(1 for _, l in filas if l == 1)}")
print("\nEjecutando motor heuristico en modo offline...\n")

tp = tn = fp = fn = 0
scores = []
niveles = Counter()
senales = Counter()
errores = 0

for url, label in filas:
    try:
        score, _prob, nivel, signals = heuristic_predictor.predict(
            url, use_tranco=False, use_virustotal=False, use_whois=False
        )
    except Exception:
        errores += 1
        continue

    scores.append(score)
    niveles[nivel.value] += 1
    for s in signals:
        senales[s.id] += 1

    pred = 1 if score > 30 else 0
    if pred == 1 and label == 1:
        tp += 1
    elif pred == 0 and label == 0:
        tn += 1
    elif pred == 1 and label == 0:
        fp += 1
    else:
        fn += 1

total = tp + tn + fp + fn
accuracy = (tp + tn) / total if total else 0
prec_mal = tp / (tp + fp) if (tp + fp) else 0
rec_mal = tp / (tp + fn) if (tp + fn) else 0
f1_mal = 2 * prec_mal * rec_mal / (prec_mal + rec_mal) if (prec_mal + rec_mal) else 0
prec_leg = tn / (tn + fn) if (tn + fn) else 0
rec_leg = tn / (tn + fp) if (tn + fp) else 0
f1_leg = 2 * prec_leg * rec_leg / (prec_leg + rec_leg) if (prec_leg + rec_leg) else 0
tasa_fp = fp / (tn + fp) if (tn + fp) else 0
tasa_fn = fn / (tp + fn) if (tp + fn) else 0

print("=" * 62)
print("METRICAS GLOBALES (offline, solo reglas locales)")
print("=" * 62)
print(f"Total analizadas          {total}")
print(f"Errores de procesamiento  {errores}")
print(f"Score minimo              {min(scores) if scores else 0}")
print(f"Score maximo              {max(scores) if scores else 0}")
print(f"Score promedio            {sum(scores)/len(scores):.2f}" if scores else "")
print(f"Accuracy global           {accuracy:.1%}")
print(f"Tasa de falsos positivos  {tasa_fp:.1%}")
print(f"Tasa de falsos negativos  {tasa_fn:.1%}")
print(f"Recall maliciosas         {rec_mal:.1%}")

print("\n" + "=" * 62)
print("MATRIZ DE CONFUSION")
print("=" * 62)
print("                    Predicho legitima   Predicho maliciosa")
print(f"Real legitima              {tn:5d}               {fp:5d}")
print(f"Real maliciosa             {fn:5d}               {tp:5d}")

print("\n" + "=" * 62)
print("POR CLASE")
print("=" * 62)
print(f"{'Clase':<26}{'Precision':>11}{'Recall':>10}{'F1':>8}{'n':>7}")
print(f"{'SAFE/LOW (legitimas)':<26}{prec_leg:>10.1%}{rec_leg:>10.1%}{f1_leg:>8.2f}{tn+fp:>7}")
print(f"{'MEDIUM/HIGH (maliciosas)':<26}{prec_mal:>10.1%}{rec_mal:>10.1%}{f1_mal:>8.2f}{tp+fn:>7}")

print("\n" + "=" * 62)
print("DISTRIBUCION POR NIVEL")
print("=" * 62)
for nivel in ("SAFE", "LOW", "MEDIUM", "HIGH"):
    n = niveles.get(nivel, 0)
    print(f"{nivel:<10}{n:>6}{n/total:>10.1%}" if total else "")

print("\n" + "=" * 62)
print("FRECUENCIA DE SENALES")
print("=" * 62)
for sid, n in senales.most_common():
    peso = heuristic_predictor.weights.get(sid, "-")
    print(f"{sid:<28}{str(peso):>6}{n:>7}{n/total:>10.1%}" if total else "")
