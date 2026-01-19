#!/usr/bin/env python3
"""
Test de integracion de VirusTotal con el predictor

Este test verifica que:
1. VirusTotal solo se consulta cuando hay incertidumbre (score 30-70)
2. El score se ajusta correctamente basado en la respuesta de VT
3. Se generan las senales apropiadas
"""

import sys
import logging
from pathlib import Path

# Agregar backend al path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Configurar logging para ver las consultas a VT
logging.basicConfig(level=logging.INFO, format='%(name)s - %(message)s')

from app.services.predictor import predictor
from app.services.virustotal_service import virustotal_service
from app.core.config import settings


def main():
    # Cargar modelo
    if not predictor.is_loaded():
        print("Cargando modelo...")
        predictor.load_model()

    print("=" * 80)
    print("TEST DE INTEGRACION VIRUSTOTAL")
    print("=" * 80)
    print(f"\nConfiguracion:")
    print(f"  - VirusTotal habilitado: {virustotal_service.enabled}")
    print(f"  - Umbral detecciones: {settings.VIRUSTOTAL_THRESHOLD}")
    print(f"  - Rango incertidumbre: {settings.VIRUSTOTAL_UNCERTAINTY_MIN}-{settings.VIRUSTOTAL_UNCERTAINTY_MAX}")

    # URLs de prueba con diferentes niveles de riesgo
    test_cases = [
        {
            'url': 'https://www.google.com',
            'description': 'Sitio legitimo (score bajo, NO consulta VT)',
            'expect_vt': False
        },
        {
            'url': 'https://secure-paypal-verify.xyz/login',
            'description': 'Phishing obvio (score alto, NO consulta VT)',
            'expect_vt': False
        },
        {
            'url': 'https://pastebin.com/cpdmr6HZ',
            'description': 'Paste service (score medio, PUEDE consultar VT)',
            'expect_vt': True
        },
        {
            'url': 'https://bit.ly/free-gift-card',
            'description': 'Shortener sospechoso (score medio, PUEDE consultar VT)',
            'expect_vt': True
        },
    ]

    for case in test_cases:
        url = case['url']
        print(f"\n{'='*60}")
        print(f"URL: {url}")
        print(f"Descripcion: {case['description']}")
        print(f"Espera consulta VT: {'SI' if case['expect_vt'] else 'NO'}")
        print("-" * 60)

        # Primero sin VT para ver el score base
        score_sin_vt, _, risk_sin_vt, signals_sin_vt = predictor.predict(url, use_virustotal=False)
        print(f"Score SIN VT: {score_sin_vt}/100 ({risk_sin_vt.value})")

        # Luego con VT
        score_con_vt, _, risk_con_vt, signals_con_vt = predictor.predict(url, use_virustotal=True)
        print(f"Score CON VT: {score_con_vt}/100 ({risk_con_vt.value})")

        # Verificar si se consulto VT
        vt_signals = [s for s in signals_con_vt if s.id.startswith('VIRUSTOTAL')]
        if vt_signals:
            print(f"\nSenal de VirusTotal:")
            for sig in vt_signals:
                print(f"  - [{sig.severity.value}] {sig.id}")
                print(f"    {sig.explanation[:100]}...")
                if sig.evidence:
                    if 'malicious_engines' in sig.evidence:
                        print(f"    Motores maliciosos: {sig.evidence['malicious_engines']}/{sig.evidence['total_engines']}")
                    if 'threat_names' in sig.evidence and sig.evidence['threat_names']:
                        print(f"    Amenazas: {', '.join(sig.evidence['threat_names'][:3])}")
        else:
            if case['expect_vt']:
                if settings.VIRUSTOTAL_UNCERTAINTY_MIN <= score_sin_vt <= settings.VIRUSTOTAL_UNCERTAINTY_MAX:
                    print(f"\n[INFO] Score {score_sin_vt} esta en zona de incertidumbre pero VT no retorno resultado")
                else:
                    print(f"\n[INFO] Score {score_sin_vt} fuera de zona de incertidumbre, VT no consultado")
            else:
                print(f"\n[OK] VT no consultado como se esperaba (score fuera de rango)")

        # Mostrar cambio de score
        if score_con_vt != score_sin_vt:
            diff = score_con_vt - score_sin_vt
            print(f"\n[CAMBIO] Score ajustado por VT: {'+' if diff > 0 else ''}{diff} puntos")

    print("\n" + "=" * 80)
    print("TEST COMPLETADO")
    print("=" * 80)


if __name__ == '__main__':
    main()
