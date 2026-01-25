#!/usr/bin/env python3
"""
Test del predictor real con las mejoras de precision
"""

import sys
from pathlib import Path

# Agregar backend al path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.services.predictor import predictor
from app.services.feature_extractor import extract_features_with_tranco
from app.services.tranco_service import tranco_service

def main():
    # Cargar modelo
    if not predictor.is_loaded():
        print("Cargando modelo...")
        predictor.load_model()

    # URLs de prueba
    test_urls = [
        ('https://www.google.com', 'Legitimo - Google'),
        ('https://www.paypal.com/login', 'Legitimo - PayPal'),
        ('https://pastebin.com/cpdmr6HZ', 'Sospechoso - Pastebin con KMS'),
        ('https://secure-paypal-verify.xyz/login', 'Phishing - Suplanta PayPal'),
        ('https://kutt.it/kms-activator', 'Phishing - Shortener + KMS'),
        ('https://amazon-gift-free.top/claim', 'Phishing - Suplanta Amazon'),
        ('http://192.168.1.1/login.php', 'Phishing - IP como host'),
        ('https://bit.ly/free-gift-card', 'Sospechoso - Shortener'),
    ]

    print('=' * 80)
    print('PRUEBA DEL PREDICTOR REAL CON MEJORAS DE PRECISION')
    print('=' * 80)

    for url, descripcion in test_urls:
        print(f'\nURL: {url}')
        print(f'Esperado: {descripcion}')

        # Usar predictor real
        score, prob, risk_level, signals = predictor.predict(url, use_tranco=True)

        print(f'  Score: {score}/100 - Riesgo: {risk_level.value}')
        print(f'  Senales detectadas: {len(signals)}')

        # Mostrar senales con detalles
        for signal in signals[:5]:  # Max 5 senales
            print(f'    - [{signal.severity.value}] {signal.id}: {signal.explanation[:80]}...')

        # Mostrar recomendaciones
        recommendations = predictor.get_recommendations(risk_level, signals)
        if recommendations:
            print(f'  Recomendaciones:')
            for rec in recommendations[:2]:
                print(f'    * {rec}')

    print('\n' + '=' * 80)
    print('PRUEBA COMPLETADA')
    print('=' * 80)


if __name__ == '__main__':
    main()
