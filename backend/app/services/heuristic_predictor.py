"""
Predictor Heuristico Standalone - Modelo independiente basado en reglas

Este modelo funciona de forma COMPLETAMENTE INDEPENDIENTE del modelo ML.
Usa reglas heuristicas con pesos calibrados usando el dataset de 7,600 URLs.

NO usa Machine Learning, solo reglas deterministas explicables.
"""

import json
import logging
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
from urllib.parse import urlparse
import re
import math

from app.schemas.analyze import Signal, Severity, RiskLevel
from app.services.tranco_service import tranco_service
from app.services.virustotal_service import virustotal_service
from app.services.whois_service import whois_service
from app.core.config import settings

logger = logging.getLogger(__name__)


# ============================================================================
# LISTAS DE PATRONES (igual que en feature_extractor.py)
# ============================================================================

SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'password',
    'confirm', 'banking', 'suspend', 'expire', 'verify', 'wallet', 'alert',
    'unusual', 'locked', 'unlock', 'validate', 'authenticate', 'credential',
    'ssn', 'social', 'security', 'paypal', 'netflix', 'amazon', 'apple',
    'microsoft', 'google', 'facebook', 'instagram', 'whatsapp', 'telegram',
    'bancolombia', 'davivienda', 'nequi', 'daviplata', 'bbva', 'banco',
    'crack', 'keygen', 'serial', 'patch', 'activator', 'kms', 'warez',
    'nulled', 'cracked', 'torrent', 'free-download', 'full-version'
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'yourls.org', 'short.io',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'acortar.link', 'acortaurl.com'
]

RISKY_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online', 'site',
    'work', 'click', 'link', 'info', 'pw', 'cc', 'ws', 'buzz', 'surf',
    'icu', 'monster', 'cam', 'email', 'life', 'live', 'world', 'today'
]

PASTE_SERVICES = [
    'pastebin.com', 'paste.ee', 'justpaste.it', 'ghostbin.com', 'paste2.org',
    'hastebin.com', 'dpaste.org', 'ideone.com', 'codepad.org', 'rentry.co',
    'del.dog', 'paste.mozilla.org', 'privatebin.net'
]

HOSTING_PLATFORMS = [
    'appspot.com', 'github.io', 'gitlab.io', 'herokuapp.com', 'netlify.app',
    'vercel.app', 'pages.dev', 'web.app', 'firebaseapp.com', 'azurewebsites.net',
    'cloudfront.net', 'amazonaws.com', 'blob.core.windows.net', 'ngrok.io',
    'trycloudflare.com', 'workers.dev', 'r2.dev', 'replit.co', 'glitch.me'
]

KNOWN_BRANDS = [
    'paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'whatsapp', 'telegram', 'twitter', 'linkedin', 'spotify',
    'bancolombia', 'davivienda', 'nequi', 'daviplata', 'bbva', 'santander',
    'banco', 'dian', 'movistar', 'claro', 'tigo', 'rappi', 'mercadolibre',
    'falabella', 'exito', 'alkosto', 'olimpica', 'colsubsidio', 'compensar'
]

OFFICIAL_DOMAINS = {
    'paypal': 'paypal.com', 'netflix': 'netflix.com', 'amazon': 'amazon.com',
    'apple': 'apple.com', 'microsoft': 'microsoft.com', 'google': 'google.com',
    'facebook': 'facebook.com', 'instagram': 'instagram.com', 'whatsapp': 'whatsapp.com',
    'bancolombia': 'bancolombia.com', 'davivienda': 'davivienda.com',
    'nequi': 'nequi.com.co', 'daviplata': 'daviplata.com', 'dian': 'dian.gov.co',
    'rappi': 'rappi.com', 'mercadolibre': 'mercadolibre.com.co'
}

TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
    'bancolombia.com', 'davivienda.com', 'bbva.com.co', 'grupobancolombia.com',
    'nequi.com.co', 'daviplata.com', 'pse.com.co', 'dian.gov.co', 'gov.co'
]


# ============================================================================
# PESOS CALIBRADOS (se ajustan con el script de calibracion)
# ============================================================================

# Pesos por defecto - seran reemplazados por pesos calibrados
DEFAULT_WEIGHTS = {
    'IP_AS_HOST': 30,
    'PUNYCODE_DETECTED': 25,
    'BRAND_IMPERSONATION': 45,
    'URL_SHORTENER': 15,
    'PASTE_SERVICE': 20,
    'HOSTING_PLATFORM': 15,
    'RISKY_TLD': 15,
    'SUSPICIOUS_WORDS': 10,  # Por palabra, max 30
    'EXCESSIVE_SUBDOMAINS': 10,
    'NO_HTTPS': 8,
    'LONG_URL': 5,
    'HIGH_DIGIT_RATIO': 8,
    'HIGH_ENTROPY': 10,
    'AT_SYMBOL': 15,
    'DOMAIN_NOT_IN_TRANCO': 12,
    'DOMAIN_TOO_NEW': 35,    # Dominio registrado hace menos de 30 dias
    # Bonificaciones (restan puntos)
    'DOMAIN_IN_TRANCO': -35,
    'TRUSTED_DOMAIN': -40,
    'VIRUSTOTAL_CLEAN': -25,
    'DOMAIN_ESTABLISHED': -15,  # Dominio con mas de 1 año
    # Penalizaciones por VirusTotal
    'VIRUSTOTAL_MALICIOUS_LOW': 25,    # 1-2 motores
    'VIRUSTOTAL_MALICIOUS_MED': 40,    # 3-4 motores
    'VIRUSTOTAL_MALICIOUS_HIGH': 60,   # 5-9 motores
    'VIRUSTOTAL_MALICIOUS_CRITICAL': 80  # 10+ motores
}


class HeuristicPredictor:
    """
    Predictor basado UNICAMENTE en reglas heuristicas.

    Este modelo es completamente independiente del modelo ML.
    Usa reglas deterministas con pesos calibrados.
    """

    def __init__(self):
        self.weights = DEFAULT_WEIGHTS.copy()
        self._weights_loaded = False
        self._weights_file = Path(__file__).parent.parent.parent / 'models' / 'heuristic_weights.json'
        self._load_calibrated_weights()

    def _load_calibrated_weights(self):
        """Carga pesos calibrados desde archivo JSON si existe."""
        try:
            if self._weights_file.exists():
                with open(self._weights_file, 'r') as f:
                    data = json.load(f)

                # El archivo tiene estructura: {version, calibration_date, metrics, weights}
                if 'weights' in data:
                    self.weights.update(data['weights'])
                    self._weights_loaded = True
                    metrics = data.get('metrics', {})
                    logger.info(f"Pesos calibrados cargados desde {self._weights_file}")
                    logger.info(f"Metricas de calibracion: accuracy={metrics.get('accuracy', 'N/A'):.2%}, f1={metrics.get('f1', 'N/A'):.2f}")
                else:
                    # Formato antiguo: solo pesos
                    self.weights.update(data)
                    self._weights_loaded = True
                    logger.info(f"Pesos cargados desde {self._weights_file} (formato antiguo)")
            else:
                logger.info("Usando pesos por defecto (no se encontro archivo de calibracion)")
        except Exception as e:
            logger.warning(f"Error cargando pesos calibrados: {e}. Usando pesos por defecto.")

    def save_weights(self, weights: Dict[str, float]):
        """Guarda pesos calibrados a archivo JSON."""
        try:
            self._weights_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._weights_file, 'w') as f:
                json.dump(weights, f, indent=2)
            self.weights = weights
            self._weights_loaded = True
            logger.info(f"Pesos guardados en {self._weights_file}")
        except Exception as e:
            logger.error(f"Error guardando pesos: {e}")

    def get_weights(self) -> Dict[str, float]:
        """Retorna los pesos actuales."""
        return self.weights.copy()

    def is_loaded(self) -> bool:
        """Siempre retorna True porque no necesita cargar modelo externo."""
        return True

    def get_model_info(self) -> dict:
        """Retorna informacion del modelo heuristico."""
        return {
            "type": "heuristic",
            "loaded": True,
            "weights_calibrated": self._weights_loaded,
            "weights_file": str(self._weights_file) if self._weights_loaded else None,
            "num_rules": len(self.weights)
        }

    # ========================================================================
    # EXTRACCION DE FEATURES
    # ========================================================================

    def _extract_features(self, url: str) -> Dict[str, Any]:
        """Extrae features de la URL para las heuristicas."""
        features = {}

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()

            # Basicas
            features['url_length'] = len(url)
            features['domain'] = domain
            features['path'] = path
            features['has_https'] = parsed.scheme == 'https'

            # TLD
            parts = domain.split('.')
            features['tld'] = parts[-1] if parts else ''
            features['tld_risk'] = features['tld'] in RISKY_TLDS

            # Subdominios
            features['num_subdomains'] = max(0, len(parts) - 2)
            features['excessive_subdomains'] = features['num_subdomains'] > 3

            # Digitos
            digits = sum(c.isdigit() for c in url)
            features['num_digits'] = digits
            features['digit_ratio'] = digits / len(url) if len(url) > 0 else 0

            # Entropia
            features['entropy'] = self._calculate_entropy(domain)

            # Patrones especificos
            features['contains_ip'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))
            features['has_punycode'] = 'xn--' in domain
            features['has_at_symbol'] = '@' in url
            features['shortener_detected'] = any(s in domain for s in SHORTENERS)
            features['paste_service_detected'] = any(p in domain for p in PASTE_SERVICES)
            features['hosting_platform'] = any(h in domain for h in HOSTING_PLATFORMS)

            # Palabras sospechosas
            suspicious_count = sum(1 for w in SUSPICIOUS_WORDS if w in full_url)
            features['suspicious_words_count'] = suspicious_count
            features['suspicious_words_found'] = [w for w in SUSPICIOUS_WORDS if w in full_url][:5]

            # Deteccion de marca
            features['brand_mentioned'] = None
            features['brand_impersonation'] = False
            for brand in KNOWN_BRANDS:
                if brand in full_url:
                    features['brand_mentioned'] = brand
                    official = OFFICIAL_DOMAINS.get(brand, f"{brand}.com")
                    # Es suplantacion si menciona la marca pero no es el dominio oficial
                    if official not in domain and brand not in domain.split('.')[0]:
                        features['brand_impersonation'] = True
                    break

            # Dominio de confianza
            features['is_trusted'] = any(td in domain for td in TRUSTED_DOMAINS)

        except Exception as e:
            logger.error(f"Error extrayendo features: {e}")
            features['error'] = str(e)

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calcula entropia de Shannon del texto."""
        if not text:
            return 0.0
        prob = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    # ========================================================================
    # GENERACION DE SENALES
    # ========================================================================

    def _generate_signals(self, url: str, features: Dict[str, Any]) -> List[Signal]:
        """Genera senales basadas en las features extraidas."""
        signals = []
        domain = features.get('domain', '')

        # IP como host
        if features.get('contains_ip'):
            signals.append(Signal(
                id="IP_AS_HOST",
                severity=Severity.HIGH,
                weight=self.weights['IP_AS_HOST'],
                evidence={"ip": domain},
                explanation=f"La URL usa una direccion IP ({domain}) en lugar de un dominio. Los sitios legitimos usan nombres de dominio."
            ))

        # Punycode
        if features.get('has_punycode'):
            signals.append(Signal(
                id="PUNYCODE_DETECTED",
                severity=Severity.HIGH,
                weight=self.weights['PUNYCODE_DETECTED'],
                evidence={"domain": domain},
                explanation=f"El dominio '{domain}' usa caracteres Unicode (punycode) que pueden imitar sitios legitimos."
            ))

        # Suplantacion de marca
        if features.get('brand_impersonation'):
            brand = features.get('brand_mentioned', 'desconocida')
            official = OFFICIAL_DOMAINS.get(brand, f"{brand}.com")
            signals.append(Signal(
                id="BRAND_IMPERSONATION",
                severity=Severity.HIGH,
                weight=self.weights['BRAND_IMPERSONATION'],
                evidence={
                    "brand": brand,
                    "fake_domain": domain,
                    "official_domain": official
                },
                explanation=f"PHISHING: Este sitio '{domain}' intenta suplantar a '{brand.upper()}'. El dominio oficial es '{official}'."
            ))

        # URL Shortener
        if features.get('shortener_detected'):
            shortener = next((s for s in SHORTENERS if s in domain), "desconocido")
            signals.append(Signal(
                id="URL_SHORTENER",
                severity=Severity.MEDIUM,
                weight=self.weights['URL_SHORTENER'],
                evidence={"shortener": shortener},
                explanation=f"Esta URL usa el acortador '{shortener}' que oculta el destino real."
            ))

        # Paste Service
        if features.get('paste_service_detected'):
            paste = next((p for p in PASTE_SERVICES if p in domain), "desconocido")
            signals.append(Signal(
                id="PASTE_SERVICE",
                severity=Severity.MEDIUM,
                weight=self.weights['PASTE_SERVICE'],
                evidence={"service": paste},
                explanation=f"Esta URL es de '{paste}', frecuentemente usado para distribuir malware."
            ))

        # Hosting Platform
        if features.get('hosting_platform'):
            platform = next((h for h in HOSTING_PLATFORMS if h in domain), "desconocido")
            signals.append(Signal(
                id="HOSTING_PLATFORM",
                severity=Severity.MEDIUM,
                weight=self.weights['HOSTING_PLATFORM'],
                evidence={"platform": platform},
                explanation=f"URL hospedada en '{platform}'. Cualquiera puede subir contenido aqui."
            ))

        # TLD de riesgo
        if features.get('tld_risk'):
            tld = features.get('tld', '')
            signals.append(Signal(
                id="RISKY_TLD",
                severity=Severity.MEDIUM,
                weight=self.weights['RISKY_TLD'],
                evidence={"tld": f".{tld}"},
                explanation=f"El dominio usa '.{tld}', un TLD con alta tasa de abuso."
            ))

        # Palabras sospechosas
        if features.get('suspicious_words_count', 0) > 0:
            count = features['suspicious_words_count']
            words = features.get('suspicious_words_found', [])
            weight = min(count * self.weights['SUSPICIOUS_WORDS'], 30)
            signals.append(Signal(
                id="SUSPICIOUS_WORDS",
                severity=Severity.MEDIUM if count < 3 else Severity.HIGH,
                weight=weight,
                evidence={"words": words, "count": count},
                explanation=f"La URL contiene {count} palabras sospechosas: {', '.join(words[:3])}."
            ))

        # Subdominios excesivos
        if features.get('excessive_subdomains'):
            signals.append(Signal(
                id="EXCESSIVE_SUBDOMAINS",
                severity=Severity.MEDIUM,
                weight=self.weights['EXCESSIVE_SUBDOMAINS'],
                evidence={"count": features.get('num_subdomains', 0)},
                explanation="La URL tiene demasiados subdominios, comun en phishing."
            ))

        # Sin HTTPS
        if not features.get('has_https'):
            signals.append(Signal(
                id="NO_HTTPS",
                severity=Severity.LOW,
                weight=self.weights['NO_HTTPS'],
                evidence={},
                explanation="La URL no usa conexion segura HTTPS."
            ))

        # URL muy larga
        if features.get('url_length', 0) > 100:
            signals.append(Signal(
                id="LONG_URL",
                severity=Severity.LOW,
                weight=self.weights['LONG_URL'],
                evidence={"length": features.get('url_length')},
                explanation="La URL es inusualmente larga."
            ))

        # Alto ratio de digitos
        if features.get('digit_ratio', 0) > 0.3:
            signals.append(Signal(
                id="HIGH_DIGIT_RATIO",
                severity=Severity.LOW,
                weight=self.weights['HIGH_DIGIT_RATIO'],
                evidence={"ratio": round(features.get('digit_ratio', 0), 2)},
                explanation="La URL contiene muchos numeros."
            ))

        # Alta entropia
        if features.get('entropy', 0) > 4.0:
            signals.append(Signal(
                id="HIGH_ENTROPY",
                severity=Severity.LOW,
                weight=self.weights['HIGH_ENTROPY'],
                evidence={"entropy": round(features.get('entropy', 0), 2)},
                explanation="El dominio parece aleatorio (alta entropia)."
            ))

        # Simbolo @
        if features.get('has_at_symbol'):
            signals.append(Signal(
                id="AT_SYMBOL",
                severity=Severity.MEDIUM,
                weight=self.weights['AT_SYMBOL'],
                evidence={},
                explanation="La URL contiene @ que puede usarse para engañar sobre el destino."
            ))

        return signals

    # ========================================================================
    # PREDICCION PRINCIPAL
    # ========================================================================

    def predict(self, url: str, use_tranco: bool = True, use_virustotal: bool = True, use_whois: bool = True) -> Tuple[int, float, RiskLevel, List[Signal]]:
        """
        Predice el riesgo de una URL usando SOLO heuristicas.

        Este metodo es completamente independiente del modelo ML.

        Args:
            url: URL a analizar
            use_tranco: Si usar la API de Tranco
            use_virustotal: Si usar VirusTotal para verificacion
            use_whois: Si usar WHOIS para verificar antiguedad del dominio

        Returns:
            Tuple[score, probability, risk_level, signals]
        """
        # Extraer features
        features = self._extract_features(url)
        domain = features.get('domain', '')

        # Generar senales
        signals = self._generate_signals(url, features)

        # Calcular score base sumando pesos de senales
        score = sum(s.weight for s in signals)

        # === VERIFICACION CON TRANCO ===
        in_tranco = False
        tranco_rank = 0

        if use_tranco and tranco_service.enabled:
            try:
                in_tranco, tranco_rank = tranco_service.check_url(url)

                if in_tranco and tranco_rank:
                    # Bonificacion por estar en Tranco (excepto hosting platforms)
                    if not features.get('hosting_platform'):
                        bonus = self.weights['DOMAIN_IN_TRANCO']
                        score = max(0, score + bonus)  # bonus es negativo
                        signals.append(Signal(
                            id="DOMAIN_IN_TRANCO",
                            severity=Severity.LOW,
                            weight=bonus,
                            evidence={"rank": tranco_rank},
                            explanation=f"Dominio verificado en Tranco Top 100k (rank: {tranco_rank})."
                        ))
            except Exception as e:
                logger.warning(f"Error consultando Tranco: {e}")

        # Fallback: lista local de dominios de confianza
        if not in_tranco and features.get('is_trusted'):
            bonus = self.weights['TRUSTED_DOMAIN']
            score = max(0, score + bonus)
            signals.append(Signal(
                id="TRUSTED_DOMAIN",
                severity=Severity.LOW,
                weight=bonus,
                evidence={"domain": domain},
                explanation="Dominio reconocido como sitio de confianza."
            ))

        # Si no esta en Tranco y tiene senales sospechosas
        if not in_tranco and not features.get('is_trusted'):
            has_suspicious = any(s.id in ['SUSPICIOUS_WORDS', 'RISKY_TLD', 'BRAND_IMPERSONATION'] for s in signals)
            if has_suspicious:
                signals.append(Signal(
                    id="DOMAIN_NOT_IN_TRANCO",
                    severity=Severity.MEDIUM,
                    weight=self.weights['DOMAIN_NOT_IN_TRANCO'],
                    evidence={"domain": domain},
                    explanation=f"El dominio '{domain}' NO esta en la lista de sitios legitimos conocidos."
                ))
                score += self.weights['DOMAIN_NOT_IN_TRANCO']

        # === VERIFICACION DE ANTIGUEDAD DEL DOMINIO (WHOIS) ===
        if use_whois and whois_service.is_available:
            # Solo consultar WHOIS si el dominio no es de confianza conocido
            # (evita consultas innecesarias para google.com, etc.)
            if not in_tranco and not features.get('is_trusted'):
                try:
                    is_new, age_days = whois_service.is_new_domain(url)

                    if is_new and age_days is not None:
                        # Dominio muy nuevo - alta sospecha
                        weight = self.weights['DOMAIN_TOO_NEW']
                        score = min(100, score + weight)
                        signals.append(Signal(
                            id="DOMAIN_TOO_NEW",
                            severity=Severity.HIGH,
                            weight=weight,
                            evidence={
                                "domain": domain,
                                "age_days": age_days,
                                "threshold_days": 30
                            },
                            explanation=f"ALERTA: El dominio '{domain}' fue registrado hace solo {age_days} dias. Los sitios de phishing suelen usar dominios recien creados."
                        ))
                    elif age_days is not None and age_days > 365:
                        # Dominio establecido (mas de 1 año) - bonificacion leve
                        bonus = self.weights.get('DOMAIN_ESTABLISHED', -15)
                        score = max(0, score + bonus)
                        signals.append(Signal(
                            id="DOMAIN_ESTABLISHED",
                            severity=Severity.LOW,
                            weight=bonus,
                            evidence={
                                "domain": domain,
                                "age_days": age_days,
                                "years": round(age_days / 365, 1)
                            },
                            explanation=f"El dominio tiene {round(age_days / 365, 1)} años de antiguedad."
                        ))

                except Exception as e:
                    logger.debug(f"Error verificando antiguedad del dominio: {e}")

        # === VERIFICACION CON VIRUSTOTAL ===
        if use_virustotal and virustotal_service.enabled:
            # Consultar VT si hay incertidumbre o es hosting platform
            should_consult = (
                30 <= score <= 70 or
                features.get('hosting_platform') or
                (not in_tranco and not features.get('is_trusted'))
            )

            if should_consult:
                try:
                    vt_result = virustotal_service.check_url(url, wait_for_analysis=False)

                    if vt_result.analyzed:
                        if vt_result.is_malicious:
                            malicious_count = vt_result.malicious_count

                            if malicious_count >= 10:
                                vt_weight = self.weights['VIRUSTOTAL_MALICIOUS_CRITICAL']
                                severity = Severity.HIGH
                            elif malicious_count >= 5:
                                vt_weight = self.weights['VIRUSTOTAL_MALICIOUS_HIGH']
                                severity = Severity.HIGH
                            elif malicious_count >= 3:
                                vt_weight = self.weights['VIRUSTOTAL_MALICIOUS_MED']
                                severity = Severity.MEDIUM
                            else:
                                vt_weight = self.weights['VIRUSTOTAL_MALICIOUS_LOW']
                                severity = Severity.LOW

                            score = min(100, score + vt_weight)
                            signals.append(Signal(
                                id="VIRUSTOTAL_DETECTION",
                                severity=severity,
                                weight=vt_weight,
                                evidence={
                                    "malicious_count": malicious_count,
                                    "total_engines": vt_result.total_engines
                                },
                                explanation=f"VIRUSTOTAL: {malicious_count} motores detectan esta URL como maliciosa."
                            ))

                        elif vt_result.harmless_count > vt_result.total_engines * 0.8:
                            bonus = self.weights['VIRUSTOTAL_CLEAN']
                            score = max(0, score + bonus)
                            signals.append(Signal(
                                id="VIRUSTOTAL_CLEAN",
                                severity=Severity.LOW,
                                weight=bonus,
                                evidence={
                                    "harmless_count": vt_result.harmless_count,
                                    "total_engines": vt_result.total_engines
                                },
                                explanation=f"VIRUSTOTAL: {vt_result.harmless_count} motores confirman que esta URL es segura."
                            ))

                except Exception as e:
                    logger.warning(f"Error consultando VirusTotal: {e}")

        # Asegurar que score este en rango [0, 100]
        score = max(0, min(100, score))
        probability = score / 100.0

        # Determinar nivel de riesgo
        if score == 0:
            risk_level = RiskLevel.SAFE
        elif score <= 30:
            risk_level = RiskLevel.LOW
        elif score <= 70:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.HIGH

        return score, probability, risk_level, signals

    def get_recommendations(self, risk_level: RiskLevel, signals: List[Signal]) -> List[str]:
        """Genera recomendaciones basadas en el nivel de riesgo."""
        recommendations = []

        if risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "NO ingrese informacion personal o credenciales en este sitio",
                "Esta URL presenta multiples indicadores de phishing",
                "Verifique la URL oficial del servicio que busca",
                "Reporte esta URL si la recibio por SMS o WhatsApp"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Proceda con precaucion",
                "Verifique la autenticidad del sitio antes de ingresar datos",
                "Considere contactar directamente al servicio por canales oficiales"
            ])
        elif risk_level == RiskLevel.SAFE:
            recommendations.extend([
                "Esta URL es segura",
                "No se detectaron indicadores de phishing"
            ])
        else:
            recommendations.extend([
                "La URL parece segura, pero siempre verifique",
                "Asegurese de que el sitio use HTTPS antes de ingresar datos sensibles"
            ])

        # Recomendaciones especificas por senal
        for signal in signals:
            if signal.id == "URL_SHORTENER":
                recommendations.append("Considere expandir la URL corta antes de visitarla")
            elif signal.id == "BRAND_IMPERSONATION":
                recommendations.append("Este sitio parece suplantar una marca. Verifique la URL oficial")
            elif signal.id == "VIRUSTOTAL_DETECTION":
                recommendations.append("ALERTA: VirusTotal ha detectado esta URL como maliciosa")

        return recommendations[:5]


# Singleton del predictor heuristico
heuristic_predictor = HeuristicPredictor()
