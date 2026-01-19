"""
Predictor de URLs - Carga modelo y genera predicciones con senales

SEGURIDAD: El modelo se verifica con hash SHA256 antes de cargar
para prevenir ejecucion de codigo malicioso via pickle.
"""

import pickle
import hashlib
import logging
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional

import pandas as pd

from app.core.config import settings
from app.services.feature_extractor import (
    extract_features,
    extract_features_with_tranco,
    get_brand_mentioned,
    is_official_domain,
    is_trusted_domain,
    SUSPICIOUS_WORDS,
    SHORTENERS,
    RISKY_TLDS,
    PASTE_SERVICES,
    HOSTING_PLATFORMS,
    KNOWN_BRANDS,
    TRUSTED_DOMAINS
)
from app.services.tranco_service import tranco_service
from app.services.virustotal_service import virustotal_service
from app.schemas.analyze import Signal, Severity, RiskLevel

logger = logging.getLogger(__name__)


class URLPredictor:
    """Predictor de URLs maliciosas."""

    # Hash SHA256 del modelo autorizado
    # IMPORTANTE: Actualizar este hash cuando se reentrene el modelo
    # Generar con: python -c "import hashlib; print(hashlib.sha256(open('models/step1_baseline.pkl','rb').read()).hexdigest())"
    # Modelo v2.0 - Entrenado con dataset balanceado (incluye legítimos NO en Tranco)
    AUTHORIZED_MODEL_HASH = "dc62a6098c0dd585bae3e77599d8396cf623f8df2846dbeffde650f9251ba43f"

    def __init__(self):
        self.pipeline = None
        self.feature_names = None
        self._loaded = False
        self._model_hash = None

    def _verify_model_integrity(self, model_path: Path) -> tuple[bool, str]:
        """
        Verifica la integridad del modelo antes de cargarlo.

        SEGURIDAD: Previene ejecucion de codigo malicioso si el archivo
        .pkl fue modificado por un atacante.

        Returns:
            Tuple[bool, str]: (es_valido, hash_calculado)
        """
        try:
            with open(model_path, 'rb') as f:
                content = f.read()

            calculated_hash = hashlib.sha256(content).hexdigest()
            is_valid = calculated_hash == self.AUTHORIZED_MODEL_HASH

            return is_valid, calculated_hash
        except Exception as e:
            logger.error(f"Error verificando integridad del modelo: {e}")
            return False, ""

    def load_model(self):
        """
        Carga el modelo desde disco con verificacion de integridad.

        SEGURIDAD: El modelo se verifica con SHA256 antes de deserializar
        para prevenir ataques de pickle malicioso.
        """
        model_path = settings.get_model_path()

        if not model_path.exists():
            logger.warning(f"Modelo no encontrado en {model_path}")
            return False

        try:
            # PASO 1: Verificar integridad ANTES de cargar
            is_valid, calculated_hash = self._verify_model_integrity(model_path)

            if not is_valid:
                logger.error(
                    f"SEGURIDAD: Hash del modelo no coincide!\n"
                    f"  Esperado: {self.AUTHORIZED_MODEL_HASH}\n"
                    f"  Calculado: {calculated_hash}\n"
                    f"  El modelo puede haber sido modificado. NO se cargara."
                )
                return False

            # PASO 2: Cargar modelo (solo si hash es valido)
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)

            self.pipeline = model_data['pipeline']
            self.feature_names = model_data['feature_names']
            self._loaded = True
            self._model_hash = calculated_hash

            logger.info(f"Modelo cargado y verificado desde {model_path}")
            logger.info(f"Hash SHA256: {calculated_hash[:16]}...")
            return True

        except Exception as e:
            logger.error(f"Error cargando modelo: {e}")
            return False

    def get_model_info(self) -> dict:
        """Retorna informacion del modelo cargado."""
        return {
            "loaded": self._loaded,
            "hash": self._model_hash[:16] + "..." if self._model_hash else None,
            "features_count": len(self.feature_names) if self.feature_names else 0,
            "verified": self._model_hash == self.AUTHORIZED_MODEL_HASH if self._model_hash else False
        }

    def is_loaded(self) -> bool:
        """Verifica si el modelo esta cargado."""
        return self._loaded

    def predict(self, url: str, use_tranco: bool = True, use_virustotal: bool = True) -> Tuple[int, float, RiskLevel, List[Signal]]:
        """
        Predice el riesgo de una URL.

        FILOSOFÍA DEL MODELO (según agente de detección):
        - datos_malos → label=1 (phishing/malicioso)
        - datos_buenos → label=0 (legítimo)
        - Si el modelo NO tiene suficiente contexto → preguntar a VirusTotal
        - NUNCA asumir, siempre verificar cuando hay incertidumbre

        Args:
            url: URL a analizar
            use_tranco: Si usar la API de Tranco para verificacion online
            use_virustotal: Si usar VirusTotal cuando hay incertidumbre

        Returns:
            Tuple[score, probability, risk_level, signals]
        """
        # Extraer features (con o sin Tranco)
        if use_tranco and tranco_service.enabled:
            features_dict = extract_features_with_tranco(url, tranco_service)
        else:
            features_dict = extract_features(url)
            # Agregar features de Tranco con valores por defecto
            features_dict['in_tranco'] = 0
            features_dict['tranco_rank'] = 0
            features_dict['brand_impersonation'] = 0

        # Generar senales basadas en heuristicas
        signals = self._generate_signals(url, features_dict)

        # Calcular score combinando ML + heuristicas
        ml_score = 0
        ml_probability = 0.5  # Incertidumbre máxima por defecto
        ml_confidence = 0.0   # Sin confianza por defecto
        heuristic_score = self._calculate_heuristic_score(signals)

        # Si el modelo esta cargado, usar ML
        if self._loaded and self.pipeline is not None:
            # Crear DataFrame con features en orden correcto
            X = pd.DataFrame([features_dict])[self.feature_names]

            # Predecir con ML
            ml_probability = self.pipeline.predict_proba(X)[0, 1]
            ml_score = int(ml_probability * 100)

            # CONFIANZA del modelo: qué tan seguro está de su predicción
            # 0.0 = totalmente incierto (prob=0.5), 1.0 = totalmente seguro (prob=0 o 1)
            ml_confidence = abs(ml_probability - 0.5) * 2

        # Combinar ML + Heuristicas (max de ambos + boost por señales criticas)
        # Las señales criticas siempre aportan al score
        critical_boost = 0
        for signal in signals:
            if signal.id in ['BRAND_IMPERSONATION', 'IP_AS_HOST', 'PUNYCODE_DETECTED']:
                critical_boost += signal.weight
            elif signal.id in ['PASTE_SERVICE', 'URL_SHORTENER', 'RISKY_TLD']:
                critical_boost += signal.weight // 2
            elif signal.id == 'SUSPICIOUS_WORDS':
                critical_boost += signal.weight // 3

        # Score final: maximo entre ML y heuristicas + boost critico
        base_score = max(ml_score, heuristic_score)
        score = min(100, base_score + critical_boost)

        # === VERIFICACIÓN DE CONTEXTO ===
        # El modelo tiene contexto si:
        # 1. El dominio está en Tranco (datos_buenos verificados)
        # 2. Hay señales claras de phishing (datos_malos conocidos)
        #
        # NOTA IMPORTANTE: El modelo ML tiene OVERFITTING en la feature in_tranco.
        # El dataset de entrenamiento tiene:
        # - TODOS los datos_buenos con in_tranco=1
        # - TODOS los datos_malos con in_tranco=0
        # Esto hace que el modelo aprenda: "si no está en Tranco = phishing"
        #
        # Por lo tanto, cuando in_tranco=0:
        # - La confianza del ML es FALSA (solo aprendió la correlación)
        # - NO debemos confiar en el ML, debemos verificar con VirusTotal

        is_infrastructure = features_dict.get('paste_service_detected') or features_dict.get('shortener_detected')
        domain_is_known = features_dict.get('in_tranco', 0) == 1
        has_clear_phishing_signals = any(s.id in ['BRAND_IMPERSONATION', 'IP_AS_HOST', 'PUNYCODE_DETECTED'] for s in signals)

        # Detectar si es una plataforma de hosting (appspot.com, github.io, etc.)
        # Estas plataformas pueden hospedar contenido malicioso aunque el dominio sea confiable
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            url_domain = parsed_url.netloc.lower()
            is_hosting_platform = any(platform in url_domain for platform in HOSTING_PLATFORMS)
            if is_hosting_platform:
                logger.info(f"Detectada plataforma de hosting: {url_domain}")
        except:
            is_hosting_platform = False

        # CORRECCIÓN POR OVERFITTING: Si in_tranco=0, el modelo NO tiene contexto real
        # porque solo aprendió la correlación in_tranco ↔ label
        # Solo confiamos en el modelo si hay señales ADICIONALES de phishing
        if not domain_is_known:
            # Dominio desconocido - el ML no tiene contexto real
            # Solo tiene contexto si hay señales claras de phishing
            has_sufficient_context = has_clear_phishing_signals
            logger.debug(f"Dominio no está en Tranco - contexto basado en señales: {has_clear_phishing_signals}")
        else:
            # Dominio conocido (Tranco) - el modelo tiene contexto
            has_sufficient_context = True

        # Si es sitio conocido (Tranco), reducir score
        # PERO NO reducir si es una plataforma de hosting (appspot.com, github.io, etc.)
        if domain_is_known and not is_infrastructure and not is_hosting_platform:
            tranco_rank = features_dict.get('tranco_rank', 0)
            # Sitios muy populares (top 1000, rank > 0.999) - son datos_buenos verificados
            if tranco_rank > 0.999:
                score = max(0, score - 50)
            elif tranco_rank > 0.99:
                score = max(0, score - 40)
            elif tranco_rank > 0.9:
                score = max(0, score - 35)
            else:
                score = max(0, score - 30)
            logger.debug(f"Dominio en Tranco (datos_buenos): {url}, tranco_rank={tranco_rank}")
        elif is_hosting_platform:
            logger.info(f"NO se aplica reduccion Tranco por ser plataforma de hosting: {url}")
        # Fallback: lista local de dominios de confianza
        elif not domain_is_known and not is_infrastructure:
            is_trusted, trusted_rank = is_trusted_domain(url)
            if is_trusted:
                score = max(0, score - 50)
                has_sufficient_context = True
                logger.debug(f"Dominio de confianza local: {url}, rank={trusted_rank}")

        # === VIRUSTOTAL: Consultar cuando el modelo NO tiene contexto suficiente ===
        # Según el agente de detección: "Si el modelo no tiene suficiente contexto,
        # debe preguntar a VirusTotal, en lugar de asumir."
        vt_consulted = False
        if use_virustotal and virustotal_service.enabled:
            uncertainty_min = settings.VIRUSTOTAL_UNCERTAINTY_MIN
            uncertainty_max = settings.VIRUSTOTAL_UNCERTAINTY_MAX

            # NUEVA LÓGICA: Consultar VT si:
            # 1. El modelo NO tiene contexto suficiente (dominio desconocido + baja confianza)
            # 2. O el score está en zona de incertidumbre tradicional (30-70)
            # 3. O es una plataforma de hosting (cualquiera puede subir contenido malicioso)
            should_consult_vt = (
                not has_sufficient_context or  # Modelo no tiene contexto
                (uncertainty_min <= score <= uncertainty_max) or  # Zona de incertidumbre
                is_hosting_platform  # Plataformas de hosting siempre consultan VT
            )

            if should_consult_vt:
                if is_hosting_platform:
                    reason = "plataforma de hosting (contenido no verificado)"
                elif not has_sufficient_context:
                    reason = "sin contexto suficiente"
                else:
                    reason = f"score {score} en zona de incertidumbre"
                logger.info(f"Consultando VirusTotal ({reason})...")
                vt_result = virustotal_service.check_url(url, wait_for_analysis=False)

                if vt_result.analyzed:
                    vt_consulted = True
                    vt_signal = self._generate_virustotal_signal(vt_result)
                    if vt_signal:
                        signals.append(vt_signal)

                    # Ajustar score basado en VirusTotal
                    if vt_result.is_malicious:
                        # VT confirma malicioso - boost escalonado según cantidad de motores
                        malicious_count = vt_result.malicious_count
                        if malicious_count >= 10:
                            vt_boost = 70  # 10+ motores = muy peligroso
                        elif malicious_count >= 5:
                            vt_boost = 55  # 5-9 motores = peligroso -> HIGH
                        elif malicious_count >= 3:
                            vt_boost = 35  # 3-4 motores = sospechoso
                        else:
                            vt_boost = 20  # 1-2 motores = poco confiable
                        score = min(100, score + vt_boost)
                        logger.info(f"VT detecta malicioso ({malicious_count} motores, boost={vt_boost}), nuevo score: {score}")
                    elif vt_result.harmless_count > vt_result.total_engines * 0.8:
                        # VT confirma seguro - esto DA contexto al modelo
                        # Reducir score significativamente porque VT verificó
                        old_score = score
                        score = max(0, score - 30)
                        has_sufficient_context = True  # Ahora tenemos contexto de VT
                        logger.info(f"VT confirma seguro ({vt_result.harmless_count} motores), score: {old_score} -> {score}")

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

    def _generate_virustotal_signal(self, vt_result) -> Optional[Signal]:
        """Genera senal basada en resultado de VirusTotal."""
        if not vt_result.analyzed:
            return None

        total_detections = vt_result.malicious_count + vt_result.suspicious_count

        if total_detections > 0:
            # Determinar severidad basada en cantidad de detecciones
            if total_detections >= 10:
                severity = Severity.HIGH
                weight = 40
            elif total_detections >= 5:
                severity = Severity.HIGH
                weight = 30
            elif total_detections >= 3:
                severity = Severity.MEDIUM
                weight = 20
            else:
                severity = Severity.LOW
                weight = 10

            return Signal(
                id="VIRUSTOTAL_DETECTION",
                severity=severity,
                weight=weight,
                evidence={
                    "malicious_engines": vt_result.malicious_count,
                    "suspicious_engines": vt_result.suspicious_count,
                    "total_engines": vt_result.total_engines,
                    "threat_names": vt_result.threat_names[:5],
                    "categories": dict(list(vt_result.categories.items())[:3]),
                    "last_analysis": vt_result.last_analysis_date
                },
                explanation=f"VIRUSTOTAL: {total_detections} de {vt_result.total_engines} motores antivirus detectan esta URL como maliciosa. Amenazas: {', '.join(vt_result.threat_names[:3]) if vt_result.threat_names else 'phishing/malware'}."
            )
        elif vt_result.harmless_count > vt_result.total_engines * 0.8:
            # Mayoria dice que es seguro - no agregar senal de alerta
            return Signal(
                id="VIRUSTOTAL_CLEAN",
                severity=Severity.LOW,
                weight=0,
                evidence={
                    "harmless_engines": vt_result.harmless_count,
                    "total_engines": vt_result.total_engines,
                    "last_analysis": vt_result.last_analysis_date
                },
                explanation=f"VIRUSTOTAL: {vt_result.harmless_count} de {vt_result.total_engines} motores confirman que esta URL es segura."
            )

        return None

    def _generate_signals(self, url: str, features: Dict[str, Any]) -> List[Signal]:
        """Genera senales explicables basadas en las features."""
        signals = []

        # Extraer dominio para evidencia detallada
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
        except:
            domain = url
            path = ""

        # IP como host
        if features.get('contains_ip'):
            signals.append(Signal(
                id="IP_AS_HOST",
                severity=Severity.HIGH,
                weight=25,
                evidence={
                    "ip_address": domain.split(':')[0],
                    "url": url,
                    "reason": "Los sitios legitimos usan nombres de dominio, no direcciones IP"
                },
                explanation=f"ALERTA: La URL usa la IP '{domain.split(':')[0]}' en lugar de un dominio. Los sitios de phishing usan IPs para evitar ser rastreados."
            ))

        # Punycode (caracteres unicode que imitan letras)
        if features.get('has_punycode'):
            signals.append(Signal(
                id="PUNYCODE_DETECTED",
                severity=Severity.HIGH,
                weight=20,
                evidence={
                    "domain": domain,
                    "technique": "Homograph Attack",
                    "example": "xn--pypal-4ve.com puede verse como 'pаypal.com' usando caracteres cirilicos",
                    "risk": "El dominio usa caracteres especiales que pueden parecer letras normales"
                },
                explanation=f"PELIGRO: El dominio '{domain}' usa caracteres Unicode (punycode) que pueden imitar sitios legitimos. Tecnica conocida como 'Homograph Attack'."
            ))

        # URL Shortener - detectar cual servicio
        if features.get('shortener_detected'):
            shortener_used = next((s for s in SHORTENERS if s in domain), "desconocido")
            signals.append(Signal(
                id="URL_SHORTENER",
                severity=Severity.MEDIUM,
                weight=15,
                evidence={
                    "shortener_service": shortener_used,
                    "domain": domain,
                    "risk": "Los acortadores ocultan el destino real de la URL",
                    "recommendation": "Usar servicios como unshorten.me para ver el destino real"
                },
                explanation=f"SOSPECHOSO: Esta URL usa el acortador '{shortener_used}' que oculta el destino real. Los atacantes usan acortadores para esconder URLs maliciosas."
            ))

        # Servicio de paste (Pastebin, etc.)
        if features.get('paste_service_detected'):
            paste_service = next((p for p in PASTE_SERVICES if p in domain), "desconocido")
            signals.append(Signal(
                id="PASTE_SERVICE",
                severity=Severity.MEDIUM,
                weight=20,
                evidence={
                    "paste_service": paste_service,
                    "domain": domain,
                    "common_threats": ["Distribucion de malware", "Enlaces de phishing", "Software pirata", "Credenciales robadas"],
                    "risk": "Los servicios de paste son usados para compartir contenido malicioso anonimamente"
                },
                explanation=f"ALERTA: Esta URL es de '{paste_service}', un servicio frecuentemente usado para distribuir malware, enlaces de phishing y software pirata. Verifique el origen antes de acceder."
            ))

        # Palabras sospechosas - detectar cuales
        suspicious_count = features.get('has_suspicious_words', 0)
        if suspicious_count > 0:
            url_lower = url.lower()
            found_words = [w for w in SUSPICIOUS_WORDS if w in url_lower][:5]  # Max 5

            # Categorizar las palabras encontradas
            phishing_words = [w for w in found_words if w in ['login', 'signin', 'verify', 'update', 'secure', 'account', 'password', 'confirm', 'validate', 'authenticate']]
            brand_words = [w for w in found_words if w in ['paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'bank']]
            piracy_words = [w for w in found_words if w in ['crack', 'keygen', 'serial', 'patch', 'activator', 'kms', 'warez', 'nulled', 'cracked', 'torrent']]

            category = "phishing" if phishing_words else ("pirateria/malware" if piracy_words else "sospechoso")

            signals.append(Signal(
                id="SUSPICIOUS_WORDS",
                severity=Severity.MEDIUM if suspicious_count < 3 else Severity.HIGH,
                weight=min(suspicious_count * 7, 25),
                evidence={
                    "words_found": found_words,
                    "count": suspicious_count,
                    "phishing_keywords": phishing_words,
                    "brand_keywords": brand_words,
                    "piracy_keywords": piracy_words,
                    "category": category
                },
                explanation=f"DETECTADO: La URL contiene {suspicious_count} palabras de {category}: {', '.join(found_words)}. Estas palabras son comunes en sitios fraudulentos."
            ))

        # TLD de riesgo - con estadisticas
        if features.get('tld_risk'):
            tld = domain.split('.')[-1] if domain else ''
            # TLDs mas peligrosos con estadisticas aproximadas
            high_risk_tlds = {'tk': '95%', 'ml': '90%', 'ga': '90%', 'cf': '90%', 'gq': '85%'}
            medium_risk_tlds = {'xyz': '60%', 'top': '55%', 'club': '50%', 'online': '45%', 'site': '45%'}

            risk_percentage = high_risk_tlds.get(tld, medium_risk_tlds.get(tld, '40%'))
            risk_category = "MUY ALTO" if tld in high_risk_tlds else "ALTO"

            signals.append(Signal(
                id="RISKY_TLD",
                severity=Severity.HIGH if tld in high_risk_tlds else Severity.MEDIUM,
                weight=15 if tld in high_risk_tlds else 10,
                evidence={
                    "tld": f".{tld}",
                    "domain": domain,
                    "risk_level": risk_category,
                    "abuse_rate": risk_percentage,
                    "reason": f"El TLD .{tld} tiene una tasa de abuso del {risk_percentage} segun estadisticas de phishing"
                },
                explanation=f"RIESGO {risk_category}: El dominio usa '.{tld}', un TLD con {risk_percentage} de tasa de abuso. Los sitios legitimos raramente usan este tipo de dominios."
            ))

        # Subdominios excesivos
        if features.get('excessive_subdomains'):
            signals.append(Signal(
                id="EXCESSIVE_SUBDOMAINS",
                severity=Severity.MEDIUM,
                weight=10,
                evidence={"count": features.get('num_subdomains', 0)},
                explanation="La URL tiene demasiados subdominios, comun en phishing"
            ))

        # Sin HTTPS
        if not features.get('has_https'):
            signals.append(Signal(
                id="NO_HTTPS",
                severity=Severity.LOW,
                weight=5,
                evidence={},
                explanation="La URL no usa conexion segura HTTPS"
            ))

        # URL muy larga
        if features.get('url_length', 0) > 100:
            signals.append(Signal(
                id="LONG_URL",
                severity=Severity.LOW,
                weight=5,
                evidence={"length": features.get('url_length')},
                explanation="La URL es inusualmente larga"
            ))

        # Alto ratio de digitos
        if features.get('digit_ratio', 0) > 0.3:
            signals.append(Signal(
                id="HIGH_DIGIT_RATIO",
                severity=Severity.LOW,
                weight=5,
                evidence={"ratio": round(features.get('digit_ratio', 0), 2)},
                explanation="La URL contiene muchos numeros"
            ))

        # Simbolo @
        if features.get('has_at_symbol'):
            signals.append(Signal(
                id="AT_SYMBOL",
                severity=Severity.MEDIUM,
                weight=15,
                evidence={},
                explanation="La URL contiene @ que puede usarse para engañar sobre el destino"
            ))

        # === SENALES DE TRANCO (verificacion online) ===

        # Suplantacion de marca (menciona marca pero no es dominio oficial)
        if features.get('brand_impersonation'):
            brand = get_brand_mentioned(url)
            from app.services.feature_extractor import OFFICIAL_DOMAINS
            official_domain = OFFICIAL_DOMAINS.get(brand, f"{brand}.com")

            signals.append(Signal(
                id="BRAND_IMPERSONATION",
                severity=Severity.HIGH,
                weight=40,
                evidence={
                    "brand_detected": brand,
                    "fake_domain": domain,
                    "official_domain": official_domain,
                    "technique": "Brand Impersonation / Typosquatting",
                    "comparison": f"'{domain}' vs '{official_domain}'",
                    "risk": "Este sitio intenta hacerse pasar por una marca conocida"
                },
                explanation=f"PHISHING DETECTADO: Este sitio '{domain}' intenta suplantar a '{brand.upper()}'. El dominio oficial es '{official_domain}'. NO ingrese sus credenciales."
            ))

        # Detectar plataforma de hosting
        is_hosting = any(platform in domain for platform in HOSTING_PLATFORMS)
        if is_hosting:
            hosting_service = next((p for p in HOSTING_PLATFORMS if p in domain), "desconocido")
            signals.append(Signal(
                id="HOSTING_PLATFORM",
                severity=Severity.MEDIUM,
                weight=15,
                evidence={
                    "platform": hosting_service,
                    "domain": domain,
                    "risk": "Cualquier persona puede hospedar contenido en esta plataforma",
                    "examples": ["phishing", "malware", "scams"]
                },
                explanation=f"ATENCION: Esta URL esta hospedada en '{hosting_service}', una plataforma donde cualquiera puede subir contenido. Aunque el dominio es confiable, el contenido puede ser malicioso."
            ))

        # Dominio NO esta en Tranco pero tiene palabras sospechosas o TLD de riesgo
        if not features.get('in_tranco') and (
            features.get('has_suspicious_words', 0) > 0 or
            features.get('tld_risk') or
            features.get('brand_impersonation')
        ):
            signals.append(Signal(
                id="DOMAIN_NOT_IN_TRANCO",
                severity=Severity.MEDIUM,
                weight=15,
                evidence={
                    "domain": domain,
                    "tranco_status": "NO VERIFICADO",
                    "database": "Tranco Top 1 Millon",
                    "implication": "Este dominio no es conocido como sitio legitimo",
                    "note": "Los sitios de phishing usan dominios nuevos o desconocidos"
                },
                explanation=f"VERIFICACION: El dominio '{domain}' NO aparece en la lista de los 1 millon de sitios web mas visitados y confiables (Tranco). Los sitios legitimos suelen estar en esta lista."
            ))

        # Dominio SI esta en Tranco (senal positiva - se maneja en el scoring)
        # No agregamos senal aqui porque los pesos deben ser >= 0
        # El scoring ya considera in_tranco para reducir el riesgo

        return signals

    def _calculate_heuristic_score(self, signals: List[Signal]) -> int:
        """Calcula score basado solo en heuristicas."""
        total_weight = sum(s.weight for s in signals)
        return min(total_weight, 100)

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

        # Agregar recomendaciones especificas por senal
        for signal in signals:
            if signal.id == "URL_SHORTENER":
                recommendations.append("Considere expandir la URL corta antes de visitarla")
            elif signal.id == "NO_HTTPS":
                recommendations.append("No ingrese contraseñas en sitios sin HTTPS")
            elif signal.id == "PASTE_SERVICE":
                recommendations.append("Los servicios de paste son usados frecuentemente para distribuir malware. Verifique el origen del enlace")
            elif signal.id == "BRAND_IMPERSONATION":
                recommendations.append("Este sitio parece suplantar una marca conocida. Verifique la URL oficial antes de continuar")
            elif signal.id == "DOMAIN_NOT_IN_TRANCO":
                recommendations.append("Este dominio no esta en la lista de sitios legitimos conocidos. Proceda con extrema precaucion")
            elif signal.id == "VIRUSTOTAL_DETECTION":
                recommendations.append("ALERTA: VirusTotal ha detectado esta URL como maliciosa. No visite este sitio.")
            elif signal.id == "VIRUSTOTAL_CLEAN":
                recommendations.append("VirusTotal confirma que esta URL es segura segun multiples motores antivirus.")

        return recommendations[:5]  # Maximo 5 recomendaciones


# Singleton del predictor
predictor = URLPredictor()
