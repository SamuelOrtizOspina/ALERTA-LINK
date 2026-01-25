"""
Servicio de integracion con VirusTotal API v3

Permite verificar URLs contra la base de datos de VirusTotal
cuando el modelo tiene incertidumbre en su prediccion.
"""

import base64
import logging
import time
import requests
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class VirusTotalResult:
    """Resultado del analisis de VirusTotal."""
    analyzed: bool = False
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    is_malicious: bool = False
    categories: Dict[str, str] = None
    threat_names: list = None
    last_analysis_date: str = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.categories is None:
            self.categories = {}
        if self.threat_names is None:
            self.threat_names = []


class VirusTotalService:
    """Servicio para consultar VirusTotal API."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.threshold = settings.VIRUSTOTAL_THRESHOLD
        self.enabled = bool(self.api_key)
        self._last_request_time = 0
        self._min_request_interval = 15  # segundos entre requests (4/minuto limite gratuito)

    def _get_headers(self) -> Dict[str, str]:
        """Obtiene headers para la API."""
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def _rate_limit(self):
        """Espera si es necesario para respetar rate limits."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            wait_time = self._min_request_interval - elapsed
            logger.debug(f"Rate limit: esperando {wait_time:.1f}s")
            time.sleep(wait_time)
        self._last_request_time = time.time()

    def _url_to_id(self, url: str) -> str:
        """Convierte URL a ID de VirusTotal (base64 sin padding)."""
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def check_url(self, url: str, wait_for_analysis: bool = True) -> VirusTotalResult:
        """
        Verifica una URL en VirusTotal.

        Args:
            url: URL a verificar
            wait_for_analysis: Si esperar cuando se envia un nuevo analisis

        Returns:
            VirusTotalResult con los hallazgos
        """
        if not self.enabled:
            return VirusTotalResult(error="VirusTotal API no configurada")

        result = VirusTotalResult()

        try:
            # Primero intentar obtener analisis existente
            url_id = self._url_to_id(url)
            existing = self._get_url_report(url_id)

            if existing:
                return existing

            # Si no existe, enviar para analisis
            if wait_for_analysis:
                analysis_id = self._submit_url(url)
                if analysis_id:
                    # Esperar y obtener resultado
                    time.sleep(5)  # Esperar un poco para que se procese
                    return self._get_analysis_result(analysis_id, url_id)

            result.error = "No se pudo obtener analisis"

        except Exception as e:
            logger.error(f"Error consultando VirusTotal: {e}")
            result.error = str(e)

        return result

    def _get_url_report(self, url_id: str) -> Optional[VirusTotalResult]:
        """Obtiene reporte existente de una URL."""
        self._rate_limit()

        try:
            response = requests.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                return self._parse_response(response.json())
            elif response.status_code == 404:
                return None  # URL no analizada previamente
            else:
                logger.warning(f"VT API error: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Error obteniendo reporte VT: {e}")
            return None

    def _submit_url(self, url: str) -> Optional[str]:
        """Envia URL para analisis y retorna el ID del analisis."""
        self._rate_limit()

        try:
            response = requests.post(
                f"{self.BASE_URL}/urls",
                headers=self._get_headers(),
                data={"url": url},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                # Extraer ID del analisis
                analysis_id = data.get("data", {}).get("id")
                logger.info(f"URL enviada a VT, analysis_id: {analysis_id}")
                return analysis_id
            else:
                logger.warning(f"Error enviando URL a VT: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Error enviando URL a VT: {e}")
            return None

    def _get_analysis_result(self, analysis_id: str, url_id: str, max_retries: int = 3) -> VirusTotalResult:
        """Obtiene resultado de un analisis en progreso."""
        for attempt in range(max_retries):
            self._rate_limit()

            try:
                # Primero verificar estado del analisis
                response = requests.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    headers=self._get_headers(),
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")

                    if status == "completed":
                        # Obtener reporte completo de la URL
                        return self._get_url_report(url_id) or VirusTotalResult(
                            analyzed=True,
                            error="Analisis completado pero no se pudo obtener reporte"
                        )
                    elif status == "queued" or status == "in-progress":
                        logger.debug(f"Analisis en progreso, intento {attempt + 1}")
                        time.sleep(10)  # Esperar mas tiempo
                        continue

            except requests.exceptions.RequestException as e:
                logger.error(f"Error obteniendo resultado de analisis: {e}")

        return VirusTotalResult(error="Timeout esperando analisis de VT")

    def _parse_response(self, data: Dict[str, Any]) -> VirusTotalResult:
        """Parsea respuesta de VT API."""
        result = VirusTotalResult(analyzed=True)

        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            result.malicious_count = stats.get("malicious", 0)
            result.suspicious_count = stats.get("suspicious", 0)
            result.harmless_count = stats.get("harmless", 0)
            result.undetected_count = stats.get("undetected", 0)
            result.total_engines = sum(stats.values())

            # Determinar si es malicioso
            result.is_malicious = (result.malicious_count + result.suspicious_count) >= self.threshold

            # Categorias asignadas por los motores
            result.categories = attributes.get("categories", {})

            # Nombres de amenazas detectadas
            last_analysis = attributes.get("last_analysis_results", {})
            threat_names = set()
            for engine, details in last_analysis.items():
                if details.get("category") in ["malicious", "suspicious"]:
                    result_name = details.get("result")
                    if result_name:
                        threat_names.add(result_name)
            result.threat_names = list(threat_names)[:10]  # Max 10

            # Fecha del ultimo analisis
            last_date = attributes.get("last_analysis_date")
            if last_date:
                from datetime import datetime
                result.last_analysis_date = datetime.fromtimestamp(last_date).isoformat()

        except Exception as e:
            logger.error(f"Error parseando respuesta VT: {e}")
            result.error = f"Error parseando respuesta: {e}"

        return result

    def get_malicious_urls(self, limit: int = 100) -> list:
        """
        Obtiene URLs maliciosas recientes de VT para entrenamiento.

        Nota: Requiere API premium para busquedas avanzadas.
        Esta funcion usa el endpoint de busqueda basico.
        """
        if not self.enabled:
            return []

        malicious_urls = []

        # Buscar URLs marcadas como phishing
        search_queries = [
            "engines:phishing",
            "engines:malware",
            "tag:phishing"
        ]

        for query in search_queries:
            if len(malicious_urls) >= limit:
                break

            self._rate_limit()

            try:
                response = requests.get(
                    f"{self.BASE_URL}/intelligence/search",
                    headers=self._get_headers(),
                    params={"query": query, "limit": min(50, limit - len(malicious_urls))},
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("data", []):
                        url = item.get("attributes", {}).get("url")
                        if url:
                            malicious_urls.append(url)

            except Exception as e:
                logger.warning(f"Error buscando URLs maliciosas: {e}")

        return malicious_urls[:limit]


# Singleton del servicio
virustotal_service = VirusTotalService()
