"""
Servicio para consultar la API de Tranco List
https://tranco-list.eu/api/

Tranco es una lista de los sitios web mas populares/confiables del mundo.
Se usa para verificar si un dominio es legitimo.
"""

import logging
import requests
from typing import Optional, Tuple
from urllib.parse import urlparse
from functools import lru_cache
import time

from app.core.config import settings

logger = logging.getLogger(__name__)


class TrancoService:
    """Servicio para consultar rankings de dominios en Tranco List."""

    BASE_URL = "https://tranco-list.eu/api"

    def __init__(self):
        self.api_key = settings.TRANCO_API_KEY
        self.enabled = bool(self.api_key)
        self._last_request_time = 0
        self._rate_limit_delay = 1.1  # 1 query/segundo + margen

        if not self.enabled:
            logger.warning("Tranco API key no configurada. Servicio deshabilitado.")

    def _rate_limit(self):
        """Respeta el rate limit de 1 query/segundo."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    def _extract_domain(self, url: str) -> str:
        """Extrae el dominio base de una URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remover puerto si existe
            if ':' in domain:
                domain = domain.split(':')[0]

            # Remover www. si existe
            if domain.startswith('www.'):
                domain = domain[4:]

            return domain
        except Exception:
            return ""

    @lru_cache(maxsize=1000)
    def get_domain_rank(self, domain: str) -> Optional[int]:
        """
        Obtiene el ranking de un dominio en Tranco List.

        Args:
            domain: Dominio a consultar (sin protocolo)

        Returns:
            Ranking del dominio (1 = mas popular) o None si no esta en la lista
        """
        if not self.enabled:
            return None

        if not domain:
            return None

        try:
            self._rate_limit()

            url = f"{self.BASE_URL}/ranks/domain/{domain}"

            response = requests.get(
                url,
                auth=(settings.TRANCO_API_EMAIL, self.api_key),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                ranks = data.get('ranks', [])

                if ranks:
                    # Retornar el ranking mas reciente
                    latest_rank = ranks[0].get('rank')
                    logger.debug(f"Dominio {domain} encontrado en Tranco: rank {latest_rank}")
                    return latest_rank

            elif response.status_code == 429:
                logger.warning("Rate limit excedido en Tranco API")

            return None

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout consultando Tranco para {domain}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error consultando Tranco API: {e}")
            return None
        except Exception as e:
            logger.error(f"Error inesperado en Tranco service: {e}")
            return None

    def check_url(self, url: str) -> Tuple[bool, Optional[int]]:
        """
        Verifica si una URL corresponde a un dominio en Tranco List.

        Args:
            url: URL completa a verificar

        Returns:
            Tuple[in_tranco, rank]: (True/False si esta en lista, ranking o None)
        """
        domain = self._extract_domain(url)

        if not domain:
            return False, None

        rank = self.get_domain_rank(domain)

        if rank is not None:
            return True, rank

        # Si no se encontro, intentar con el dominio padre
        # Ej: si mail.google.com no esta, probar google.com
        parts = domain.split('.')
        if len(parts) > 2:
            parent_domain = '.'.join(parts[-2:])
            rank = self.get_domain_rank(parent_domain)
            if rank is not None:
                return True, rank

        return False, None

    def is_legitimate_domain(self, url: str, threshold: int = 100000) -> bool:
        """
        Verifica si un dominio es legitimo basado en su ranking.

        Args:
            url: URL a verificar
            threshold: Ranking maximo para considerar legitimo (default: top 100k)

        Returns:
            True si el dominio esta en el top {threshold} de Tranco
        """
        in_tranco, rank = self.check_url(url)

        if in_tranco and rank is not None:
            return rank <= threshold

        return False


# Singleton del servicio
tranco_service = TrancoService()
