"""
Servicio para consultar informacion WHOIS de dominios.
Permite detectar dominios recien registrados (indicador de phishing).
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urlparse
import asyncio
from functools import lru_cache

logger = logging.getLogger(__name__)


class WhoisService:
    """
    Servicio para consultar antiguedad de dominios via WHOIS.

    Dominios muy nuevos (< 30 dias) son frecuentemente usados en phishing
    porque los atacantes registran dominios desechables.
    """

    # Umbral en dias para considerar un dominio como "nuevo"
    NEW_DOMAIN_THRESHOLD_DAYS = 30

    # Cache de resultados (evita consultas repetidas)
    _cache: Dict[str, Tuple[Optional[int], datetime]] = {}
    _cache_ttl_hours = 24  # Resultados validos por 24 horas

    def __init__(self):
        """Inicializa el servicio WHOIS."""
        self._whois_available = self._check_whois_available()
        if not self._whois_available:
            logger.warning("python-whois no disponible - antiguedad de dominio deshabilitada")

    def _check_whois_available(self) -> bool:
        """Verifica si la biblioteca whois esta instalada."""
        try:
            import whois
            return True
        except ImportError:
            return False

    def _extract_domain(self, url: str) -> str:
        """
        Extrae el dominio base de una URL.

        Args:
            url: URL completa

        Returns:
            Dominio base (ej: 'example.com' de 'https://sub.example.com/path')
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remover puerto si existe
            if ':' in domain:
                domain = domain.split(':')[0]

            # Remover www
            if domain.startswith('www.'):
                domain = domain[4:]

            return domain
        except Exception:
            return ""

    def _get_from_cache(self, domain: str) -> Optional[Tuple[Optional[int], datetime]]:
        """Obtiene resultado del cache si existe y no ha expirado."""
        if domain in self._cache:
            age_days, cached_at = self._cache[domain]
            # Verificar si el cache ha expirado
            hours_since_cache = (datetime.now() - cached_at).total_seconds() / 3600
            if hours_since_cache < self._cache_ttl_hours:
                return (age_days, cached_at)
        return None

    def _add_to_cache(self, domain: str, age_days: Optional[int]) -> None:
        """Agrega resultado al cache."""
        self._cache[domain] = (age_days, datetime.now())

        # Limpiar cache si crece demasiado (max 1000 entradas)
        if len(self._cache) > 1000:
            # Eliminar las entradas mas antiguas
            sorted_items = sorted(self._cache.items(), key=lambda x: x[1][1])
            for key, _ in sorted_items[:500]:
                del self._cache[key]

    def get_domain_age_days(self, url: str) -> Optional[int]:
        """
        Obtiene la antiguedad del dominio en dias.

        Args:
            url: URL a verificar

        Returns:
            Antiguedad en dias, o None si no se pudo obtener
        """
        if not self._whois_available:
            return None

        domain = self._extract_domain(url)
        if not domain:
            return None

        # Verificar cache
        cached = self._get_from_cache(domain)
        if cached is not None:
            age_days, _ = cached
            logger.debug(f"WHOIS cache hit para {domain}: {age_days} dias")
            return age_days

        try:
            import whois

            # Consultar WHOIS
            w = whois.whois(domain)

            if w is None:
                self._add_to_cache(domain, None)
                return None

            # Obtener fecha de creacion
            creation_date = w.creation_date

            if creation_date is None:
                self._add_to_cache(domain, None)
                return None

            # Algunos dominios retornan lista de fechas
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            # Calcular antiguedad
            if isinstance(creation_date, datetime):
                # Si tiene timezone, normalizarlo
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)

                age_days = (datetime.now() - creation_date).days
                self._add_to_cache(domain, age_days)

                logger.info(f"WHOIS: {domain} creado hace {age_days} dias")
                return age_days

            self._add_to_cache(domain, None)
            return None

        except Exception as e:
            logger.debug(f"Error consultando WHOIS para {domain}: {e}")
            # No cachear errores para permitir reintentos
            return None

    def is_new_domain(self, url: str, threshold_days: Optional[int] = None) -> Tuple[bool, Optional[int]]:
        """
        Verifica si el dominio es recien registrado.

        Args:
            url: URL a verificar
            threshold_days: Umbral en dias (default: 30)

        Returns:
            Tuple[es_nuevo, antiguedad_dias]
        """
        if threshold_days is None:
            threshold_days = self.NEW_DOMAIN_THRESHOLD_DAYS

        age_days = self.get_domain_age_days(url)

        if age_days is None:
            # No se pudo obtener la antiguedad
            return False, None

        is_new = age_days < threshold_days
        return is_new, age_days

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Verifica una URL y retorna informacion de antiguedad.

        Args:
            url: URL a verificar

        Returns:
            Dict con informacion del dominio
        """
        domain = self._extract_domain(url)
        age_days = self.get_domain_age_days(url)
        is_new, _ = self.is_new_domain(url)

        return {
            'domain': domain,
            'age_days': age_days,
            'is_new_domain': is_new,
            'threshold_days': self.NEW_DOMAIN_THRESHOLD_DAYS,
            'whois_available': self._whois_available
        }

    @property
    def is_available(self) -> bool:
        """Indica si el servicio WHOIS esta disponible."""
        return self._whois_available


# Instancia singleton
whois_service = WhoisService()
