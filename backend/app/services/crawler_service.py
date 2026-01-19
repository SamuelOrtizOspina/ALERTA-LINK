"""
Crawler Headless Service - Analisis profundo de URLs sospechosas

Usa Playwright para renderizar paginas y detectar:
- Redirecciones sospechosas
- Formularios de login/phishing
- Campos de tarjeta de credito
- Contenido que imita marcas conocidas
- Paginas de error o parking
"""

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse
import base64

logger = logging.getLogger(__name__)


@dataclass
class CrawlEvidence:
    """Evidencia recolectada durante el crawl."""
    has_login_form: bool = False
    has_password_field: bool = False
    has_credit_card_field: bool = False
    has_suspicious_inputs: bool = False
    page_title: str = ""
    form_actions: List[str] = field(default_factory=list)
    external_form_submission: bool = False
    brand_logos_detected: List[str] = field(default_factory=list)
    suspicious_text_patterns: List[str] = field(default_factory=list)
    ssl_error: bool = False
    is_parking_page: bool = False
    is_error_page: bool = False
    screenshot_base64: Optional[str] = None
    html_hash: str = ""
    scripts_count: int = 0
    iframes_count: int = 0
    hidden_inputs_count: int = 0


@dataclass
class CrawlResult:
    """Resultado del crawling."""
    success: bool
    final_url: str
    redirect_chain: List[str]
    status_code: int
    evidence: CrawlEvidence
    error_message: Optional[str] = None
    duration_ms: int = 0


class CrawlerService:
    """
    Servicio de crawling headless para analisis profundo de URLs.

    Detecta indicadores de phishing que solo son visibles
    al renderizar la pagina con JavaScript.
    """

    # Patrones de texto sospechoso en paginas de phishing
    SUSPICIOUS_TEXT_PATTERNS = [
        r'verify\s+your\s+(account|identity|information)',
        r'confirm\s+your\s+(password|credentials|details)',
        r'update\s+your\s+(payment|billing|account)',
        r'unusual\s+activity',
        r'suspended\s+account',
        r'verify\s+immediately',
        r'your\s+account\s+(has\s+been|will\s+be)\s+(suspended|locked|closed)',
        r'enter\s+your\s+(ssn|social\s+security)',
        r'ingrese\s+su\s+(clave|contrasena|password)',
        r'actualice\s+sus\s+datos',
        r'verifique\s+su\s+(cuenta|identidad)',
        r'su\s+cuenta\s+(ha\s+sido|sera)\s+(suspendida|bloqueada)',
    ]

    # Marcas que son frecuentemente suplantadas
    BRAND_PATTERNS = {
        'paypal': [r'paypal', r'pay\s*pal'],
        'netflix': [r'netflix'],
        'amazon': [r'amazon', r'prime'],
        'apple': [r'apple\s*id', r'icloud'],
        'microsoft': [r'microsoft', r'outlook', r'office\s*365'],
        'google': [r'google', r'gmail'],
        'facebook': [r'facebook', r'meta'],
        'instagram': [r'instagram'],
        'whatsapp': [r'whatsapp', r'wh?ats\s*app'],
        'bancolombia': [r'bancolombia', r'banco\s*colombia'],
        'davivienda': [r'davivienda'],
        'nequi': [r'nequi'],
        'daviplata': [r'daviplata', r'davi\s*plata'],
    }

    # Indicadores de paginas de parking/error
    PARKING_INDICATORS = [
        r'domain\s+for\s+sale',
        r'this\s+domain\s+is\s+parked',
        r'buy\s+this\s+domain',
        r'dominio\s+en\s+venta',
        r'pagina\s+no\s+encontrada',
        r'coming\s+soon',
        r'under\s+construction',
    ]

    def __init__(self):
        """Inicializa el servicio de crawling."""
        self._playwright_available = self._check_playwright()
        if not self._playwright_available:
            logger.warning("Playwright no disponible - crawler headless deshabilitado")

    def _check_playwright(self) -> bool:
        """Verifica si Playwright esta instalado."""
        try:
            from playwright.async_api import async_playwright
            return True
        except ImportError:
            return False

    @property
    def is_available(self) -> bool:
        """Indica si el crawler esta disponible."""
        return self._playwright_available

    async def crawl_url(
        self,
        url: str,
        timeout_seconds: int = 20,
        max_redirects: int = 5,
        take_screenshot: bool = False
    ) -> CrawlResult:
        """
        Realiza crawling headless de una URL.

        Args:
            url: URL a analizar
            timeout_seconds: Timeout maximo
            max_redirects: Maximo de redirecciones a seguir
            take_screenshot: Si capturar screenshot (aumenta tiempo)

        Returns:
            CrawlResult con toda la evidencia recolectada
        """
        if not self._playwright_available:
            return CrawlResult(
                success=False,
                final_url=url,
                redirect_chain=[],
                status_code=0,
                evidence=CrawlEvidence(),
                error_message="Playwright no disponible"
            )

        import time
        start_time = time.time()

        try:
            from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

            redirect_chain = []
            evidence = CrawlEvidence()
            final_url = url
            status_code = 0

            async with async_playwright() as p:
                # Usar Chromium en modo headless
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                    ]
                )

                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 720},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    ignore_https_errors=False,  # Detectar errores SSL
                )

                page = await context.new_page()

                # Capturar redirecciones
                async def handle_response(response):
                    nonlocal redirect_chain, status_code
                    if response.request.is_navigation_request():
                        redirect_chain.append(response.url)
                        status_code = response.status

                page.on('response', handle_response)

                try:
                    # Navegar a la URL
                    response = await page.goto(
                        url,
                        timeout=timeout_seconds * 1000,
                        wait_until='networkidle'
                    )

                    if response:
                        status_code = response.status
                        final_url = page.url

                    # Esperar un poco para JavaScript
                    await page.wait_for_timeout(1000)

                    # Analizar contenido
                    evidence = await self._analyze_page_content(page, take_screenshot)

                    # Verificar si hubo demasiadas redirecciones
                    if len(redirect_chain) > max_redirects:
                        evidence.suspicious_text_patterns.append(
                            f"Demasiadas redirecciones ({len(redirect_chain)})"
                        )

                except PlaywrightTimeout:
                    return CrawlResult(
                        success=False,
                        final_url=final_url,
                        redirect_chain=redirect_chain,
                        status_code=status_code,
                        evidence=evidence,
                        error_message="Timeout al cargar la pagina",
                        duration_ms=int((time.time() - start_time) * 1000)
                    )

                except Exception as e:
                    error_msg = str(e)
                    # Detectar errores SSL
                    if 'ssl' in error_msg.lower() or 'certificate' in error_msg.lower():
                        evidence.ssl_error = True

                    return CrawlResult(
                        success=False,
                        final_url=final_url,
                        redirect_chain=redirect_chain,
                        status_code=status_code,
                        evidence=evidence,
                        error_message=error_msg,
                        duration_ms=int((time.time() - start_time) * 1000)
                    )

                finally:
                    await browser.close()

            return CrawlResult(
                success=True,
                final_url=final_url,
                redirect_chain=redirect_chain,
                status_code=status_code,
                evidence=evidence,
                duration_ms=int((time.time() - start_time) * 1000)
            )

        except Exception as e:
            logger.error(f"Error en crawl: {e}")
            return CrawlResult(
                success=False,
                final_url=url,
                redirect_chain=[],
                status_code=0,
                evidence=CrawlEvidence(),
                error_message=str(e),
                duration_ms=int((time.time() - start_time) * 1000)
            )

    async def _analyze_page_content(
        self,
        page,
        take_screenshot: bool = False
    ) -> CrawlEvidence:
        """
        Analiza el contenido de la pagina en busca de indicadores de phishing.
        """
        evidence = CrawlEvidence()

        try:
            # Obtener titulo
            evidence.page_title = await page.title() or ""

            # Obtener HTML
            html_content = await page.content()
            evidence.html_hash = hashlib.md5(html_content.encode()).hexdigest()[:16]

            # Contar elementos
            evidence.scripts_count = await page.locator('script').count()
            evidence.iframes_count = await page.locator('iframe').count()
            evidence.hidden_inputs_count = await page.locator('input[type="hidden"]').count()

            # Buscar formularios de login
            password_fields = await page.locator('input[type="password"]').count()
            evidence.has_password_field = password_fields > 0

            # Buscar formularios
            forms = await page.locator('form').all()
            for form in forms:
                action = await form.get_attribute('action') or ''
                evidence.form_actions.append(action)

                # Verificar si el form envia a dominio externo
                if action.startswith('http'):
                    form_domain = urlparse(action).netloc
                    page_domain = urlparse(page.url).netloc
                    if form_domain and form_domain != page_domain:
                        evidence.external_form_submission = True

            # Detectar campos de login
            email_fields = await page.locator('input[type="email"], input[name*="email"], input[name*="user"], input[id*="email"], input[id*="user"]').count()
            evidence.has_login_form = password_fields > 0 and email_fields > 0

            # Detectar campos de tarjeta de credito
            cc_patterns = ['card', 'credit', 'cvv', 'cvc', 'expir', 'tarjeta', 'numero']
            cc_fields = 0
            for pattern in cc_patterns:
                cc_fields += await page.locator(f'input[name*="{pattern}" i], input[id*="{pattern}" i], input[placeholder*="{pattern}" i]').count()
            evidence.has_credit_card_field = cc_fields > 2

            # Detectar campos sospechosos (SSN, PIN, etc)
            suspicious_patterns = ['ssn', 'social', 'pin', 'cedula', 'documento', 'identidad']
            for pattern in suspicious_patterns:
                count = await page.locator(f'input[name*="{pattern}" i], input[id*="{pattern}" i]').count()
                if count > 0:
                    evidence.has_suspicious_inputs = True
                    break

            # Analizar texto de la pagina
            text_content = await page.inner_text('body')
            text_lower = text_content.lower()

            # Buscar patrones de texto sospechoso
            for pattern in self.SUSPICIOUS_TEXT_PATTERNS:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    evidence.suspicious_text_patterns.append(pattern)

            # Detectar marcas suplantadas
            page_domain = urlparse(page.url).netloc.lower()
            for brand, patterns in self.BRAND_PATTERNS.items():
                # Verificar si la marca aparece en el contenido pero NO es el dominio oficial
                official_domains = [f'{brand}.com', f'{brand}.co', f'{brand}.com.co']
                is_official = any(d in page_domain for d in official_domains)

                if not is_official:
                    for pattern in patterns:
                        if re.search(pattern, text_lower, re.IGNORECASE):
                            evidence.brand_logos_detected.append(brand)
                            break

            # Detectar paginas de parking/error
            for pattern in self.PARKING_INDICATORS:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    evidence.is_parking_page = True
                    break

            # Detectar paginas de error
            error_indicators = ['404', 'not found', 'error', 'no existe']
            title_lower = evidence.page_title.lower()
            if any(ind in title_lower for ind in error_indicators):
                evidence.is_error_page = True

            # Capturar screenshot si se solicita
            if take_screenshot:
                try:
                    screenshot_bytes = await page.screenshot(type='jpeg', quality=50)
                    evidence.screenshot_base64 = base64.b64encode(screenshot_bytes).decode()
                except Exception as e:
                    logger.debug(f"Error capturando screenshot: {e}")

        except Exception as e:
            logger.error(f"Error analizando contenido: {e}")

        return evidence

    def generate_signals_from_crawl(
        self,
        result: CrawlResult,
        original_url: str
    ) -> List[Dict[str, Any]]:
        """
        Genera senales de phishing basadas en el resultado del crawl.

        Returns:
            Lista de senales en formato dict
        """
        signals = []
        evidence = result.evidence

        # Redireccion a dominio diferente
        if result.final_url != original_url:
            orig_domain = urlparse(original_url).netloc
            final_domain = urlparse(result.final_url).netloc

            if orig_domain != final_domain:
                signals.append({
                    'id': 'REDIRECT_TO_DIFFERENT_DOMAIN',
                    'severity': 'MEDIUM',
                    'weight': 20,
                    'evidence': {
                        'original_domain': orig_domain,
                        'final_domain': final_domain,
                        'redirect_count': len(result.redirect_chain)
                    },
                    'explanation': f"La URL redirige a un dominio diferente: {orig_domain} -> {final_domain}"
                })

        # Demasiadas redirecciones
        if len(result.redirect_chain) > 3:
            signals.append({
                'id': 'EXCESSIVE_REDIRECTS',
                'severity': 'MEDIUM',
                'weight': 15,
                'evidence': {
                    'redirect_count': len(result.redirect_chain),
                    'chain': result.redirect_chain[:5]
                },
                'explanation': f"La URL tiene {len(result.redirect_chain)} redirecciones, lo cual es sospechoso."
            })

        # Formulario de login detectado
        if evidence.has_login_form:
            signals.append({
                'id': 'LOGIN_FORM_DETECTED',
                'severity': 'MEDIUM',
                'weight': 15,
                'evidence': {
                    'has_password': evidence.has_password_field,
                    'form_actions': evidence.form_actions[:3]
                },
                'explanation': "Se detecto un formulario de login. Verifique que sea el sitio oficial."
            })

        # Formulario envia a dominio externo
        if evidence.external_form_submission:
            signals.append({
                'id': 'FORM_SUBMITS_EXTERNALLY',
                'severity': 'HIGH',
                'weight': 35,
                'evidence': {
                    'form_actions': evidence.form_actions
                },
                'explanation': "ALERTA: El formulario envia datos a un dominio diferente al de la pagina."
            })

        # Campos de tarjeta de credito
        if evidence.has_credit_card_field:
            signals.append({
                'id': 'CREDIT_CARD_FORM',
                'severity': 'HIGH',
                'weight': 25,
                'evidence': {},
                'explanation': "Se detectaron campos para ingresar datos de tarjeta de credito."
            })

        # Campos sospechosos (SSN, cedula, etc)
        if evidence.has_suspicious_inputs:
            signals.append({
                'id': 'SUSPICIOUS_INPUT_FIELDS',
                'severity': 'HIGH',
                'weight': 30,
                'evidence': {},
                'explanation': "Se detectaron campos para datos sensibles (SSN, cedula, PIN)."
            })

        # Marcas suplantadas
        if evidence.brand_logos_detected:
            brands = list(set(evidence.brand_logos_detected))
            signals.append({
                'id': 'BRAND_CONTENT_DETECTED',
                'severity': 'HIGH',
                'weight': 40,
                'evidence': {
                    'brands': brands
                },
                'explanation': f"El contenido menciona marcas conocidas ({', '.join(brands)}) pero NO es el sitio oficial."
            })

        # Texto de phishing detectado
        if evidence.suspicious_text_patterns:
            signals.append({
                'id': 'PHISHING_TEXT_DETECTED',
                'severity': 'HIGH',
                'weight': 30,
                'evidence': {
                    'patterns_found': len(evidence.suspicious_text_patterns)
                },
                'explanation': "Se detectaron frases tipicas de phishing (verificar cuenta, actividad inusual, etc)."
            })

        # Error SSL
        if evidence.ssl_error:
            signals.append({
                'id': 'SSL_CERTIFICATE_ERROR',
                'severity': 'HIGH',
                'weight': 35,
                'evidence': {},
                'explanation': "Error de certificado SSL. El sitio no tiene conexion segura valida."
            })

        # Pagina de parking
        if evidence.is_parking_page:
            signals.append({
                'id': 'PARKING_PAGE',
                'severity': 'MEDIUM',
                'weight': 20,
                'evidence': {},
                'explanation': "Esta es una pagina de parking o dominio en venta."
            })

        # Muchos iframes (pueden ocultar contenido)
        if evidence.iframes_count > 3:
            signals.append({
                'id': 'EXCESSIVE_IFRAMES',
                'severity': 'LOW',
                'weight': 10,
                'evidence': {
                    'count': evidence.iframes_count
                },
                'explanation': f"La pagina tiene {evidence.iframes_count} iframes, lo cual puede ocultar contenido malicioso."
            })

        # Muchos inputs ocultos
        if evidence.hidden_inputs_count > 5:
            signals.append({
                'id': 'EXCESSIVE_HIDDEN_INPUTS',
                'severity': 'LOW',
                'weight': 10,
                'evidence': {
                    'count': evidence.hidden_inputs_count
                },
                'explanation': f"La pagina tiene {evidence.hidden_inputs_count} campos ocultos."
            })

        return signals


# Singleton del servicio
crawler_service = CrawlerService()
