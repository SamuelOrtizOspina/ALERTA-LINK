"""
Servicio de analisis de contenido web para deteccion de phishing

Analiza el HTML de una pagina para detectar:
- Formularios de login/password falsos
- Logos de marcas conocidas (suplantacion)
- Inputs de tarjetas de credito
- Tecnicas de ofuscacion
- Redirecciones sospechosas
"""

import re
import logging
import requests
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class ContentAnalysisResult:
    """Resultado del analisis de contenido."""
    analyzed: bool = False
    error: Optional[str] = None
    signals: List[Dict[str, Any]] = None
    summary: Dict[str, Any] = None

    def __post_init__(self):
        if self.signals is None:
            self.signals = []
        if self.summary is None:
            self.summary = {}


class ContentAnalyzer:
    """Analizador de contenido web para deteccion de phishing."""

    # Marcas conocidas y sus logos/keywords
    KNOWN_BRANDS = {
        'paypal': {
            'keywords': ['paypal', 'pay pal', 'paypa1'],
            'logo_patterns': ['paypal-logo', 'pp-logo', 'paypal_logo'],
            'official_domain': 'paypal.com'
        },
        'amazon': {
            'keywords': ['amazon', 'amaz0n', 'amazan'],
            'logo_patterns': ['amazon-logo', 'a-logo', 'amazon_logo'],
            'official_domain': 'amazon.com'
        },
        'apple': {
            'keywords': ['apple', 'icloud', 'appleid', 'app1e'],
            'logo_patterns': ['apple-logo', 'apple_logo'],
            'official_domain': 'apple.com'
        },
        'microsoft': {
            'keywords': ['microsoft', 'outlook', 'office365', 'micr0soft'],
            'logo_patterns': ['microsoft-logo', 'ms-logo', 'office-logo'],
            'official_domain': 'microsoft.com'
        },
        'google': {
            'keywords': ['google', 'gmail', 'g00gle'],
            'logo_patterns': ['google-logo', 'gmail-logo'],
            'official_domain': 'google.com'
        },
        'facebook': {
            'keywords': ['facebook', 'meta', 'faceb00k'],
            'logo_patterns': ['facebook-logo', 'fb-logo'],
            'official_domain': 'facebook.com'
        },
        'netflix': {
            'keywords': ['netflix', 'netf1ix'],
            'logo_patterns': ['netflix-logo', 'nf-logo'],
            'official_domain': 'netflix.com'
        },
        'bank': {
            'keywords': ['bank', 'banking', 'banco', 'credit union'],
            'logo_patterns': ['bank-logo'],
            'official_domain': None
        },
        'chase': {
            'keywords': ['chase', 'jpmorgan'],
            'logo_patterns': ['chase-logo'],
            'official_domain': 'chase.com'
        },
        'wellsfargo': {
            'keywords': ['wells fargo', 'wellsfargo'],
            'logo_patterns': ['wellsfargo-logo', 'wf-logo'],
            'official_domain': 'wellsfargo.com'
        }
    }

    # Patrones de inputs sospechosos
    SENSITIVE_INPUT_PATTERNS = {
        'password': r'(password|passwd|pwd|contraseña|clave)',
        'credit_card': r'(card.?number|credit.?card|tarjeta|cvv|cvc|expir)',
        'ssn': r'(ssn|social.?security|seguro.?social)',
        'pin': r'(pin|código.?secreto)',
        'otp': r'(otp|one.?time|código.?verificación|2fa|token)',
    }

    def __init__(self, timeout: int = 10, max_content_length: int = 500000):
        self.timeout = timeout
        self.max_content_length = max_content_length

    def analyze_url(self, url: str) -> ContentAnalysisResult:
        """
        Analiza el contenido de una URL.

        Args:
            url: URL a analizar

        Returns:
            ContentAnalysisResult con los hallazgos
        """
        result = ContentAnalysisResult()

        try:
            # Obtener contenido
            html, final_url = self._fetch_content(url)
            if not html:
                result.error = "No se pudo obtener el contenido"
                return result

            result.analyzed = True

            # Parsear HTML
            soup = BeautifulSoup(html, 'html.parser')

            # Analizar diferentes aspectos
            signals = []

            # 1. Analizar formularios
            form_signals = self._analyze_forms(soup, url, final_url)
            signals.extend(form_signals)

            # 2. Detectar suplantacion de marca
            brand_signals = self._detect_brand_impersonation(soup, html, url)
            signals.extend(brand_signals)

            # 3. Analizar inputs sensibles
            input_signals = self._analyze_sensitive_inputs(soup)
            signals.extend(input_signals)

            # 4. Detectar tecnicas de ofuscacion
            obfuscation_signals = self._detect_obfuscation(soup, html)
            signals.extend(obfuscation_signals)

            # 5. Analizar redirecciones
            redirect_signals = self._analyze_redirects(soup, html, url)
            signals.extend(redirect_signals)

            result.signals = signals
            result.summary = self._generate_summary(signals, soup)

        except Exception as e:
            logger.error(f"Error analizando {url}: {e}")
            result.error = str(e)

        return result

    def _fetch_content(self, url: str) -> Tuple[Optional[str], str]:
        """Obtiene el contenido HTML de una URL."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }

            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False  # Para sitios con certificados invalidos
            )

            # Limitar tamaño
            if len(response.content) > self.max_content_length:
                return response.text[:self.max_content_length], response.url

            return response.text, response.url

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout al obtener {url}")
            return None, url
        except Exception as e:
            logger.warning(f"Error obteniendo {url}: {e}")
            return None, url

    def _analyze_forms(self, soup: BeautifulSoup, original_url: str, final_url: str) -> List[Dict]:
        """Analiza formularios en busca de indicadores de phishing."""
        signals = []
        forms = soup.find_all('form')

        parsed_url = urlparse(final_url)
        current_domain = parsed_url.netloc.lower()

        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            # Verificar si el formulario envia datos a otro dominio
            if action:
                if action.startswith('http'):
                    action_domain = urlparse(action).netloc.lower()
                    if action_domain and action_domain != current_domain:
                        signals.append({
                            'id': 'FORM_EXTERNAL_ACTION',
                            'severity': 'HIGH',
                            'weight': 30,
                            'evidence': {
                                'form_index': i,
                                'action_url': action,
                                'action_domain': action_domain,
                                'page_domain': current_domain,
                                'risk': 'El formulario envia datos a un dominio externo'
                            },
                            'explanation': f'PELIGRO: El formulario envia datos a "{action_domain}" que es diferente al sitio actual "{current_domain}". Esto es una tecnica comun de phishing.'
                        })

            # Verificar si tiene inputs de password/login
            password_inputs = form.find_all('input', {'type': 'password'})
            if password_inputs:
                signals.append({
                    'id': 'FORM_PASSWORD_INPUT',
                    'severity': 'MEDIUM',
                    'weight': 15,
                    'evidence': {
                        'form_index': i,
                        'password_fields': len(password_inputs),
                        'method': method
                    },
                    'explanation': f'El formulario contiene {len(password_inputs)} campo(s) de contraseña. Verifique que este en el sitio oficial antes de ingresar credenciales.'
                })

        return signals

    def _detect_brand_impersonation(self, soup: BeautifulSoup, html: str, url: str) -> List[Dict]:
        """Detecta suplantacion de marcas conocidas."""
        signals = []
        html_lower = html.lower()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        for brand, info in self.KNOWN_BRANDS.items():
            # Buscar keywords de la marca en el contenido
            brand_found = False
            found_keywords = []

            for keyword in info['keywords']:
                if keyword in html_lower:
                    brand_found = True
                    found_keywords.append(keyword)

            # Buscar logos
            found_logos = []
            for pattern in info['logo_patterns']:
                if pattern in html_lower:
                    found_logos.append(pattern)

            # Si encontramos la marca pero no es el dominio oficial
            if brand_found and info['official_domain']:
                official = info['official_domain']
                if official not in domain and domain != official:
                    signals.append({
                        'id': 'BRAND_IN_CONTENT',
                        'severity': 'HIGH',
                        'weight': 35,
                        'evidence': {
                            'brand': brand,
                            'official_domain': official,
                            'current_domain': domain,
                            'keywords_found': found_keywords,
                            'logos_found': found_logos,
                            'technique': 'Brand Impersonation'
                        },
                        'explanation': f'ALERTA DE PHISHING: El contenido de la pagina menciona "{brand.upper()}" pero el dominio "{domain}" NO es el oficial "{official}". Este sitio intenta hacerse pasar por {brand.upper()}.'
                    })

            # Detectar logos de marcas
            if found_logos and info['official_domain'] and info['official_domain'] not in domain:
                signals.append({
                    'id': 'BRAND_LOGO_DETECTED',
                    'severity': 'HIGH',
                    'weight': 25,
                    'evidence': {
                        'brand': brand,
                        'logos_detected': found_logos,
                        'domain': domain
                    },
                    'explanation': f'Se detectaron referencias a logos de {brand.upper()} en un sitio que no es el oficial. Posible intento de suplantacion.'
                })

        return signals

    def _analyze_sensitive_inputs(self, soup: BeautifulSoup) -> List[Dict]:
        """Analiza inputs que solicitan informacion sensible."""
        signals = []
        inputs = soup.find_all('input')
        labels = soup.find_all('label')

        # Combinar texto de inputs y labels
        all_text = ' '.join([
            str(inp.get('name', '')) + ' ' +
            str(inp.get('placeholder', '')) + ' ' +
            str(inp.get('id', ''))
            for inp in inputs
        ])
        all_text += ' '.join([label.get_text() for label in labels])
        all_text = all_text.lower()

        sensitive_found = {}
        for category, pattern in self.SENSITIVE_INPUT_PATTERNS.items():
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            if matches:
                sensitive_found[category] = matches

        if sensitive_found:
            severity = 'HIGH' if 'credit_card' in sensitive_found or 'ssn' in sensitive_found else 'MEDIUM'
            weight = 30 if 'credit_card' in sensitive_found else 20

            signals.append({
                'id': 'SENSITIVE_DATA_REQUEST',
                'severity': severity,
                'weight': weight,
                'evidence': {
                    'sensitive_fields': sensitive_found,
                    'categories': list(sensitive_found.keys())
                },
                'explanation': f'El sitio solicita informacion sensible: {", ".join(sensitive_found.keys())}. Verifique cuidadosamente antes de proporcionar estos datos.'
            })

        return signals

    def _detect_obfuscation(self, soup: BeautifulSoup, html: str) -> List[Dict]:
        """Detecta tecnicas de ofuscacion comunes en phishing."""
        signals = []

        # Base64 encoded content
        base64_pattern = r'data:text/html;base64,[A-Za-z0-9+/=]{50,}'
        if re.search(base64_pattern, html):
            signals.append({
                'id': 'BASE64_OBFUSCATION',
                'severity': 'HIGH',
                'weight': 25,
                'evidence': {
                    'technique': 'Base64 encoding',
                    'risk': 'Contenido oculto mediante codificacion Base64'
                },
                'explanation': 'Se detectó contenido codificado en Base64, una técnica común usada para ocultar código malicioso.'
            })

        # JavaScript ofuscado
        scripts = soup.find_all('script')
        for script in scripts:
            text = script.get_text()
            # Detectar patrones de ofuscacion
            if re.search(r'(eval\s*\(|document\.write\s*\(|unescape\s*\(|String\.fromCharCode)', text):
                signals.append({
                    'id': 'JS_OBFUSCATION',
                    'severity': 'MEDIUM',
                    'weight': 15,
                    'evidence': {
                        'technique': 'JavaScript obfuscation',
                        'indicators': ['eval()', 'document.write()', 'unescape()', 'fromCharCode']
                    },
                    'explanation': 'Se detectaron técnicas de ofuscación JavaScript que podrían ocultar comportamiento malicioso.'
                })
                break

        # Iframes ocultos
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            style = iframe.get('style', '')
            width = iframe.get('width', '')
            height = iframe.get('height', '')

            if 'display:none' in style or 'visibility:hidden' in style or width == '0' or height == '0':
                signals.append({
                    'id': 'HIDDEN_IFRAME',
                    'severity': 'HIGH',
                    'weight': 20,
                    'evidence': {
                        'src': iframe.get('src', 'unknown'),
                        'style': style
                    },
                    'explanation': 'Se detectó un iframe oculto que podría estar cargando contenido malicioso sin que el usuario lo vea.'
                })
                break

        return signals

    def _analyze_redirects(self, soup: BeautifulSoup, html: str, url: str) -> List[Dict]:
        """Analiza redirecciones sospechosas."""
        signals = []

        # Meta refresh redirects
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if 'url=' in content.lower():
                signals.append({
                    'id': 'META_REDIRECT',
                    'severity': 'MEDIUM',
                    'weight': 15,
                    'evidence': {
                        'meta_content': content,
                        'technique': 'Meta refresh redirect'
                    },
                    'explanation': 'El sitio usa redireccion automatica mediante meta refresh, lo cual puede ser usado para engañar al usuario.'
                })

        # JavaScript redirects
        if re.search(r'(window\.location|document\.location|location\.href)\s*=', html):
            signals.append({
                'id': 'JS_REDIRECT',
                'severity': 'LOW',
                'weight': 10,
                'evidence': {
                    'technique': 'JavaScript redirect'
                },
                'explanation': 'El sitio contiene redirecciones JavaScript.'
            })

        return signals

    def _generate_summary(self, signals: List[Dict], soup: BeautifulSoup) -> Dict:
        """Genera un resumen del analisis."""
        total_weight = sum(s.get('weight', 0) for s in signals)
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for signal in signals:
            sev = signal.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Contar elementos de la pagina
        forms = len(soup.find_all('form'))
        inputs = len(soup.find_all('input'))
        links = len(soup.find_all('a'))

        return {
            'total_signals': len(signals),
            'total_weight': total_weight,
            'severity_breakdown': severity_counts,
            'page_elements': {
                'forms': forms,
                'inputs': inputs,
                'links': links
            },
            'risk_assessment': 'HIGH' if total_weight > 50 else ('MEDIUM' if total_weight > 20 else 'LOW')
        }


# Singleton del analizador
content_analyzer = ContentAnalyzer()
