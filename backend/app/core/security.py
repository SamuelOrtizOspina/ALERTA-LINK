"""
Modulo de seguridad SSRF para ALERTA-LINK
Bloquea IPs privadas, localhost y rangos peligrosos
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple


class SSRFError(Exception):
    """Excepcion para intentos de SSRF."""
    pass


# Rangos de IP privadas/reservadas
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('224.0.0.0/4'),  # Multicast
    ipaddress.ip_network('240.0.0.0/4'),  # Reserved
    ipaddress.ip_network('100.64.0.0/10'),  # Carrier-grade NAT
    ipaddress.ip_network('198.18.0.0/15'),  # Benchmark
    ipaddress.ip_network('::1/128'),  # IPv6 localhost
    ipaddress.ip_network('fc00::/7'),  # IPv6 private
    ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
]

# Hostnames peligrosos
BLOCKED_HOSTNAMES = [
    'localhost',
    'localhost.localdomain',
    '0.0.0.0',
    'metadata.google.internal',  # GCP metadata
    '169.254.169.254',  # AWS/GCP metadata
    'metadata.internal',
]


def is_private_ip(ip_str: str) -> bool:
    """Verifica si una IP es privada o reservada."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in PRIVATE_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def is_ip_address(host: str) -> bool:
    """Verifica si el host es una direccion IP."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_url_safe(url: str) -> Tuple[bool, str]:
    """
    Valida que una URL sea segura (no SSRF).

    Returns:
        Tuple[bool, str]: (es_segura, mensaje_error)
    """
    if not url:
        return False, "URL vacia"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"URL malformada: {e}"

    # Verificar protocolo
    if parsed.scheme not in ('http', 'https'):
        return False, f"Protocolo no permitido: {parsed.scheme}"

    # Obtener hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "No se pudo extraer hostname"

    # Verificar hostnames bloqueados
    hostname_lower = hostname.lower()
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Hostname bloqueado: {hostname}"

    # Si es IP, verificar que no sea privada
    if is_ip_address(hostname):
        if is_private_ip(hostname):
            return False, f"IP privada bloqueada: {hostname}"
    else:
        # Resolver DNS y verificar
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
            for family, type_, proto, canonname, sockaddr in ips:
                ip = sockaddr[0]
                if is_private_ip(ip):
                    return False, f"El hostname {hostname} resuelve a IP privada: {ip}"
        except socket.gaierror:
            # No podemos resolver, pero permitimos (puede ser dominio nuevo)
            pass

    # Verificar puerto sospechoso
    port = parsed.port
    if port and port not in (80, 443, 8080, 8443):
        # Permitir pero loguear como advertencia
        pass

    return True, "OK"


def normalize_url(url: str) -> str:
    """
    Normaliza una URL para comparacion.

    - Lowercase
    - Sin trailing slash
    - Sin fragmento (#)
    """
    if not url:
        return ""

    url = url.strip().lower()

    # Remover fragmento
    if '#' in url:
        url = url.split('#')[0]

    # Remover trailing slash (excepto si es solo el dominio)
    parsed = urlparse(url)
    if parsed.path == '/':
        url = url.rstrip('/')
    elif parsed.path.endswith('/'):
        url = url.rstrip('/')

    return url


def validate_and_normalize_url(url: str) -> Tuple[str, str]:
    """
    Valida y normaliza una URL.

    Returns:
        Tuple[str, str]: (url_normalizada, error_message)
        Si hay error, url_normalizada sera vacia.
    """
    is_safe, error = validate_url_safe(url)
    if not is_safe:
        return "", error

    normalized = normalize_url(url)
    return normalized, ""
