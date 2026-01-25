"""
Tests para validacion SSRF
"""

import pytest
from app.core.security import validate_url_safe, normalize_url, is_private_ip


class TestSSRFProtection:
    """Tests de proteccion SSRF."""

    def test_blocks_private_ip_192(self, client, private_ip_url):
        """Test que bloquea 192.168.x.x."""
        response = client.post(
            "/analyze",
            json={"url": private_ip_url}
        )
        assert response.status_code == 400
        assert "privada" in response.json()["detail"].lower() or "blocked" in response.json()["detail"].lower()

    def test_blocks_localhost(self, client, localhost_url):
        """Test que bloquea localhost."""
        response = client.post(
            "/analyze",
            json={"url": localhost_url}
        )
        assert response.status_code == 400

    def test_blocks_10_network(self, client):
        """Test que bloquea 10.x.x.x."""
        response = client.post(
            "/analyze",
            json={"url": "http://10.0.0.1/admin"}
        )
        assert response.status_code == 400

    def test_blocks_172_network(self, client):
        """Test que bloquea 172.16-31.x.x."""
        response = client.post(
            "/analyze",
            json={"url": "http://172.16.0.1/admin"}
        )
        assert response.status_code == 400

    def test_allows_public_ip(self, client):
        """Test que permite IPs publicas."""
        response = client.post(
            "/analyze",
            json={"url": "http://8.8.8.8/"}
        )
        # Puede dar error por otras razones, pero no por SSRF
        if response.status_code == 400:
            assert "privada" not in response.json()["detail"].lower()


class TestValidateUrlSafe:
    """Tests unitarios para validate_url_safe."""

    def test_valid_https_url(self):
        """Test URL HTTPS valida."""
        is_safe, error = validate_url_safe("https://google.com")
        assert is_safe is True

    def test_valid_http_url(self):
        """Test URL HTTP valida."""
        is_safe, error = validate_url_safe("http://example.com")
        assert is_safe is True

    def test_invalid_protocol(self):
        """Test protocolo invalido."""
        is_safe, error = validate_url_safe("ftp://example.com")
        assert is_safe is False
        assert "protocolo" in error.lower() or "protocol" in error.lower()

    def test_empty_url(self):
        """Test URL vacia."""
        is_safe, error = validate_url_safe("")
        assert is_safe is False


class TestNormalizeUrl:
    """Tests unitarios para normalize_url."""

    def test_lowercase(self):
        """Test conversion a lowercase."""
        assert normalize_url("HTTPS://GOOGLE.COM") == "https://google.com"

    def test_remove_trailing_slash(self):
        """Test remover trailing slash."""
        assert normalize_url("https://google.com/") == "https://google.com"

    def test_keep_path(self):
        """Test mantener path."""
        assert normalize_url("https://google.com/path") == "https://google.com/path"

    def test_remove_fragment(self):
        """Test remover fragmento."""
        result = normalize_url("https://google.com/page#section")
        assert "#" not in result


class TestIsPrivateIp:
    """Tests unitarios para is_private_ip."""

    def test_192_168(self):
        """Test 192.168.x.x es privada."""
        assert is_private_ip("192.168.1.1") is True

    def test_10_network(self):
        """Test 10.x.x.x es privada."""
        assert is_private_ip("10.0.0.1") is True

    def test_172_network(self):
        """Test 172.16.x.x es privada."""
        assert is_private_ip("172.16.0.1") is True

    def test_127_localhost(self):
        """Test 127.x.x.x es privada."""
        assert is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        """Test IP publica."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
