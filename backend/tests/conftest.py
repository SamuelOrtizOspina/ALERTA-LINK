"""
Configuracion de pytest para tests del backend
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    """Cliente de pruebas para FastAPI."""
    return TestClient(app)


@pytest.fixture
def valid_url():
    """URL legitima para pruebas."""
    return "https://www.google.com"


@pytest.fixture
def suspicious_url():
    """URL sospechosa para pruebas."""
    return "https://paypa1-secure.xyz/login"


@pytest.fixture
def private_ip_url():
    """URL con IP privada (debe ser bloqueada)."""
    return "http://192.168.1.1/admin"


@pytest.fixture
def localhost_url():
    """URL localhost (debe ser bloqueada)."""
    return "http://127.0.0.1:8080/api"
