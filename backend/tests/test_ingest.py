"""
Tests para el endpoint /ingest
"""

import pytest


def test_ingest_valid_url(client, valid_url):
    """Test ingestion de URL valida."""
    response = client.post(
        "/ingest",
        json={
            "url": valid_url,
            "label": 0,
            "source": "manual"
        }
    )
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "received"
    assert "id" in data
    assert data["stored"] is True


def test_ingest_malicious_url(client, suspicious_url):
    """Test ingestion de URL maliciosa."""
    response = client.post(
        "/ingest",
        json={
            "url": suspicious_url,
            "label": 1,
            "source": "manual",
            "metadata": {"reporter": "test"}
        }
    )
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "received"


def test_ingest_without_label(client, valid_url):
    """Test ingestion sin label (opcional)."""
    response = client.post(
        "/ingest",
        json={
            "url": valid_url,
            "source": "feed"
        }
    )
    assert response.status_code == 200


def test_ingest_blocks_private_ip(client, private_ip_url):
    """Test que ingest bloquea IPs privadas."""
    response = client.post(
        "/ingest",
        json={
            "url": private_ip_url,
            "label": 1
        }
    )
    assert response.status_code == 400


def test_ingest_invalid_label(client, valid_url):
    """Test que label invalido retorna error."""
    response = client.post(
        "/ingest",
        json={
            "url": valid_url,
            "label": 5  # Solo 0 o 1 son validos
        }
    )
    assert response.status_code == 422  # Validation error
