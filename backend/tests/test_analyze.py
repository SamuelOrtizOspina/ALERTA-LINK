"""
Tests para el endpoint /analyze
"""

import pytest


def test_analyze_valid_url(client, valid_url):
    """Test analisis de URL valida."""
    response = client.post(
        "/analyze",
        json={"url": valid_url}
    )
    assert response.status_code == 200

    data = response.json()
    assert "url" in data
    assert "score" in data
    assert "risk_level" in data
    assert "signals" in data
    assert "recommendations" in data
    assert data["score"] >= 0
    assert data["score"] <= 100
    assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH"]


def test_analyze_suspicious_url(client, suspicious_url):
    """Test analisis de URL sospechosa."""
    response = client.post(
        "/analyze",
        json={"url": suspicious_url}
    )
    assert response.status_code == 200

    data = response.json()
    # URL sospechosa deberia tener score alto
    assert data["score"] > 30
    assert len(data["signals"]) > 0


def test_analyze_invalid_url_format(client):
    """Test que URL invalida retorna error."""
    response = client.post(
        "/analyze",
        json={"url": "not-a-valid-url"}
    )
    assert response.status_code == 400


def test_analyze_empty_url(client):
    """Test que URL vacia retorna error."""
    response = client.post(
        "/analyze",
        json={"url": ""}
    )
    assert response.status_code == 422  # Validation error


def test_analyze_with_options(client, valid_url):
    """Test analisis con opciones."""
    response = client.post(
        "/analyze",
        json={
            "url": valid_url,
            "options": {
                "enable_crawler": False,
                "timeout_seconds": 10
            }
        }
    )
    assert response.status_code == 200


def test_analyze_returns_timestamps(client, valid_url):
    """Test que /analyze retorna timestamps."""
    response = client.post(
        "/analyze",
        json={"url": valid_url}
    )
    assert response.status_code == 200

    data = response.json()
    assert "timestamps" in data
    assert "duration_ms" in data["timestamps"]
    assert data["timestamps"]["duration_ms"] >= 0
