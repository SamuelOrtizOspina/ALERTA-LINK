"""
Tests para el endpoint /report
"""

import pytest


def test_report_phishing(client, suspicious_url):
    """Test reporte de phishing."""
    response = client.post(
        "/report",
        json={
            "url": suspicious_url,
            "label": "phishing",
            "comment": "Recibido por SMS"
        }
    )
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "received"
    assert "report_id" in data
    assert data["message"] == "Gracias. Tu reporte fue registrado."


def test_report_malware(client):
    """Test reporte de malware."""
    response = client.post(
        "/report",
        json={
            "url": "https://malware-site.xyz/download",
            "label": "malware"
        }
    )
    assert response.status_code == 200


def test_report_scam(client):
    """Test reporte de estafa."""
    response = client.post(
        "/report",
        json={
            "url": "https://premio-gratis.xyz/",
            "label": "scam",
            "comment": "Me dijeron que gane un premio"
        }
    )
    assert response.status_code == 200


def test_report_unknown(client):
    """Test reporte con label unknown."""
    response = client.post(
        "/report",
        json={
            "url": "https://sospechoso.xyz/",
            "label": "unknown"
        }
    )
    assert response.status_code == 200


def test_report_invalid_label(client):
    """Test que label invalido retorna error."""
    response = client.post(
        "/report",
        json={
            "url": "https://example.com",
            "label": "invalid_label"
        }
    )
    assert response.status_code == 422


def test_report_blocks_private_ip(client, private_ip_url):
    """Test que report bloquea IPs privadas."""
    response = client.post(
        "/report",
        json={
            "url": private_ip_url,
            "label": "phishing"
        }
    )
    assert response.status_code == 400
