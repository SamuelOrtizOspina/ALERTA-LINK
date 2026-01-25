"""
Tests para el endpoint /health
"""


def test_health_endpoint_returns_ok(client):
    """Test que /health retorna status ok."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "model_loaded" in data


def test_health_endpoint_has_correct_content_type(client):
    """Test que /health retorna JSON."""
    response = client.get("/health")
    assert "application/json" in response.headers["content-type"]
