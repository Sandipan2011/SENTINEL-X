from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get('/health')
    assert response.status_code == 200
    payload = response.json()
    assert payload['status'] == 'ok'


def test_replay_endpoint_returns_alerts():
    response = client.get('/api/replay')
    assert response.status_code == 200
    payload = response.json()
    assert 'flow_count' in payload
    assert 'alert_count' in payload
    assert payload['alert_count'] >= 0


def test_dashboard_serves_html():
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert 'SENTINEL-X' in response.text
