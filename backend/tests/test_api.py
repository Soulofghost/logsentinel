import os
import pytest
from fastapi.testclient import TestClient

os.environ["LOGSENTINEL_DB"] = "test_logsentinel_api.db"

from app.database import init_db
from app.main import app

@pytest.fixture(scope="module", autouse=True)
def setup_api_db():
    if os.path.exists("test_logsentinel_api.db"):
        os.remove("test_logsentinel_api.db")
    init_db()
    yield
    if os.path.exists("test_logsentinel_api.db"):
        try:
            os.remove("test_logsentinel_api.db")
        except Exception:
            pass

client = TestClient(app)

def test_health_check():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "LogSentinel" in data["service"]

def test_ingest_benign_log():
    payload = {
        "message": "GET /static/css/main.css HTTP/1.1 200",
        "source": "nginx_access.log"
    }
    res = client.post("/api/v1/logs", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert "log_id" in data
    assert len(data["alerts_triggered"]) == 0

def test_ingest_malicious_sqli_log():
    payload = {
        "message": "GET /products?id=1 UNION SELECT username, password FROM users-- HTTP/1.1 200",
        "source": "waf.log"
    }
    res = client.post("/api/v1/logs", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert len(data["alerts_triggered"]) >= 1
    assert data["alerts_triggered"][0]["rule_id"] == "RULE-WEB-SQLI"

def test_list_logs_and_alerts():
    logs_res = client.get("/api/v1/logs")
    assert logs_res.status_code == 200
    assert len(logs_res.json()) >= 2

    alerts_res = client.get("/api/v1/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]

    # Status update lifecycle: OPEN -> INVESTIGATING -> RESOLVED
    patch_res = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "INVESTIGATING"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "INVESTIGATING"

    resolve_res = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "RESOLVED"})
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"

def test_metrics_summary():
    metrics_res = client.get("/api/v1/alerts/metrics/summary")
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert metrics["total_logs"] >= 2
    assert "resolved_alerts" in metrics
