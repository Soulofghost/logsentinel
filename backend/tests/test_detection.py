import os
import pytest

os.environ["LOGSENTINEL_DB"] = "test_logsentinel.db"

from app.database import init_db
from app.engine.detector import parse_log_line, analyze_and_correlate

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    if os.path.exists("test_logsentinel.db"):
        os.remove("test_logsentinel.db")
    init_db()
    yield
    if os.path.exists("test_logsentinel.db"):
        try:
            os.remove("test_logsentinel.db")
        except Exception:
            pass

def test_parse_linux_auth_log():
    raw = "Failed password for invalid user admin from 198.51.100.42 port 51234 ssh2"
    parsed = parse_log_line(raw, "auth.log")
    assert parsed["ip_address"] == "198.51.100.42"
    assert parsed["username"] == "admin"
    assert parsed["source"] == "auth.log"

def test_detect_sqli_exploit():
    log = {
        "raw_message": "GET /api/v1/auth?user=admin%27%20OR%201=1-- HTTP/1.1 200",
        "ip_address": "203.0.113.5",
        "source": "nginx_access.log"
    }
    alerts = analyze_and_correlate(log)
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "RULE-WEB-SQLI"
    assert alerts[0]["severity"] == "CRITICAL"
    assert "T1190" in alerts[0]["mitre_technique"]
    assert "iptables" in alerts[0]["playbook_command"]

def test_detect_path_traversal():
    log = {
        "raw_message": "GET /download?file=../../../../etc/passwd HTTP/1.1 403",
        "ip_address": "192.0.2.77",
        "source": "nginx_access.log"
    }
    alerts = analyze_and_correlate(log)
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "RULE-PATH-TRAV"
    assert alerts[0]["severity"] == "HIGH"
    assert "T1083" in alerts[0]["mitre_technique"]

def test_detect_privilege_escalation():
    log = {
        "raw_message": "bob : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "ip_address": "127.0.0.1",
        "username": "bob",
        "source": "auth.log"
    }
    alerts = analyze_and_correlate(log)
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "RULE-PRIV-ESC"
    assert alerts[0]["severity"] == "CRITICAL"
    assert "T1548" in alerts[0]["mitre_technique"]
    assert "pkill -u bob" in alerts[0]["playbook_command"]

def test_detect_scanner_reconnaissance():
    log = {
        "raw_message": 'GET /index.php HTTP/1.1 404 "Mozilla/5.0" "sqlmap/1.6#stable"',
        "ip_address": "198.51.100.99",
        "source": "nginx_access.log"
    }
    alerts = analyze_and_correlate(log)
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "RULE-SCANNER"
    assert alerts[0]["severity"] == "MEDIUM"
