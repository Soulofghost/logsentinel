import re
import uuid
import urllib.parse
from typing import Dict, Any, Optional, List
from app.database import get_db_connection

# Detection Patterns
PATTERNS = {
    "ssh_failure": re.compile(r"Failed password for (?:invalid user )?(\w+) from ([\d\.]+)"),
    "sudo_abuse": re.compile(r"COMMAND=.*(?:cat\s+/etc/shadow|chmod\s+777\s+/etc|sudoers|useradd)", re.IGNORECASE),
    "sqli": re.compile(r"(?:UNION\s+SELECT|['\"]\s*OR\s*['\"\d=]|SELECT\s+.*FROM|INFORMATION_SCHEMA)", re.IGNORECASE),
    "path_traversal": re.compile(r"(?:\.\./|\.\.\\|/etc/passwd)", re.IGNORECASE),
    "scanner_agents": re.compile(r"(?:sqlmap|nikto|nmap|masscan|zgrab)", re.IGNORECASE)
}

def parse_log_line(raw_line: str, source: str = "syslog") -> Dict[str, Any]:
    ip = None
    user = None

    # Try IP extraction
    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_line)
    if ip_match:
        ip = ip_match.group(0)

    # Try user extraction
    ssh_match = PATTERNS["ssh_failure"].search(raw_line)
    if ssh_match:
        user = ssh_match.group(1)
        ip = ssh_match.group(2)
    elif "USER=" in raw_line:
        u_match = re.search(r"USER=(\w+)", raw_line)
        if u_match:
            user = u_match.group(1)

    return {
        "source": source,
        "raw_message": raw_line.strip(),
        "ip_address": ip,
        "username": user
    }

def analyze_and_correlate(log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    triggered_alerts = []
    msg = log_entry["raw_message"]
    decoded_msg = urllib.parse.unquote(msg)
    ip = log_entry.get("ip_address")

    # 1. Privilege Escalation (Host security)
    if PATTERNS["sudo_abuse"].search(msg) or PATTERNS["sudo_abuse"].search(decoded_msg):
        triggered_alerts.append({
            "id": "alert-" + str(uuid.uuid4())[:8],
            "rule_id": "RULE-PRIV-ESC",
            "rule_name": "Unauthorized Sudo / Root Privilege Escalation",
            "severity": "CRITICAL",
            "mitre_technique": "T1548.003 (Sudo Caching & Abuse)",
            "source_ip": ip or "127.0.0.1",
            "description": f"User attempted high-risk root access command: {msg[:120]}...",
            "playbook_command": f"pkill -u {log_entry.get('username') or 'attacker'} && usermod -L {log_entry.get('username') or 'attacker'}",
            "status": "OPEN"
        })

    # 2. SQL Injection
    if PATTERNS["sqli"].search(msg) or PATTERNS["sqli"].search(decoded_msg):
        triggered_alerts.append({
            "id": "alert-" + str(uuid.uuid4())[:8],
            "rule_id": "RULE-WEB-SQLI",
            "rule_name": "SQL Injection Exploit Payload in Log Stream",
            "severity": "CRITICAL",
            "mitre_technique": "T1190 (Exploit Public-Facing App)",
            "source_ip": ip or "0.0.0.0",
            "description": f"Detected malicious SQL injection syntax in URI or body payload: {msg[:120]}...",
            "playbook_command": f"iptables -A INPUT -s {ip or '0.0.0.0'} -j DROP && nginx -s reload",
            "status": "OPEN"
        })

    # 3. Path Traversal
    elif PATTERNS["path_traversal"].search(msg) or PATTERNS["path_traversal"].search(decoded_msg):
        triggered_alerts.append({
            "id": "alert-" + str(uuid.uuid4())[:8],
            "rule_id": "RULE-PATH-TRAV",
            "rule_name": "Directory Path Traversal Attempt",
            "severity": "HIGH",
            "mitre_technique": "T1083 (File and Directory Discovery)",
            "source_ip": ip or "0.0.0.0",
            "description": f"Unauthorized relative path traversal syntax detected: {msg[:120]}...",
            "playbook_command": f"iptables -A INPUT -s {ip or '0.0.0.0'} -j DROP",
            "status": "OPEN"
        })

    # 4. Scanner Reconnaissance
    if PATTERNS["scanner_agents"].search(msg) or PATTERNS["scanner_agents"].search(decoded_msg):
        triggered_alerts.append({
            "id": "alert-" + str(uuid.uuid4())[:8],
            "rule_id": "RULE-SCANNER",
            "rule_name": "Automated Security Scanner Fingerprint",
            "severity": "MEDIUM",
            "mitre_technique": "T1595.002 (Vulnerability Scanning)",
            "source_ip": ip or "0.0.0.0",
            "description": f"Known automated scanner User-Agent/traffic detected in logs: {msg[:120]}...",
            "playbook_command": f"iptables -A INPUT -s {ip or '0.0.0.0'} -j DROP",
            "status": "OPEN"
        })

    # Persist alerts to DB
    if triggered_alerts:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for a in triggered_alerts:
                cursor.execute("""
                    INSERT INTO alerts (id, rule_id, rule_name, severity, mitre_technique, source_ip, description, playbook_command, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (a["id"], a["rule_id"], a["rule_name"], a["severity"], a["mitre_technique"], a["source_ip"], a["description"], a["playbook_command"], a["status"]))
            conn.commit()

    return triggered_alerts
