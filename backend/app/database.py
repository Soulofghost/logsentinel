import sqlite3
from contextlib import contextmanager
from typing import Generator
from app.config import DB_PATH

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            raw_message TEXT NOT NULL,
            ip_address TEXT,
            username TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            parsed_data_json TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
            mitre_technique TEXT NOT NULL,
            source_ip TEXT,
            description TEXT NOT NULL,
            playbook_command TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('OPEN', 'INVESTIGATING', 'RESOLVED')) DEFAULT 'OPEN',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Seed demo incidents if empty
    cursor.execute("SELECT count(*) FROM alerts")
    if cursor.fetchone()[0] == 0:
      seed_demo_alerts(cursor)
      conn.commit()

    conn.close()

def seed_demo_alerts(cursor: sqlite3.Cursor):
    alerts = [
        (
            "alert-101",
            "RULE-SSH-BRUTE",
            "SSH Credential Brute Force Detected",
            "HIGH",
            "T1110.001 (Password Guessing)",
            "198.51.100.42",
            "Detected 14 failed SSH authentication attempts within 30s against port 22",
            "iptables -A INPUT -s 198.51.100.42 -j DROP && fail2ban-client set sshd banip 198.51.100.42",
            "OPEN"
        ),
        (
            "alert-102",
            "RULE-WEB-SQLI",
            "SQL Injection Exploit Payload in HTTP URI",
            "CRITICAL",
            "T1190 (Exploit Public-Facing Application)",
            "203.0.113.88",
            "Inbound HTTP GET request containing stacked UNION SELECT query on /api/v1/auth",
            "nginx -s reload && ufw deny from 203.0.113.88 to any port 443",
            "INVESTIGATING"
        ),
        (
            "alert-103",
            "RULE-PRIV-ESC",
            "Unauthorized Sudoers Shadow File Access",
            "CRITICAL",
            "T1548.003 (Sudo and Sudo Caching)",
            "127.0.0.1",
            "User 'deploy_bot' executed unauthorized command 'sudo cat /etc/shadow'",
            "pkill -u deploy_bot && usermod -L deploy_bot",
            "OPEN"
        )
    ]

    for a in alerts:
        cursor.execute("""
            INSERT INTO alerts (id, rule_id, rule_name, severity, mitre_technique, source_ip, description, playbook_command, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, a)

    # Seed demo logs
    logs = [
        ("log-1", "auth.log", "Failed password for invalid user root from 198.51.100.42 port 49122 ssh2", "198.51.100.42", "root"),
        ("log-2", "auth.log", "Failed password for invalid user admin from 198.51.100.42 port 49124 ssh2", "198.51.100.42", "admin"),
        ("log-3", "nginx_access.log", "GET /api/v1/users?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1 500", "203.0.113.88", None),
        ("log-4", "auth.log", "deploy_bot : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow", "127.0.0.1", "deploy_bot"),
        ("log-5", "syslog", "systemd[1]: Started Docker Application Container Engine.", "127.0.0.1", "system")
    ]
    for l in logs:
        cursor.execute("INSERT INTO logs (id, source, raw_message, ip_address, username) VALUES (?, ?, ?, ?, ?)", l)

@contextmanager
def get_db_connection() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
