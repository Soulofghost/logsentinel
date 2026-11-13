import uuid
from fastapi import APIRouter, HTTPException
from typing import List, Optional
from app.database import get_db_connection
from app.schemas import LogIngestRequest, LogResponse
from app.engine.detector import parse_log_line, analyze_and_correlate

router = APIRouter(prefix="/logs", tags=["Logs"])

@router.get("", response_model=List[LogResponse])
def get_logs(limit: int = 50):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [
            LogResponse(
                id=r["id"],
                source=r["source"],
                raw_message=r["raw_message"],
                ip_address=r["ip_address"],
                username=r["username"],
                timestamp=r["timestamp"]
            )
            for r in rows
        ]

@router.post("", response_model=dict, status_code=201)
def ingest_log(req: LogIngestRequest):
    parsed = parse_log_line(req.message, req.source or "syslog")
    log_id = "log-" + str(uuid.uuid4())[:8]

    # Insert into database
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO logs (id, source, raw_message, ip_address, username)
            VALUES (?, ?, ?, ?, ?)
        """, (log_id, parsed["source"], parsed["raw_message"], parsed["ip_address"], parsed["username"]))
        conn.commit()

    # Correlate and detect threats
    alerts = analyze_and_correlate(parsed)

    return {
        "log_id": log_id,
        "parsed": parsed,
        "alerts_triggered": alerts
    }
