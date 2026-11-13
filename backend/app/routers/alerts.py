from fastapi import APIRouter, HTTPException
from typing import List, Optional
from app.database import get_db_connection
from app.schemas import AlertResponse, AlertStatusUpdate, SOCMetricsResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
def get_alerts(status: Optional[str] = None):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM alerts"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status.upper())
        query += " ORDER BY created_at DESC"

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        return [
            AlertResponse(
                id=r["id"],
                rule_id=r["rule_id"],
                rule_name=r["rule_name"],
                severity=r["severity"],
                mitre_technique=r["mitre_technique"],
                source_ip=r["source_ip"],
                description=r["description"],
                playbook_command=r["playbook_command"],
                status=r["status"],
                created_at=r["created_at"]
            )
            for r in rows
        ]

@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(alert_id: str, update: AlertStatusUpdate):
    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED"]
    status_clean = update.status.upper()
    if status_clean not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (status_clean, alert_id))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found.")
        conn.commit()

        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        r = cursor.fetchone()
        return AlertResponse(
            id=r["id"],
            rule_id=r["rule_id"],
            rule_name=r["rule_name"],
            severity=r["severity"],
            mitre_technique=r["mitre_technique"],
            source_ip=r["source_ip"],
            description=r["description"],
            playbook_command=r["playbook_command"],
            status=r["status"],
            created_at=r["created_at"]
        )

@router.get("/metrics/summary", response_model=SOCMetricsResponse)
def get_metrics():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        total_logs = cursor.execute("SELECT count(*) FROM logs").fetchone()[0]
        open_alerts = cursor.execute("SELECT count(*) FROM alerts WHERE status = 'OPEN'").fetchone()[0]
        investigating = cursor.execute("SELECT count(*) FROM alerts WHERE status = 'INVESTIGATING'").fetchone()[0]
        resolved = cursor.execute("SELECT count(*) FROM alerts WHERE status = 'RESOLVED'").fetchone()[0]
        critical = cursor.execute("SELECT count(*) FROM alerts WHERE severity = 'CRITICAL'").fetchone()[0]
        high = cursor.execute("SELECT count(*) FROM alerts WHERE severity = 'HIGH'").fetchone()[0]

        return SOCMetricsResponse(
            total_logs=total_logs,
            open_alerts=open_alerts,
            critical_alerts=critical,
            high_alerts=high,
            investigating_alerts=investigating,
            resolved_alerts=resolved
        )
