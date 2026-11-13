from pydantic import BaseModel, Field
from typing import Optional, List

class LogIngestRequest(BaseModel):
    source: Optional[str] = "syslog"
    message: str = Field(..., min_length=1)

class LogResponse(BaseModel):
    id: str
    source: str
    raw_message: str
    ip_address: Optional[str] = None
    username: Optional[str] = None
    timestamp: str

class AlertResponse(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: str
    source_ip: Optional[str] = None
    description: str
    playbook_command: str
    status: str
    created_at: str

class AlertStatusUpdate(BaseModel):
    status: str

class SOCMetricsResponse(BaseModel):
    total_logs: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    investigating_alerts: int
    resolved_alerts: int
