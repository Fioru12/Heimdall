from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from storage.database import SentinelDatabase
from core.parser import LogParser
from core.detector import RuleDetector
from core.responder import ActiveResponder

app = FastAPI(
    title="Heimdall HIDS API",
    description="Host Intrusion Detection System & Active Response REST API",
    version="1.0.0"
)

db = SentinelDatabase()
parser = LogParser()
detector = RuleDetector()
responder = ActiveResponder(dry_run=True) # Safe default for API testing

class LogIngestRequest(BaseModel):
    log_line: str
    log_type: Optional[str] = "auto"

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "Heimdall HIDS",
        "version": "1.0.0",
        "endpoints": [
            "/api/v1/alerts",
            "/api/v1/stats",
            "/api/v1/ingest",
            "/api/v1/blocked"
        ]
    }

@app.get("/api/v1/alerts", response_model=List[Dict[str, Any]])
def get_alerts(limit: int = 50):
    return db.get_alerts(limit=limit)

@app.get("/api/v1/stats")
def get_stats():
    return db.get_stats()

@app.post("/api/v1/ingest")
def ingest_log(payload: LogIngestRequest):
    """
    Ingests a log line, parses it, evaluates detection rules, and triggers active response if needed.
    """
    parsed = parser.parse_line(payload.log_line, log_source_type=payload.log_type)
    if not parsed:
        return {"status": "ignored", "reason": "Log format not recognized or non-security event"}

    alerts = detector.evaluate(parsed)
    actions_executed = []

    for alert in alerts:
        action = "LOGGED"
        if alert.get("severity") in ["HIGH", "CRITICAL"]:
            ip = alert.get("source_ip")
            if ip and ip != "N/A":
                success = responder.block_ip(ip, reason=alert.get("rule_title"))
                if success:
                    action = "BLOCKED_IP"
                    db.record_blocked_ip(ip, reason=alert.get("rule_title"))

        db.save_alert(alert, action_taken=action)
        actions_executed.append({"alert": alert["rule_title"], "action": action})

    return {
        "status": "processed",
        "parsed_event": parsed,
        "alerts_triggered": len(alerts),
        "actions": actions_executed
    }

@app.get("/api/v1/blocked")
def get_blocked_ips():
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
