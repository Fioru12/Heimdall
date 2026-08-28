import os
import secrets
from fastapi import FastAPI, HTTPException, Body, Depends, Header, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from storage.database import HeimdallDatabase
from core.parser import LogParser
from core.detector import RuleDetector
from core.responder import ActiveResponder
from core.notifier import TelegramNotifier, gjallarhorn_configured, send_alert_via_gjallarhorn
from core.config import load_config

app = FastAPI(
    title="Heimdall HIDS API",
    description="Host Intrusion Detection System & Active Response REST API",
    version="1.0.0"
)

config = load_config()

API_KEY = os.environ.get("HEIMDALL_API_KEY")
if not API_KEY:
    API_KEY = secrets.token_urlsafe(24)
    print(f"[SECURITY WARNING] HEIMDALL_API_KEY not set. Generated a random key for this run:")
    print(f"    {API_KEY}")
    print(f"    Set HEIMDALL_API_KEY in your environment to use a stable key across restarts.")

db = HeimdallDatabase(db_path=config.get("database", {}).get("path", "heimdall.db"))
parser = LogParser()
detector = RuleDetector()
responder = ActiveResponder(dry_run=config.get("responder", {}).get("dry_run", True))

_tg_config = config.get("telegram", {})
notifier = TelegramNotifier(
    bot_token=_tg_config.get("bot_token", ""),
    chat_id=_tg_config.get("chat_id", ""),
) if _tg_config.get("enabled") else None


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")


class LogIngestRequest(BaseModel):
    log_line: str = Field(..., max_length=8192)
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


@app.get("/api/v1/alerts", response_model=List[Dict[str, Any]], dependencies=[Depends(require_api_key)])
def get_alerts(limit: int = Query(default=50, ge=1, le=500)):
    return db.get_alerts(limit=limit)


@app.get("/api/v1/stats", dependencies=[Depends(require_api_key)])
def get_stats():
    return db.get_stats()


@app.post("/api/v1/ingest", dependencies=[Depends(require_api_key)])
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
        # Prefer the centralized Gjallarhorn hub when it's configured;
        # otherwise fall back to the direct Telegram notifier.
        if gjallarhorn_configured():
            send_alert_via_gjallarhorn(alert, action=action)
        elif notifier:
            notifier.send_alert(alert, action=action)
        actions_executed.append({"alert": alert["rule_title"], "action": action})

    return {
        "status": "processed",
        "parsed_event": parsed,
        "alerts_triggered": len(alerts),
        "actions": actions_executed
    }


@app.get("/api/v1/blocked", dependencies=[Depends(require_api_key)])
def get_blocked_ips():
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
