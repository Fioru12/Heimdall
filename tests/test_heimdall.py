import pytest
import os
from core.parser import LogParser
from core.detector import RuleDetector
from core.responder import ActiveResponder
from storage.database import HeimdallDatabase

def test_log_parser_ssh():
    parser = LogParser()
    line = "Jul 23 14:00:12 server01 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
    parsed = parser.parse_line(line)
    assert parsed is not None
    assert parsed["source_ip"] == "192.168.1.50"
    assert parsed["username"] == "admin"
    assert parsed["log_type"] == "ssh_auth"

def test_log_parser_windows():
    parser = LogParser()
    line = "[2026-07-23 14:00:12] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 10.0.0.15"
    parsed = parser.parse_line(line)
    assert parsed is not None
    assert parsed["source_ip"] == "10.0.0.15"
    assert parsed["username"] == "Administrator"
    assert parsed["event_id"] == "4625"

def test_rule_detector():
    detector = RuleDetector()
    # Add a test rule or check loaded rules
    assert len(detector.rules) > 0

    # Evaluate multiple failed logins to trigger threshold
    event = {
        "timestamp": "2026-07-23 14:00:12",
        "log_type": "ssh_auth",
        "source_ip": "10.0.0.99",
        "username": "root",
        "raw_log": "Failed password for invalid user root from 10.0.0.99",
        "status": "failed_login"
    }

    # Rule ssh_bruteforce has threshold 3
    alerts = []
    for _ in range(3):
        alerts = detector.evaluate(event)

    assert len(alerts) > 0
    assert alerts[0]["source_ip"] == "10.0.0.99"
    assert alerts[0]["severity"] == "HIGH"

def test_database_persistence():
    db_path = "test_sentinel.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    db = HeimdallDatabase(db_path=db_path)
    test_alert = {
        "rule_title": "Test Alert",
        "severity": "HIGH",
        "source_ip": "1.2.3.4",
        "username": "test",
        "description": "Test description",
        "count": 3,
        "timestamp": "2026-07-23 14:00:00",
        "raw_log": "test log"
    }
    db.save_alert(test_alert, action_taken="BLOCKED_IP")
    db.record_blocked_ip("1.2.3.4", "Test Alert")

    stats = db.get_stats()
    assert stats["total_alerts"] == 1
    assert stats["total_blocked_ips"] == 1

    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "1.2.3.4"

    if os.path.exists(db_path):
        os.remove(db_path)

def test_active_responder():
    responder = ActiveResponder(dry_run=True)
    success = responder.block_ip("192.168.1.100", reason="Test Brute Force")
    assert success is True
    assert "192.168.1.100" in responder.blocked_ips


from core.responder import AlertNotifier

def test_alert_notifier_init():
    notifier = AlertNotifier()
    assert notifier.webhook_urls == []
    assert notifier.email_config is None

def test_alert_notifier_configure_webhooks():
    notifier = AlertNotifier()
    notifier.configure_webhooks(["https://hooks.slack.com/test", "not_a_url", "https://discord.com/api/test"])
    assert len(notifier.webhook_urls) == 2

def test_alert_notifier_webhook_no_urls():
    notifier = AlertNotifier()
    result = notifier.send_webhook("Test Alert", "high", "Details here")
    assert result is False

def test_alert_notifier_webhook_bad_url():
    notifier = AlertNotifier()
    notifier.configure_webhooks(["http://127.0.0.1:19999/test"])
    result = notifier.send_webhook("Test Alert", "high", "Details here")
    assert result is False

def test_alert_notifier_email_no_config():
    notifier = AlertNotifier()
    result = notifier.send_email("Subject", "Body")
    assert result is False

def test_alert_notifier_notify_returns_dict():
    notifier = AlertNotifier()
    result = notifier.notify("Test", "medium", "Details")
    assert isinstance(result, dict)
    assert "webhook" in result
    assert "email" in result
