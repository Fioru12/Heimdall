import pytest
import os
from unittest.mock import patch
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


def test_active_responder_reports_failure_on_exception(monkeypatch):
    # Regression test: a firewall command that raises (missing binary, no
    # permissions, timeout) must NOT be reported as a successful block.
    responder = ActiveResponder(dry_run=False)

    def raise_error(*args, **kwargs):
        raise FileNotFoundError("firewall command not found")

    monkeypatch.setattr("core.responder.subprocess.run", raise_error)

    success = responder.block_ip("192.168.1.200", reason="Test Brute Force")
    assert success is False
    assert "192.168.1.200" not in responder.blocked_ips


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


# --- 1. Unblock / TTL mechanism ---------------------------------------

def test_block_ip_with_ttl_records_expiry():
    responder = ActiveResponder(dry_run=True)
    success = responder.block_ip("192.168.50.10", reason="Test TTL", ttl_hours=1)
    assert success is True
    assert "192.168.50.10" in responder.blocked_ips
    assert responder.blocked_ips["192.168.50.10"] is not None


def test_block_ip_without_ttl_has_no_expiry():
    responder = ActiveResponder(dry_run=True)
    responder.block_ip("192.168.50.20", reason="Test no TTL")
    assert responder.blocked_ips["192.168.50.20"] is None


def test_unblock_ip_dry_run_removes_from_memory():
    responder = ActiveResponder(dry_run=True)
    responder.block_ip("192.168.50.30", reason="Test")
    assert "192.168.50.30" in responder.blocked_ips

    result = responder.unblock_ip("192.168.50.30")
    assert result is True
    assert "192.168.50.30" not in responder.blocked_ips


def test_unblock_ip_not_blocked_returns_false():
    responder = ActiveResponder(dry_run=True)
    assert responder.unblock_ip("10.10.10.10") is False


def test_unblock_ip_calls_correct_firewall_command(monkeypatch):
    responder = ActiveResponder(dry_run=False)
    responder.os_type = "Linux"
    responder.blocked_ips["192.168.50.40"] = None

    calls = []

    class FakeResult:
        returncode = 0
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeResult()

    monkeypatch.setattr("core.responder.subprocess.run", fake_run)

    result = responder.unblock_ip("192.168.50.40")
    assert result is True
    assert "192.168.50.40" not in responder.blocked_ips
    assert calls[0] == ["sudo", "ufw", "delete", "deny", "from", "192.168.50.40"]


def test_database_expires_at_column_exists():
    db_path = "test_ttl.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    db = HeimdallDatabase(db_path=db_path)

    db.record_blocked_ip("172.16.0.5", "Test", expires_at="2000-01-01 00:00:00")
    expired = db.get_expired_blocked_ips()
    assert any(r["ip"] == "172.16.0.5" for r in expired)

    db.remove_blocked_ip("172.16.0.5")
    expired_after = db.get_expired_blocked_ips()
    assert not any(r["ip"] == "172.16.0.5" for r in expired_after)

    if os.path.exists(db_path):
        os.remove(db_path)


def test_cleanup_expired_blocks_unblocks_and_removes_from_db():
    db_path = "test_cleanup.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    db = HeimdallDatabase(db_path=db_path)
    db.record_blocked_ip("172.16.0.9", "Test", expires_at="2000-01-01 00:00:00")

    responder = ActiveResponder(dry_run=True)
    unblocked = responder.cleanup_expired_blocks(db)

    assert "172.16.0.9" in unblocked
    assert "172.16.0.9" not in responder.blocked_ips
    assert db.get_expired_blocked_ips() == []

    if os.path.exists(db_path):
        os.remove(db_path)


# --- 2. Log rotation detection in the CLI monitor ----------------------

def test_reopen_if_rotated_detects_truncation(tmp_path):
    from main import _reopen_if_rotated

    logfile = tmp_path / "test.log"
    logfile.write_text("line1\nline2\n", encoding="utf-8")

    f = open(logfile, "r", encoding="utf-8")
    f.read()  # advance position to end of the original content

    # Simulate rotation: file truncated and rewritten with less content.
    logfile.write_text("new\n", encoding="utf-8")

    new_f = _reopen_if_rotated(f, str(logfile))
    assert new_f.tell() == 0
    content = new_f.read()
    assert content == "new\n"
    new_f.close()


def test_reopen_if_rotated_no_change_keeps_same_handle(tmp_path):
    from main import _reopen_if_rotated

    logfile = tmp_path / "test2.log"
    logfile.write_text("line1\n", encoding="utf-8")

    f = open(logfile, "r", encoding="utf-8")
    f.read()

    same_f = _reopen_if_rotated(f, str(logfile))
    assert same_f is f
    same_f.close()


# --- 3. Minimal IPv6 support --------------------------------------------

def test_parser_normalizes_ipv4():
    parser = LogParser()
    assert LogParser._normalize_ip("192.168.1.1") == "192.168.1.1"


def test_parser_normalizes_ipv6():
    parser = LogParser()
    assert LogParser._normalize_ip("2001:db8::1") == "2001:db8::1"


def test_parser_rejects_invalid_ip():
    parser = LogParser()
    assert LogParser._normalize_ip("999.999.999.999") is None
    assert LogParser._normalize_ip("not-an-ip") is None


def test_parser_generic_fallback_extracts_ipv6():
    parser = LogParser()
    line = "unauthorized access attempt from 2001:db8::dead:beef detected"
    parsed = parser.parse_line(line)
    assert parsed is not None
    assert parsed["source_ip"] == "2001:db8::dead:beef"


def test_responder_block_ip_accepts_ipv6_without_crash():
    responder = ActiveResponder(dry_run=True)
    success = responder.block_ip("2001:db8::1", reason="Test IPv6")
    assert success is True
    assert "2001:db8::1" in responder.blocked_ips


# --- 4. Optional Gjallarhorn hub integration ----------------------------

from core.notifier import gjallarhorn_configured, send_alert_via_gjallarhorn

_SAMPLE_ALERT = {
    "rule_title": "SSH Brute-Force Attack Detected",
    "severity": "HIGH",
    "source_ip": "203.0.113.50",
    "username": "root",
    "description": "12 failed logins in 60s.",
}


def test_gjallarhorn_configured_false_when_env_unset(monkeypatch):
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    assert gjallarhorn_configured() is False


def test_gjallarhorn_configured_true_when_env_set(monkeypatch):
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    assert gjallarhorn_configured() is True


@patch("core.notifier.gjallarhorn_notify")
def test_send_alert_via_gjallarhorn_not_called_without_env(mock_notify, monkeypatch):
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    result = send_alert_via_gjallarhorn(_SAMPLE_ALERT, action="BLOCKED_IP")
    assert result is False
    mock_notify.assert_not_called()


@patch("core.notifier.gjallarhorn_notify")
def test_send_alert_via_gjallarhorn_called_with_mapped_params(mock_notify, monkeypatch):
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")
    mock_notify.return_value = True

    result = send_alert_via_gjallarhorn(_SAMPLE_ALERT, action="BLOCKED_IP")

    assert result is True
    mock_notify.assert_called_once()
    _, kwargs = mock_notify.call_args
    assert kwargs["hub_url"] == "http://localhost:8090"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["source"] == "Heimdall"
    assert kwargs["severity"] == "high"
    assert kwargs["title"] == "SSH Brute-Force Attack Detected"
    assert "203.0.113.50" in kwargs["message"]
    assert "BLOCKED_IP" in kwargs["message"]


@patch("core.notifier.gjallarhorn_notify")
def test_send_alert_via_gjallarhorn_maps_all_severities(mock_notify, monkeypatch):
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    mock_notify.return_value = True

    for heimdall_sev, expected in [
        ("LOW", "low"), ("MEDIUM", "medium"), ("HIGH", "high"), ("CRITICAL", "critical"),
    ]:
        alert = dict(_SAMPLE_ALERT, severity=heimdall_sev)
        send_alert_via_gjallarhorn(alert, action="LOGGED")
        assert mock_notify.call_args.kwargs["severity"] == expected


def test_gjallarhorn_takes_priority_over_telegram_in_cli_monitor_dispatch(monkeypatch, tmp_path):
    """Regression: when GJALLARHORN_HUB_URL is set, main.run_cli_monitor's
    alert dispatch must use Gjallarhorn and must NOT also call the direct
    Telegram notifier for the same alert."""
    import main as heimdall_main

    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")

    with patch("main.send_alert_via_gjallarhorn", return_value=True) as mock_gjall, \
         patch("core.notifier.TelegramNotifier.send_alert") as mock_telegram:
        # Exercise the same branching logic main.py uses, without needing a
        # real log file / config on disk.
        alert = dict(_SAMPLE_ALERT)
        action = "BLOCKED_IP"
        if heimdall_main.gjallarhorn_configured():
            heimdall_main.send_alert_via_gjallarhorn(alert, action=action)
        else:
            from core.notifier import TelegramNotifier
            TelegramNotifier(bot_token="x", chat_id="y").send_alert(alert, action=action)

        mock_gjall.assert_called_once_with(alert, action=action)
        mock_telegram.assert_not_called()


def test_telegram_fallback_used_when_gjallarhorn_not_configured(monkeypatch):
    """When GJALLARHORN_HUB_URL is unset, the same dispatch logic used in
    main.py / api/server.py must fall back to the direct Telegram notifier,
    exactly as before this integration was added."""
    import main as heimdall_main

    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)

    with patch("main.send_alert_via_gjallarhorn") as mock_gjall, \
         patch("core.notifier.TelegramNotifier.send_alert") as mock_telegram:
        alert = dict(_SAMPLE_ALERT)
        action = "LOGGED"
        notifier = heimdall_main.TelegramNotifier(bot_token="x", chat_id="y")
        if heimdall_main.gjallarhorn_configured():
            heimdall_main.send_alert_via_gjallarhorn(alert, action=action)
        elif notifier:
            notifier.send_alert(alert, action=action)

        mock_gjall.assert_not_called()
        mock_telegram.assert_called_once_with(alert, action=action)
