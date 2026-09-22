import pytest
import os
import json
from unittest.mock import patch, MagicMock
from heimdall_agent import tail_and_forward, _save_agent_secret, _load_agent_secret, enroll_agent, send_heartbeat, AGENT_SECRET_FILE

@patch("urllib.request.urlopen")
def test_heimdall_agent_forwards_log(mock_urlopen, tmp_path):
    log_file = tmp_path / "test_auth.log"
    log_file.write_text("Jul 23 14:00:12 host sshd[123]: Failed password for root from 1.2.3.4\n")

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"status": "success"}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    # Test file reading without infinite loop
    with patch("time.sleep", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            tail_and_forward("http://localhost:18000", "test-key", str(log_file), poll_interval=0.01, from_beginning=True)

    assert mock_urlopen.called


def test_agent_secret_roundtrip(tmp_path, monkeypatch):
    secret_file = tmp_path / "secret"
    monkeypatch.setattr("heimdall_agent.AGENT_SECRET_FILE", str(secret_file))
    _save_agent_secret("s3cr3t-value")
    assert _load_agent_secret() == "s3cr3t-value"


def test_agent_secret_missing_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr("heimdall_agent.AGENT_SECRET_FILE", str(tmp_path / "nonexistent"))
    assert _load_agent_secret() == ""


@patch("urllib.request.urlopen")
def test_enroll_agent_saves_secret(mock_urlopen, tmp_path, monkeypatch):
    secret_file = tmp_path / "secret"
    monkeypatch.setattr("heimdall_agent.AGENT_SECRET_FILE", str(secret_file))
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "agent_id": "agent_123", "tenant_id": 1, "status": "active",
        "agent_secret": "issued-secret-123",
    }).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    assert enroll_agent("http://localhost:8080", "enroll-token") is True
    assert secret_file.read_text() == "issued-secret-123"


@patch("urllib.request.urlopen")
def test_send_heartbeat_includes_agent_secret(mock_urlopen, tmp_path, monkeypatch):
    secret_file = tmp_path / "secret"
    secret_file.write_text("persisted-secret")
    monkeypatch.setattr("heimdall_agent.AGENT_SECRET_FILE", str(secret_file))
    monkeypatch.setattr("heimdall_agent.AGENT_ID_FILE", str(tmp_path / "id"))

    mock_resp = MagicMock()
    mock_resp.read.return_value = b"{}"
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    assert send_heartbeat("http://localhost:8080") is True
    req = mock_urlopen.call_args[0][0]
    sent_payload = json.loads(req.data.decode("utf-8"))
    assert sent_payload["agent_id"]
    assert sent_payload["agent_secret"] == "persisted-secret"
