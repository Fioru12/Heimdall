import pytest
import os
import json
from unittest.mock import patch, MagicMock
from heimdall_agent import tail_and_forward

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
