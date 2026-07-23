import re
from datetime import datetime
from typing import Dict, Any, Optional

class LogParser:
    """
    Parses different log formats (Linux auth.log, Windows Security Event logs, custom JSON/syslog)
    to extract structured information (timestamp, source IP, username, event type).
    """

    # Regex for Linux SSH failed login / auth log
    # Example: "Jul 23 14:00:12 hostname sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
    SSH_FAILED_REGEX = re.compile(
        r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>[\w\-]+)\s+(?P<process>[\w\-\[\]]+):\s+Failed password for (?:invalid user\s+)?(?P<user>[\w\-]+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    )

    # Regex for Windows Event Log simulation format
    # Example: "[2026-07-23 14:00:12] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 10.0.0.15"
    WIN_FAILED_REGEX = re.compile(
        r'^\[(?P<timestamp>[^\]]+)\]\s+(?P<source>[\w\-]+):\s+EventID\s+(?P<event_id>\d+)\s+-\s+(?P<message>.+?)(?:Account:\s+(?P<user>[\w\-]+))?(?:,\s+Source IP:\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?$'
    )

    def parse_line(self, line: str, log_source_type: str = "auto") -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None

        # Try parsing as Linux SSH auth log
        match_ssh = self.SSH_FAILED_REGEX.match(line)
        if match_ssh:
            data = match_ssh.groupdict()
            return {
                "timestamp": data.get("timestamp"),
                "log_type": "ssh_auth",
                "source_ip": data.get("ip"),
                "username": data.get("user"),
                "raw_log": line,
                "status": "failed_login"
            }

        # Try parsing as Windows Event Log
        match_win = self.WIN_FAILED_REGEX.match(line)
        if match_win:
            data = match_win.groupdict()
            return {
                "timestamp": data.get("timestamp"),
                "log_type": "windows_security",
                "source_ip": data.get("ip"),
                "username": data.get("user"),
                "event_id": data.get("event_id"),
                "raw_log": line,
                "status": "failed_login" if data.get("event_id") == "4625" else "suspicious"
            }

        # Generic fallback for custom logs or simulation
        # Looking for IP addresses or keywords like 'failed', 'attack', 'unauthorized'
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        source_ip = ip_match.group(0) if ip_match else None

        if any(kw in line.lower() for kw in ["fail", "error", "unauthorized", "deny", "attack", "malicious"]):
            return {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "log_type": "generic_security",
                "source_ip": source_ip,
                "username": "unknown",
                "raw_log": line,
                "status": "suspicious"
            }

        return None
