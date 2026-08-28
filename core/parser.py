import re
import ipaddress
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

    # Rough candidate matcher for IPv6 literals in free-form log text
    # (e.g. "2001:db8::1", "fe80::1", "::1"). Validated/normalized via the
    # `ipaddress` module afterwards, since a regex alone can't reliably tell
    # a real IPv6 address apart from other colon-separated tokens.
    IPV6_CANDIDATE_REGEX = re.compile(r'(?<![\w:.])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:.])')

    @staticmethod
    def _normalize_ip(ip_str: Optional[str]) -> Optional[str]:
        """
        Validates an extracted IP string (v4 or v6) using the stdlib
        `ipaddress` module and returns its normalized string form, or None
        if it isn't actually a valid IP address.
        """
        if not ip_str:
            return None
        try:
            return str(ipaddress.ip_address(ip_str))
        except ValueError:
            return None

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
                "source_ip": self._normalize_ip(data.get("ip")) or data.get("ip"),
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
                "source_ip": self._normalize_ip(data.get("ip")) or data.get("ip"),
                "username": data.get("user"),
                "event_id": data.get("event_id"),
                "raw_log": line,
                "status": "failed_login" if data.get("event_id") == "4625" else "suspicious"
            }

        # Generic fallback for custom logs or simulation
        # Looking for IP addresses or keywords like 'failed', 'attack', 'unauthorized'
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        source_ip = self._normalize_ip(ip_match.group(0)) if ip_match else None

        if not source_ip:
            # No IPv4 match; look for an IPv6 literal instead.
            for candidate in self.IPV6_CANDIDATE_REGEX.findall(line):
                normalized = self._normalize_ip(candidate)
                if normalized:
                    source_ip = normalized
                    break

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
