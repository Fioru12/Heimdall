import json
import urllib.request
import urllib.error
from typing import Dict, Any

class TelegramNotifier:
    """
    Sends alert notifications to a Telegram channel when high-severity
    security events are detected by Heimdall.
    """

    def __init__(self, bot_token: str = "", chat_id: str = ""):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = bool(bot_token and chat_id)

    def send_alert(self, alert: Dict[str, Any], action: str = "LOGGED") -> bool:
        if not self.enabled:
            return False

        severity = alert.get("severity", "UNKNOWN")
        rule = alert.get("rule_title", "Unknown Rule")
        ip = alert.get("source_ip", "N/A")
        username = alert.get("username", "N/A")
        description = alert.get("description", "")

        emoji = "[!]" if severity in ["HIGH", "CRITICAL"] else "[*]"

        message = (
            f"{emoji} HEIMDALL SECURITY ALERT\n"
            f"-------------------------\n"
            f"Severity: {severity}\n"
            f"Rule: {rule}\n"
            f"Source IP: {ip}\n"
            f"Username: {username}\n"
            f"Action: {action}\n"
            f"-------------------------\n"
            f"{description}"
        )

        return self._send(message)

    def send_summary(self, stats: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False

        message = (
            f"HEIMDALL DAILY SUMMARY\n"
            f"----------------------\n"
            f"Total Alerts: {stats.get('total_alerts', 0)}\n"
            f"Blocked IPs: {stats.get('total_blocked_ips', 0)}\n"
            f"Severity: {stats.get('severity_breakdown', {})}"
        )

        return self._send(message)

    def _send(self, text: str) -> bool:
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = json.dumps({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "TEXT"
            }).encode("utf-8")

            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[TELEGRAM ERROR] Failed to send notification: {e}")
            return False
