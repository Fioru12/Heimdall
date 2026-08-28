import json
import os
import urllib.request
import urllib.error
from typing import Dict, Any

from core.gjallarhorn_client import notify as gjallarhorn_notify

# Heimdall alert severities are LOW/MEDIUM/HIGH/CRITICAL; Gjallarhorn's hub
# expects lowercase values ("low"/"medium"/"high"/"critical"). Anything that
# doesn't map cleanly falls back to "low" rather than dropping the alert.
_GJALLARHORN_SEVERITY_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _map_severity_for_gjallarhorn(severity: str) -> str:
    return _GJALLARHORN_SEVERITY_MAP.get(str(severity).upper(), "low")


def gjallarhorn_configured() -> bool:
    """True if GJALLARHORN_HUB_URL is set in the environment, i.e. Heimdall
    should route alerts through the centralized Gjallarhorn hub instead of
    (or in addition to) the direct Telegram notifier."""
    return bool(os.environ.get("GJALLARHORN_HUB_URL"))


def send_alert_via_gjallarhorn(alert: Dict[str, Any], action: str = "LOGGED") -> bool:
    """Sends an alert to the Gjallarhorn hub, if configured.

    No-op (returns False) when GJALLARHORN_HUB_URL isn't set. Never raises -
    delegates to gjallarhorn_client.notify(), which already swallows network
    errors and returns False on failure.
    """
    hub_url = os.environ.get("GJALLARHORN_HUB_URL")
    if not hub_url:
        return False

    api_key = os.environ.get("GJALLARHORN_API_KEY", "")
    severity = alert.get("severity", "LOW")
    rule = alert.get("rule_title", "Unknown Rule")
    ip = alert.get("source_ip", "N/A")
    username = alert.get("username", "N/A")
    description = alert.get("description", "")

    message = (
        f"Source IP: {ip}\n"
        f"Username: {username}\n"
        f"Action: {action}\n"
        f"{description}"
    )

    return gjallarhorn_notify(
        hub_url=hub_url,
        api_key=api_key,
        source="Heimdall",
        severity=_map_severity_for_gjallarhorn(severity),
        title=rule,
        message=message,
    )


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
            }).encode("utf-8")

            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[TELEGRAM ERROR] Failed to send notification: {e}")
            return False
