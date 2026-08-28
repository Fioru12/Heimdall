import subprocess
import platform
import logging
import json
import urllib.request
import urllib.error
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import Dict, Any, List, Optional

logger = logging.getLogger("Heimdall")

class AlertNotifier:
    """
    Sends alert notifications via webhook (Slack/Discord/generic) and/or email (SMTP).
    """

    def __init__(self):
        self.webhook_urls: List[str] = []
        self.email_config: Optional[Dict[str, Any]] = None

    def configure_webhooks(self, urls: List[str]):
        self.webhook_urls = [u for u in urls if u and u.startswith("http")]

    def configure_email(self, smtp_host: str, smtp_port: int, username: str, password: str, from_addr: str, to_addrs: List[str]):
        self.email_config = {
            "host": smtp_host,
            "port": smtp_port,
            "username": username,
            "password": password,
            "from": from_addr,
            "to": to_addrs,
        }

    def send_webhook(self, title: str, severity: str, details: str) -> bool:
        sent = False
        payload = json.dumps({
            "text": f"**[{severity.upper()}] Heimdall Alert: {title}**\n{details}",
            "username": "Asgard SOC",
            "content": f"**[{severity.upper()}] {title}**\n{details}",
        }).encode("utf-8")

        for url in self.webhook_urls:
            try:
                req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
                sent = True
            except Exception as e:
                logger.warning(f"Webhook failed for {url}: {e}")
        return sent

    def send_email(self, subject: str, body: str) -> bool:
        if not self.email_config:
            return False
        try:
            cfg = self.email_config
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = cfg["from"]
            msg["To"] = ", ".join(cfg["to"])

            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
                server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.send_message(msg)
            return True
        except Exception as e:
            logger.warning(f"Email alert failed: {e}")
            return False

    def notify(self, title: str, severity: str, details: str) -> Dict[str, bool]:
        return {
            "webhook": self.send_webhook(title, severity, details),
            "email": self.send_email(f"[{severity.upper()}] Heimdall: {title}", details),
        }


class ActiveResponder:
    """
    Executes automated defense actions when high-severity security alerts are triggered,
    such as blocking malicious source IPs using system firewalls (UFW / iptables / Windows Firewall).
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.os_type = platform.system()
        # Maps blocked IP -> expires_at (ISO timestamp string) or None for a
        # permanent block. Using a dict (rather than a set) lets us track TTLs
        # while keeping `ip in self.blocked_ips` membership checks working.
        self.blocked_ips: Dict[str, Optional[str]] = {}
        self.notifier = AlertNotifier()

    @staticmethod
    def _compute_expiry(ttl_hours: Optional[float]) -> Optional[str]:
        if not ttl_hours:
            return None
        expiry = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        return expiry.strftime("%Y-%m-%d %H:%M:%S")

    def block_ip(self, ip: str, reason: str = "", ttl_hours: Optional[float] = None) -> bool:
        """
        Blocks an IP address using host firewall depending on the OS.
        Sends alert notification via configured webhook/email channels.

        If ttl_hours is provided, the block is temporary: the resulting
        expiry timestamp is recorded in self.blocked_ips[ip] so callers
        (e.g. cleanup_expired_blocks) can persist/enforce it.
        """
        if not ip or ip == "N/A" or ip in self.blocked_ips:
            return False

        expires_at = self._compute_expiry(ttl_hours)

        print(f"\n[ACTIVE RESPONSE] Triggered block for malicious IP: {ip} | Reason: {reason}")

        if self.dry_run:
            print(f"[DRY-RUN] Would execute firewall block command for {ip}")
            self.blocked_ips[ip] = expires_at
            self.notifier.notify(f"IP Block (Dry-Run): {ip}", "medium", f"Reason: {reason}\nAction: Would block via firewall (dry-run mode)")
            return True

        success = False
        try:
            if self.os_type == "Linux":
                cmd = ["sudo", "ufw", "deny", "from", ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"[SUCCESS] IP {ip} successfully blocked via UFW.")
                    success = True
                else:
                    cmd_ipt = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                    res_ipt = subprocess.run(cmd_ipt, capture_output=True, text=True, timeout=10)
                    if res_ipt.returncode == 0:
                        print(f"[SUCCESS] IP {ip} successfully blocked via iptables.")
                        success = True
                    else:
                        print(f"[ERROR] Failed to block IP via firewall: {result.stderr or res_ipt.stderr}")
            elif self.os_type == "Windows":
                rule_name = f"SecOps-Block-{ip}"
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"[SUCCESS] IP {ip} successfully blocked via Windows Firewall.")
                    success = True
                else:
                    print(f"[ERROR] Failed to block IP via Windows Firewall: {result.stderr}")
            else:
                print(f"[WARNING] OS {self.os_type} not supported for automated firewall blocking.")
        except Exception as e:
            print(f"[EXCEPTION] Error executing active response firewall block: {e}")
            logger.error(f"Firewall block failed for {ip}: {e}")
            success = False

        if success:
            self.blocked_ips[ip] = expires_at
            self.notifier.notify(f"IP Blocked: {ip}", "high", f"Reason: {reason}\nFirewall: {self.os_type}\nStatus: Success")
        else:
            self.notifier.notify(f"IP Block FAILED: {ip}", "critical", f"Reason: {reason}\nFirewall: {self.os_type}\nStatus: Failed - the IP is still able to reach this host.")

        return success

    def unblock_ip(self, ip: str) -> bool:
        """
        Removes a previously applied firewall block for `ip` and drops it
        from self.blocked_ips. Used both for manual unblocking (e.g. a
        false positive) and by cleanup_expired_blocks() for TTL expiry.
        """
        if not ip or ip not in self.blocked_ips:
            return False

        print(f"\n[ACTIVE RESPONSE] Removing firewall block for IP: {ip}")

        if self.dry_run:
            print(f"[DRY-RUN] Would remove firewall block command for {ip}")
            self.blocked_ips.pop(ip, None)
            return True

        success = False
        try:
            if self.os_type == "Linux":
                cmd = ["sudo", "ufw", "delete", "deny", "from", ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"[SUCCESS] IP {ip} successfully unblocked via UFW.")
                    success = True
                else:
                    cmd_ipt = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                    res_ipt = subprocess.run(cmd_ipt, capture_output=True, text=True, timeout=10)
                    if res_ipt.returncode == 0:
                        print(f"[SUCCESS] IP {ip} successfully unblocked via iptables.")
                        success = True
                    else:
                        print(f"[ERROR] Failed to remove firewall block: {result.stderr or res_ipt.stderr}")
            elif self.os_type == "Windows":
                rule_name = f"SecOps-Block-{ip}"
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"[SUCCESS] IP {ip} successfully unblocked via Windows Firewall.")
                    success = True
                else:
                    print(f"[ERROR] Failed to remove Windows Firewall rule: {result.stderr}")
            else:
                print(f"[WARNING] OS {self.os_type} not supported for automated firewall unblocking.")
        except Exception as e:
            print(f"[EXCEPTION] Error executing active response firewall unblock: {e}")
            logger.error(f"Firewall unblock failed for {ip}: {e}")
            success = False

        if success:
            self.blocked_ips.pop(ip, None)

        return success

    def cleanup_expired_blocks(self, db) -> List[str]:
        """
        Queries the database for blocked IPs whose TTL has elapsed, removes
        the corresponding firewall rule for each, and deletes them from the
        blocked_ips table. Returns the list of IPs that were unblocked.

        Not wired to a scheduler/cron by design - call this periodically
        (e.g. via `python main.py unblock-expired`) or from an external
        cron/systemd timer.
        """
        unblocked = []
        for record in db.get_expired_blocked_ips():
            ip = record.get("ip")
            if not ip:
                continue
            # Make sure the in-memory state knows about this IP even if it
            # was blocked in a previous process run.
            self.blocked_ips.setdefault(ip, record.get("expires_at"))
            if self.unblock_ip(ip):
                db.remove_blocked_ip(ip)
                unblocked.append(ip)
        return unblocked
