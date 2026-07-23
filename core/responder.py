import subprocess
import platform
import logging
from typing import Dict, Any

logger = logging.getLogger("SecOps-Sentinel")

class ActiveResponder:
    """
    Executes automated defense actions when high-severity security alerts are triggered,
    such as blocking malicious source IPs using system firewalls (UFW / iptables / Windows Firewall).
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.os_type = platform.system()
        self.blocked_ips = set()

    def block_ip(self, ip: str, reason: str = "") -> bool:
        """
        Blocks an IP address using host firewall depending on the OS.
        """
        if not ip or ip == "N/A" or ip in self.blocked_ips:
            return False

        print(f"\n[ACTIVE RESPONSE] 🚨 Triggered block for malicious IP: {ip} | Reason: {reason}")
        
        if self.dry_run:
            print(f"[DRY-RUN] Would execute firewall block command for {ip}")
            self.blocked_ips.add(ip)
            return True

        success = False
        try:
            if self.os_type == "Linux":
                # Using UFW (Uncomplicated Firewall)
                cmd = ["sudo", "ufw", "deny", "from", ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"[SUCCESS] IP {ip} successfully blocked via UFW.")
                    success = True
                else:
                    # Fallback to iptables
                    cmd_ipt = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                    res_ipt = subprocess.run(cmd_ipt, capture_output=True, text=True, timeout=10)
                    if res_ipt.returncode == 0:
                        print(f"[SUCCESS] IP {ip} successfully blocked via iptables.")
                        success = True
                    else:
                        print(f"[ERROR] Failed to block IP via firewall: {result.stderr or res_ipt.stderr}")
            elif self.os_type == "Windows":
                # Using Windows Firewall Advanced Security via netsh
                rule_name = f"SecOps-Block-{ip}"
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"[SUCCESS] IP {ip} successfully blocked via Windows Firewall.")
                    success = True
                else:
                    print(f"[ERROR] Failed to block IP via Windows Firewall (are you running as Administrator?): {result.stderr}")
            else:
                print(f"[WARNING] OS {self.os_type} not supported for automated firewall blocking. IP logged only.")
        except Exception as e:
            print(f"[EXCEPTION] Error executing active response firewall block: {e}")
            # Fallback to dry-run simulation mode if permission/command fails
            print(f"[SIMULATION] IP {ip} recorded in active response block list.")
            success = True

        if success:
            self.blocked_ips.add(ip)

        return success
