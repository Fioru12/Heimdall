import sys
# Ensure UTF-8 output encoding for Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from core.parser import LogParser
from core.detector import RuleDetector
from core.responder import ActiveResponder
from storage.database import HeimdallDatabase
from core.colors import Colors

def run_demo():
    print(Colors.BLUE + "=" * 60 + Colors.ENDC)
    print(f"{Colors.BOLD} Heimdall Local Demonstration & Live Test{Colors.ENDC}")
    print(Colors.BLUE + "=" * 60 + Colors.ENDC)

    parser = LogParser()
    detector = RuleDetector()
    responder = ActiveResponder(dry_run=True)
    db = HeimdallDatabase("demo_heimdall.db")

    logs = [
        "Jul 23 14:00:10 server01 sshd[1234]: Failed password for invalid user root from 203.0.113.50 port 51234 ssh2",
        "Jul 23 14:00:12 server01 sshd[1234]: Failed password for invalid user root from 203.0.113.50 port 51234 ssh2",
        "Jul 23 14:00:15 server01 sshd[1234]: Failed password for invalid user root from 203.0.113.50 port 51234 ssh2",
        "[2026-07-23 14:05:01] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 198.51.100.22",
        "[2026-07-23 14:05:03] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 198.51.100.22",
        "[2026-07-23 14:05:06] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 198.51.100.22",
    ]

    for i, log_line in enumerate(logs, 1):
        print(f"\n{Colors.BOLD}[Ingest {i}]{Colors.ENDC} Processing log: {log_line}")
        parsed = parser.parse_line(log_line)
        if parsed:
            print(f"   Parsed Event -> Type: {parsed['log_type']}, IP: {parsed['source_ip']}, User: {parsed['username']}")
            alerts = detector.evaluate(parsed)
            if alerts:
                for alert in alerts:
                    print(f"   {Colors.GREEN}[ALERT] TRIGGERED:{Colors.ENDC} {alert['rule_title']} ({alert['severity']})")
                    action = "LOGGED"
                    if alert["severity"] in ["HIGH", "CRITICAL"]:
                        ip = alert.get("source_ip")
                        if ip and ip != "N/A":
                            if responder.block_ip(ip, reason=alert["rule_title"]):
                                action = "BLOCKED_IP"
                                db.record_blocked_ip(ip, reason=alert["rule_title"])
                    db.save_alert(alert, action_taken=action)
            else:
                print("   [Info] Event evaluated (threshold not reached yet).")
        else:
            print("   [Warning] Log line not recognized.")

    print("\n" + Colors.BLUE + "=" * 60 + Colors.ENDC)
    print(f" Demonstration Complete! Database Statistics:")
    stats = db.get_stats()
    print(f" - Total Alerts Recorded: {stats['total_alerts']}")
    print(f" - Severity Breakdown: {stats['severity_breakdown']}")
    print(f" - Total Blocked IPs: {stats['total_blocked_ips']}")
    print(Colors.BLUE + "=" * 60 + Colors.ENDC)

if __name__ == "__main__":
    run_demo()
