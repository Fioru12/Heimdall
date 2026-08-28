import os
import sys
import argparse
import uvicorn
from core.parser import LogParser
from core.detector import RuleDetector
from core.responder import ActiveResponder
from core.notifier import TelegramNotifier, gjallarhorn_configured, send_alert_via_gjallarhorn
from core.config import load_config
from storage.database import HeimdallDatabase

def run_api(host: str = "127.0.0.1", port: int = 8000, reload: bool = False):
    print(f"Starting Heimdall API Server on http://{host}:{port} ...")
    uvicorn.run("api.server:app", host=host, port=port, reload=reload)

def _reopen_if_rotated(f, logfile: str):
    """
    Detects log rotation (logrotate-style rename+recreate, or truncation)
    and transparently reopens the file from the start so the monitor keeps
    seeing new events instead of silently going stale on the old inode/handle.

    Uses inode comparison on platforms that support it (POSIX); falls back
    to a simple "current size < last read position" truncation check
    everywhere else (including Windows).
    """
    try:
        current_stat = os.stat(logfile)
    except FileNotFoundError:
        # File temporarily missing during rotation; keep the old handle,
        # the next iteration will retry.
        return f

    rotated = False
    try:
        fd_stat = os.fstat(f.fileno())
        if hasattr(current_stat, "st_ino") and hasattr(fd_stat, "st_ino") and current_stat.st_ino and fd_stat.st_ino:
            if current_stat.st_ino != fd_stat.st_ino:
                rotated = True
    except (OSError, ValueError):
        pass

    if not rotated and current_stat.st_size < f.tell():
        # File got smaller than our read position -> truncated/recreated.
        rotated = True

    if rotated:
        print(f"[INFO] Detected log rotation for {logfile}, reopening file.")
        try:
            f.close()
        except Exception:
            pass
        new_f = open(logfile, "r", encoding="utf-8")
        return new_f

    return f


def run_cli_monitor(logfile: str):
    print(f"Starting Heimdall live file monitor on {logfile} ...")
    config = load_config()
    parser = LogParser()
    detector = RuleDetector()
    responder = ActiveResponder(dry_run=config.get("responder", {}).get("dry_run", True))
    db = HeimdallDatabase(db_path=config.get("database", {}).get("path", "heimdall.db"))
    ttl_hours = config.get("responder", {}).get("block_ttl_hours")

    tg_config = config.get("telegram", {})
    notifier = TelegramNotifier(
        bot_token=tg_config.get("bot_token", ""),
        chat_id=tg_config.get("chat_id", ""),
    ) if tg_config.get("enabled") else None

    import time
    try:
        f = open(logfile, "r", encoding="utf-8")
        f.seek(0, 2) # Go to end of file
        try:
            while True:
                line = f.readline()
                if not line:
                    f = _reopen_if_rotated(f, logfile)
                    time.sleep(0.5)
                    continue

                parsed = parser.parse_line(line)
                if parsed:
                    print(f"[LOG] {parsed}")
                    alerts = detector.evaluate(parsed)
                    for alert in alerts:
                        print(f"🚨 ALERT: {alert['rule_title']} | Severity: {alert['severity']} | IP: {alert['source_ip']}")
                        action = "LOGGED"
                        if alert['severity'] in ["HIGH", "CRITICAL"] and alert['source_ip'] != "N/A":
                            if responder.block_ip(alert['source_ip'], alert['rule_title'], ttl_hours=ttl_hours):
                                action = "BLOCKED_IP"
                                expires_at = responder.blocked_ips.get(alert['source_ip'])
                                db.record_blocked_ip(alert['source_ip'], alert['rule_title'], expires_at=expires_at)
                        db.save_alert(alert, action_taken=action)
                        # Prefer the centralized Gjallarhorn hub when it's
                        # configured; otherwise fall back to the direct
                        # Telegram notifier already configured below.
                        if gjallarhorn_configured():
                            send_alert_via_gjallarhorn(alert, action=action)
                        elif notifier:
                            notifier.send_alert(alert, action=action)
        finally:
            f.close()
    except FileNotFoundError:
        print(f"Error: Log file '{logfile}' not found.")
    except KeyboardInterrupt:
        print("\nStopping Heimdall monitor.")


def run_unblock_expired():
    config = load_config()
    responder = ActiveResponder(dry_run=config.get("responder", {}).get("dry_run", True))
    db = HeimdallDatabase(db_path=config.get("database", {}).get("path", "heimdall.db"))

    unblocked = responder.cleanup_expired_blocks(db)
    if unblocked:
        print(f"[INFO] Unblocked {len(unblocked)} expired IP(s): {', '.join(unblocked)}")
    else:
        print("[INFO] No expired IP blocks to remove.")

def main():
    parser = argparse.ArgumentParser(description="Heimdall: HIDS & Active Response Engine")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # API command
    api_parser = subparsers.add_parser("api", help="Start FastAPI REST API server")
    api_parser.add_argument("--host", default="127.0.0.1")
    api_parser.add_argument("--port", type=int, default=8000)
    api_parser.add_argument("--reload", action="store_true", help="Enable uvicorn auto-reload (development only)")

    # Monitor command
    mon_parser = subparsers.add_parser("monitor", help="Monitor a log file in real time")
    mon_parser.add_argument("logfile", help="Path to log file to monitor")

    # Simulate command
    subparsers.add_parser("simulate", help="Run attack simulation test")

    # Unblock-expired command
    subparsers.add_parser("unblock-expired", help="Remove firewall rules for IP blocks whose TTL has expired")

    args = parser.parse_args()

    if args.command == "api":
        run_api(args.host, args.port, reload=args.reload)
    elif args.command == "monitor":
        run_cli_monitor(args.logfile)
    elif args.command == "simulate":
        import simulate_attacks
        simulate_attacks.run_simulation()
    elif args.command == "unblock-expired":
        run_unblock_expired()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
