import sys
import argparse
import uvicorn
from core.parser import LogParser
from core.detector import RuleDetector
from core.responder import ActiveResponder
from storage.database import HeimdallDatabase

def run_api(host: str = "127.0.0.1", port: int = 8000):
    print(f"Starting Heimdall API Server on http://{host}:{port} ...")
    uvicorn.run("api.server:app", host=host, port=port, reload=True)

def run_cli_monitor(logfile: str):
    print(f"Starting Heimdall live file monitor on {logfile} ...")
    parser = LogParser()
    detector = RuleDetector()
    responder = ActiveResponder(dry_run=True)
    db = HeimdallDatabase()

    import time
    try:
        with open(logfile, "r", encoding="utf-8") as f:
            f.seek(0, 2) # Go to end of file
            while True:
                line = f.readline()
                if not line:
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
                            if responder.block_ip(alert['source_ip'], alert['rule_title']):
                                action = "BLOCKED_IP"
                                db.record_blocked_ip(alert['source_ip'], alert['rule_title'])
                        db.save_alert(alert, action_taken=action)
    except FileNotFoundError:
        print(f"Error: Log file '{logfile}' not found.")
    except KeyboardInterrupt:
        print("\nStopping Heimdall monitor.")

def main():
    parser = argparse.ArgumentParser(description="Heimdall: HIDS & Active Response Engine")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # API command
    api_parser = subparsers.add_parser("api", help="Start FastAPI REST API server")
    api_parser.add_argument("--host", default="127.0.0.1")
    api_parser.add_argument("--port", type=int, default=8000)

    # Monitor command
    mon_parser = subparsers.add_parser("monitor", help="Monitor a log file in real time")
    mon_parser.add_argument("logfile", help="Path to log file to monitor")

    # Simulate command
    subparsers.add_parser("simulate", help="Run attack simulation test")

    args = parser.parse_args()

    if args.command == "api":
        run_api(args.host, args.port)
    elif args.command == "monitor":
        run_cli_monitor(args.logfile)
    elif args.command == "simulate":
        import simulate_attacks
        simulate_attacks.run_simulation()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
