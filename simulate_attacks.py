import time
import requests
import sys

API_URL = "http://127.0.0.1:8000/api/v1/ingest"

ATTACK_LOGS = [
    "Jul 23 14:00:10 server01 sshd[1234]: Failed password for invalid user root from 203.0.113.50 port 51234 ssh2",
    "Jul 23 14:00:12 server01 sshd[1234]: Failed password for invalid user root from 203.0.113.50 port 51236 ssh2",
    "Jul 23 14:00:15 server01 sshd[1234]: Failed password for invalid user root from 203.0.113.50 port 51238 ssh2",
    "[2026-07-23 14:05:01] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 198.51.100.22",
    "[2026-07-23 14:05:03] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 198.51.100.22",
    "[2026-07-23 14:05:06] Security-Auditing: EventID 4625 - An account failed to log on. Account: Administrator, Source IP: 198.51.100.22",
]

def run_simulation():
    print("=" * 60)
    print(" SecOps-Sentinel Attack Simulation Tool")
    print("=" * 60)
    print(f"Target API: {API_URL}\n")

    for i, log in enumerate(ATTACK_LOGS, 1):
        print(f"[{i}/{len(ATTACK_LOGS)}] Sending log: {log}")
        try:
            response = requests.post(API_URL, json={"log_line": log})
            if response.status_code == 200:
                data = response.json()
                print(f"   Response Status: {data.get('status')}")
                if data.get("alerts_triggered", 0) > 0:
                    print(f"   🚨 ALERTS TRIGGERED: {data.get('alerts_triggered')}")
                    for action in data.get("actions", []):
                        print(f"      - Rule: {action['alert']} | Action: {action['action']}")
                else:
                    print("   [Info] Event processed (threshold not yet reached).")
            else:
                print(f"   [Error] API returned status code {response.status_code}. Is the server running?")
        except requests.exceptions.ConnectionError:
            print("   [Error] Connection refused. Start the FastAPI server first using: python main.py api")
            sys.exit(1)
        
        time.sleep(1)

    print("\nSimulation complete! Check alerts and blocked IPs via API or database.")

if __name__ == "__main__":
    run_simulation()
