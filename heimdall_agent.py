"""
Heimdall Remote Agent.

Tails a local log file (e.g. auth.log, syslog, or Windows Event simulation log)
and forwards log lines via HTTP POST to the Heimdall Master REST API endpoint.

Usage:
    python heimdall_agent.py --server http://localhost:18000 --api-key YOUR_KEY --log-file /var/log/auth.log
"""

import argparse
import time
import os
import sys
import json
import urllib.request
import urllib.error

def tail_and_forward(server_url: str, api_key: str, log_file_path: str, poll_interval: float = 1.0, from_beginning: bool = False):
    endpoint = f"{server_url.rstrip('/')}/api/v1/ingest"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key
    }

    print(f"[HEIMDALL AGENT] Starting remote log monitor on: {log_file_path}")
    print(f"[HEIMDALL AGENT] Forwarding to: {endpoint}")

    if not os.path.exists(log_file_path):
        print(f"[HEIMDALL AGENT] File {log_file_path} does not exist yet. Waiting for creation...")
        while not os.path.exists(log_file_path):
            time.sleep(poll_interval)

    with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
        if not from_beginning:
            # Seek to end of file for live tailing
            f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue

            line_str = line.strip()
            if not line_str:
                continue

            payload = json.dumps({"log_line": line_str, "log_type": "auto"}).encode("utf-8")
            req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")

            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    res_body = json.loads(resp.read().decode("utf-8"))
                    if res_body.get("status") != "ignored":
                        print(f"[FORWARDED] {line_str[:60]}... -> {res_body.get('status')}")
            except urllib.error.HTTPError as e:
                print(f"[ERROR] HTTP {e.code}: {e.reason}")
            except urllib.error.URLError as e:
                print(f"[ERROR] Connection failed: {e.reason}")
            except Exception as e:
                print(f"[ERROR] {e}")


def main():
    parser = argparse.ArgumentParser(description="Heimdall Remote Log Forwarding Agent")
    parser.add_argument("--server", default="http://localhost:18000", help="Heimdall Master API URL")
    parser.add_argument("--api-key", required=True, help="Heimdall API Key")
    parser.add_argument("--log-file", required=True, help="Path to log file to monitor")
    args = parser.parse_args()

    try:
        tail_and_forward(args.server, args.api_key, args.log_file)
    except KeyboardInterrupt:
        print("\n[HEIMDALL AGENT] Stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()
