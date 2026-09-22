"""
Heimdall Remote Agent.

Tails a local log file (e.g. auth.log, syslog, or Windows Event simulation log)
and forwards log lines via HTTP POST to the Heimdall Master REST API endpoint.

Usage:
    python heimdall_agent.py --server http://localhost:18000 --api-key YOUR_KEY --log-file /var/log/auth.log
"""

from typing import Optional
import argparse
import time
import os
import sys
import json
import socket
import secrets
import urllib.request
import urllib.error

AGENT_ID_FILE = ".heimdall_agent_id"
AGENT_SECRET_FILE = ".heimdall_agent_secret"

def get_or_create_agent_id() -> str:
    if os.path.exists(AGENT_ID_FILE):
        try:
            with open(AGENT_ID_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    agent_id = "agent_" + secrets.token_hex(8)
    try:
        with open(AGENT_ID_FILE, "w", encoding="utf-8") as f:
            f.write(agent_id)
    except Exception:
        pass
    return agent_id


def _save_agent_secret(agent_secret: str) -> None:
    try:
        with open(AGENT_SECRET_FILE, "w", encoding="utf-8") as f:
            f.write(agent_secret)
    except Exception:
        pass


def _load_agent_secret() -> str:
    if os.path.exists(AGENT_SECRET_FILE):
        try:
            with open(AGENT_SECRET_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""


def enroll_agent(server_url: str, token: str, agent_name: Optional[str] = None) -> bool:
    endpoint = f"{server_url.rstrip('/')}/api/v1/agents/register"
    agent_id = get_or_create_agent_id()
    name = agent_name or socket.gethostname()
    os_type = sys.platform
    payload = json.dumps({
        "token": token,
        "agent_id": agent_id,
        "name": name,
        "ip_address": "127.0.0.1",
        "os_type": os_type,
    }).encode("utf-8")

    req = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            agent_secret = data.get("agent_secret", "")
            if agent_secret:
                _save_agent_secret(agent_secret)
            print(f"[HEIMDALL AGENT] Successfully registered with server! Agent ID: {agent_id}, Tenant: {data.get('tenant_id')}")
            return True
    except Exception as e:
        print(f"[HEIMDALL AGENT] Enrollment failed: {e}")
        return False


def send_heartbeat(server_url: str) -> bool:
    endpoint = f"{server_url.rstrip('/')}/api/v1/agents/heartbeat"
    agent_id = get_or_create_agent_id()
    agent_secret = _load_agent_secret()
    payload = json.dumps({"agent_id": agent_id, "agent_secret": agent_secret, "status": "active"}).encode("utf-8")
    req = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return True
    except Exception:
        return False


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

    last_hb = 0
    with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
        if not from_beginning:
            f.seek(0, os.SEEK_END)

        while True:
            now = time.time()
            if now - last_hb > 30:
                send_heartbeat(server_url)
                last_hb = now

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
    parser.add_argument("--server", default="http://localhost:8080", help="Heimdall/Ragnarok Master API URL")
    parser.add_argument("--api-key", default="default", help="Heimdall API Key")
    parser.add_argument("--log-file", help="Path to log file to monitor")
    parser.add_argument("--enroll-token", help="Enrollment token to register agent with Ragnarok")
    args = parser.parse_args()

    if args.enroll_token:
        enroll_agent(args.server, args.enroll_token)
        if not args.log_file:
            return

    if not args.log_file:
        print("Error: --log-file is required for log monitoring mode.")
        sys.exit(1)

    try:
        tail_and_forward(args.server, args.api_key, args.log_file)
    except KeyboardInterrupt:
        print("\n[HEIMDALL AGENT] Stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()

