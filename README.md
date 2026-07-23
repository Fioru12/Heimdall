# Heimdall 🛡️ (HIDS & Active Response Engine)

[![CI Pipeline](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml/badge.svg)](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-teal.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Heimdall** is a lightweight, production-grade **Host Intrusion Detection System (HIDS) and Active Response Engine** built from scratch in Python. It monitors system/auth logs in real-time, evaluates events against customizable YAML detection rules (Sigma-style), logs security incidents to an SQLite database, exposes a REST API via **FastAPI**, and automatically executes defensive countermeasures (such as blocking malicious source IPs via system firewalls).

Designed as an advanced portfolio project for aspiring **Junior SOC Analysts, Security Engineers, and Sysadmins transitioning into Cybersecurity**.

---

## 🏗️ Architecture & Component Design

```text
 Heimdall/
│
├── core/
│   ├── parser.py       # Normalizes Linux auth.log, Windows Security Event logs, and custom syslog streams
│   ├── detector.py     # Evaluation engine supporting threshold counting & sliding time windows
│   └── responder.py    # Active Response module executing firewall bans (UFW/iptables/Windows Firewall)
│
├── rules/              # Sigma-style YAML detection signatures
│   ├── ssh_bruteforce.yaml
│   └── windows_failed_logins.yaml
│
├── storage/
│   └── database.py     # SQLite persistence layer for alerts, audit trails, and blocked IPs
│
├── api/                # FastAPI REST interface for querying telemetry and alerts
│   └── server.py
│
├── tests/              # Comprehensive test suite (pytest)
│   └── test_sentinel.py
│
├── main.py             # CLI entrypoint (API server, live file monitor, simulation runner)
└── simulate_attacks.py # Automated red-team simulation tool for testing detection & response
```

---

## ✨ Key Features

1. **Multi-Format Log Parser**: Parses Linux SSH authentication logs, Windows Security Event logs (Event ID 4625), and general security streams.
2. **Modular YAML Detection Rules**: Decouples logic from code. Rules define patterns, severities, alert thresholds, and time windows (sliding windows).
3. **Automated Active Response**: Automatically invokes system firewalls (`ufw`, `iptables`, or Windows Firewall `netsh`) upon detecting high-severity brute-force attacks.
4. **Persistent Telemetry Storage**: Stores historical alerts, threat indicators, and mitigation actions in a structured SQLite database.
5. **FastAPI REST Endpoints**: Exposes endpoints for SIEM integration, dashboard querying, and real-time event ingestion.
6. **Comprehensive Test Coverage**: Tested and verified with `pytest` for robust reliability.

---

## 🚀 Quickstart Guide

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Fioru12/Heimdall.git
cd Heimdall
pip install -r requirements.txt
```

### 2. Running Unit Tests

Verify everything works correctly out of the box:

```bash
pytest
```

### 3. Starting the REST API Server

```bash
python main.py api
```

The FastAPI server will be available at `http://127.0.0.1:8000`. You can explore the interactive API documentation at `http://127.0.0.1:8000/docs`.

### 4. Running the Attack Simulation

To test the detection engine and active response without setting up a vulnerable environment manually, run the simulation script in a separate terminal:

```bash
python main.py simulate
```

**Sample Output:**
```text
============================================================
 SecOps-Sentinel Attack Simulation Tool
============================================================
Target API: http://127.0.0.1:8000/api/v1/ingest

[1/6] Sending log: Failed password for invalid user root from 203.0.113.50
   Response Status: processed
   [Info] Event processed (threshold not yet reached).
[2/6] Sending log: Failed password for invalid user root from 203.0.113.50
   Response Status: processed
   [Info] Event processed (threshold not yet reached).
[3/6] Sending log: Failed password for invalid user root from 203.0.113.50
   Response Status: processed
   🚨 ALERTS TRIGGERED: 1
      - Rule: SSH Brute-Force Attack Detected | Action: BLOCKED_IP

[ACTIVE RESPONSE] 🚨 Triggered block for malicious IP: 203.0.113.50 | Reason: SSH Brute-Force Attack Detected
[SIMULATION] IP 203.0.113.50 recorded in active response block list.
```

---

## 📊 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Service health status and overview |
| `GET` | `/api/v1/alerts` | Retrieve recent security alerts (supports limit query param) |
| `GET` | `/api/v1/stats` | Security statistics (severity breakdown, total alerts, blocked IPs) |
| `POST` | `/api/v1/ingest` | Ingest and evaluate a log line in real-time |
| `GET` | `/api/v1/blocked` | List all actively blocked IP addresses and reasons |

---

## 📝 Example YAML Rule (`rules/ssh_bruteforce.yaml`)

```yaml
id: SSH_BRUTE_FORCE_01
title: SSH Brute-Force Attack Detected
severity: HIGH
log_source: auth.log
pattern: "Failed password for"
threshold: 3
timeframe: 30
description: "Multiple failed SSH login attempts detected from the same IP address within a short time window."
```

---

## 💡 Why This Project Stands Out to Employers
- **Bridges Sysadmin & Security:** Combines core OS knowledge (logs, firewalls) with defensive software engineering.
- **Shows Coding Capability:** Demonstrates clean Python architecture, object-oriented design, regex parsing, and REST API development.
- **Real-World Relevance:** Implements concepts identical to commercial SIEM and EDR solutions (Sigma rules, sliding-window correlation, automated active response).

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
