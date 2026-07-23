<div align="center">

# HEIMDALL

### Asgard Cybersecurity Suite - Module I

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![CI](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)

> **Heimdall** - *Il guardiano del Bifrost* - e' un **Host Intrusion Detection System** con risposta automatica.
> Monitora i log di sistema, li valuta contro regole YAML e blocca gli attaccanti senza intervento umano.

</div>

---

## Executive Summary

Heimdall non si limita a loggare: **reagisce**. Monitora i tentativi di intrusione (SSH brute-force, accessi Windows falliti) e attiva automaticamente il firewall locale per bloccare l'attaccante.

```
  Log Linux/Windows  -->  Parser strutturato  -->  Detector a regole YAML
                                                          |
                                                    Alert generato
                                                          |
                                                   +------|------+
                                                   |             |
                                             SQLite DB      Active Response
                                                           (blocco firewall)
```

---

## Caratteristiche Tecniche

| Modulo | Descrizione |
|:---|:---|
| **Log Parser** | Regex engine per Linux SSH logs, Windows Event 4625 e stream generici |
| **HIDS Core** | Detection engine basato su file YAML con sliding window temporale |
| **Active Response** | Blocco IP via ufw / iptables / netsh (con modalita dry-run) |
| **SQLite Storage** | Persistenza alert, audit trail storico e IP bloccati |
| **REST API** | FastAPI per ingestione log, query alert, statistiche |

### Regole di rilevamento supportate

| Regola | Severita | Trigger |
|:---|:---:|:---|
| SSH_BRUTE_FORCE_01 | HIGH | 3+ password fallite in 30 secondi |
| WIN_FAILED_LOGON_01 | HIGH | 3+ login falliti Windows (Event 4625) in 30 secondi |
| PORT_SCAN_01 | MEDIUM | 2+ connessioni non autorizzate in 60 secondi |

---

## Struttura del Progetto

```
Heimdall/
+-- core/
|   +-- colors.py         ANSI colori per output terminale
|   +-- parser.py         Linux auth.log + Windows Event 4625 + generico
|   +-- detector.py       Sliding window + soglie configurabili
|   +-- responder.py      UFW / iptables / Windows Firewall (dry-run)
|
+-- rules/                Regole Sigma-style in YAML
|   +-- ssh_bruteforce.yaml
|   +-- windows_failed_logins.yaml
|   +-- port_scan_suspicious.yaml
|
+-- storage/
|   +-- database.py       Persistenza SQLite (alert, IP bloccati, statistiche)
|
+-- api/
|   +-- server.py         REST API con FastAPI + Swagger interattivo
|
+-- tests/
|   +-- test_heimdall.py  5 test pytest
|
+-- config.yaml           Configurazione centralizzata
+-- main.py               CLI: api | monitor | simulate
+-- run_local_demo.py     Demo standalone con output colorato
+-- simulate_attacks.py   Simulatore red-team automatico
+-- SECURITY.md           Security policy
+-- requirements.txt
```

---

## Quickstart

```bash
# Clone e installa
git clone https://github.com/Fioru12/Heimdall.git
cd Heimdall
pip install -r requirements.txt

# Esegui i test
pytest

# Avvia il server API
python main.py api

# Simula un attacco brute-force
python main.py simulate

# Demo standalone (senza server, con output colorato)
python run_local_demo.py
```

---

## API Endpoints

| Method | Endpoint | Descrizione |
|:---:|:---|:---|
| GET | / | Stato del servizio |
| POST | /api/v1/ingest | Invia una riga di log per analisi in tempo reale |
| GET | /api/v1/alerts | Ultimi alert registrati |
| GET | /api/v1/stats | Statistiche severita e IP bloccati |
| GET | /api/v1/blocked | Lista IP bloccati con motivazione |

Documentazione Swagger disponibile su http://127.0.0.1:8000/docs dopo l'avvio.

---

## Demo: Output Terminale

```
============================================================
 Heimdall Local Demonstration & Live Test
============================================================

[Ingest 1] Processing log: Failed password for root from 203.0.113.50
   Parsed Event -> Type: ssh_auth, IP: 203.0.113.50
   [Info] Event evaluated (threshold not reached yet).

[Ingest 3] Processing log: Failed password for root from 203.0.113.50
   [ALERT] TRIGGERED: SSH Brute-Force Attack Detected (HIGH)

[ACTIVE RESPONSE] Triggered block for malicious IP: 203.0.113.50
[DRY-RUN] Would execute firewall block command for 203.0.113.50

============================================================
 Demonstration Complete! Database Statistics:
 - Total Alerts Recorded: 2
 - Severity Breakdown: {'HIGH': 2}
 - Total Blocked IPs: 2
============================================================
```

---

## Esempio di Regola YAML

```yaml
id: SSH_BRUTE_FORCE_01
title: SSH Brute-Force Attack Detected
severity: HIGH
pattern: "Failed password for"
threshold: 3
timeframe: 30
description: "Tentativi SSH multipli falliti dallo stesso IP in 30 secondi."
```

---

## Suite Asgard

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS - Rilevamento & Active Response | Fatto |
| **Mjolnir** | Incident Response - Triage & Forensics | Fatto |
| **Bifrost** | Network Telemetry - Port Analysis & Encryption | Fatto |

---

<div align="center">

**[Fioru12](https://github.com/Fioru12)** - MIT License

</div>
