<div align="center">

```
    ██╗  ██╗██╗███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
    ██║  ██║██║██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ███████║██║█████╗  ███████╗██║     ██║   ██║██║  ██║█████╗  
    ██╔══██║██║██╔══╝  ╚════██║██║     ██║   ██║██║  ██║██╔══╝  
    ██║  ██║██║███████╗███████║╚██████╗╚██████╔╝██████╔╝███████╗
    ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
```

### **Asgard Cybersecurity Suite** &mdash; Module I

<br/>

[![CI](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml/badge.svg)](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=flat-square&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)

<br/>

**Heimdall** &mdash; *il guardiano del Bifr&ouml;st* &mdash; &egrave; un sistema di rilevamento intrusioni host (HIDS) con risposta automatica.
Monitora i log di sistema in tempo reale, li valuta contro regole YAML personalizzabili e, quando rileva un attacco, **blocca l'IP malevolo tramite firewall** senza intervento umano.

</div>

---

## Perch&egrave; esiste Heimdall

In un SOC reale il flusso di lavoro &egrave;: **Log &rarr; SIEM &rarr; Alert &rarr; Risposta**.
Heimdall implementa l'intera catena in un'unica applicazione Python:

```
  Log Linux/Windows  ──▶  Parser strutturato  ──▶  Detector a regole YAML
                                                          │
                                                    Alert generato
                                                          │
                                                   ┌──────┴──────┐
                                                   ▼              ▼
                                             SQLite DB      Active Response
                                                           (blocco firewall)
```

---

## Architettura

<details>
<summary><b>Struttura completa del progetto</b></summary>

```
Heimdall/
├── core/
│   ├── parser.py         Linux auth.log + Windows Event 4625 + generico
│   ├── detector.py       Sliding window + soglie configurabili
│   └── responder.py      UFW / iptables / Windows Firewall (dry-run)
│
├── rules/                Regole Sigma-style in YAML
│   ├── ssh_bruteforce.yaml
│   ├── windows_failed_logins.yaml
│   └── port_scan_suspicious.yaml
│
├── storage/
│   └── database.py       Persistenza SQLite (alert, IP bloccati, statistiche)
│
├── api/
│   └── server.py         REST API con FastAPI + Swagger interattivo
│
├── tests/
│   └── test_sentinel.py  Suite completa pytest
│
├── config.yaml           Configurazione centralizzata
├── main.py               CLI: api | monitor | simulate
├── run_local_demo.py     Demo standalone per test locali
└── simulate_attacks.py   Simulatore red-team automatico
```

</details>

---

## Funzionalit&agrave;

| Modulo | Cosa fa |
|:---|:---|
| **Log Parser** | Normalizza Linux SSH logs, Windows Event 4625 e stream generici con regex |
| **Rule Detector** | Valuta eventi contro regole YAML con finestre temporali scorrevoli e soglie |
| **Active Response** | Blocca IP malevoli via `ufw`, `iptables` o `netsh advfirewall` (con modalit&agrave; dry-run) |
| **SQLite Storage** | Persistenza alert, audit trail storico e IP bloccati |
| **REST API** | Endpoint per ingestione log, query alert, statistiche e lista IP bloccati |

---

## Quickstart

```bash
# Clona e installa
git clone https://github.com/Fioru12/Heimdall.git
cd Heimdall
pip install -r requirements.txt

# Test
pytest

# Avvia il server API
python main.py api

# Simula un attacco brute-force
python main.py simulate

# Demo standalone (senza server)
python run_local_demo.py
```

---

## API

| Method | Endpoint | Descrizione |
|:---:|:---|:---|
| `GET` | `/` | Stato del servizio |
| `POST` | `/api/v1/ingest` | Invia una riga di log per analisi in tempo reale |
| `GET` | `/api/v1/alerts` | Ultimi alert registrati |
| `GET` | `/api/v1/stats` | Statistiche severit&agrave; e IP bloccati |
| `GET` | `/api/v1/blocked` | Lista IP bloccati con motivazione |

Documentazione interattiva Swagger disponibile su `http://127.0.0.1:8000/docs` dopo l'avvio.

---

## Esempio di regola YAML

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

Heimdall &egrave; il primo modulo della **suite Asgard** &mdash; un ecosistema di strumenti di sicurezza che coprono le aree chiave di un Security Operations Center:

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS &middot; Rilevamento & Active Response | `Fatto` |
| **Mjolnir** | Incident Response &middot; Triage & Forensics | `Fatto` |
| **Bifrost** | Network Telemetry &middot; Crittografia & Port Analysis | `In arrivo` |

---

<div align="center">

*Costruito come progetto portfolio dimostrativo &mdash; pronto per essere mostrato ai recruiter e ai technical lead.*

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License

</div>
