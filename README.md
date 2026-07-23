# <div align="center">Heimdall 🛡️</div>
<div align="center">
  <sub><i>Il Guardiano del Bifröst &mdash; HIDS & Active Response Engine</i></sub>
</div>

<br/>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![CI](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)

</div>

<br/>

> [!IMPORTANT]
> **Heimdall** è il primo modulo della **suite Asgard**. 
> È un Host Intrusion Detection System progettato per trasformare i log di sistema in **azioni difensive automatizzate** in tempo reale.

---

## 🧠 Executive Summary
In un SOC moderno, il tempo di risposta è tutto. **Heimdall** riduce il gap tra l'evento di sicurezza e la mitigazione, implementando l'intero flusso `SIEM &rarr; Detection &rarr; Response` in una sola pipeline Python efficiente.

```
  Log Files  ──▶  Parser  ──▶  Detector (YAML) ──▶  SQLite Storage
                                    │
                                    ▼
                             Active Response (Firewall)
```

---

## 🚀 Caratteristiche Tecniche

| Funzionalità | Descrizione |
|:---|:---|
| 🔍 **Log Parser** | Normalizzazione multi-format (Linux Auth, Windows Event) |
| 🧠 **YAML Rules** | Detection logic basata su file YAML (Sigma-style) |
| 🛡️ **Active Response** | Blocco IP automatizzato via `iptables`/`ufw`/`netsh` |
| 📊 **REST API** | API FastAPI per interrogazione telemetria e alert |

> [!TIP]
> Heimdall utilizza una logica di **sliding window** per il rilevamento di brute-force, garantendo precisione ed evitando alert fatigue.

---

## 🛠️ Quickstart

```bash
# Installazione
git clone https://github.com/Fioru12/Heimdall.git
cd Heimdall
pip install -r requirements.txt

# Test
pytest

# Avvio API & Demo
python main.py api
python run_local_demo.py
```

---

## 🔗 Suite Asgard

Heimdall è il primo pilastro dell'ecosistema **Asgard**:

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS &middot; Rilevamento & Response | `Fatto` |
| **Mjolnir** | IR &middot; Triage & Forensics | `Fatto` |
| **Bifrost** | Rete &middot; Telemetria & Report Cifrati | `Fatto` |

---

<div align="center">

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License

</div>
