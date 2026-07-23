<div align="center">

# HEIMDALL

### **Asgard Cybersecurity Suite — Module I**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![CI Pipeline](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Perché ho costruito Heimdall?**  
> Nei SOC si finisce spesso schiacciati tra due estremi: agenti commerciali pesanti come macigni e impossibili da personalizzare, o script bash sparsi che si rompono al primo cambio di formato dei log. Avevo bisogno di un HIDS leggero, in puro Python, che facesse una cosa sola ma la facesse bene: leggere i log di autenticazione, accorgersi di un brute-force in corso tramite finestra temporale, bloccare l'IP sul firewall locale e mandarmi un avviso su Telegram prima che finissi il caffè.

---

## Come Funziona (Senza fronzoli)

Heimdall monitora i flussi di log (SSH su Linux o Event ID 4625 su Windows), valuta gli eventi contro regole YAML configurabili e attiva una risposta automatica.

```
  Log Stream (SSH/Windows)  -->  Regex Parser  -->  YAML Rule Engine (Sliding Window)
                                                          |
                                                    [ALERT TRIGGERED]
                                                          |
                                           +--------------+--------------+
                                           |                             |
                                           v                             v
                                     SQLite Storage               Active Response
                                     (Audit Trail)               (UFW / Netsh Block)
                                                                         |
                                                                         v
                                                                 Telegram Notification
```

---

## Architettura & Design Pragmatico

- **Zero Bloat**: Nessun database pesante o dipendenze oscure. Utilizza SQLite per l'audit trail locale e regex ottimizzate per il parsing.
- **Sliding Window Detection**: Non basta un singolo fallimento per fare scattare l'allarme. Il motore valuta soglie temporali (es. 3 tentativi in 30 secondi).
- **Active Response con Safety Net**: Il modulo di blocco supporta la modalità `dry-run` nativa, fondamentale per testare le regole su server di produzione senza rischiare di auto-escludersi.

---

## Quick Start

```bash
# Clona e installa
git clone https://github.com/Fioru12/Heimdall.git
cd Heimdall
pip install -r requirements.txt

# Testa subito con la demo locale colorata
python run_local_demo.py

# Esegui i test unitari
pytest -v
```

---

## Utilizzo CLI

```bash
# Avvia il monitoraggio live
python main.py monitor

# Avvia le API REST FastAPI
python main.py api --port 8000

# Esegui una simulazione di attacco
python main.py simulate
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
description: "Rilevati tentativi multipli di login falliti dallo stesso IP in un intervallo ristretto."
```

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>
