<div align="center">

```
    ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     
    ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     
    ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     
    ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     
    ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗
    ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

### **Asgard Cybersecurity Suite** &mdash; Module I

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![CI](https://github.com/Fioru12/Heimdall/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)

<br/>

> [!IMPORTANT]
> **Heimdall** è il primo modulo della **suite Asgard**. 
> Trasforma i log grezzi in **azioni difensive in tempo reale**.

</div>

---

### 🧠 Executive Summary
Heimdall non si limita a loggare: **reagisce**. Monitora i tentativi di intrusione (SSH brute-force, accessi Windows falliti) e attiva automaticamente il firewall locale per bloccare l'attaccante.

```mermaid
graph LR
    A[Log Files] -->|Parser| B(Detector)
    B -->|Alert| C{Severità High?}
    C -->|Sì| D[Active Response]
    C -->|No| E[SQLite Storage]
    D --> F[Blocco Firewall]
```

---

### 🚀 Caratteristiche Tecniche

| Modulo | Descrizione |
|:---|:---|
| 🔍 **Parser** | Regex engine per Linux/Windows log |
| 🛡️ **HIDS Core** | Detection engine basato su file YAML |
| 🧱 **Responder** | Blocco IP via `ufw`/`iptables`/`netsh` |
| 📊 **Dashboard API** | FastAPI per consultazione telemetria |

> [!TIP]
> Heimdall usa una **sliding window** temporale per evitare di bloccare utenti legittimi per errori di digitazione sporadici.

---

### 🛠️ Setup Rapido

```bash
git clone https://github.com/Fioru12/Heimdall.git
cd Heimdall
pip install -r requirements.txt

# Start demo
python main.py api & python run_local_demo.py
```

---

<div align="center">

**[Suite Asgard](https://github.com/Fioru12/Heimdall)** &middot; MIT License

</div>
