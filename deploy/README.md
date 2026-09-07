# Guida al Deployment dell'Agente Windows Heimdall 🛡️

Questo agente PowerShell è progettato specificamente per le **PMI e ambienti Active Directory aziendali**.
**Zero dipendenze esterne**: non richiede l'installazione di Python né di librerie esterne sui PC o server client.

---

## 1. Funzionalità di Monitoraggio

L'agente intercetta in tempo reale dal Registro Eventi di Windows (Event Viewer):
- **Event ID 4625 (Security)**: Tentativo di accesso fallito (attacchi Brute-Force via RDP, SMB o console locale).
- **Event ID 4672 (Security)**: Assegnazione di privilegi speciali (accesso amministrativo / privilege escalation).
- **Event ID 4720 (Security)**: Creazione di un nuovo account utente locale o di dominio (rilevamento backdoor).
- **Event ID 7045 (System)**: Installazione di un nuovo servizio Windows (tipica persistenza malware/ransomware).

I dati vengono formattati e inoltrati in modo asincrono all'API di Heimdall Master via HTTPS/HTTP POST.

---

## 2. Test Locale Immediato

Puoi testare l'agente su qualsiasi macchina Windows aprendo PowerShell:

```powershell
# Esecuzione in modalità di test (dry-run senza invio dati di rete):
powershell.exe -ExecutionPolicy Bypass -File .\Deploy-HeimdallAgent.ps1 -TestRun
```

---

## 3. Distribuzione Tramite Active Directory GPO (Group Policy)

Per distribuire l'agente su 10, 50 o 500 macchine contemporaneamente nel dominio:

1. Salva lo script in una cartella condivisa accessibile a tutti i computer di dominio (es. `\\dominio.local\NETLOGON\Heimdall\Deploy-HeimdallAgent.ps1`).
2. Apri la console **Gestione Criteri di Gruppo** (`gpmc.msc`).
3. Crea un nuovo GPO: *"Distribuzione Agente Sicurezza Heimdall"*.
4. Naviga in:  
   `Configurazione computer -> Criteri -> Impostazioni di Windows -> Script (Avvio/Arresto) -> Avvio`.
5. Aggiungi uno script PowerShell all'avvio con i seguenti parametri:
   - **File script**: `\\dominio.local\NETLOGON\Heimdall\Deploy-HeimdallAgent.ps1`
   - **Parametri**: `-ServerUrl "http://soc-master.lan:18000" -ApiKey "CHIAVE_SEGRETA" -InstallTask`

Al riavvio delle macchine, lo script registrerà automaticamente un'attività pianificata (*HeimdallWindowsSecurityAgent*) con privilegi di `SYSTEM` che rimarrà attiva in background e si riavvierà automaticamente.

---

## 4. Distribuzione Tramite Microsoft Intune / NinjaOne / Datto RMM

Se gestisci endpoint in smart working o cloud:

Carica `Deploy-HeimdallAgent.ps1` come script di configurazione eseguito con permessi di **System**:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Deploy-HeimdallAgent.ps1 -ServerUrl "https://tuo-soc.dominio.it:18000" -ApiKey "CHIAVE_SEGRETA" -InstallTask
```

Per disinstallare o rimuovere l'agente:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Deploy-HeimdallAgent.ps1 -UninstallTask
```
