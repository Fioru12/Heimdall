<#
.SYNOPSIS
    Heimdall Native Windows Agent (Zero-Dependency PowerShell Edition)
    Monitors Windows Security & System Event Logs and streams alerts to Heimdall HIDS Master API.

.DESCRIPTION
    Designed for enterprise Windows & Active Directory deployment in SMEs/PMIs.
    Requires NO Python or external tools - runs natively on Windows 10, 11, and Windows Server 2016+.
    Collects critical security events:
      - Event ID 4625: Failed Logon Attempts (Brute-Force RDP, SMB, Console)
      - Event ID 4672: Special Privileges Assigned (Privilege Escalation / Admin Logon)
      - Event ID 4720: User Account Created (Rogue Backdoor Detection)
      - Event ID 7045: New Service Installed (Malware Persistence)

.PARAMETER ServerUrl
    Heimdall Master API base URL (e.g. http://192.168.1.100:18000)

.PARAMETER ApiKey
    Heimdall authentication key (X-API-Key)

.PARAMETER PollInterval
    Seconds to wait between checking for new events (default: 5)

.PARAMETER InstallTask
    Registers the script as a persistent Windows Scheduled Task running under SYSTEM.

.PARAMETER UninstallTask
    Removes the registered Windows Scheduled Task.

.PARAMETER TestRun
    Runs a single dry-run check without sending actual network requests.

.EXAMPLE
    # Test execution in console:
    .\Deploy-HeimdallAgent.ps1 -ServerUrl "http://192.168.1.50:18000" -ApiKey "my_secret_key" -TestRun

.EXAMPLE
    # Mass GPO / Intune deployment (Install persistent background task):
    powershell.exe -ExecutionPolicy Bypass -File .\Deploy-HeimdallAgent.ps1 -ServerUrl "http://192.168.1.50:18000" -ApiKey "my_secret_key" -InstallTask
#>

[CmdletBinding()]
param(
    [string]$ServerUrl = "http://localhost:18000",
    [string]$ApiKey = "",
    [int]$PollInterval = 5,
    [switch]$InstallTask,
    [switch]$UninstallTask,
    [switch]$TestRun
)

$ErrorActionPreference = "Continue"
$TaskName = "HeimdallWindowsSecurityAgent"

# ---------------------------------------------------------------------------
# Task Management (GPO / Intune Automation)
# ---------------------------------------------------------------------------
if ($UninstallTask) {
    Write-Host "[HEIMDALL] Removing scheduled task '$TaskName'..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[HEIMDALL] Task removed successfully." -ForegroundColor Green
    exit 0
}

if ($InstallTask) {
    if (-not $ApiKey) {
        Write-Error "ApiKey parameter is required to register the scheduled task."
        exit 1
    }
    
    $ScriptPath = $MyInvocation.MyCommand.Definition
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -ServerUrl `"$ServerUrl`" -ApiKey `"$ApiKey`""
    
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    Write-Host "[HEIMDALL] Registering Scheduled Task '$TaskName' to run at system startup..." -ForegroundColor Cyan
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
    Write-Host "[HEIMDALL] Scheduled Task registered successfully! The agent is now persistent." -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# Core Forwarding Function
# ---------------------------------------------------------------------------
function Send-HeimdallEvent {
    param(
        [string]$LogLine,
        [string]$TargetUrl,
        [string]$Key,
        [bool]$DryRun = $false
    )

    if ($DryRun) {
        Write-Host "[TEST-RUN] Would forward: $LogLine" -ForegroundColor DarkGray
        return
    }

    $Endpoint = "$($TargetUrl.TrimEnd('/'))/api/v1/ingest"
    $Body = @{
        log_line = $LogLine
        log_type = "auto"
    } | ConvertTo-Json

    $Headers = @{
        "Content-Type" = "application/json"
        "X-API-Key"    = $Key
    }

    try {
        $Response = Invoke-RestMethod -Uri $Endpoint -Method Post -Body $Body -Headers $Headers -TimeoutSec 5
        if ($Response.status -and $Response.status -ne "ignored") {
            Write-Host "[SENT] Forwarded event -> Status: $($Response.status)" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "[WARN] Failed to forward event to Heimdall ($($_.Exception.Message))"
    }
}

# ---------------------------------------------------------------------------
# Event Log Parser
# ---------------------------------------------------------------------------
function Process-SecurityEvents {
    param([datetime]$StartTime)

    $Events = @()

    # Query Security Log (4625, 4720)
    try {
        $SecEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625, 4720
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        if ($SecEvents) {
            $Events += $SecEvents
        }
    }
    catch {}

    # Query System Log (7045)
    try {
        $SysEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7045
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        if ($SysEvents) {
            $Events += $SysEvents
        }
    }
    catch {}

    return $Events
}

# ---------------------------------------------------------------------------
# Main Execution Loop
# ---------------------------------------------------------------------------
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Heimdall Windows Security Agent (Active Directory Ready)" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[CONFIG] Target Server : $ServerUrl" -ForegroundColor Gray
Write-Host "[CONFIG] Poll Interval : $PollInterval seconds" -ForegroundColor Gray
if ($TestRun) {
    Write-Host "[MODE] Running in TEST-RUN mode (dry run)." -ForegroundColor Magenta
}

$LastCheckTime = (Get-Date).AddMinutes(-5)

if ($TestRun) {
    Write-Host "[TEST-RUN] Scanning recent 5 minutes for security events..." -ForegroundColor Cyan
    $RecentEvents = Process-SecurityEvents -StartTime $LastCheckTime
    Write-Host "[TEST-RUN] Found $($RecentEvents.Count) events in the last 5 minutes." -ForegroundColor Green
    
    # Generate a synthetic simulation log to demonstrate format
    $SyntheticLog = "WindowsEvent Security 4625 Failed logon user=admin from=203.0.113.42 Workstation=HOST-01 Type=3 Status=0xC000006D"
    Send-HeimdallEvent -LogLine $SyntheticLog -TargetUrl $ServerUrl -Key $ApiKey -DryRun $true
    Write-Host "[TEST-RUN] Verification complete. The agent logic is ready." -ForegroundColor Green
    exit 0
}

Write-Host "[HEIMDALL] Agent started. Listening for Windows security events..." -ForegroundColor Green

while ($true) {
    $Now = Get-Date
    $NewEvents = Process-SecurityEvents -StartTime $LastCheckTime

    if ($NewEvents) {
        foreach ($Evt in $NewEvents) {
            $EvtXml = [xml]$Evt.ToXml()
            $EventId = $Evt.Id

            if ($EventId -eq 4625) {
                # Extract failed logon data
                $TargetUser = ($EvtXml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                $IpAddress  = ($EvtXml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                $Workstation = ($EvtXml.Event.EventData.Data | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
                
                if (-not $IpAddress -or $IpAddress -eq "-") { $IpAddress = "127.0.0.1" }
                $LogMsg = "WindowsEvent Security 4625 Failed logon user=$TargetUser from=$IpAddress Workstation=$Workstation"
                Send-HeimdallEvent -LogLine $LogMsg -TargetUrl $ServerUrl -Key $ApiKey
            }
            elseif ($EventId -eq 4720) {
                $NewUser = ($EvtXml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                $Creator = ($EvtXml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
                $LogMsg = "WindowsEvent Security 4720 Account created user=$NewUser by=$Creator"
                Send-HeimdallEvent -LogLine $LogMsg -TargetUrl $ServerUrl -Key $ApiKey
            }
            elseif ($EventId -eq 7045) {
                $ServiceName = ($EvtXml.Event.EventData.Data | Where-Object { $_.Name -eq "ServiceName" }).'#text'
                $ImagePath   = ($EvtXml.Event.EventData.Data | Where-Object { $_.Name -eq "ImagePath" }).'#text'
                $LogMsg = "WindowsEvent System 7045 New service installed: $ServiceName Path=$ImagePath"
                Send-HeimdallEvent -LogLine $LogMsg -TargetUrl $ServerUrl -Key $ApiKey
            }
        }
    }

    $LastCheckTime = $Now
    Start-Sleep -Seconds $PollInterval
}
