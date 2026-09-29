<#
.SYNOPSIS
  Installa il guest agent WEBCQUISITION nella VM Windows di acquisizione.

.DESCRIPTION
  Normalmente eseguito in automatico da "webcquisition vmware-setup" (guest-setup.ps1).
  Uso manuale: come amministratore NELLA VM, dalla cartella del bundle creato con
  scripts/build-agent-bundle.py, PRIMA di creare lo snapshot "pulito".
  - copia il bundle in -InstallDir;
  - installa agent.json in C:\ProgramData\WEBCQUISITION (ACL: solo Administrators, SYSTEM e l'utente operatore);
  - crea uno Scheduled Task "At logon" per l'utente operatore (sessione interattiva: GUI visibili);
  - crea una regola firewall in ingresso limitata all'IP host-only della VM e all'IP dell'host.

.EXAMPLE
  .\install-agent.ps1 -AgentJson .\agent.json -OperatorUser "forensic" -HostIp 192.168.150.1
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string]$AgentJson,
  [Parameter(Mandatory=$true)] [string]$OperatorUser,
  [Parameter(Mandatory=$true)] [string]$HostIp,
  [string]$InstallDir = "C:\Program Files\WEBCQUISITION\agent",
  [string]$PythonW = ""
)
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Eseguire come amministratore."
  }
}
Assert-Admin

if (-not $PythonW) {
  $py = (Get-Command pythonw.exe -ErrorAction SilentlyContinue)
  if (-not $py) { throw "pythonw.exe non trovato: installare Python 3.10+ per tutti gli utenti o indicare -PythonW." }
  $PythonW = $py.Source
}
$cfg = Get-Content -Raw -Path $AgentJson | ConvertFrom-Json
if (-not $cfg.listen_host -or $cfg.listen_host -eq "0.0.0.0") { throw "listen_host deve essere l'IP host-only della VM." }
if ($cfg.token.Length -lt 32) { throw "token assente o troppo corto." }

# 1. File del bundle
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Recurse -Force -Path (Join-Path $src "lib"), (Join-Path $src "run_agent.pyw"), (Join-Path $src "BUNDLE-SHA256SUMS.txt") -Destination $InstallDir

# 2. Configurazione con ACL restrittiva (contiene il token)
$dataDir = "C:\ProgramData\WEBCQUISITION"
New-Item -ItemType Directory -Force -Path $dataDir, (Join-Path $dataDir "logs") | Out-Null
$cfgPath = Join-Path $dataDir "agent.json"
Copy-Item -Force -Path $AgentJson -Destination $cfgPath
# SID invece dei nomi (i nomi dei gruppi sono localizzati: Administrators, Administratoren, ...)
icacls $cfgPath /inheritance:r /grant:r "*S-1-5-18:(R)" "*S-1-5-32-544:(F)" "$($OperatorUser):(R)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls su $cfgPath fallito" }
icacls (Join-Path $dataDir "logs") /grant "$($OperatorUser):(OI)(CI)M" | Out-Null

# 3. Scheduled Task nella sessione interattiva dell'operatore
$action = New-ScheduledTaskAction -Execute $PythonW -Argument "`"$InstallDir\run_agent.pyw`" --config `"$cfgPath`"" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $OperatorUser
# Privilegi LIMITATI: Firefox e gli altri processi avviati dall'agent non devono girare elevati.
$principal = New-ScheduledTaskPrincipal -UserId $OperatorUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "WEBCQUISITION Agent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

# 4. Firewall: solo dall'host, solo sull'IP host-only
Get-NetFirewallRule -DisplayName "WEBCQUISITION Agent" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "WEBCQUISITION Agent" -Direction Inbound -Protocol TCP -LocalPort $cfg.listen_port `
  -LocalAddress $cfg.listen_host -RemoteAddress $HostIp -Action Allow -Profile Any | Out-Null

# 5. Avvio immediato se l'operatore è già connesso (altrimenti partirà al prossimo logon)
try { Start-ScheduledTask -TaskName "WEBCQUISITION Agent" -ErrorAction Stop } catch { }

Write-Host "Agent installato in $InstallDir"
Write-Host "Verifica: & `"$PythonW`" `"$InstallDir\run_agent.pyw`" --config `"$cfgPath`" --check  (usare python.exe per vedere l'output)"
Write-Host "Ricordare: SSLKEYLOGFILE NON deve essere impostata globalmente; creare lo snapshot pulito dopo il primo logon di verifica."
