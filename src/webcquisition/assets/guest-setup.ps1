<#
  WEBCQUISITION - preparazione automatica del guest Windows.
  Eseguito da "webcquisition vmware-setup" tramite VMware Tools (vmrun runProgramInGuest),
  oppure manualmente come amministratore se le guest operations non ottengono privilegi elevati:

    powershell -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\webcq-setup\guest-setup.ps1

  Legge i parametri da setup-params.json nella stessa cartella e scrive setup-result.json.
  I file sensibili (agent.json con il token, password per l'accesso automatico) vengono
  cancellati da questa cartella al termine.
#>
param([string]$WorkDir = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$resultPath = Join-Path $WorkDir 'setup-result.json'
# Funzioni sostituibili dai test automatici (tests/test_guest_setup_ps1.py); su Windows valgono queste.
if (-not (Get-Command Test-WebcqIsAdmin -ErrorAction SilentlyContinue)) {
  function Test-WebcqIsAdmin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
}
if (-not (Get-Command Get-WebcqIdentity -ErrorAction SilentlyContinue)) {
  function Get-WebcqIdentity { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
}
$result = [ordered]@{
  ok = $false; code = $null; message = $null
  started_at_utc = (Get-Date).ToUniversalTime().ToString('o'); finished_at_utc = $null
  computer = $env:COMPUTERNAME; run_as = (Get-WebcqIdentity)
  steps = @(); warnings = @(); checks = [ordered]@{}; leftover_sensitive = @()
}
function Add-Step([string]$name, $detail) { $script:result.steps += [ordered]@{ name = $name; ok = $true; detail = $detail }; Write-WebcqProgress "ok: $name" }
function Add-Warn([string]$msg) { $script:result.warnings += $msg }
function Fail([string]$code, [string]$msg) { $e = New-Object System.Exception($msg); $e.Data['code'] = $code; throw $e }
# Converte qualsiasi valore in tipi JSON semplici. Indispensabile in Windows PowerShell 5.1: una stringa
# letta con Get-Content porta proprietà nascoste (PSPath, PSDrive, PSProvider...) che ConvertTo-Json
# esplorerebbe ricorsivamente (grafo enorme: di fatto un blocco). Anche oggetti .NET inattesi diventano testo.
function ConvertTo-WebcqPlain($o, [int]$depth = 0) {
  if ($null -eq $o) { return $null }
  if ($o -is [string]) { return [string]::new($o.ToCharArray()) }  # nuova istanza: nessuna proprietà nascosta
  if ($o -is [bool] -or $o -is [int] -or $o -is [long] -or $o -is [double] -or $o -is [decimal]) { return $o }
  if ($depth -ge 8) { return [string]::new(([string]$o).ToCharArray()) }
  if ($o -is [System.Collections.IDictionary]) {
    $h = [ordered]@{}
    foreach ($k in @($o.Keys)) { $h[[string]$k] = ConvertTo-WebcqPlain $o[$k] ($depth + 1) }
    return $h
  }
  if ($o -is [System.Management.Automation.PSCustomObject]) {
    $h = [ordered]@{}
    foreach ($pr in $o.PSObject.Properties) { $h[$pr.Name] = ConvertTo-WebcqPlain $pr.Value ($depth + 1) }
    return $h
  }
  if ($o -is [System.Collections.IEnumerable]) {
    $list = New-Object System.Collections.ArrayList
    foreach ($item in $o) { [void]$list.Add((ConvertTo-WebcqPlain $item ($depth + 1))) }
    return ,$list.ToArray()
  }
  return [string]::new(([string]$o).ToCharArray())
}
function Write-Result { $script:result.finished_at_utc = (Get-Date).ToUniversalTime().ToString('o')
  Write-WebcqProgress 'scrittura del risultato'
  $json = ConvertTo-Json -InputObject (ConvertTo-WebcqPlain $script:result) -Depth 12
  [IO.File]::WriteAllText($resultPath, $json, (New-Object System.Text.UTF8Encoding($false))) }
$keepFiles = $false
$progressPath = Join-Path $WorkDir 'setup-progress.log'
function Write-WebcqProgress([string]$msg) {
  try { Add-Content -Path $script:progressPath -Value ("{0} {1}" -f (Get-Date).ToUniversalTime().ToString('HH:mm:ss'), $msg) -Encoding UTF8 } catch { }
}
# Esegue un programma con timeout, stdin chiuso (nessuna attesa di input) e output catturato.
function Invoke-WebcqNative([string]$Exe, [string[]]$Arguments, [int]$TimeoutSec = 120) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  $psi.Arguments = (@($Arguments) | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
  $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
  $proc = [System.Diagnostics.Process]::Start($psi)
  $proc.StandardInput.Close()
  $o = $proc.StandardOutput.ReadToEndAsync()
  $e = $proc.StandardError.ReadToEndAsync()
  if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
    try { $proc.Kill() } catch { }
    return [pscustomobject]@{ ExitCode = -1; Out = ''; Err = "timeout dopo $TimeoutSec s"; TimedOut = $true }
  }
  $proc.WaitForExit()
  [pscustomobject]@{ ExitCode = $proc.ExitCode; Out = $o.Result; Err = $e.Result; TimedOut = $false }
}

try {
  Write-WebcqProgress 'avvio dello script di preparazione'
  $p = Get-Content -Raw -Path (Join-Path $WorkDir 'setup-params.json') | ConvertFrom-Json
  $result.run_id = $p.run_id
  $installDir = if ($p.install_dir) { $p.install_dir } else { 'C:\Program Files\WEBCQUISITION\agent' }
  $agentConfigPath = if ($p.agent_config_path) { $p.agent_config_path } else { 'C:\ProgramData\WEBCQUISITION\agent.json' }
  $agentJsonPath = Join-Path $WorkDir 'agent.json'
  $agentCfg = Get-Content -Raw -Path $agentJsonPath | ConvertFrom-Json

  # 1. privilegi
  if (-not (Test-WebcqIsAdmin)) {
    $keepFiles = $true
    Fail 'NOT_ELEVATED' ("Il processo non ha privilegi di amministratore (UAC). Eseguire nella VM, in un PowerShell " +
      "'Esegui come amministratore': powershell -NoProfile -ExecutionPolicy Bypass -File `"$WorkDir\guest-setup.ps1`"")
  }
  Add-Step 'elevation' 'ok'

  # 2. utente operatore
  $op = Get-LocalUser -Name $p.operator_user -ErrorAction SilentlyContinue
  if (-not $op) { Fail 'OPERATOR_NOT_FOUND' "utente locale '$($p.operator_user)' non trovato nella VM" }
  if (-not $op.Enabled) { Fail 'OPERATOR_DISABLED' "l'utente '$($p.operator_user)' è disabilitato" }
  Add-Step 'operator_user' $p.operator_user

  # 3. Python (per tutti gli utenti, non Microsoft Store)
  Write-WebcqProgress 'ricerca di Python'
  $cands = @()
  $cands += @(Get-ChildItem 'C:\Program Files\Python3*\pythonw.exe', 'C:\Python3*\pythonw.exe' -ErrorAction SilentlyContinue |
              Sort-Object FullName -Descending | ForEach-Object { $_.FullName })
  $c = Get-Command pythonw.exe -ErrorAction SilentlyContinue; if ($c) { $cands += $c.Source }
  $py = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($py -and -not ($cands | Where-Object { $_ -notmatch 'WindowsApps' })) {
    $r = Invoke-WebcqNative $py.Source @('-3', '-c', 'import sys;print(sys.executable)') 30
    if ($r.TimedOut) { Add-Warn 'il launcher py.exe non risponde (possibile richiesta interattiva del Python install manager)' }
    elseif ($r.ExitCode -eq 0 -and $r.Out.Trim()) { $cands += (Join-Path (Split-Path $r.Out.Trim()) 'pythonw.exe') }
  }
  $pyw = $cands | Where-Object { $_ -and (Test-Path $_) -and ($_ -notmatch 'WindowsApps') } | Select-Object -First 1
  if (-not $pyw) {
    $found = @(Get-ChildItem 'C:\Users\*\AppData\Local\Programs\Python\Python3*\python.exe', 'C:\Users\*\AppData\Local\Python\*\python.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $hint = if ($found) { " Trovate solo installazioni per singolo utente: $($found -join ', ')." } else { '' }
    Fail 'PYTHON_NOT_FOUND' ('Python 3.10+ per tutti gli utenti non trovato (atteso in C:\Program Files\Python3xx).' + $hint +
      ' Installarlo con l''installer classico di python.org: Customize installation > "Install Python for all users".')
  }
  $pyexe = Join-Path (Split-Path $pyw) 'python.exe'
  Write-WebcqProgress "Python trovato: $pyexe"
  $r = Invoke-WebcqNative $pyexe @('-c', 'import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)') 60
  if ($r.TimedOut) { Fail 'PYTHON_NOT_RESPONDING' "$pyexe non risponde" }
  if ($r.ExitCode -ne 0) { Fail 'PYTHON_TOO_OLD' "Python in $pyexe è più vecchio di 3.10" }
  $pyver = (Invoke-WebcqNative $pyexe @('-c', 'import platform;print(platform.python_version())') 60).Out.Trim()
  if ($pyw -like "$env:SystemDrive\Users\*") { Add-Warn "Python è installato nel profilo di un utente ($pyw): installarlo per tutti gli utenti" }
  if ((Invoke-WebcqNative $pyexe @('-c', 'import tkinter') 60).ExitCode -ne 0) { Add-Warn 'tkinter non disponibile: il pannello WEBCQUISITION non comparirà (reinstallare Python con tcl/tk)' }
  $result.checks.python = [ordered]@{ pythonw = $pyw; version = $pyver }
  Add-Step 'python' $pyver

  # 4. Wireshark / Npcap / Firefox
  Write-WebcqProgress 'controllo di Wireshark, Npcap e Firefox'
  if (-not (Test-Path $agentCfg.dumpcap_path)) { Fail 'WIRESHARK_NOT_FOUND' "dumpcap non trovato in $($agentCfg.dumpcap_path): installare Wireshark" }
  $npcap = Get-Service -Name npcap -ErrorAction SilentlyContinue
  if (-not $npcap) { Fail 'NPCAP_NOT_FOUND' 'servizio Npcap non presente: installare Npcap (incluso nell''installer di Wireshark)' }
  $npParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters' -ErrorAction SilentlyContinue
  if ($npParams -and $npParams.AdminOnly -eq 1) {
    Fail 'NPCAP_ADMIN_ONLY' ("Npcap è installato con 'Restrict Npcap driver's access to Administrators only': " +
      "reinstallarlo senza questa opzione (l'agent gira con privilegi limitati)")
  }
  if ($npcap.Status -ne 'Running') { try { Start-Service npcap } catch { Add-Warn "servizio Npcap non avviato: $($_.Exception.Message)" } }
  $r = Invoke-WebcqNative $agentCfg.dumpcap_path @('-v') 60
  $dumpcapVer = (("$($r.Out)`n$($r.Err)").Trim() -split "`r?`n" | Select-Object -First 1) -as [string]
  if (-not (Test-Path $agentCfg.wireshark_path)) { Add-Warn "Wireshark.exe non trovato in $($agentCfg.wireshark_path): la vista GUI non sarà disponibile" }
  if (-not (Test-Path $agentCfg.firefox_path)) { Fail 'FIREFOX_NOT_FOUND' "Firefox non trovato in $($agentCfg.firefox_path): installare Firefox dall'installer ufficiale Mozilla" }
  if ($agentCfg.firefox_path -match 'WindowsApps') { Fail 'FIREFOX_STORE' 'la versione Microsoft Store di Firefox non è supportata (key log TLS)' }
  $ffVer = $null
  $ini = Join-Path (Split-Path $agentCfg.firefox_path) 'application.ini'
  if (Test-Path $ini) { $ffVer = ((Select-String -Path $ini -Pattern '^Version=(.*)$').Matches | Select-Object -First 1).Groups[1].Value }
  $result.checks.tools = [ordered]@{ dumpcap = $dumpcapVer; npcap = [string]$npcap.Status; firefox = $ffVer }
  Add-Step 'tools' $result.checks.tools

  Write-WebcqProgress 'configurazione delle schede di rete'
  # 5. rete: scheda di controllo (host-only) e scheda di acquisizione, riconosciute dal MAC del .vmx
  $ctlMac = ($p.control_mac -replace ':', '-').ToUpper()
  $capMac = ($p.capture_mac -replace ':', '-').ToUpper()
  $ctl = Get-NetAdapter | Where-Object { $_.MacAddress -eq $ctlMac }
  $cap = Get-NetAdapter | Where-Object { $_.MacAddress -eq $capMac }
  if (-not $ctl) { Fail 'CONTROL_NIC_NOT_FOUND' "scheda host-only con MAC $ctlMac non trovata nel guest" }
  if (-not $cap) { Fail 'CAPTURE_NIC_NOT_FOUND' "scheda di acquisizione con MAC $capMac non trovata nel guest" }
  $idx = $ctl.ifIndex
  Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Disabled
  Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $idx -IPAddress $p.control_ip -PrefixLength ([int]$p.prefix_length) | Out-Null
  Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses
  Set-DnsClient -InterfaceIndex $idx -RegisterThisConnectionsAddress $false
  foreach ($pair in @(@($ctl, $p.control_nic_name), @($cap, $p.capture_nic_name))) {
    $a = $pair[0]; $new = $pair[1]
    if ($a.Name -ne $new) {
      if (Get-NetAdapter -Name $new -ErrorAction SilentlyContinue) { Fail 'NIC_NAME_TAKEN' "esiste già una scheda chiamata '$new'" }
      Rename-NetAdapter -Name $a.Name -NewName $new
    }
  }
  try { Set-NetConnectionProfile -InterfaceIndex $idx -NetworkCategory Private -ErrorAction Stop } catch { Add-Warn "profilo di rete della scheda di controllo non impostato: $($_.Exception.Message)" }
  $result.checks.network = [ordered]@{ control_nic = $p.control_nic_name; control_ip = $p.control_ip; prefix_length = $p.prefix_length; capture_nic = $p.capture_nic_name }
  Add-Step 'network' $result.checks.network

  # 6. SSLKEYLOGFILE globale: va rimossa (il key log è impostato per-processo dall'agent)
  $removed = @()
  foreach ($scope in 'Machine', 'User') {
    if ([Environment]::GetEnvironmentVariable('SSLKEYLOGFILE', $scope)) { [Environment]::SetEnvironmentVariable('SSLKEYLOGFILE', $null, $scope); $removed += $scope }
  }
  if ($removed) { Add-Warn "rimossa la variabile SSLKEYLOGFILE globale (ambito: $($removed -join ', ')). Verificare anche il profilo dell'operatore." }
  Add-Step 'sslkeylogfile' ($(if ($removed) { "rimossa: $($removed -join ',')" } else { 'assente' }))

  # 7. agent
  Write-WebcqProgress "installazione dell'agent"
  $bundleDir = Join-Path $WorkDir 'bundle'
  if (Test-Path $bundleDir) { Remove-Item -Recurse -Force $bundleDir }
  Expand-Archive -Path (Join-Path $WorkDir 'agent-bundle.zip') -DestinationPath $bundleDir
  & (Join-Path $bundleDir 'install-agent.ps1') -AgentJson $agentJsonPath -OperatorUser $p.operator_user -HostIp $p.host_ip -PythonW $pyw -InstallDir $installDir | Out-Null
  Write-WebcqProgress "verifica dell'agent (interfacce, strumenti)"
  $env:PYTHONIOENCODING = 'utf-8'
  $r = Invoke-WebcqNative $pyexe @((Join-Path $installDir 'run_agent.pyw'), '--config', $agentConfigPath, '--check') 300
  if ($r.TimedOut) { Fail 'AGENT_CHECK_TIMEOUT' "la verifica dell'agent non ha risposto entro 300 s" }
  if ($r.ExitCode -ne 0) { Fail 'AGENT_CHECK_FAILED' "verifica dell'agent fallita (rc=$($r.ExitCode)): $($r.Err)" }
  $check = $r.Out | ConvertFrom-Json
  $result.checks.agent = [ordered]@{
    tools_present = $check.tools_present; interfaces = $check.interfaces.interfaces
    global_sslkeylogfile = $check.sysinfo.global_sslkeylogfile; windows = $check.sysinfo.windows
    bundle_sha256sums = [IO.File]::ReadAllText((Join-Path $installDir 'BUNDLE-SHA256SUMS.txt'))
  }
  if (-not ($check.interfaces.interfaces | Where-Object { $_.is_control })) { Fail 'CONTROL_NOT_DETECTED' "l'agent non riconosce la scheda di controllo ($($p.control_ip))" }
  if (-not ($check.interfaces.interfaces | Where-Object { $_.friendly_name -eq $p.capture_nic_name })) { Fail 'CAPTURE_NOT_DETECTED' "dumpcap non vede la scheda '$($p.capture_nic_name)'" }
  Add-Step 'agent' 'installato e verificato'

  # 8. opzioni
  if ($p.autologon) {
    $pwFile = Join-Path $WorkDir 'operator.pw'
    $pw = (Get-Content -Raw -Path $pwFile).TrimEnd("`r", "`n")
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $wl -Name AutoAdminLogon -Value '1'
    Set-ItemProperty $wl -Name DefaultUserName -Value $p.operator_user
    Set-ItemProperty $wl -Name DefaultDomainName -Value $env:COMPUTERNAME
    Set-ItemProperty $wl -Name DefaultPassword -Value $pw
    Add-Warn "accesso automatico attivo per '$($p.operator_user)': la password è memorizzata in chiaro nel registro della VM"
    Add-Step 'autologon' $p.operator_user
  }
  if ($p.disable_windows_update) {
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service wuauserv -StartupType Disabled
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force | Out-Null
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord
    Add-Step 'windows_update' 'disattivato'
  }

  $result.ok = $true
  $result.code = 'OK'
}
catch {
  Write-WebcqProgress ("errore: " + $_.Exception.Message)
  $result.ok = $false
  $result.code = $(if ($_.Exception.Data['code']) { $_.Exception.Data['code'] } else { 'SETUP_ERROR' })
  $result.message = $_.Exception.Message
}
finally {
  # La pulizia non deve MAI impedire la scrittura del risultato: ogni cancellazione è isolata,
  # ritentata (file appena estratti possono essere bloccati per qualche secondo dall'antivirus)
  # e un eventuale fallimento diventa un avviso.
  if (-not $keepFiles) {
    Write-WebcqProgress 'pulizia dei file temporanei'
    $targets = @('agent.json', 'operator.pw', 'agent-bundle.zip', 'setup-params.json', 'bundle') | ForEach-Object { Join-Path $WorkDir $_ }
    foreach ($fp in $targets) {
      $done = $false
      for ($i = 0; $i -lt 10 -and -not $done; $i++) {
        try {
          if (Test-Path $fp) { Remove-Item -LiteralPath $fp -Recurse -Force -ErrorAction Stop }
          $done = $true
        } catch { Start-Sleep -Seconds 1 }
      }
      if (-not $done) {
        $name = Split-Path -Leaf $fp
        $sens = if ($name -in @('agent.json', 'operator.pw')) { ' (CONTIENE DATI SENSIBILI: cancellarlo a mano prima dello snapshot)' } else { '' }
        $result.warnings += "impossibile cancellare $fp$sens"
        if ($sens) { $result.leftover_sensitive += $fp }
      }
    }
  }
  try { Write-Result }
  catch {
    # ultima risorsa: risultato minimo, così l'host non resta in attesa
    $min = @{ ok = [bool]$result.ok; code = [string]$result.code; run_id = [string]$result.run_id
              message = "risultato completo non serializzabile: $($_.Exception.Message)"
              finished_at_utc = (Get-Date).ToUniversalTime().ToString('o'); steps = @(); warnings = @() }
    [IO.File]::WriteAllText($resultPath, (ConvertTo-Json -InputObject $min), (New-Object System.Text.UTF8Encoding($false)))
  }
  Write-WebcqProgress 'script terminato'
}
if ($result.ok) { exit 0 } else { exit 1 }
