# Esegue guest-setup.ps1 con i cmdlet Windows sostituiti da simulazioni (solo per i test).
param([string]$Script, [string]$WorkDir, [string]$CallsOut, [string]$AdaptersJson)
$global:Calls = New-Object System.Collections.ArrayList
$global:Adapters = @($AdaptersJson | ConvertFrom-Json)
function Log($name, $data) { [void]$global:Calls.Add([ordered]@{ cmd = $name; data = $data }) }

function Test-WebcqIsAdmin { $env:WEBCQ_TEST_ADMIN -ne '0' }
function Get-WebcqIdentity { 'TEST\admin' }
function Get-LocalUser { [CmdletBinding()] param($Name) if ($Name -eq 'forensic') { [pscustomobject]@{ Name = $Name; Enabled = $true } } }
function Get-Service { [CmdletBinding()] param($Name) [pscustomobject]@{ Name = $Name; Status = 'Running' } }
function Start-Service { [CmdletBinding()] param($Name) }
function Get-NetAdapter { [CmdletBinding()] param($Name)
  if ($Name) { $global:Adapters | Where-Object { $_.Name -eq $Name } } else { $global:Adapters } }
function Rename-NetAdapter { [CmdletBinding()] param($Name, $NewName)
  ($global:Adapters | Where-Object { $_.Name -eq $Name }).Name = $NewName; Log 'Rename-NetAdapter' @{ from = $Name; to = $NewName } }
function Set-NetIPInterface { [CmdletBinding()] param($InterfaceIndex, $AddressFamily, $Dhcp) Log 'Set-NetIPInterface' @{ idx = $InterfaceIndex; dhcp = $Dhcp } }
function Get-NetIPAddress { [CmdletBinding()] param($InterfaceIndex, $AddressFamily) @() }
function Remove-NetIPAddress { [CmdletBinding(SupportsShouldProcess)] param([Parameter(ValueFromPipeline)]$InputObject) }
function Get-NetRoute { [CmdletBinding()] param($InterfaceIndex, $DestinationPrefix) @() }
function Remove-NetRoute { [CmdletBinding(SupportsShouldProcess)] param([Parameter(ValueFromPipeline)]$InputObject) }
function New-NetIPAddress { [CmdletBinding()] param($InterfaceIndex, $IPAddress, $PrefixLength)
  Log 'New-NetIPAddress' @{ idx = $InterfaceIndex; ip = $IPAddress; prefix = $PrefixLength } }
function Set-DnsClientServerAddress { [CmdletBinding()] param($InterfaceIndex, [switch]$ResetServerAddresses) Log 'Set-DnsClientServerAddress' @{ idx = $InterfaceIndex } }
function Set-DnsClient { [CmdletBinding()] param($InterfaceIndex, $RegisterThisConnectionsAddress) Log 'Set-DnsClient' @{ register = $RegisterThisConnectionsAddress } }
function Set-NetConnectionProfile { [CmdletBinding()] param($InterfaceIndex, $NetworkCategory) }
function Get-ItemProperty { [CmdletBinding()] param($Path) if ($env:WEBCQ_TEST_NPCAP_ADMINONLY -eq '1') { [pscustomobject]@{ AdminOnly = 1 } } }
function Set-ItemProperty { [CmdletBinding()] param($Path, $Name, $Value, $Type) Log 'Set-ItemProperty' @{ path = $Path; name = $Name; value = $Value } }

if ($env:WEBCQ_TEST_LOCKED) {
  # simula file bloccati (antivirus / processo che li tiene aperti)
  function Remove-Item { [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [switch]$Recurse, [switch]$Force)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    foreach ($pat in ($env:WEBCQ_TEST_LOCKED -split ';')) { if ($target -like "*$pat") { throw "file in uso: $target" } }
    Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters }
}
& $Script -WorkDir $WorkDir
$rc = $LASTEXITCODE
$global:Calls | ConvertTo-Json -Depth 6 | Set-Content -Path $CallsOut -Encoding UTF8
exit $rc
