"""Enumerazione delle interfacce di rete del guest.

Combina due fonti:
  * ``dumpcap -D``: i nomi di dispositivo effettivamente catturabili (``\\Device\\NPF_{GUID}``);
  * PowerShell ``Get-NetAdapter``/``Get-NetIPAddress``/``Get-NetRoute``: nome amichevole,
    GUID, IPv4, presenza di default gateway.

L'interfaccia che porta l'IP del canale di controllo (``control_ip``) viene marcata
``is_control=True``: host e agent rifiutano di usarla come interfaccia di cattura.
Le funzioni di parsing/merge sono pure e testate senza Windows.
"""

from __future__ import annotations

import json
import re

from .winutil import run

_DUMPCAP_LINE = re.compile(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$")
_GUID = re.compile(r"\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?")

PS_ADAPTERS = r"""
$ErrorActionPreference = 'SilentlyContinue'
@(Get-NetAdapter | ForEach-Object {
  $ip = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4
  $gw = Get-NetRoute -InterfaceIndex $_.ifIndex -DestinationPrefix '0.0.0.0/0'
  [pscustomobject]@{
    Name = $_.Name; Guid = [string]$_.InterfaceGuid; Description = $_.InterfaceDescription
    Mac = $_.MacAddress; Status = [string]$_.Status; IPv4 = @($ip | ForEach-Object { $_.IPAddress })
    Gateway = [bool]$gw
  }
}) | ConvertTo-Json -Depth 4
"""


def parse_dumpcap_list(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _DUMPCAP_LINE.match(line)
        if not m:
            continue
        name, display = m.group(2), m.group(3)
        g = _GUID.search(name)
        out.append({"index": int(m.group(1)), "name": name, "display": display,
                    "guid": g.group(1).upper() if g else None})
    return out


def parse_adapters_json(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):  # ConvertTo-Json con un solo elemento restituisce un oggetto
        data = [data]
    out = []
    for a in data:
        g = _GUID.search(str(a.get("Guid") or ""))
        ipv4 = a.get("IPv4") or []
        if isinstance(ipv4, str):
            ipv4 = [ipv4]
        out.append({"friendly_name": a.get("Name"), "guid": g.group(1).upper() if g else None,
                    "description": a.get("Description"), "mac": a.get("Mac"), "status": a.get("Status"),
                    "ipv4": [ip for ip in ipv4 if ip], "has_default_gateway": bool(a.get("Gateway"))})
    return out


def merge_interfaces(dumpcap: list[dict], adapters: list[dict], control_ip: str | None) -> list[dict]:
    by_guid = {a["guid"]: a for a in adapters if a.get("guid")}
    merged = []
    for d in dumpcap:
        a = by_guid.get(d.get("guid") or "", {})
        ipv4 = a.get("ipv4", [])
        merged.append({
            "name": d["name"], "display": d.get("display"), "index": d.get("index"),
            "friendly_name": a.get("friendly_name") or d.get("display"), "guid": d.get("guid"),
            "description": a.get("description"), "mac": a.get("mac"), "status": a.get("status"),
            "ipv4": ipv4, "has_default_gateway": a.get("has_default_gateway", False),
            "is_control": bool(control_ip and control_ip in ipv4),
        })
    return merged


def enumerate_interfaces(dumpcap_path: str, control_ip: str | None) -> dict:
    rc, out, err = run([dumpcap_path, "-D"], timeout=60)
    if rc != 0:
        return {"interfaces": [], "error": f"dumpcap -D rc={rc}: {err.strip()[:500]}"}
    rc2, ps_out, ps_err = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", PS_ADAPTERS], timeout=90)
    try:
        adapters = parse_adapters_json(ps_out) if rc2 == 0 else []
    except ValueError:
        adapters = []
    result = {"interfaces": merge_interfaces(parse_dumpcap_list(out), adapters, control_ip)}
    if rc2 != 0 or not adapters:
        result["warning"] = f"dettagli adattatori non disponibili (PowerShell rc={rc2}): {ps_err.strip()[:300]}"
    return result
