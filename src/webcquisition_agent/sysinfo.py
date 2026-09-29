"""Raccolta dei metadati di sistema del guest (metadata/sysinfo.json).

Si raccolgono solo informazioni tecniche necessarie a documentare l'ambiente di
acquisizione (versioni, fuso orario, sincronizzazione oraria, variabili TLS).
Nessun dato personale oltre al nome del computer e dell'account locale.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket
import sys
import time
from pathlib import Path

from webcquisition_common import __version__
from webcquisition_common.timeutil import iso_utc, local_timezone_description

from .winutil import IS_WINDOWS, run


def _reg_values(root_name: str, key: str, names: list[str]) -> dict:
    if not IS_WINDOWS:
        return {}
    import winreg
    root = getattr(winreg, root_name)
    out = {}
    try:
        with winreg.OpenKey(root, key) as k:
            for n in names:
                try:
                    out[n] = winreg.QueryValueEx(k, n)[0]
                except OSError:
                    pass
    except OSError:
        pass
    return out


def windows_version() -> dict:
    info = _reg_values("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                       ["ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild", "UBR", "EditionID",
                        "InstallationType"])
    info["platform"] = platform.platform()
    build = info.get("CurrentBuild")
    if build and str(build).isdigit() and int(build) >= 22000 and "Windows 10" in str(info.get("ProductName", "")):
        info["note"] = "ProductName nel registro riporta 'Windows 10' anche su Windows 11 (build >= 22000)"
    return info


def firefox_version(firefox_path: str) -> str | None:
    ini = Path(firefox_path).parent / "application.ini"
    try:
        for line in ini.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


def firefox_build_info(firefox_path: str) -> dict:
    ini = Path(firefox_path).parent / "application.ini"
    out = {}
    try:
        for line in ini.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and line.split("=", 1)[0] in ("Vendor", "Name", "Version", "BuildID", "SourceStamp"):
                k, v = line.split("=", 1)
                out[k] = v.strip()
    except OSError:
        pass
    return out


def tool_version(path: str) -> str | None:
    rc, out, err = run([path, "-v"], timeout=30)
    text = (out or err).strip().splitlines()
    return text[0].strip() if text else None


def global_sslkeylogfile() -> dict:
    """SSLKEYLOGFILE impostata a livello globale (processo, utente, sistema).

    Se presente, altri processi (o Firefox avviato fuori da WEBCQUISITION) potrebbero
    scrivere segreti TLS in un file diverso da quello del caso: va segnalato.
    """
    found = {}
    if os.environ.get("SSLKEYLOGFILE"):
        found["process"] = os.environ["SSLKEYLOGFILE"]
    user = _reg_values("HKEY_CURRENT_USER", r"Environment", ["SSLKEYLOGFILE"])
    if user:
        found["user"] = user["SSLKEYLOGFILE"]
    system = _reg_values("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                         ["SSLKEYLOGFILE"])
    if system:
        found["system"] = system["SSLKEYLOGFILE"]
    return found


def time_sync_status() -> dict:
    if not IS_WINDOWS:
        return {"available": False}
    rc, out, _ = run(["w32tm", "/query", "/status"], timeout=30)
    rc2, tz, _ = run(["tzutil", "/g"], timeout=15)
    return {"w32tm_rc": rc, "w32tm_status": out.strip()[:2000], "tzutil": tz.strip() if rc2 == 0 else None}


def collect(settings) -> dict:
    tz = local_timezone_description()
    tz["time_tzname"] = list(time.tzname)
    glob = global_sslkeylogfile()
    return {
        "collected_at_utc": iso_utc(),
        "agent_version": __version__,
        "agent_id": settings.agent_id,
        "python": sys.version.split()[0],
        "computer_name": socket.gethostname(),
        "account": getpass.getuser(),
        "windows": windows_version(),
        "firefox_version": firefox_version(settings.firefox_path),
        "firefox_build": firefox_build_info(settings.firefox_path),
        "wireshark_version": tool_version(settings.dumpcap_path),
        "tools": {"dumpcap": settings.dumpcap_path, "tshark": settings.tshark_path,
                  "wireshark": settings.wireshark_path, "firefox": settings.firefox_path},
        "timezone": tz,
        "time_sync": time_sync_status(),
        "global_sslkeylogfile": "; ".join(f"{k}={v}" for k, v in glob.items()) or None,
        "global_sslkeylogfile_detail": glob,
    }
