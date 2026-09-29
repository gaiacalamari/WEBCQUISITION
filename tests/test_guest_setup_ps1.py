"""Esecuzione reale di guest-setup.ps1 (PowerShell 7) con cmdlet Windows simulati.

Verifica la logica dello script: controlli dei prerequisiti, configurazione di rete,
installazione dell'agent, gestione degli errori, pulizia dei file sensibili.
Saltato se PowerShell non è disponibile (su Windows si usano i cmdlet reali, non simulabili qui).
"""

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from webcquisition.bundle import asset_text

PWSH = os.environ.get("WEBCQ_PWSH") or shutil.which("pwsh") or ("/tmp/pwsh/pwsh" if Path("/tmp/pwsh/pwsh").exists() else None)
pytestmark = pytest.mark.skipif(PWSH is None or os.name == "nt", reason="PowerShell 7 su Linux/macOS non disponibile")
HARNESS = Path(__file__).with_name("ps1_harness.ps1")

INSTALL_STUB = r'''
param($AgentJson, $OperatorUser, $HostIp, $PythonW, $InstallDir)
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
@{ agent_json = $AgentJson; operator = $OperatorUser; host_ip = $HostIp; pythonw = $PythonW } | ConvertTo-Json | Set-Content (Join-Path $InstallDir 'install-args.json')
Copy-Item $AgentJson (Join-Path $env:WEBCQ_TEST_PROGRAMDATA 'agent.json')
Copy-Item (Join-Path $PSScriptRoot 'run_agent.pyw') (Join-Path $InstallDir 'run_agent.pyw')
'abc  lib/x.py' | Set-Content (Join-Path $InstallDir 'BUNDLE-SHA256SUMS.txt')
'''
FAKE_AGENT_CHECK = r'''
import json, sys
assert "--check" in sys.argv
print(json.dumps({"tools_present": {"dumpcap": True}, "sysinfo": {"global_sslkeylogfile": None, "windows": {}},
                  "interfaces": {"interfaces": [
                      {"name": "\\Device\\NPF_{1}", "friendly_name": "WEBCQ-Acquisizione", "is_control": False},
                      {"name": "\\Device\\NPF_{2}", "friendly_name": "WEBCQ-Controllo", "is_control": True}]}}))
'''


@pytest.fixture
def env(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    tools = tmp_path / "tools"
    tools.mkdir()
    dumpcap = tools / "dumpcap.exe"
    dumpcap.write_text("#!/bin/sh\necho 'Dumpcap (Wireshark) 4.4.2'\n")
    dumpcap.chmod(0o755)
    (tools / "Wireshark.exe").write_text("")
    ff = tmp_path / "firefox"
    ff.mkdir()
    (ff / "firefox.exe").write_text("")
    (ff / "application.ini").write_text("[App]\nVersion=128.5.0esr\n")
    pybin = tmp_path / "pybin"
    pybin.mkdir()
    for n in ("pythonw.exe", "python.exe"):
        (pybin / n).symlink_to(sys.executable)
    progdata = tmp_path / "programdata"
    progdata.mkdir()
    return {"tmp": tmp_path, "work": work, "dumpcap": dumpcap, "wireshark": tools / "Wireshark.exe",
            "firefox": ff / "firefox.exe", "pybin": pybin, "progdata": progdata}


def run(env, admin=True, params=None, agent=None, adapters=None, bundle=True, npcap_admin_only=False, locked=""):
    w = env["work"]
    p = {"operator_user": "forensic", "host_ip": "192.168.150.1", "control_ip": "192.168.150.10", "prefix_length": 24,
         "control_mac": "00:0c:29:aa:bb:02", "capture_mac": "00:0c:29:aa:bb:01", "control_nic_name": "WEBCQ-Controllo",
         "capture_nic_name": "WEBCQ-Acquisizione", "autologon": False, "disable_windows_update": False,
         "run_id": "run-123", "install_dir": str(env["tmp"] / "install"), "agent_config_path": str(env["progdata"] / "agent.json")}
    p.update(params or {})
    (w / "setup-params.json").write_text(json.dumps(p))
    a = {"listen_host": "192.168.150.10", "token": "t" * 48, "agent_id": "vm-1", "dumpcap_path": str(env["dumpcap"]),
         "wireshark_path": str(env["wireshark"]), "firefox_path": str(env["firefox"])}
    a.update(agent or {})
    (w / "agent.json").write_text(json.dumps(a))
    if bundle:
        with zipfile.ZipFile(w / "agent-bundle.zip", "w") as z:
            z.writestr("install-agent.ps1", INSTALL_STUB)
            z.writestr("run_agent.pyw", FAKE_AGENT_CHECK)
    (w / "guest-setup.ps1").write_text(asset_text("guest-setup.ps1"))
    if p.get("autologon"):
        (w / "operator.pw").write_text("PwOperatore!\n")
    adapters = adapters if adapters is not None else [
        {"Name": "Ethernet0", "MacAddress": "00-0C-29-AA-BB-01", "ifIndex": 4},
        {"Name": "Ethernet1", "MacAddress": "00-0C-29-AA-BB-02", "ifIndex": 7}]
    calls_out = env["tmp"] / f"calls-{os.urandom(3).hex()}.json"
    e = {**os.environ, "PATH": f"{env['pybin']}{os.pathsep}{os.environ['PATH']}", "WEBCQ_TEST_ADMIN": "1" if admin else "0",
         "WEBCQ_TEST_PROGRAMDATA": str(env["progdata"]), "WEBCQ_TEST_NPCAP_ADMINONLY": "1" if npcap_admin_only else "0",
         "WEBCQ_TEST_LOCKED": locked}
    proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(HARNESS), "-Script", str(w / "guest-setup.ps1"),
                           "-WorkDir", str(w), "-CallsOut", str(calls_out), "-AdaptersJson", json.dumps(adapters)],
                          capture_output=True, text=True, env=e, timeout=180)
    result = json.loads((w / "setup-result.json").read_text(encoding="utf-8-sig"))
    calls = json.loads(calls_out.read_text(encoding="utf-8-sig") or "[]") if calls_out.exists() else []
    if isinstance(calls, dict):
        calls = [calls]
    return proc, result, calls


def test_success(env):
    proc, result, calls = run(env)
    assert result["ok"] and result["code"] == "OK", (result, proc.stderr)
    assert proc.returncode == 0
    names = [s["name"] for s in result["steps"]]
    assert names == ["elevation", "operator_user", "python", "tools", "network", "sslkeylogfile", "agent"]
    assert result["checks"]["tools"]["firefox"] == "128.5.0esr"
    assert "4.4.2" in result["checks"]["tools"]["dumpcap"]
    ip = next(c for c in calls if c["cmd"] == "New-NetIPAddress")["data"]
    assert ip == {"idx": 7, "ip": "192.168.150.10", "prefix": 24}  # sulla scheda host-only (MAC ...:02)
    renames = {c["data"]["from"]: c["data"]["to"] for c in calls if c["cmd"] == "Rename-NetAdapter"}
    assert renames == {"Ethernet1": "WEBCQ-Controllo", "Ethernet0": "WEBCQ-Acquisizione"}
    assert any(c["cmd"] == "Set-NetIPInterface" and c["data"]["dhcp"] == "Disabled" for c in calls)
    inst = json.loads((env["tmp"] / "install" / "install-args.json").read_text(encoding="utf-8-sig"))
    assert inst["operator"] == "forensic" and inst["host_ip"] == "192.168.150.1" and inst["pythonw"].endswith("pythonw.exe")
    for f in ("agent.json", "agent-bundle.zip", "setup-params.json", "operator.pw"):
        assert not (env["work"] / f).exists(), f
    assert not (env["work"] / "bundle").exists()
    raw = (env["work"] / "setup-result.json").read_text(encoding="utf-8-sig")
    assert "PSProvider" not in raw and "PSPath" not in raw
    assert result["checks"]["agent"]["bundle_sha256sums"].startswith("abc")


def test_not_elevated_keeps_files_for_manual_run(env):
    proc, result, _ = run(env, admin=False)
    assert result["code"] == "NOT_ELEVATED" and proc.returncode == 1
    assert "amministratore" in result["message"]
    assert (env["work"] / "agent.json").exists() and (env["work"] / "setup-params.json").exists()


def test_firefox_missing(env):
    _, result, _ = run(env, agent={"firefox_path": str(env["tmp"] / "nope" / "firefox.exe")})
    assert result["code"] == "FIREFOX_NOT_FOUND" and not (env["work"] / "agent.json").exists()


def test_firefox_store_rejected(env):
    store = env["tmp"] / "WindowsApps" / "firefox.exe"
    store.parent.mkdir()
    store.write_text("")
    _, result, _ = run(env, agent={"firefox_path": str(store)})
    assert result["code"] == "FIREFOX_STORE"


def test_dumpcap_missing(env):
    _, result, _ = run(env, agent={"dumpcap_path": str(env["tmp"] / "x.exe")})
    assert result["code"] == "WIRESHARK_NOT_FOUND"


def test_unknown_operator(env):
    _, result, _ = run(env, params={"operator_user": "nessuno"})
    assert result["code"] == "OPERATOR_NOT_FOUND"


def test_control_nic_not_found(env):
    _, result, _ = run(env, adapters=[{"Name": "Ethernet0", "MacAddress": "00-0C-29-AA-BB-01", "ifIndex": 4}])
    assert result["code"] == "CONTROL_NIC_NOT_FOUND"


def test_autologon(env):
    _, result, calls = run(env, params={"autologon": True})
    assert result["ok"], result
    props = {c["data"]["name"]: c["data"]["value"] for c in calls if c["cmd"] == "Set-ItemProperty"}
    assert props["AutoAdminLogon"] == "1" and props["DefaultUserName"] == "forensic"
    assert props["DefaultPassword"] == "PwOperatore!"
    assert any("in chiaro" in w for w in result["warnings"])
    assert not (env["work"] / "operator.pw").exists()


def test_npcap_admin_only_rejected(env):
    _, result, _ = run(env, npcap_admin_only=True)
    assert result["code"] == "NPCAP_ADMIN_ONLY"


def test_progress_log_and_run_id(env):
    _, result, _ = run(env)
    assert result["run_id"] == "run-123"
    log = (env["work"] / "setup-progress.log").read_text(encoding="utf-8-sig")
    for text in ("avvio dello script", "ricerca di Python", "ok: agent", "script terminato"):
        assert text in log, text


def test_locked_files_do_not_prevent_result(env):
    """Un file non cancellabile (antivirus) non deve impedire la scrittura del risultato."""
    proc, result, _ = run(env, locked="bundle;agent.json")
    assert result["ok"] and result["code"] == "OK", (result, proc.stderr)
    assert any("DATI SENSIBILI" in w for w in result["warnings"])
    assert any(p.endswith("agent.json") for p in result["leftover_sensitive"])
    assert not (env["work"] / "setup-params.json").exists()  # gli altri file sono stati cancellati
    assert "script terminato" in (env["work"] / "setup-progress.log").read_text(encoding="utf-8-sig")


def test_result_serialization_is_plain(env, tmp_path):
    """Regressione: in Windows PowerShell 5.1 le stringhe da Get-Content portano PSDrive/PSProvider e
    ConvertTo-Json -Depth 10 si blocca. ConvertTo-WebcqPlain deve eliminare ogni oggetto complesso."""
    import re
    script = asset_text("guest-setup.ps1")
    fn = re.search(r"function ConvertTo-WebcqPlain.*?\n}\n", script, re.S).group(0)
    probe = tmp_path / "probe.ps1"
    (tmp_path / "sums.txt").write_text("abc  lib/x.py\n")
    probe.write_text(fn + r'''
$s = Get-Content -Raw -Path (Join-Path $PSScriptRoot 'sums.txt')
$s = $s | Add-Member -NotePropertyName Extra -NotePropertyValue (Get-PSDrive -PSProvider FileSystem | Select-Object -First 1) -PassThru
$obj = [ordered]@{ sums = $s; drive = (Get-PSDrive -PSProvider FileSystem | Select-Object -First 1); n = 3; ok = $true
                   list = @('a', 1); nested = [pscustomobject]@{ x = @([pscustomobject]@{ y = 'z' }) }; empty = @() }
$plain = ConvertTo-WebcqPlain $obj
if ($null -ne $plain.sums.PSObject.Properties['Extra']) { throw 'proprietà nascoste non rimosse' }
if ($null -ne $plain.sums.PSObject.Properties['PSPath']) { throw 'PSPath non rimosso' }
if ($plain.drive -isnot [string]) { throw 'oggetto .NET non convertito in testo' }
ConvertTo-Json -InputObject $plain -Depth 12 -Compress
''', encoding="utf-8")
    proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(probe)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["n"] == 3 and data["ok"] is True and data["list"] == ["a", 1]
    assert data["nested"] == {"x": [{"y": "z"}]} and data["empty"] == []
    assert isinstance(data["drive"], str) and "PSProvider" not in proc.stdout
