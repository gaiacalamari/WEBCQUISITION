"""Simulatore di ``vmrun`` con stato, per testare il provider VMware reale senza VMware."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from webcquisition.providers.base import CommandResult
from webcquisition.providers.vmware import parse_vmx, read_vmx_text, set_vmx_values

VMX_TEMPLATE = """.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "21"
displayName = "Forensic Windows"
guestOS = "windows11-64"
uuid.bios = "56 4d 3c 5e 2a 1b 9f 07-8c 44 a1 b2 c3 d4 e5 f6"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000e"
ethernet0.addressType = "generated"
ethernet1.present = "TRUE"
ethernet1.connectionType = "hostonly"
ethernet1.virtualDev = "e1000e"
ethernet1.addressType = "generated"
"""

WIN_DHCP_CONF = """# Configuration file for ISC 2.0 vmnetdhcp operating on NT.
allow unknown-clients;
default-lease-time 1800;
# Virtual ethernet segment 1
subnet 192.168.150.0 netmask 255.255.255.0 {
range 192.168.150.128 192.168.150.254;
option broadcast-address 192.168.150.255;
}
host VMnet1 {
    hardware ethernet 00:50:56:C0:00:01;
    fixed-address 192.168.150.1;
    option domain-name-servers 0.0.0.0;
}
# Virtual ethernet segment 8
subnet 192.168.44.0 netmask 255.255.255.0 {
range 192.168.44.128 192.168.44.254;
option routers 192.168.44.2;
}
host VMnet8 {
    hardware ethernet 00:50:56:C0:00:08;
    fixed-address 192.168.44.1;
}
"""


class FakeVmrun:
    """Implementa i comandi vmrun usati da WEBCQUISITION su una VM finta."""

    def __init__(self, root: Path, vmx_text: str = VMX_TEMPLATE, snapshots=None, guest_mode: str = "ok"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.vmx = self.root / "Forensic Windows" / "Forensic Windows.vmx"
        self.vmx.parent.mkdir(exist_ok=True)
        self.vmx.write_text(vmx_text, encoding="utf-8")
        self.guestfs = self.root / "guestfs"
        self.guestfs.mkdir(exist_ok=True)
        self.running = False
        self.tools = "notInstalled"
        self.snapshots = list(snapshots or [])
        self.guest_mode = guest_mode  # ok | not_elevated | fail | no_tools
        self.calls: list[list[str]] = []
        self.guest_runs = 0
        self.agent_id: str | None = None
        self.passwords_seen: set[str] = set()
        self.stop_soft_works = True
        self.manual_run_after_fetches: int | None = None
        self.boots = 0
        self.deleted: list[str] = []
        self.start_hangs = False  # vmrun start non risponde (finestra di dialogo di Workstation)
        self.start_hangs_vm_off = False
        self._fetches = 0

    # --------------------------------------------------------------- helpers
    def _gpath(self, p: str) -> Path:
        return self.guestfs / p.replace("\\", "/").replace(":", "")

    def _ok(self, out: str = "") -> CommandResult:
        return CommandResult(0, out, "")

    def _err(self, msg: str, rc: int = 255) -> CommandResult:
        return CommandResult(rc, f"Error: {msg}", "")

    def _assign_macs(self):
        text = read_vmx_text(self.vmx)
        kv = parse_vmx(text)
        upd = {}
        for i, mac in ((0, "00:0c:29:aa:bb:01"), (1, "00:0c:29:aa:bb:02")):
            if kv.get(f"ethernet{i}.present", "").upper() == "TRUE" and not kv.get(f"ethernet{i}.generatedaddress"):
                upd[f"ethernet{i}.generatedAddress"] = mac
        if upd:
            self.vmx.write_text(set_vmx_values(text, upd), encoding="utf-8")

    def _simulate_guest_setup(self):
        work = self._gpath(r"C:\Windows\Temp\webcq-setup")
        self.guest_runs += 1
        result = {"ok": False, "code": None, "message": None, "started_at_utc": f"2026-01-01T00:00:{self.guest_runs:02d}Z",
                  "finished_at_utc": f"2026-01-01T00:01:{self.guest_runs:02d}Z", "steps": [], "warnings": [],
                  "checks": {}}
        params_path = work / "setup-params.json"
        if params_path.exists():
            result["run_id"] = json.loads(params_path.read_text(encoding="utf-8")).get("run_id")
        with open(work / "setup-progress.log", "a", encoding="utf-8") as fh:
            fh.write(f"00:00:{self.guest_runs:02d} avvio dello script di preparazione\n")
        if self.guest_mode == "not_elevated" and self.guest_runs == 1:
            result.update(code="NOT_ELEVATED", message="non elevato")
            (work / "setup-result.json").write_text(json.dumps(result), encoding="utf-8-sig")
            return 1
        if self.guest_mode == "fail":
            result.update(code="PYTHON_NOT_FOUND", message="Python non trovato")
        else:
            params = json.loads((work / "setup-params.json").read_text(encoding="utf-8"))
            agent = json.loads((work / "agent.json").read_text(encoding="utf-8"))
            assert (work / "agent-bundle.zip").is_file() and (work / "guest-setup.ps1").is_file()
            assert params["control_mac"] == "00:0c:29:aa:bb:02" and params["capture_mac"] == "00:0c:29:aa:bb:01"
            self.agent_id = agent["agent_id"]
            self.params = params
            result.update(ok=True, code="OK", steps=[{"name": n, "ok": True} for n in
                                                     ("elevation", "python", "tools", "network", "agent")],
                          warnings=["esempio di avviso dal guest"])
        for f in ("agent.json", "operator.pw", "agent-bundle.zip", "setup-params.json"):
            (work / f).unlink(missing_ok=True)
        (work / "setup-result.json").write_text(json.dumps(result), encoding="utf-8-sig")
        return 0 if result["ok"] else 1

    # --------------------------------------------------------------- runner
    def run(self, args, timeout=120):
        self.calls.append(list(args))
        if len(args) == 1:
            return CommandResult(255, "vmrun version 1.17.0 build-24995812\n\nUsage: vmrun [AUTHENTICATION-FLAGS] ...", "")
        a = list(args[1:])
        assert a[0] == "-T"
        a = a[2:]
        auth = None
        if a and a[0] == "-gu":
            auth = (a[1], a[3])
            self.passwords_seen.add(a[3])
            a = a[4:]
        cmd, rest = a[0], a[1:]
        vmx_ok = not rest or Path(rest[0]).resolve() == self.vmx.resolve() or cmd == "list"
        if not vmx_ok:
            return self._err("The virtual machine cannot be found")
        if cmd == "list":
            return self._ok(f"Total running VMs: {int(self.running)}\n" + (f"{self.vmx}\n" if self.running else ""))
        if cmd == "listSnapshots":
            return self._ok(f"Total snapshots: {len(self.snapshots)}\n" + "".join(s + "\n" for s in self.snapshots))
        if cmd == "checkToolsState":
            return self._ok(self.tools + "\n")
        if cmd == "start":
            if self.running:
                return self._err("The virtual machine is already running")
            if self.start_hangs_vm_off:
                from webcquisition.providers import ProviderError
                raise ProviderError("timeout eseguendo vmrun -T")
            text = read_vmx_text(self.vmx)
            if parse_vmx(text).get("checkpoint.vmstate"):  # ripresa da sospensione: memoria intatta
                self.vmx.write_text(set_vmx_values(text, {"checkpoint.vmState": None}), encoding="utf-8")
            else:
                self.boots += 1
            self.running = True
            self.tools = "installed" if self.guest_mode == "no_tools" else "running"
            self._assign_macs()
            if self.start_hangs:
                from webcquisition.providers import ProviderError
                raise ProviderError("timeout eseguendo vmrun -T")
            return self._ok()
        if cmd == "stop":
            if not self.running:
                return self._err("The virtual machine is not powered on")
            if rest[1] == "soft" and not self.stop_soft_works:
                return self._err("The VMware Tools are not running")
            self.running, self.tools = False, "unknown"
            return self._ok()
        if cmd == "reset":
            return self._ok()
        if cmd == "snapshot":
            self.snapshots.append(rest[1])
            return self._ok()
        if cmd == "revertToSnapshot":
            if rest[1] not in self.snapshots:
                return self._err("Invalid snapshot name")
            return self._ok()
        # guest operations
        if auth is None:
            return self._err("Invalid user name or password for the guest OS")
        if self.tools != "running":
            return self._err("The VMware Tools are not running in the virtual machine")
        if cmd == "directoryExistsInGuest":
            return self._ok("The directory exists." if self._gpath(rest[1]).is_dir() else "The directory does not exist.")
        if cmd == "deleteFileInGuest":
            self.deleted.append(rest[1])
            self._gpath(rest[1]).unlink(missing_ok=True)
            return self._ok()
        if cmd == "createDirectoryInGuest":
            self._gpath(rest[1]).mkdir(parents=True, exist_ok=True)
            return self._ok()
        if cmd == "copyFileFromHostToGuest":
            dst = self._gpath(rest[2])
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(rest[1], dst)
            return self._ok()
        if cmd == "copyFileFromGuestToHost":
            self._fetches += 1
            if (self.manual_run_after_fetches is not None and self._fetches == self.manual_run_after_fetches):
                self.guest_mode = "ok"
                self._simulate_guest_setup()  # l'operatore ha eseguito lo script a mano
            src = self._gpath(rest[1])
            if not src.is_file():
                return self._err("A file was not found")
            shutil.copy2(src, rest[2])
            return self._ok()
        if cmd == "runProgramInGuest":
            assert "guest-setup.ps1" in " ".join(rest)
            self.no_wait = "-noWait" in rest
            rc = self._simulate_guest_setup()
            return CommandResult(rc, "" if rc == 0 else f"Guest program exited with non-zero exit code: {rc}", "")
        return self._err(f"comando non simulato: {cmd}")


class FakeAgentClient:
    """Client dell'agent per la verifica finale del setup."""

    def __init__(self, vmrun: FakeVmrun, interactive_after: int = 0):
        self.vmrun = vmrun
        self.calls = 0
        self.interactive_after = interactive_after

    def health(self):
        from webcquisition.guest_client import AgentUnreachable
        from webcquisition_common import PROTOCOL_VERSION
        from webcquisition_common.timeutil import iso_utc
        self.calls += 1
        if not self.vmrun.running:
            raise AgentUnreachable("VM spenta")
        return {"agent_id": self.vmrun.agent_id, "agent_version": "0.2.0", "protocol": PROTOCOL_VERSION,
                "utc": iso_utc(), "interactive_session": self.calls > self.interactive_after, "session_active": False}

    def interfaces(self):
        return {"interfaces": [
            {"name": r"\Device\NPF_{1}", "friendly_name": "WEBCQ-Acquisizione", "ipv4": ["192.168.44.130"],
             "has_default_gateway": True, "is_control": False},
            {"name": r"\Device\NPF_{2}", "friendly_name": "WEBCQ-Controllo", "ipv4": ["192.168.150.10"],
             "has_default_gateway": False, "is_control": True},
        ]}


def power_off_hard(fake: FakeVmrun):
    """Come 'Power Off' in Workstation o chiusura brusca della finestra."""
    fake.running, fake.tools = False, "unknown"


def suspend(fake: FakeVmrun):
    fake.running, fake.tools = False, "unknown"
    fake.vmx.write_text(set_vmx_values(read_vmx_text(fake.vmx), {"checkpoint.vmState": "win11.vmss"}),
                        encoding="utf-8")
