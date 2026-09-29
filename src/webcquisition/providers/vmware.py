"""Provider VMware Workstation Pro (e Fusion) basato su ``vmrun``.

Convenzioni:
  * ``vm`` è il percorso del file ``.vmx``;
  * identità = ``uuid.bios`` del .vmx, normalizzato (32 cifre esadecimali);
  * schede di rete lette dal .vmx: ``ethernet0`` è la NIC **1** di WEBCQUISITION,
    ``ethernet1`` la NIC **2**, ecc. Tipo = ``connectionType`` (``nat``, ``hostonly``,
    ``bridged``; per ``custom`` il tipo diventa ``custom:<vmnetN>``);
  * stato: acceso se compare in ``vmrun list``; sospeso se il .vmx riferisce un file
    ``.vmss`` (``checkpoint.vmState``); altrimenti spento.

Le *guest operations* (copia file, esecuzione di programmi) richiedono VMware Tools
attivi e credenziali di un account del guest: sono usate SOLO dalla preparazione
automatica della VM (``webcquisition vmware-setup``), mai durante un'acquisizione.

VMware Workstation Player non è supportato: ``vmrun`` con Player non gestisce gli
snapshot, indispensabili per ripartire ogni volta da uno stato pulito.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Callable

from .base import HypervisorProvider, NicInfo, ProviderError, VMInfo, VMState, normalize_uuid

DEFAULT_PATHS = {
    "win32": [r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
              r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"],
    "darwin": ["/Applications/VMware Fusion.app/Contents/Library/vmrun"],
    "linux": ["/usr/bin/vmrun", "/usr/local/bin/vmrun"],
}
HOST_TYPES = ("ws", "fusion")
TOOLS_STATES = ("running", "installed", "notinstalled", "unknown")
_VMX_LINE = re.compile(r'^\s*([A-Za-z0-9_.:\-]+)\s*=\s*"(.*)"\s*$')


def read_vmx_text(path: Path) -> str:
    raw = Path(path).read_bytes()
    m = re.search(rb'^\s*\.encoding\s*=\s*"([^"]+)"', raw, re.MULTILINE | re.IGNORECASE)
    for enc in ([m.group(1).decode("ascii", "ignore")] if m else []) + ["utf-8", "cp1252"]:
        try:
            return raw.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def parse_vmx(text: str) -> dict[str, str]:
    kv = {}
    for line in text.splitlines():
        m = _VMX_LINE.match(line)
        if m:
            kv[m.group(1).lower()] = m.group(2)
    return kv


def set_vmx_values(text: str, updates: dict[str, str | None]) -> str:
    """Aggiorna/aggiunge/rimuove (valore None) chiavi del .vmx preservando le altre righe."""
    pending = {k.lower(): (k, v) for k, v in updates.items()}
    out = []
    for line in text.splitlines():
        m = _VMX_LINE.match(line)
        if m and m.group(1).lower() in pending:
            _key, value = pending.pop(m.group(1).lower())
            if value is not None:
                out.append(f'{m.group(1)} = "{value}"')
            continue
        out.append(line)
    for key, value in pending.values():
        if value is not None:
            out.append(f'{key} = "{value}"')
    return "\n".join(out) + "\n"


def vmx_nics(kv: dict) -> list[NicInfo]:
    nics = []
    for i in range(0, 10):
        if kv.get(f"ethernet{i}.present", "FALSE").upper() != "TRUE":
            continue
        ctype = kv.get(f"ethernet{i}.connectiontype", "bridged").lower()
        vnet = kv.get(f"ethernet{i}.vnet")
        if ctype == "custom":
            ctype = f"custom:{(vnet or '?').lower()}"
        mac = kv.get(f"ethernet{i}.generatedaddress") or kv.get(f"ethernet{i}.address")
        nics.append(NicInfo(index=i + 1, attachment=ctype, network=vnet, mac=mac.lower() if mac else None,
                            connected=kv.get(f"ethernet{i}.startconnected", "TRUE").upper() == "TRUE"))
    return nics


def parse_count_list(text: str, header: str) -> list[str]:
    """Output di ``vmrun list`` / ``listSnapshots``: riga 'Total ...: N' seguita dagli elementi."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines and lines[0].lower().startswith(header.lower()):
        lines = lines[1:]
    return lines


def default_vmrun() -> str:
    found = shutil.which("vmrun")
    if found:
        return found
    for p in DEFAULT_PATHS.get(sys.platform if sys.platform in DEFAULT_PATHS else "linux", []):
        if os.path.exists(p):
            return p
    return "vmrun"


class GuestAuth:
    """Credenziali del guest per le guest operations (mai registrate nei log)."""

    def __init__(self, user: str, password: str):
        self.user, self._password = user, password

    def flags(self) -> list[str]:
        return ["-gu", self.user, "-gp", self._password]

    def __repr__(self) -> str:
        return f"GuestAuth(user={self.user!r}, password=***)"


class VMwareProvider(HypervisorProvider):
    name = "vmware"
    stable = False  # diventa True dopo la validazione documentata su hardware reale (docs/TESTING.md)

    def __init__(self, runner=None, executable=None, host_type: str = "ws"):
        super().__init__(runner, executable)
        if host_type not in HOST_TYPES:
            raise ProviderError(f"vmrun host type non supportato: {host_type} (ammessi: {HOST_TYPES}; "
                                "VMware Player non è supportato perché non gestisce gli snapshot)")
        self.host_type = host_type
        self.executable = self.executable or default_vmrun()
        self.last_start_warning: str | None = None

    # ------------------------------------------------------------ vmrun
    def _vmrun(self, *args: str, auth: GuestAuth | None = None, timeout: float = 300, check: bool = True):
        cmd = [self.executable, "-T", self.host_type, *(auth.flags() if auth else []), *args]
        r = self.runner.run(cmd, timeout=timeout)
        out = (r.stdout + r.stderr).strip()
        if check and (r.returncode != 0 or out.startswith("Error")):
            raise ProviderError(f"vmrun {args[0]} fallito (rc={r.returncode}): {out[:500]}")
        return r

    def is_available(self) -> bool:
        try:
            r = self.runner.run([self.executable], timeout=30)
        except ProviderError:
            return False
        return "vmrun" in (r.stdout + r.stderr).lower()

    def version(self) -> str:
        r = self.runner.run([self.executable], timeout=30)
        m = re.search(r"vmrun version ([^\s]+)(?:\s+build-(\d+))?", r.stdout + r.stderr)
        if not m:
            return "unknown"
        return m.group(1) + (f" build-{m.group(2)}" if m.group(2) else "")

    @staticmethod
    def _vmx(vm: str) -> Path:
        vmx = Path(vm)
        if vmx.suffix.lower() != ".vmx":
            raise ProviderError(f"hypervisor.vm_name deve essere il percorso del file .vmx, non '{vm}'")
        if not vmx.is_file():
            raise ProviderError(f"file .vmx non trovato: {vm}")
        return vmx

    def running_vms(self) -> list[str]:
        return parse_count_list(self._vmrun("list", timeout=60).stdout, "Total running VMs")

    def _is_running(self, vmx: Path) -> bool:
        target = os.path.normcase(os.path.abspath(str(vmx)))
        return any(os.path.normcase(os.path.abspath(p)) == target for p in self.running_vms())

    def snapshots(self, vm: str) -> list[str]:
        r = self._vmrun("listSnapshots", str(self._vmx(vm)), timeout=120, check=False)
        if r.returncode != 0:
            raise ProviderError(f"vmrun listSnapshots fallito: {(r.stdout + r.stderr).strip()[:300]}")
        return parse_count_list(r.stdout, "Total snapshots")

    def get_info(self, vm: str) -> VMInfo:
        vmx = self._vmx(vm)
        kv = parse_vmx(read_vmx_text(vmx))
        if any(k.startswith("encryption.") for k in kv):
            raise ProviderError("la VM è cifrata: non supportata (vmrun richiederebbe la password a ogni comando)")
        if self._is_running(vmx):
            state = VMState.RUNNING
        elif kv.get("checkpoint.vmstate"):
            state = VMState.SAVED  # sospesa: va spenta, non ripresa
        else:
            state = VMState.POWERED_OFF
        return VMInfo(name=kv.get("displayname", vmx.stem), uuid=normalize_uuid(kv.get("uuid.bios")), state=state,
                      nics=vmx_nics(kv), snapshots=self.snapshots(vm),
                      raw={k: v for k, v in kv.items() if not k.startswith(("guestinfo.", "answer."))})

    def restore_snapshot(self, vm: str, snapshot: str) -> None:
        names = self.snapshots(vm)
        if names.count(snapshot) > 1:
            raise ProviderError(f"esistono {names.count(snapshot)} snapshot chiamati '{snapshot}': nome ambiguo")
        if snapshot not in names:
            raise ProviderError(f"snapshot '{snapshot}' non trovato; disponibili: {names}")
        self._vmrun("revertToSnapshot", str(self._vmx(vm)), snapshot, timeout=900)

    def take_snapshot(self, vm: str, name: str, description: str = "") -> None:
        if name in self.snapshots(vm):
            raise ProviderError(f"esiste già uno snapshot chiamato '{name}'")
        self._vmrun("snapshot", str(self._vmx(vm)), name, timeout=1800)  # vmrun non gestisce descrizioni

    #: oltre questo tempo ``vmrun start`` è considerato bloccato (tipicamente da una finestra di dialogo
    #: di Workstation o da privilegi diversi tra prompt e Workstation): se la VM risulta accesa si prosegue
    start_timeout_s: float = 120

    def start(self, vm: str, gui: bool = True) -> None:
        vmx = self._vmx(vm)
        try:
            self._vmrun("start", str(vmx), "gui" if gui else "nogui", timeout=self.start_timeout_s)
        except ProviderError as exc:
            try:
                running = self._is_running(vmx)
            except ProviderError:
                running = False
            if running:
                self.last_start_warning = f"vmrun start non ha risposto ({exc}) ma la VM risulta accesa"
                return
            raise ProviderError(
                f"{exc}. La VM non si è avviata: controllare in VMware Workstation eventuali finestre di dialogo "
                "(es. 'moved or copied' → 'I Moved It') e usare un prompt con gli stessi privilegi di Workstation "
                "(normalmente NON 'Esegui come amministratore')") from exc

    def request_shutdown(self, vm: str) -> None:
        self._vmrun("stop", str(self._vmx(vm)), "soft", timeout=300)

    def force_poweroff(self, vm: str) -> None:
        self._vmrun("stop", str(self._vmx(vm)), "hard", timeout=120)

    def reboot(self, vm: str) -> None:
        self._vmrun("reset", str(self._vmx(vm)), "soft", timeout=300)

    def tools_state(self, vm: str) -> str | None:
        try:
            r = self._vmrun("checkToolsState", str(self._vmx(vm)), timeout=60, check=False)
        except ProviderError:
            return None
        text = (r.stdout + r.stderr).strip().lower().replace(" ", "")
        return next((s for s in TOOLS_STATES if s in text), "unknown")

    def wait_tools_running(self, vm: str, timeout_s: float, *, poll_s: float = 3.0,
                           sleep: Callable[[float], None] = time.sleep,
                           monotonic: Callable[[], float] = time.monotonic) -> None:
        deadline = monotonic() + timeout_s
        last = None
        while True:
            last = self.tools_state(vm)
            if last == "running":
                return
            if monotonic() >= deadline:
                break
            sleep(poll_s)
        raise ProviderError(f"VMware Tools non attivi nel guest entro {timeout_s}s (stato: {last}). "
                            "Installare/aggiornare VMware Tools nella VM.")

    # ------------------------------------------------------------ guest operations (solo setup)
    def copy_to_guest(self, vm: str, auth: GuestAuth, src: Path, dst: str) -> None:
        self._vmrun("copyFileFromHostToGuest", str(self._vmx(vm)), str(src), dst, auth=auth, timeout=900)

    def copy_from_guest(self, vm: str, auth: GuestAuth, src: str, dst: Path) -> None:
        self._vmrun("copyFileFromGuestToHost", str(self._vmx(vm)), src, str(dst), auth=auth, timeout=900)

    def mkdir_in_guest(self, vm: str, auth: GuestAuth, path: str) -> None:
        r = self._vmrun("directoryExistsInGuest", str(self._vmx(vm)), path, auth=auth, check=False)
        text = (r.stdout + r.stderr).lower()
        if r.returncode != 0 or "does not exist" in text:
            self._vmrun("createDirectoryInGuest", str(self._vmx(vm)), path, auth=auth)

    def delete_in_guest(self, vm: str, auth: GuestAuth, path: str) -> None:
        """Cancella un file nel guest; nessun errore se non esiste."""
        self._vmrun("deleteFileInGuest", str(self._vmx(vm)), path, auth=auth, timeout=120, check=False)

    def run_in_guest(self, vm: str, auth: GuestAuth, program: str, args: list[str], timeout: float = 1800,
                     interactive: bool = False, no_wait: bool = False) -> int:
        """Esegue un programma nel guest e ne restituisce il codice di uscita (non solleva su rc != 0).

        Con ``no_wait`` ritorna subito dopo l'avvio (codice 0): l'esito va letto da file nel guest.
        """
        flags = (["-noWait"] if no_wait else []) + (["-activeWindow", "-interactive"] if interactive else [])
        r = self._vmrun("runProgramInGuest", str(self._vmx(vm)), *flags, program, *args, auth=auth,
                        timeout=timeout, check=False)
        text = (r.stdout + r.stderr).strip()
        if text.startswith("Error") and "exit code" not in text.lower():
            raise ProviderError(f"vmrun runProgramInGuest fallito: {text[:500]}")
        m = re.search(r"exit code:\s*(-?\d+)", text, re.IGNORECASE)
        return int(m.group(1)) if m else r.returncode
