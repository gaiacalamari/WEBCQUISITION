"""Astrazione hypervisor.

WEBCQUISITION supporta VMware Workstation Pro (provider ``vmware``, basato su
``vmrun``) e un provider simulato per test e ``--dry-run``. L'orchestratore conosce
SOLO questa interfaccia.
"""

from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Callable, Iterable


class ProviderError(RuntimeError):
    pass


class VMState(str, Enum):
    RUNNING = "running"
    POWERED_OFF = "poweroff"
    SAVED = "saved"
    PAUSED = "paused"
    ABORTED = "aborted"
    STARTING = "starting"
    STOPPING = "stopping"
    UNKNOWN = "unknown"


@dataclass
class NicInfo:
    index: int
    attachment: str
    network: str | None = None
    mac: str | None = None
    #: False se la scheda non è collegata all'accensione (VMware: ethernetN.startConnected)
    connected: bool | None = None


@dataclass
class VMInfo:
    name: str
    uuid: str
    state: VMState
    nics: list[NicInfo] = field(default_factory=list)
    snapshots: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        d.pop("raw", None)
        return d


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    """Esegue comandi esterni. Iniettabile nei test per simulare gli hypervisor.

    L'output viene scritto su file temporanei e NON su pipe: ``vmrun start ... gui`` avvia
    l'interfaccia di VMware Workstation, che eredita gli handle di output e li tiene aperti
    finché Workstation resta aperto. Con le pipe, Python (su Windows anche dopo il timeout)
    aspetterebbe la chiusura di quegli handle all'infinito. Con i file si attende solo la
    fine del processo lanciato.
    """

    def run(self, args: list[str], timeout: float | None = 120) -> CommandResult:
        import tempfile
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err, creationflags=flags)
            except FileNotFoundError as exc:
                raise ProviderError(f"eseguibile non trovato: {args[0]}") from exc
            try:
                rc = p.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                p.kill()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                raise ProviderError(f"timeout eseguendo {args[0]} {args[1] if len(args) > 1 else ''}") from exc
            return CommandResult(rc, self._read(out), self._read(err))

    @staticmethod
    def _read(fh) -> str:
        fh.seek(0)
        data = fh.read()
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            import locale
            return data.decode(locale.getpreferredencoding(False) or "cp1252", errors="replace")


class HypervisorProvider(ABC):
    name: str = "abstract"
    #: True se l'implementazione è testata su hardware reale (vedi docs/HYPERVISORS.md)
    stable: bool = False

    def __init__(self, runner: CommandRunner | None = None, executable: str | None = None):
        self.runner = runner or CommandRunner()
        self.executable = executable

    @abstractmethod
    def is_available(self) -> bool: ...

    def tools_state(self, vm: str) -> str | None:
        """Stato degli strumenti di integrazione nel guest (VMware Tools), se disponibile."""
        return None

    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def get_info(self, vm: str) -> VMInfo: ...

    @abstractmethod
    def restore_snapshot(self, vm: str, snapshot: str) -> None: ...

    @abstractmethod
    def take_snapshot(self, vm: str, name: str, description: str = "") -> None: ...

    @abstractmethod
    def start(self, vm: str, gui: bool = True) -> None: ...

    @abstractmethod
    def request_shutdown(self, vm: str) -> None:
        """Arresto controllato (ACPI / guest shutdown)."""

    @abstractmethod
    def force_poweroff(self, vm: str) -> None:
        """Spegnimento forzato: usare solo come ultima risorsa (registrato come warning)."""

    def wait_for_state(
        self,
        vm: str,
        states: Iterable[VMState],
        timeout_s: float,
        *,
        poll_s: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> VMState:
        wanted = set(states)
        deadline = monotonic() + timeout_s
        last = VMState.UNKNOWN
        while True:
            last = self.get_info(vm).state
            if last in wanted:
                return last
            if monotonic() >= deadline:
                raise ProviderError(
                    f"timeout ({timeout_s}s) in attesa degli stati {[s.value for s in wanted]}; stato attuale {last.value}"
                )
            sleep(poll_s)


def normalize_uuid(value: str | None) -> str:
    """UUID confrontabili: minuscole, senza spazi né trattini (VMware usa '56 4d ... -...')."""
    return "".join(ch for ch in (value or "").lower() if ch in "0123456789abcdef")
