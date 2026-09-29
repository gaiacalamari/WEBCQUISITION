"""Provider fittizio per test e ``--dry-run``. Nessuna VM reale viene toccata.

Lo stato può essere persistito su file JSON, così che comandi CLI separati
(start / status / stop) in dry-run vedano la stessa "VM".
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import HypervisorProvider, NicInfo, ProviderError, VMInfo, VMState


class FakeProvider(HypervisorProvider):
    name = "fake"
    stable = True

    def __init__(
        self,
        vm_name: str = "fake-vm",
        uuid: str = "00000000-0000-0000-0000-00000000f00d",
        nics: list[dict] | None = None,
        snapshots: list[str] | None = None,
        state: VMState = VMState.POWERED_OFF,
        failures: set[str] | None = None,
        state_file: Path | None = None,
    ):
        super().__init__()
        self.vm_name = vm_name
        self.uuid = uuid
        self.nics = nics if nics is not None else [
            {"index": 1, "attachment": "nat"},
            {"index": 2, "attachment": "hostonly", "network": "vmnet1"},
        ]
        self.snapshots = list(snapshots if snapshots is not None else ["clean"])
        self.failures = set(failures or ())
        self.calls: list[tuple] = []
        self.state_file = Path(state_file) if state_file else None
        self.state = state
        if self.state_file and self.state_file.exists():
            saved = json.loads(self.state_file.read_text())
            self.state = VMState(saved["state"])
            self.snapshots = saved.get("snapshots", self.snapshots)

    def _persist(self) -> None:
        if self.state_file:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps({"state": self.state.value, "snapshots": self.snapshots}))

    def _check_vm(self, vm: str) -> None:
        if vm != self.vm_name:
            raise ProviderError(f"VM non trovata: {vm}")

    def is_available(self) -> bool:
        return "unavailable" not in self.failures

    def version(self) -> str:
        return "fake-1.0"

    def get_info(self, vm: str) -> VMInfo:
        self._check_vm(vm)
        return VMInfo(
            name=vm,
            uuid=self.uuid,
            state=self.state,
            nics=[NicInfo(**n) for n in self.nics],
            snapshots=list(self.snapshots),
        )

    def restore_snapshot(self, vm: str, snapshot: str) -> None:
        self._check_vm(vm)
        self.calls.append(("restore_snapshot", snapshot))
        if snapshot not in self.snapshots:
            raise ProviderError(f"snapshot non trovato: {snapshot}")

    def take_snapshot(self, vm: str, name: str, description: str = "") -> None:
        self._check_vm(vm)
        self.calls.append(("take_snapshot", name))
        self.snapshots.append(name)
        self._persist()

    def start(self, vm: str, gui: bool = True) -> None:
        self._check_vm(vm)
        self.calls.append(("start", gui))
        if "start_fails" in self.failures:
            raise ProviderError("avvio VM fallito (simulato)")
        self.state = VMState.RUNNING
        self._persist()

    def request_shutdown(self, vm: str) -> None:
        self._check_vm(vm)
        self.calls.append(("request_shutdown",))
        if "shutdown_hangs" not in self.failures:
            self.state = VMState.POWERED_OFF
            self._persist()

    def force_poweroff(self, vm: str) -> None:
        self._check_vm(vm)
        self.calls.append(("force_poweroff",))
        self.state = VMState.POWERED_OFF
        self._persist()

    def crash(self) -> None:
        """Simula un crash della VM (usato nei test)."""
        self.state = VMState.ABORTED
        self._persist()
