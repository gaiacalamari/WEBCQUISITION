"""Rilevamento dei file prodotti dall'operatore nella cartella del caso.

L'operatore può salvare file (screenshot nativi, download, note) nella radice della
cartella del caso o in ``operator/``. Ogni nuovo file viene registrato con SHA-256
alla prima rilevazione (OPERATOR_FILE_DETECTED); modifiche successive producono
OPERATOR_FILE_MODIFIED con il nuovo hash. Il polling (non ReadDirectoryChangesW)
è una scelta di semplicità e portabilità; l'hash definitivo è comunque quello del
manifest al sigillo.
"""

from __future__ import annotations

import threading
from pathlib import Path

from webcquisition_common.events import EventLog, EventType
from webcquisition_common.hashing import sha256_file

AGENT_ROOT_FILES = {"README.txt"}


class OperatorFileWatcher:
    def __init__(self, case_dir: Path, events: EventLog, interval: float = 2.0):
        self.case_dir = Path(case_dir)
        self.events = events
        self.interval = interval
        self._seen: dict[str, tuple[int, int, str]] = {}
        self._pending: dict[str, tuple[int, int]] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _candidates(self):
        for p in self.case_dir.iterdir():
            if p.is_file() and p.name not in AGENT_ROOT_FILES:
                yield p.name, p
        op = self.case_dir / "operator"
        if op.is_dir():
            for p in op.rglob("*"):
                if p.is_file():
                    yield p.relative_to(self.case_dir).as_posix(), p

    def scan(self, final: bool = False) -> None:
        with self._lock:
            for rel, p in self._candidates():
                try:
                    st = p.stat()
                except OSError:
                    continue
                sig = (st.st_size, st.st_mtime_ns)
                prev = self._seen.get(rel)
                if prev and prev[:2] == sig:
                    continue
                # attende che il file sia stabile per due scansioni (scrittura completata)
                if not final and self._pending.get(rel) != sig:
                    self._pending[rel] = sig
                    continue
                self._pending.pop(rel, None)
                try:
                    digest, size = sha256_file(p)
                except OSError:
                    continue
                self._seen[rel] = (sig[0], sig[1], digest)
                ev = EventType.OPERATOR_FILE_MODIFIED if prev else EventType.OPERATOR_FILE_DETECTED
                self.events.emit(ev, component="watcher", data={"path": rel, "size": size, "sha256": digest})

    def count(self) -> int:
        return len(self._seen)

    def start(self) -> dict:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="watcher")
        self._thread.start()
        return {"enabled": True, "interval_s": self.interval}

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self.scan()
            except Exception:  # noqa: BLE001 - il watcher non deve interrompere la sessione
                pass

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(self.interval + 5)
        self.scan(final=True)
