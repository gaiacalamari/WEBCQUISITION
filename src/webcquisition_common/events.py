"""Modello degli eventi e log JSONL a catena di hash (tamper-evident).

Ogni riga è un oggetto JSON con i campi:

    schema_version, seq, timestamp, event, severity, case_id, source,
    component, message, data, prev_hash, hash

``hash`` = SHA-256 della serializzazione canonica (chiavi ordinate, separatori
compatti, UTF-8) di tutti gli altri campi. ``prev_hash`` è l'hash dell'evento
precedente (64 zeri per il primo). Qualsiasi modifica, cancellazione o
riordino di righe viene rilevato da :func:`verify_chain`.

NOTA: la catena rende le manomissioni *evidenti*, non *impossibili*: chi
controlla il file può riscrivere l'intera catena. Per questo l'hash di testa
viene riportato nel sigillo finale (hashes/package-seal.json) e mostrato
all'operatore, che dovrebbe annotarlo nel verbale.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from enum import Enum
from pathlib import Path
from typing import Callable

from .timeutil import iso_utc

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64


class Severity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    # --- caso e configurazione
    CASE_CREATED = "CASE_CREATED"
    CASE_LOADED = "CASE_LOADED"
    CONFIG_LOADED = "CONFIG_LOADED"
    STATE_CHANGED = "STATE_CHANGED"
    ACQUISITION_START_REQUESTED = "ACQUISITION_START_REQUESTED"
    # --- hypervisor / VM
    HYPERVISOR_DETECTED = "HYPERVISOR_DETECTED"
    VM_IDENTITY_VERIFIED = "VM_IDENTITY_VERIFIED"
    NETWORK_CONFIG_VERIFIED = "NETWORK_CONFIG_VERIFIED"
    SNAPSHOT_RESTORED = "SNAPSHOT_RESTORED"
    VM_START_REQUESTED = "VM_START_REQUESTED"
    VM_STARTED = "VM_STARTED"
    AGENT_WAITING = "AGENT_WAITING"
    GUEST_TOOLS_RUNNING = "GUEST_TOOLS_RUNNING"
    VM_READY = "VM_READY"
    AGENT_UNREACHABLE = "AGENT_UNREACHABLE"
    AGENT_RECONNECTED = "AGENT_RECONNECTED"
    CLOCK_OFFSET_MEASURED = "CLOCK_OFFSET_MEASURED"
    # --- preparazione guest
    CASE_DIRECTORY_CREATED = "CASE_DIRECTORY_CREATED"
    GUEST_SYSINFO_COLLECTED = "GUEST_SYSINFO_COLLECTED"
    TLS_KEYLOG_INITIALIZED = "TLS_KEYLOG_INITIALIZED"
    TLS_KEYLOG_ACTIVE = "TLS_KEYLOG_ACTIVE"
    TLS_KEYLOG_EMPTY = "TLS_KEYLOG_EMPTY"
    # --- cattura
    INTERFACE_SELECTED = "INTERFACE_SELECTED"
    WIRESHARK_START_REQUESTED = "WIRESHARK_START_REQUESTED"
    WIRESHARK_STARTED = "WIRESHARK_STARTED"
    WIRESHARK_GUI_STARTED = "WIRESHARK_GUI_STARTED"
    CAPTURE_STARTED = "CAPTURE_STARTED"
    CAPTURE_TRAFFIC_VERIFIED = "CAPTURE_TRAFFIC_VERIFIED"
    CAPTURE_STALLED = "CAPTURE_STALLED"
    CAPTURE_PROCESS_DIED = "CAPTURE_PROCESS_DIED"
    CAPTURE_FILE_ROTATED = "CAPTURE_FILE_ROTATED"
    # --- browser
    FIREFOX_PROFILE_CREATED = "FIREFOX_PROFILE_CREATED"
    FIREFOX_STARTED = "FIREFOX_STARTED"
    FIREFOX_EXITED_UNEXPECTEDLY = "FIREFOX_EXITED_UNEXPECTEDLY"
    # --- operatore
    SCREENSHOT_SERVICE_STARTED = "SCREENSHOT_SERVICE_STARTED"
    SCREENSHOT_CREATED = "SCREENSHOT_CREATED"
    OPERATOR_FILE_DETECTED = "OPERATOR_FILE_DETECTED"
    OPERATOR_FILE_MODIFIED = "OPERATOR_FILE_MODIFIED"
    USER_ACTION = "USER_ACTION"
    ACQUISITION_ACTIVE = "ACQUISITION_ACTIVE"
    HEALTH_CHECK = "HEALTH_CHECK"
    DISK_SPACE_LOW = "DISK_SPACE_LOW"
    # --- chiusura
    STOP_REQUESTED = "STOP_REQUESTED"
    FIREFOX_STOP_REQUESTED = "FIREFOX_STOP_REQUESTED"
    FIREFOX_STOPPED = "FIREFOX_STOPPED"
    CAPTURE_STOP_REQUESTED = "CAPTURE_STOP_REQUESTED"
    CAPTURE_STOPPED = "CAPTURE_STOPPED"
    GUEST_SEAL_STARTED = "GUEST_SEAL_STARTED"
    GUEST_SEALED = "GUEST_SEALED"
    # --- export e integrità
    EXPORT_STARTED = "EXPORT_STARTED"
    FILE_EXPORTED = "FILE_EXPORTED"
    EXPORT_HASH_MISMATCH = "EXPORT_HASH_MISMATCH"
    EXPORT_COMPLETED = "EXPORT_COMPLETED"
    EXPORT_FAILED = "EXPORT_FAILED"
    HASH_CALCULATED = "HASH_CALCULATED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    PCAP_SUMMARY = "PCAP_SUMMARY"
    # --- arresto VM
    VM_SHUTDOWN_REQUESTED = "VM_SHUTDOWN_REQUESTED"
    VM_SHUTDOWN = "VM_SHUTDOWN"
    VM_FORCED_POWEROFF = "VM_FORCED_POWEROFF"
    SNAPSHOT_TAKEN = "SNAPSHOT_TAKEN"
    # --- output
    MANIFEST_WRITTEN = "MANIFEST_WRITTEN"
    REPORT_GENERATED = "REPORT_GENERATED"
    CASE_COMPLETED = "CASE_COMPLETED"
    CASE_INCOMPLETE = "CASE_INCOMPLETE"
    CASE_FAILED = "CASE_FAILED"
    # --- spegnimento della VM dall'interno e recupero
    GUEST_SHUTDOWN_REQUESTED = "GUEST_SHUTDOWN_REQUESTED"
    GUEST_SHUTDOWN_RELEASED = "GUEST_SHUTDOWN_RELEASED"
    RECOVERY_STARTED = "RECOVERY_STARTED"
    RECOVERY_COMPLETED = "RECOVERY_COMPLETED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    # --- preparazione della VM (vmware-setup)
    VM_SETUP_STARTED = "VM_SETUP_STARTED"
    VM_SETUP_STEP = "VM_SETUP_STEP"
    VM_SETUP_COMPLETED = "VM_SETUP_COMPLETED"
    VM_SETUP_FAILED = "VM_SETUP_FAILED"
    # --- generici
    WARNING = "WARNING"
    ERROR = "ERROR"


class EventChainError(Exception):
    """Il log eventi esistente non è integro: non si può proseguire la catena."""


def compute_event_hash(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k != "hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scan(path: Path) -> dict:
    prev = GENESIS_HASH
    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            if not line:
                return {"valid": False, "count": count, "head_hash": prev, "error": f"riga vuota {lineno}"}
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                return {"valid": False, "count": count, "head_hash": prev, "error": f"JSON non valido alla riga {lineno}: {exc}"}
            if rec.get("seq") != count + 1:
                return {"valid": False, "count": count, "head_hash": prev, "error": f"sequenza non continua alla riga {lineno}"}
            if rec.get("prev_hash") != prev:
                return {"valid": False, "count": count, "head_hash": prev, "error": f"prev_hash non coerente alla riga {lineno}"}
            if compute_event_hash(rec) != rec.get("hash"):
                return {"valid": False, "count": count, "head_hash": prev, "error": f"hash non valido alla riga {lineno} (contenuto alterato)"}
            prev = rec["hash"]
            count += 1
    return {"valid": True, "count": count, "head_hash": prev, "error": None}


def verify_chain(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        return {"valid": False, "count": 0, "head_hash": None, "error": "file inesistente"}
    return _scan(path)


def read_events(path: Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class EventLog:
    """Scrittore thread-safe, append-only, con fsync dopo ogni evento."""

    def __init__(
        self,
        path: Path,
        case_id: str,
        source: str,
        *,
        clock: Callable[[], str] = iso_utc,
        durable: bool = True,
        listeners: list[Callable[[dict], None]] | None = None,
    ) -> None:
        self.path = Path(path)
        self.case_id = case_id
        self.source = source
        self._clock = clock
        self._durable = durable
        self._listeners = list(listeners or [])
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS_HASH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size > 0:
            result = _scan(self.path)
            if not result["valid"]:
                raise EventChainError(
                    f"Il log eventi {self.path} non è integro ({result['error']}). "
                    "Non viene modificato: conservarlo e analizzarlo manualmente."
                )
            self._seq = result["count"]
            self._prev = result["head_hash"]
        self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        self._closed = False

    @property
    def head_hash(self) -> str:
        return self._prev

    @property
    def count(self) -> int:
        return self._seq

    def add_listener(self, fn: Callable[[dict], None]) -> None:
        self._listeners.append(fn)

    def emit(
        self,
        event: EventType | str,
        *,
        severity: Severity | str = Severity.INFO,
        component: str = "",
        message: str = "",
        data: dict | None = None,
    ) -> dict:
        event = EventType(event)
        severity = Severity(severity)
        # Normalizza i dati in tipi JSON puri, così hash calcolato == hash verificabile.
        clean = json.loads(json.dumps(data or {}, default=str, ensure_ascii=False))
        with self._lock:
            if self._closed:
                raise RuntimeError("EventLog chiuso")
            self._seq += 1
            record = {
                "schema_version": SCHEMA_VERSION,
                "seq": self._seq,
                "timestamp": self._clock(),
                "event": event.value,
                "severity": severity.value,
                "case_id": self.case_id,
                "source": self.source,
                "component": component,
                "message": message,
                "data": clean,
                "prev_hash": self._prev,
            }
            record["hash"] = compute_event_hash(record)
            self._fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            self._fh.flush()
            if self._durable:
                os.fsync(self._fh.fileno())
            self._prev = record["hash"]
        for listener in self._listeners:
            try:
                listener(record)
            except Exception:  # un listener difettoso non deve bloccare il log
                pass
        return record

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._fh.close()
                self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
