"""Sessione di acquisizione nel guest: la macchina a stati lato agent.

Vincoli forensi applicati qui (indipendentemente dall'host):
  * una sola sessione per avvio dell'agent; la cartella del caso non deve esistere;
  * Firefox può partire solo con la cattura già attiva (nessun traffico non catturato);
  * l'interfaccia di controllo non può essere catturata;
  * il sigillo (manifest SHA-256) richiede che cattura e browser siano fermi;
  * dopo il sigillo il log eventi del caso è chiuso e i file sono in sola lettura;
    si possono scaricare solo i file elencati nel manifest.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import threading
import time
from pathlib import Path

from webcquisition_common import PROTOCOL_VERSION, __version__
from webcquisition_common import protocol as P
from webcquisition_common.events import EventLog, EventType, Severity
from webcquisition_common.hashing import build_manifest, format_sha256sums, sha256_file
from webcquisition_common.paths import UnsafePathError, normalize_relpath, safe_join, validate_case_id
from webcquisition_common.timeutil import iso_utc

from . import sysinfo as sysinfo_mod
from . import winutil
from .capture import CaptureError, CaptureManager
from .firefox import FirefoxError, FirefoxManager
from .hotkey import HotkeyListener
from .interfaces import enumerate_interfaces
from .panel import ControlPanel
from .screenshot import ScreenshotService
from .shutdown_guard import ShutdownGuard
from .watcher import OperatorFileWatcher

GUEST_README = """WEBCQUISITION - cartella di acquisizione {case_id}
Creata il {created} (UTC) dall'agent {agent_id} (versione {version}).

network/      PCAPNG prodotti da dumpcap/tshark (REPERTO ORIGINALE)
tls/          sslkeylog.log: segreti di sessione TLS scritti da Firefox.
              MATERIALE SENSIBILE: consente di decifrare il traffico catturato.
browser/      profilo Firefox dedicato al caso
screenshots/  screenshot WEBCQUISITION (PNG + metadati JSON)
operator/     file salvati dall'operatore (anche la radice di questa cartella è monitorata)
metadata/     informazioni di sistema, comandi, preferenze, manifest SHA-256
logs/         log eventi del guest (JSONL con catena di hash)

Non modificare né spostare file durante l'acquisizione.
"""


class AgentAPIError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code = code
        self.status = status
        self.message = message
        super().__init__(f"{code}: {message}")


class Session:
    def __init__(self, settings, *, desktop_fn=winutil.resolve_desktop, sysinfo_fn=sysinfo_mod.collect,
                 interfaces_fn=None, capture_factory=CaptureManager, firefox_factory=FirefoxManager,
                 screenshot_factory=ScreenshotService, hotkey_factory=HotkeyListener,
                 panel_factory=ControlPanel, watcher_factory=OperatorFileWatcher,
                 guard_factory=ShutdownGuard, interactive_fn=winutil.interactive_session,
                 disk_usage=shutil.disk_usage, durable=True, monotonic=time.monotonic, host_timeout_s: float = 120):
        self.settings = settings
        self._desktop_fn = desktop_fn
        self._sysinfo_fn = sysinfo_fn
        self._interfaces_fn = interfaces_fn or (lambda s: enumerate_interfaces(s.dumpcap_path, s.control_ip))
        self._capture_factory = capture_factory
        self._firefox_factory = firefox_factory
        self._screenshot_factory = screenshot_factory
        self._hotkey_factory = hotkey_factory
        self._panel_factory = panel_factory
        self._watcher_factory = watcher_factory
        self._guard_factory = guard_factory
        self._monotonic = monotonic
        self.host_timeout_s = host_timeout_s
        self._last_host_contact: float | None = None
        self.guard = None
        self.released = False
        self.recovered = False
        self._interactive = interactive_fn
        self._disk_usage = disk_usage
        self._durable = durable
        self._lock = threading.RLock()
        self.case_id: str | None = None
        self.case_dir: Path | None = None
        self.events: EventLog | None = None
        self.capture = self.firefox = self.shots = self.hotkey = self.panel = self.watcher = None
        self.stop_requested = False
        self.stop_source: str | None = None
        self.stopped = False
        self.sealed = False
        self._files: dict[str, dict] = {}

    # ------------------------------------------------------------ helpers
    def _require_session(self):
        if self.case_dir is None:
            raise AgentAPIError("NO_SESSION", "nessuna sessione preparata", 409)

    def _require_open(self):
        self._require_session()
        if self.stopped:
            raise AgentAPIError("SESSION_STOPPED", "la sessione è già stata chiusa", 409)

    def _emit(self, event, component="session", severity=Severity.INFO, message="", **data):
        if self.events is not None and not self.events.closed:
            self.events.emit(event, component=component, severity=severity, message=message, data=data)

    def touch_host(self):
        """Chiamato a ogni richiesta autenticata dell'host."""
        self._last_host_contact = self._monotonic()

    def host_present(self) -> bool:
        return (self._last_host_contact is not None
                and self._monotonic() - self._last_host_contact <= self.host_timeout_s)

    def should_block_shutdown(self) -> bool:
        return self.case_dir is not None and not self.released and self.host_present()

    def on_guest_shutdown(self):
        self._emit(EventType.GUEST_SHUTDOWN_REQUESTED, component="shutdown",
                   message="spegnimento di Windows richiesto dall'operatore: rimandato fino alla copia del materiale")
        self.request_stop("guest_shutdown")

    # ------------------------------------------------------------ API
    def health(self) -> dict:
        return {"agent_id": self.settings.agent_id, "agent_version": __version__, "protocol": PROTOCOL_VERSION,
                "utc": iso_utc(), "interactive_session": bool(self._interactive()),
                "session_active": self.case_dir is not None, "case_id": self.case_id, "simulated": False}

    def prepare(self, req: dict) -> dict:
        with self._lock:
            if self.case_dir is not None:
                raise AgentAPIError("SESSION_ACTIVE", f"sessione già attiva per {self.case_id}: "
                                    "riavviare la VM dallo snapshot pulito", 409)
            try:
                case_id = validate_case_id(str(req.get("case_id", "")))
            except ValueError as exc:
                raise AgentAPIError("CASE_ID_INVALID", str(exc)) from exc
            desktop = Path(self._desktop_fn())
            case_dir = desktop / case_id
            if case_dir.exists():
                raise AgentAPIError("CASE_DIR_EXISTS", f"{case_dir} esiste già: nessuna sovrascrittura", 409)
            tls = bool((req.get("tls") or {}).get("enabled", True))
            try:
                case_dir.mkdir(parents=True)
                for sub in P.GUEST_SUBDIRS:
                    (case_dir / sub).mkdir()
            except OSError as exc:
                raise AgentAPIError("CASE_DIR_CREATE_FAILED", f"creazione di {case_dir} fallita: {exc}", 500) from exc
            self.case_id, self.case_dir = case_id, case_dir
            self.events = EventLog(case_dir / "logs" / "guest-events.jsonl", case_id, "guest", durable=self._durable)
            self._emit(EventType.CASE_DIRECTORY_CREATED, path=str(case_dir), operator=req.get("operator"))
            (case_dir / "README.txt").write_text(GUEST_README.format(
                case_id=case_id, created=iso_utc(), agent_id=self.settings.agent_id, version=__version__),
                encoding="utf-8")
            try:
                info = self._sysinfo_fn(self.settings)
            except Exception as exc:  # noqa: BLE001 - metadati best-effort, errore documentato
                info = {"error": str(exc)}
                self._emit(EventType.WARNING, severity=Severity.WARNING, message=f"sysinfo incompleta: {exc}")
            (case_dir / "metadata" / "sysinfo.json").write_text(json.dumps(info, indent=2, ensure_ascii=False),
                                                                 encoding="utf-8")
            self._emit(EventType.GUEST_SYSINFO_COLLECTED, windows=info.get("windows"),
                       firefox_version=info.get("firefox_version"), wireshark_version=info.get("wireshark_version"))
            keylog = case_dir / "tls" / "sslkeylog.log"
            if tls:
                keylog.touch(exist_ok=False)  # pre-creato: il file appartiene al caso sin dall'inizio
                self._emit(EventType.TLS_KEYLOG_INITIALIZED, path=str(keylog))
            if info.get("global_sslkeylogfile"):
                self._emit(EventType.WARNING, severity=Severity.WARNING,
                           message="SSLKEYLOGFILE globale presente nella VM", value=info["global_sslkeylogfile"])
            return {"guest_case_dir": str(case_dir), "keylog_path": str(keylog) if tls else None,
                    "desktop_dir": str(desktop), "sysinfo": info}

    def interfaces(self) -> dict:
        return self._interfaces_fn(self.settings)

    def capture_start(self, req: dict) -> dict:
        with self._lock:
            self._require_open()
            iface = req.get("interface")
            if not iface:
                raise AgentAPIError("INTERFACE_REQUIRED", "interfaccia di cattura non specificata")
            known = {i["name"]: i for i in self.interfaces().get("interfaces", [])}
            if iface not in known:
                raise AgentAPIError("INTERFACE_NOT_FOUND", f"interfaccia {iface} non presente in dumpcap -D", 404)
            if known[iface].get("is_control"):
                raise AgentAPIError("INTERFACE_IS_CONTROL", "rifiutata: è l'interfaccia del canale di controllo")
            self._emit(EventType.WIRESHARK_START_REQUESTED, interface=iface, engine=req.get("engine"),
                       mode=req.get("mode"))
            self.capture = self._capture_factory(self.settings, self.case_dir, self.events)
            try:
                return self.capture.start(req)
            except CaptureError as exc:
                self._emit(EventType.ERROR, severity=Severity.ERROR, message=str(exc), code=exc.code)
                raise AgentAPIError(exc.code, str(exc), 500) from exc

    def capture_status(self) -> dict:
        self._require_session()
        if self.capture is None:
            return {"running": False, "returncode": None, "files": [], "packets": 0, "bytes": 0,
                    "interfaces": [], "gui_running": False, "stderr_tail": ""}
        return self.capture.status()

    def firefox_start(self, req: dict) -> dict:
        with self._lock:
            self._require_open()
            if self.capture is None or not self.capture.running():
                raise AgentAPIError("CAPTURE_NOT_RUNNING",
                                    "Firefox può essere avviato solo con la cattura attiva", 409)
            self.firefox = self._firefox_factory(self.settings, self.case_dir, self.events)
            try:
                return self.firefox.start(req)
            except FirefoxError as exc:
                self._emit(EventType.ERROR, severity=Severity.ERROR, message=str(exc), code=exc.code)
                raise AgentAPIError(exc.code, str(exc), 500) from exc

    def _screenshot(self, trigger: str):
        try:
            return self.shots.take(trigger)
        except Exception as exc:  # noqa: BLE001
            self._emit(EventType.ERROR, component="screenshot", severity=Severity.ERROR,
                       message=f"screenshot fallito: {exc}", trigger=trigger)
            return None

    def request_stop(self, source: str):
        if not self.stop_requested:
            self.stop_requested, self.stop_source = True, source
            self._emit(EventType.USER_ACTION, action="stop_requested", source=source)

    def ui_start(self, req: dict) -> dict:
        with self._lock:
            self._require_open()
            self.shots = self._screenshot_factory(self.case_dir, self.events, case_id=self.case_id)
            out = {"hotkey": {"enabled": False, "error": None, "disabled_by_config": True},
                   "panel": {"enabled": False, "error": None, "disabled_by_config": True},
                   "watcher": {"enabled": False}}
            if req.get("hotkey_enabled", True):
                self.hotkey = self._hotkey_factory(req.get("hotkey", "ctrl+alt+s"),
                                                   lambda: self._screenshot("hotkey"))
                out["hotkey"] = self.hotkey.start()
            if req.get("control_panel", True):
                self.panel = self._panel_factory(self.case_id, self.status, self._screenshot, self.request_stop)
                out["panel"] = self.panel.start()
            self.watcher = self._watcher_factory(self.case_dir, self.events)
            out["watcher"] = self.watcher.start()
            out["shutdown_guard"] = {"enabled": False, "disabled_by_config": True}
            if req.get("block_guest_shutdown", True):
                self.guard = self._guard_factory(self.should_block_shutdown, self.on_guest_shutdown)
                out["shutdown_guard"] = self.guard.start()
            self._emit(EventType.SCREENSHOT_SERVICE_STARTED, **out)
            return out

    def status(self) -> dict:
        if self.case_dir is None:
            return {"session_active": False, "case_id": None, "capture": None, "firefox": None, "keylog": None,
                    "screenshots": 0, "operator_files": 0, "stop_requested": False, "disk_free_bytes": None,
                    "guest_utc": iso_utc(), "sealed": False}
        keylog = self.case_dir / "tls" / "sslkeylog.log"
        try:
            free = self._disk_usage(str(self.case_dir)).free
        except OSError:
            free = None
        return {
            "session_active": True, "case_id": self.case_id, "capture": self.capture_status(),
            "firefox": {"running": bool(self.firefox and self.firefox.running()),
                        "pid": self.firefox.proc.pid if self.firefox and self.firefox.proc else None},
            "keylog": {"exists": keylog.exists(), "size": keylog.stat().st_size if keylog.exists() else 0},
            "screenshots": self.shots.count() if self.shots else 0,
            "operator_files": self.watcher.count() if self.watcher else 0,
            "stop_requested": self.stop_requested, "stop_source": self.stop_source,
            "disk_free_bytes": free, "guest_utc": iso_utc(), "sealed": self.sealed, "stopped": self.stopped,
        }

    def stop(self, req: dict) -> dict:
        with self._lock:
            self._require_session()
            if self.stopped:
                raise AgentAPIError("SESSION_STOPPED", "sessione già chiusa", 409)
            order = req.get("order", "browser_first")
            if order not in ("browser_first", "capture_first"):
                raise AgentAPIError("STOP_ORDER_INVALID", f"ordine non valido: {order}")
            timeout = float(req.get("graceful_timeout_s", 30))
            self.request_stop(self.stop_source or "host")
            result = {"order": order}

            def stop_ff():
                self._emit(EventType.FIREFOX_STOP_REQUESTED)
                r = self.firefox.stop(timeout) if self.firefox else {"stopped": True, "graceful": True,
                                                                      "returncode": None, "note": "mai avviato"}
                self._emit(EventType.FIREFOX_STOPPED, **r)
                result["firefox"] = r

            def stop_cap():
                self._emit(EventType.CAPTURE_STOP_REQUESTED)
                r = self.capture.stop(timeout) if self.capture else {"stopped": True, "graceful": True,
                                                                      "returncode": None, "note": "mai avviata"}
                self._emit(EventType.CAPTURE_STOPPED, **r)
                result["capture"] = r
                result["gui"] = self.capture.stop_gui() if self.capture else {"stopped": True}

            for step in ((stop_ff, stop_cap) if order == "browser_first" else (stop_cap, stop_ff)):
                try:
                    step()
                except Exception as exc:  # noqa: BLE001 - si prosegue con gli altri passi
                    self._emit(EventType.ERROR, severity=Severity.ERROR, message=f"arresto: {exc}")
            for comp in (self.hotkey, self.panel):
                if comp:
                    try:
                        comp.stop()
                    except Exception:  # noqa: BLE001
                        pass
            if self.watcher:
                self.watcher.stop()  # scansione finale
            self.stopped = True
            return result

    def seal(self) -> dict:
        with self._lock:
            self._require_session()
            if not self.stopped:
                raise AgentAPIError("SESSION_NOT_STOPPED", "chiudere la sessione prima del sigillo", 409)
            if self.sealed:
                raise AgentAPIError("ALREADY_SEALED", "sessione già sigillata", 409)
            self._emit(EventType.GUEST_SEAL_STARTED)
            self.events.close()  # da qui il log del caso non cambia più: può essere incluso nel manifest
            manifest = build_manifest(self.case_dir, exclude=[P.GUEST_MANIFEST_REL, P.GUEST_SUMS_REL],
                                      extra={"case_id": self.case_id, "agent_id": self.settings.agent_id,
                                             "agent_version": __version__, "sealed_at_utc": iso_utc(),
                                             "root": str(self.case_dir)})
            mpath = self.case_dir / P.GUEST_MANIFEST_REL
            spath = self.case_dir / P.GUEST_SUMS_REL
            with open(mpath, "x", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=2, ensure_ascii=False)
            with open(spath, "x", encoding="utf-8", newline="\n") as fh:
                fh.write(format_sha256sums(manifest["files"]))
            msha, msize = sha256_file(mpath)
            ssha, ssize = sha256_file(spath)
            files = manifest["files"] + [{"path": P.GUEST_MANIFEST_REL, "size": msize, "sha256": msha},
                                         {"path": P.GUEST_SUMS_REL, "size": ssize, "sha256": ssha}]
            self._files = {f["path"]: f for f in files if not f.get("symlink")}
            for f in self._files:
                try:
                    p = safe_join(self.case_dir, f)
                    os.chmod(p, stat.S_IREAD)
                except OSError:
                    pass
            self.sealed = True
            return {"manifest": manifest, "manifest_sha256": msha, "file_count": len(files)}

    def release(self) -> dict:
        """L'host ha terminato la copia: lo spegnimento di Windows non viene più bloccato."""
        with self._lock:
            self.released = True
            if self.guard:
                try:
                    self.guard.release()
                except Exception:  # noqa: BLE001
                    pass
            return {"released": True, "shutdown_was_requested": self.stop_source == "guest_shutdown"}

    def recover(self, req: dict) -> dict:
        """Riapre, dopo un riavvio, la cartella di un caso interrotto da uno spegnimento non controllato.

        Nessun processo viene riavviato: la sessione nasce già chiusa, pronta per sigillo ed export.
        Se il sigillo era già stato fatto (VM persa durante la copia), si riusa il manifest esistente.
        """
        with self._lock:
            if self.case_dir is not None:
                raise AgentAPIError("SESSION_ACTIVE", f"sessione già attiva per {self.case_id}", 409)
            try:
                case_id = validate_case_id(str(req.get("case_id", "")))
            except ValueError as exc:
                raise AgentAPIError("CASE_ID_INVALID", str(exc)) from exc
            case_dir = Path(self._desktop_fn()) / case_id
            if not case_dir.is_dir():
                raise AgentAPIError("CASE_DIR_NOT_FOUND", f"{case_dir} non esiste: nulla da recuperare", 404)
            self.case_id, self.case_dir = case_id, case_dir
            self.stopped = self.recovered = True
            mpath = case_dir / P.GUEST_MANIFEST_REL
            spath = case_dir / P.GUEST_SUMS_REL
            if mpath.exists() and spath.exists():
                manifest = json.loads(mpath.read_text(encoding="utf-8"))
                msha, msize = sha256_file(mpath)
                ssha, ssize = sha256_file(spath)
                files = manifest["files"] + [{"path": P.GUEST_MANIFEST_REL, "size": msize, "sha256": msha},
                                             {"path": P.GUEST_SUMS_REL, "size": ssize, "sha256": ssha}]
                self._files = {f["path"]: f for f in files if not f.get("symlink")}
                self.sealed = True
                return {"case_id": case_id, "already_sealed": True, "manifest_sha256": msha,
                        "manifest": manifest, "file_count": len(files)}
            self.events = EventLog(case_dir / P.GUEST_RECOVERY_EVENTS_REL, case_id, "guest", durable=self._durable)
            self._emit(EventType.RECOVERY_STARTED, component="recovery",
                       message="VM riavviata dopo uno spegnimento non controllato: recupero della cartella del caso")
            return {"case_id": case_id, "already_sealed": False}

    def list_files(self) -> dict:
        if not self.sealed:
            raise AgentAPIError("NOT_SEALED", "sessione non sigillata", 409)
        return {"files": list(self._files.values())}

    def open_file(self, rel: str) -> tuple[Path, int]:
        if not self.sealed:
            raise AgentAPIError("NOT_SEALED", "sessione non sigillata", 409)
        try:
            rel = normalize_relpath(rel)
            path = safe_join(self.case_dir, rel)
        except (UnsafePathError, ValueError) as exc:
            raise AgentAPIError("PATH_UNSAFE", str(exc), 400) from exc
        if rel not in self._files:
            raise AgentAPIError("FILE_NOT_IN_MANIFEST", rel, 404)
        return path, path.stat().st_size
