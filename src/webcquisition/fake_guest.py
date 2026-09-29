"""Guest agent simulato, per test automatici e ``--dry-run``.

Produce una cartella caso con la stessa struttura del guest reale, un PCAPNG
SINTETICO (valido, parsabile), un key log fittizio chiaramente marcato e un
log eventi guest reale. Tutti i contenuti sono dichiarati come simulati.

Opzioni di fault injection (``options``):
    unreachable             health/status sollevano AgentUnreachable
    never_ready             health risponde interactive_session=False
    prepare_error           prepare fallisce
    capture_start_error     avvio cattura fallisce
    capture_wrong_iface     il PCAPNG riporta un'interfaccia diversa
    no_traffic              la cattura non cresce mai
    capture_dies            il processo di cattura muore dopo il primo pacchetto
    firefox_fail            Firefox non parte
    keylog_empty            il key log resta vuoto
    corrupt_download        {path: n}: corrompe le prime n copie del file
    stop_after_status_calls n: il pannello guest chiede lo stop dopo n status()
    unreachable_after_status n: l'agent sparisce dopo n status()
    guest_shutdown_after_status_calls n: l'operatore spegne Windows dopo n status()

``link``: oggetto con attributi ``running`` e ``boots`` (es. il simulatore di vmrun dei test):
a VM spenta l'agent è irraggiungibile; dopo un riavvio l'agent riparte senza sessione in memoria
(i file sul "disco" restano), come l'agent reale.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from webcquisition_common import PROTOCOL_VERSION, __version__
from webcquisition_common import protocol as P
from webcquisition_common.events import EventLog, EventType
from webcquisition_common.hashing import StreamingHasher, build_manifest, format_sha256sums, sha256_file
from webcquisition_common.paths import safe_join, validate_case_id
from webcquisition_common.pcapng import summarize, synthetic_pcapng
from webcquisition_common.timeutil import iso_utc

from .guest_client import AgentError, AgentUnreachable, GuestClient

CAPTURE_IFACE = r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"
CONTROL_IFACE = r"\Device\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"


class FakeGuestClient(GuestClient):
    def __init__(self, root: Path, agent_id: str = "fake-agent", options: dict | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.desktop = self.root / "Desktop"
        self.desktop.mkdir(exist_ok=True)
        self.agent_id = agent_id
        self.options = dict(options or {})
        self._state_path = self.root / "_fake_state.json"
        self.s = {
            "session_active": False, "case_id": None, "capture_running": False, "packets": 0,
            "firefox_running": False, "stop_requested": False, "sealed": False, "status_calls": 0,
            "iface": None, "files": [], "downloads": {}, "tls": True,
        }
        if self._state_path.exists():
            self.s.update(json.loads(self._state_path.read_text()))
        self.link = None
        self.released = False

    # ----------------------------------------------------------------- helpers
    def _save(self):
        self._state_path.write_text(json.dumps(self.s))

    def _reachable(self):
        if self.link is not None:
            if not self.link.running:
                raise AgentUnreachable("VM spenta")
            if self.s.get("boot") is None:
                self.s["boot"] = self.link.boots
            elif self.s["boot"] != self.link.boots:  # riavvio: l'agent riparte senza sessione
                self.s.update(boot=self.link.boots, session_active=False, case_id=None, capture_running=False,
                              firefox_running=False, stop_requested=False, stop_source=None, sealed=False, files=[],
                              recovering=False)
                self.options.pop("guest_shutdown_after_status_calls", None)
        if self.options.get("unreachable"):
            raise AgentUnreachable("agent simulato non raggiungibile")
        n = self.options.get("unreachable_after_status")
        if n is not None and self.s["status_calls"] >= n:
            raise AgentUnreachable("agent simulato scomparso")

    @property
    def case_dir(self) -> Path:
        return self.desktop / self.s["case_id"]

    def _events(self) -> EventLog:
        rel = P.GUEST_RECOVERY_EVENTS_REL if self.s.get("recovering") else "logs/guest-events.jsonl"
        return EventLog(self.case_dir / rel, self.s["case_id"], "guest", durable=False)

    def _emit(self, event, **data):
        with self._events() as log:
            log.emit(event, component="fake-agent", data=data)

    def _write_capture(self):
        iface = "\\Device\\NPF_{99999999-0000-0000-0000-000000000000}" if self.options.get("capture_wrong_iface") else self.s["iface"]
        path = self.case_dir / "network" / "capture_00001_20260101000000.pcapng"
        path.write_bytes(synthetic_pcapng(iface, self.s["packets"], 1_780_000_000.0))

    # ----------------------------------------------------------------- API
    def health(self):
        self._reachable()
        return {
            "agent_id": self.agent_id, "agent_version": __version__, "protocol": PROTOCOL_VERSION,
            "utc": iso_utc(), "interactive_session": not self.options.get("never_ready"),
            "session_active": self.s["session_active"], "case_id": self.s["case_id"], "simulated": True,
        }

    def prepare(self, request):
        self._reachable()
        if self.options.get("prepare_error"):
            raise AgentError("PREPARE_FAILED", "errore simulato in preparazione")
        if self.s["session_active"]:
            raise AgentError("SESSION_ACTIVE", "sessione già attiva", 409)
        case_id = validate_case_id(request["case_id"])
        case_dir = self.desktop / case_id
        if case_dir.exists():
            raise AgentError("CASE_DIR_EXISTS", f"{case_dir} esiste già", 409)
        case_dir.mkdir()
        for sub in P.GUEST_SUBDIRS:
            (case_dir / sub).mkdir()
        self.s.update(session_active=True, case_id=case_id, tls=request.get("tls", {}).get("enabled", True))
        self._emit(EventType.CASE_DIRECTORY_CREATED, path=str(case_dir))
        sysinfo = {
            "simulated": True, "collected_at_utc": iso_utc(),
            "windows": {"ProductName": "Windows (simulato)", "CurrentBuild": "00000"},
            "firefox_version": "0.0-simulated", "wireshark_version": "dumpcap 0.0-simulated",
            "timezone": {"name": "UTC", "utc_offset_seconds": 0}, "time_sync": "simulato",
            "global_sslkeylogfile": None,
        }
        (case_dir / "metadata" / "sysinfo.json").write_text(json.dumps(sysinfo, indent=2))
        self._emit(EventType.GUEST_SYSINFO_COLLECTED)
        keylog = case_dir / "tls" / "sslkeylog.log"
        if self.s["tls"]:
            keylog.touch()
            self._emit(EventType.TLS_KEYLOG_INITIALIZED, path=str(keylog))
        (case_dir / "README.txt").write_text("SIMULAZIONE --dry-run: questo NON è un reperto.\n")
        self._save()
        return {"guest_case_dir": str(case_dir), "keylog_path": str(keylog) if self.s["tls"] else None,
                "desktop_dir": str(self.desktop), "sysinfo": sysinfo}

    def interfaces(self):
        self._reachable()
        return {"interfaces": [
            {"name": CAPTURE_IFACE, "display": "Ethernet", "friendly_name": "Ethernet",
             "guid": "11111111-2222-3333-4444-555555555555", "ipv4": ["10.0.2.15"],
             "has_default_gateway": True, "is_control": False},
            {"name": CONTROL_IFACE, "display": "Ethernet 2", "friendly_name": "Ethernet 2",
             "guid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "ipv4": ["192.168.150.10"],
             "has_default_gateway": False, "is_control": True},
        ]}

    def capture_start(self, request):
        self._reachable()
        if self.options.get("capture_start_error"):
            raise AgentError("CAPTURE_START_FAILED", "dumpcap non avviato (simulato)")
        self.s.update(capture_running=True, iface=request["interface"], packets=0)
        self._write_capture()
        self._emit(EventType.WIRESHARK_STARTED, interface=request["interface"])
        self._save()
        return {"engine_pid": 4242, "gui_pid": 4343 if request.get("mode") == "dual" else None,
                "command": ["dumpcap", "-i", request["interface"], "-w", "network/capture.pcapng"]}

    def capture_status(self):
        self._reachable()
        if self.s["capture_running"]:
            if self.options.get("capture_dies") and self.s["packets"] > 0:
                self.s["capture_running"] = False
            elif not self.options.get("no_traffic"):
                self.s["packets"] += 5
                self._write_capture()
        self._save()
        files, total_packets, total_bytes, ifnames = [], 0, 0, []
        for f in sorted((self.case_dir / "network").glob("capture_*.pcapng")):
            summ = summarize(f)
            files.append({"path": f"network/{f.name}", "size": f.stat().st_size, "packets": summ.packets,
                          "interfaces": summ.interface_names, "valid": summ.valid})
            total_packets += summ.packets
            total_bytes += f.stat().st_size
            ifnames += summ.interface_names
        return {"running": self.s["capture_running"], "returncode": None if self.s["capture_running"] else 0,
                "files": files, "packets": total_packets, "bytes": total_bytes,
                "interfaces": sorted(set(ifnames)), "gui_running": self.s["capture_running"], "stderr_tail": ""}

    def firefox_start(self, request):
        self._reachable()
        if self.options.get("firefox_fail"):
            raise AgentError("FIREFOX_START_FAILED", "firefox.exe non trovato (simulato)")
        profile = self.case_dir / "browser" / "firefox-profile"
        profile.mkdir(parents=True, exist_ok=True)
        (profile / "user.js").write_text('user_pref("network.trr.mode", 5);\n')
        (profile / "places.sqlite").write_bytes(b"SQLite format 3\x00 (simulato)")
        if self.s["tls"] and not self.options.get("keylog_empty"):
            (self.case_dir / "tls" / "sslkeylog.log").write_text(
                "# SIMULATO\nCLIENT_RANDOM " + "00" * 32 + " " + "11" * 48 + "\n")
        self.s["firefox_running"] = True
        self._emit(EventType.FIREFOX_STARTED, pid=5151)
        self._save()
        return {"pid": 5151, "version": "0.0-simulated", "profile_dir": str(profile), "command": ["firefox.exe"]}

    def ui_start(self, request):
        self._reachable()
        self._emit(EventType.SCREENSHOT_SERVICE_STARTED)
        return {"hotkey": {"enabled": True, "hotkey": request.get("hotkey"), "error": None},
                "panel": {"enabled": False, "error": "simulato"}, "watcher": {"enabled": True},
                "simulated": True}

    def status(self):
        self._reachable()
        self.s["status_calls"] += 1
        n = self.options.get("stop_after_status_calls")
        if n is not None and self.s["status_calls"] >= n:
            self.s["stop_requested"] = True
            self.s.setdefault("stop_source", "guest_panel")
        n = self.options.get("guest_shutdown_after_status_calls")
        if n is not None and self.s["status_calls"] >= n and not self.s["stop_requested"]:
            self.s.update(stop_requested=True, stop_source="guest_shutdown")
        if self.s["status_calls"] == 2 and self.s["session_active"]:
            shot = self.case_dir / "screenshots" / "screenshot-0001.png"
            if not shot.exists():
                shot.write_bytes(b"\x89PNG\r\n\x1a\n(simulato)")
                digest, _ = sha256_file(shot)
                (self.case_dir / "screenshots" / "screenshot-0001.json").write_text(
                    json.dumps({"file": shot.name, "sha256": digest, "taken_at_utc": iso_utc(), "simulated": True}))
                self._emit(EventType.SCREENSHOT_CREATED, file=shot.name, sha256=digest)
        self._save()
        keylog = self.case_dir / "tls" / "sslkeylog.log" if self.s["case_id"] else None
        shots = len(list((self.case_dir / "screenshots").glob("*.png"))) if self.s["case_id"] else 0
        return {
            "session_active": self.s["session_active"], "case_id": self.s["case_id"],
            "capture": self.capture_status() if self.s["case_id"] else None,
            "firefox": {"running": self.s["firefox_running"], "pid": 5151},
            "keylog": {"exists": bool(keylog and keylog.exists()),
                       "size": keylog.stat().st_size if keylog and keylog.exists() else 0},
            "screenshots": shots, "operator_files": 0, "stop_requested": self.s["stop_requested"],
            "stop_source": self.s.get("stop_source"),
            "disk_free_bytes": 50 * 1024**3, "guest_utc": iso_utc(), "sealed": self.s["sealed"],
        }

    def stop(self, request):
        self._reachable()
        self.s.update(capture_running=False, firefox_running=False)
        self._emit(EventType.FIREFOX_STOPPED, graceful=True)
        self._emit(EventType.CAPTURE_STOPPED, graceful=True)
        self._save()
        return {"order": request.get("order"),
                "firefox": {"stopped": True, "graceful": True, "returncode": 0},
                "capture": {"stopped": True, "graceful": True, "returncode": 0},
                "gui": {"stopped": True}}

    def seal(self):
        self._reachable()
        self._emit(EventType.GUEST_SEAL_STARTED)
        manifest = build_manifest(self.case_dir, exclude=[P.GUEST_MANIFEST_REL, P.GUEST_SUMS_REL],
                                  extra={"case_id": self.s["case_id"], "agent_id": self.agent_id, "simulated": True})
        mpath = self.case_dir / P.GUEST_MANIFEST_REL
        mpath.write_text(json.dumps(manifest, indent=2))
        (self.case_dir / P.GUEST_SUMS_REL).write_text(format_sha256sums(manifest["files"]))
        msha, msize = sha256_file(mpath)
        ssha, ssize = sha256_file(self.case_dir / P.GUEST_SUMS_REL)
        files = manifest["files"] + [
            {"path": P.GUEST_MANIFEST_REL, "size": msize, "sha256": msha},
            {"path": P.GUEST_SUMS_REL, "size": ssize, "sha256": ssha},
        ]
        self.s.update(sealed=True, files=files)
        self._save()
        return {"manifest": manifest, "manifest_sha256": msha, "file_count": len(files)}

    def release(self):
        self._reachable()
        self.released = True
        if self.link is not None and self.s.get("stop_source") == "guest_shutdown":
            self.link.running = False  # Windows completa lo spegnimento avviato dall'operatore
        return {"released": True, "shutdown_was_requested": self.s.get("stop_source") == "guest_shutdown"}

    def recover(self, request):
        self._reachable()
        if self.s["session_active"]:
            raise AgentError("SESSION_ACTIVE", "sessione già attiva", 409)
        case_id = validate_case_id(request["case_id"])
        case_dir = self.desktop / case_id
        if not case_dir.is_dir():
            raise AgentError("CASE_DIR_NOT_FOUND", str(case_dir), 404)
        self.s.update(session_active=True, case_id=case_id)
        mpath = case_dir / P.GUEST_MANIFEST_REL
        if mpath.exists():
            manifest = json.loads(mpath.read_text())
            msha, msize = sha256_file(mpath)
            ssha, ssize = sha256_file(case_dir / P.GUEST_SUMS_REL)
            files = manifest["files"] + [{"path": P.GUEST_MANIFEST_REL, "size": msize, "sha256": msha},
                                         {"path": P.GUEST_SUMS_REL, "size": ssize, "sha256": ssha}]
            self.s.update(sealed=True, files=files)
            self._save()
            return {"case_id": case_id, "already_sealed": True, "manifest": manifest, "manifest_sha256": msha,
                    "file_count": len(files)}
        with EventLog(case_dir / P.GUEST_RECOVERY_EVENTS_REL, case_id, "guest", durable=False) as log:
            log.emit(EventType.RECOVERY_STARTED, component="fake-agent")
        self.s["recovering"] = True
        self._save()
        return {"case_id": case_id, "already_sealed": False}

    def list_files(self):
        self._reachable()
        if not self.s["sealed"]:
            raise AgentError("NOT_SEALED", "sessione non sigillata", 409)
        return {"files": self.s["files"]}

    def download(self, rel_path, dest):
        self._reachable()
        if rel_path not in {f["path"] for f in self.s["files"]}:
            raise AgentError("FILE_NOT_IN_MANIFEST", rel_path, 404)
        src = safe_join(self.case_dir, rel_path)
        corrupt = self.options.get("corrupt_download", {})
        done = self.s["downloads"].get(rel_path, 0)
        self.s["downloads"][rel_path] = done + 1
        self._save()
        hasher = StreamingHasher()
        with open(src, "rb") as fin, open(dest, "xb") as fout:
            data = fin.read()
            if done < corrupt.get(rel_path, 0):
                data = data + b"CORRUPTED"
            hasher.update(data)
            fout.write(data)
        return hasher.hexdigest(), hasher.size

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)
