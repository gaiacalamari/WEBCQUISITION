"""Gestione della cattura di rete nel guest.

Strategia (docs/CAPTURE.md):
  * il REPERTO è prodotto da ``dumpcap`` (default) o ``tshark``, in formato PCAPNG,
    con ring buffer a sola dimensione (``-b filesize:N``, senza ``files:``: nessun file
    viene mai eliminato) in ``network/capture_NNNNN_YYYYMMDDhhmmss.pcapng``;
  * in modalità ``dual`` si avvia anche la GUI di Wireshark sulla stessa interfaccia,
    come vista di controllo per l'operatore. La GUI cattura in un file temporaneo
    proprio, FUORI dalla cartella del caso, che non è un reperto;
  * la verifica è programmatica: processo vivo, file PCAPNG presenti, nome
    interfaccia negli Interface Description Block, crescita del contatore pacchetti;
  * l'arresto è pulito (CTRL+C alla console di dumpcap tramite helper ``ctrlc``) con
    fallback forzato registrato come tale.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

from webcquisition_common.events import EventLog, EventType, Severity
from webcquisition_common.pcapng import IncrementalPcapngReader
from webcquisition_common.timeutil import iso_utc

from . import winutil

CAPTURE_BASENAME = "capture.pcapng"


class CaptureError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def build_command(settings, request: dict, network_dir: Path) -> list[str]:
    engine = request.get("engine", "dumpcap")
    if engine not in ("dumpcap", "tshark"):
        raise CaptureError("CAPTURE_ENGINE_INVALID", f"motore di cattura non supportato: {engine}")
    exe = settings.dumpcap_path if engine == "dumpcap" else settings.tshark_path
    size_kb = int(request.get("ring_filesize_mb", 512)) * 1024
    cmd = [exe, "-i", request["interface"], "-w", str(network_dir / CAPTURE_BASENAME)]
    if size_kb > 0:
        cmd += ["-b", f"filesize:{size_kb}"]
    if request.get("snaplen"):
        cmd += ["-s", str(int(request["snaplen"]))]
    if request.get("capture_filter"):
        cmd += ["-f", request["capture_filter"]]
    if engine == "tshark":
        cmd += ["-F", "pcapng", "-q", "-n"]
    return cmd


def build_gui_command(settings, request: dict) -> list[str]:
    cmd = [settings.wireshark_path, "-i", request["interface"], "-k"]
    if request.get("capture_filter"):
        cmd += ["-f", request["capture_filter"]]
    return cmd


class CaptureManager:
    def __init__(self, settings, case_dir: Path, events: EventLog, popen=subprocess.Popen,
                 stopper=None):
        self.settings = settings
        self.case_dir = Path(case_dir)
        self.network_dir = self.case_dir / "network"
        self.events = events
        self._popen = popen
        self._stopper = stopper or self._send_ctrl_c
        self.proc = None
        self.gui = None
        self.command: list[str] | None = None
        self._readers: dict[str, IncrementalPcapngReader] = {}
        self._lock = threading.Lock()
        self._stderr = None
        self.stopped = False

    # --------------------------------------------------------------- avvio
    def start(self, request: dict) -> dict:
        if self.proc is not None:
            raise CaptureError("CAPTURE_ALREADY_STARTED", "la cattura è già stata avviata in questa sessione")
        if any(self.network_dir.glob("*.pcapng")):
            raise CaptureError("CAPTURE_FILES_EXIST", "la cartella network/ contiene già file PCAPNG")
        self.command = build_command(self.settings, request, self.network_dir)
        exe = Path(self.command[0])
        if winutil.IS_WINDOWS and not exe.is_file():
            raise CaptureError("CAPTURE_ENGINE_NOT_FOUND", f"eseguibile di cattura non trovato: {exe}")
        meta = {"command": self.command, "engine": request.get("engine", "dumpcap"), "mode": request.get("mode"),
                "interface": request["interface"], "requested_at_utc": iso_utc(),
                "note": "Il reperto è prodotto da questo comando. La GUI di Wireshark (se presente) è solo una "
                        "vista di controllo e non scrive nella cartella del caso."}
        (self.case_dir / "metadata" / "capture-command.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self._stderr = open(self.case_dir / "logs" / "dumpcap-stderr.log", "ab")
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": self._stderr, "stdin": subprocess.DEVNULL,
                  "cwd": str(self.network_dir)}
        if winutil.IS_WINDOWS:
            # Console propria (nascosta) così CTRL+C può essere indirizzato solo a dumpcap.
            kwargs["creationflags"] = winutil.CREATE_NEW_CONSOLE
            kwargs["startupinfo"] = winutil.hidden_startupinfo()
        try:
            self.proc = self._popen(self.command, **kwargs)
        except OSError as exc:
            raise CaptureError("CAPTURE_START_FAILED", f"avvio del motore di cattura fallito: {exc}") from exc
        self.events.emit(EventType.WIRESHARK_STARTED, component="capture",
                         data={"pid": self.proc.pid, "command": self.command})
        gui_pid = None
        if request.get("mode", "dual") == "dual":
            gui_pid = self._start_gui(request)
        return {"engine_pid": self.proc.pid, "gui_pid": gui_pid, "command": self.command}

    def _start_gui(self, request: dict) -> int | None:
        cmd = build_gui_command(self.settings, request)
        try:
            if winutil.IS_WINDOWS and not Path(cmd[0]).is_file():
                raise OSError(f"{cmd[0]} non trovato")
            self.gui = self._popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL, cwd=str(Path.home()))
        except OSError as exc:
            self.events.emit(EventType.WARNING, severity=Severity.WARNING, component="capture",
                             message=f"GUI Wireshark non avviata: {exc}. La cattura del reperto prosegue.")
            return None
        self.events.emit(EventType.WIRESHARK_GUI_STARTED, component="capture",
                         data={"pid": self.gui.pid, "command": cmd})
        return self.gui.pid

    # --------------------------------------------------------------- stato
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def status(self) -> dict:
        with self._lock:
            files, packets, total, ifnames = [], 0, 0, set()
            for f in sorted(self.network_dir.glob("capture_*.pcapng")):
                reader = self._readers.setdefault(f.name, IncrementalPcapngReader(f))
                s = reader.update()
                size = f.stat().st_size
                files.append({"path": f"network/{f.name}", "size": size, "packets": s.packets,
                              "interfaces": s.interface_names, "valid": s.valid, "error": s.error})
                packets += s.packets
                total += size
                ifnames.update(s.interface_names)
        rc = None if self.proc is None else self.proc.poll()
        return {"running": self.running(), "returncode": rc, "files": files, "packets": packets, "bytes": total,
                "interfaces": sorted(ifnames), "gui_running": self.gui is not None and self.gui.poll() is None,
                "stderr_tail": self._stderr_tail()}

    def _stderr_tail(self, n: int = 2000) -> str:
        p = self.case_dir / "logs" / "dumpcap-stderr.log"
        try:
            data = p.read_bytes()[-n:]
            return data.decode("utf-8", errors="replace")
        except OSError:
            return ""

    # --------------------------------------------------------------- arresto
    @staticmethod
    def _send_ctrl_c(pid: int) -> bool:
        if not winutil.IS_WINDOWS:
            import os
            import signal
            try:
                os.kill(pid, signal.SIGINT)
                return True
            except OSError:
                return False
        # Eseguito per percorso (script autonomo, solo stdlib): funziona anche con pythonw e bundle.
        from . import ctrlc
        rc, _, _ = winutil.run([sys.executable, str(Path(ctrlc.__file__)), str(pid)], timeout=30)
        return rc == 0

    def stop(self, timeout: float) -> dict:
        result = {"stopped": False, "graceful": False, "returncode": None}
        if self.proc is None:
            result.update(stopped=True, note="cattura mai avviata")
            return result
        if self.proc.poll() is None:
            sent = self._stopper(self.proc.pid)
            try:
                self.proc.wait(timeout=timeout)
                result["graceful"] = sent
            except subprocess.TimeoutExpired:
                self.events.emit(EventType.WARNING, severity=Severity.WARNING, component="capture",
                                 message="dumpcap non ha risposto a CTRL+C: arresto forzato")
                winutil.kill_tree(self.proc.pid, force=True)
                try:
                    self.proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    pass
        else:
            result["note"] = "il processo di cattura era già terminato"
        result["returncode"] = self.proc.poll()
        result["stopped"] = result["returncode"] is not None
        if self._stderr:
            self._stderr.close()
        self.stopped = True
        return result

    def stop_gui(self) -> dict:
        if self.gui is None or self.gui.poll() is not None:
            return {"stopped": True, "running_before": False}
        # La GUI cattura su file temporaneo proprio (non reperto): chiusura forzata per evitare
        # il dialogo "salvare i pacchetti?" che bloccherebbe l'arresto.
        winutil.kill_tree(self.gui.pid, force=True)
        try:
            self.gui.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
        return {"stopped": self.gui.poll() is not None, "running_before": True, "forced": True}
