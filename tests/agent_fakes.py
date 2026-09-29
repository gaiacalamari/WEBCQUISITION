"""Componenti simulati per testare la Session dell'agent su qualsiasi OS."""

from pathlib import Path

from webcquisition_agent.settings import AgentSettings
from webcquisition_common.pcapng import synthetic_pcapng

CAP = r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"
CTL = r"\Device\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
TOKEN = "t" * 48


def settings():
    return AgentSettings.from_dict({"listen_host": "127.0.0.1", "token": TOKEN, "agent_id": "agent-test"})


def interfaces(_s):
    return {"interfaces": [
        {"name": CAP, "friendly_name": "Ethernet", "ipv4": ["10.0.2.15"], "has_default_gateway": True,
         "is_control": False},
        {"name": CTL, "friendly_name": "Ethernet 2", "ipv4": ["192.168.150.10"], "has_default_gateway": False,
         "is_control": True},
    ]}


class FakeProc:
    _pid = 1000

    def __init__(self):
        FakeProc._pid += 1
        self.pid = FakeProc._pid
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class FakeCapture:
    def __init__(self, settings, case_dir, events):
        self.case_dir = Path(case_dir)
        self.proc = None
        self.packets = 0

    def start(self, req):
        self.proc = FakeProc()
        self.iface = req["interface"]
        self._write()
        return {"engine_pid": self.proc.pid, "gui_pid": None, "command": ["dumpcap"]}

    def _write(self):
        (self.case_dir / "network" / "capture_00001_20260101000000.pcapng").write_bytes(
            synthetic_pcapng(self.iface, self.packets, 1_780_000_000.0))

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def status(self):
        if self.running():
            self.packets += 3
            self._write()
        return {"running": self.running(), "returncode": None, "files": [{"path": "network/x"}],
                "packets": self.packets, "bytes": 0, "interfaces": [self.iface], "gui_running": False,
                "stderr_tail": ""}

    def stop(self, timeout):
        self.proc.returncode = 0
        return {"stopped": True, "graceful": True, "returncode": 0}

    def stop_gui(self):
        return {"stopped": True}


class FakeFirefox:
    def __init__(self, settings, case_dir, events):
        self.case_dir = Path(case_dir)
        self.proc = None

    def start(self, req):
        self.proc = FakeProc()
        (self.case_dir / "browser" / "firefox-profile").mkdir()
        (self.case_dir / "tls" / "sslkeylog.log").write_text("CLIENT_RANDOM aa bb\n")
        return {"pid": self.proc.pid, "version": "test", "profile_dir": "x", "command": ["firefox"]}

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self, timeout):
        self.proc.returncode = 0
        return {"stopped": True, "graceful": True, "returncode": 0}


class Disabled:
    def __init__(self, *a, **k):
        pass

    def start(self, *a, **k):
        return {"enabled": False, "error": "test"}

    def stop(self):
        pass


def make_session(tmp_path, **overrides):
    from webcquisition_agent.session import Session
    kw = dict(desktop_fn=lambda: tmp_path / "Desktop", sysinfo_fn=lambda s: {"windows": {"ProductName": "test"}},
              interfaces_fn=interfaces, capture_factory=FakeCapture, firefox_factory=FakeFirefox,
              hotkey_factory=Disabled, panel_factory=Disabled, interactive_fn=lambda: True, durable=False)
    kw.update(overrides)
    (tmp_path / "Desktop").mkdir(exist_ok=True)
    return Session(settings(), **kw)
