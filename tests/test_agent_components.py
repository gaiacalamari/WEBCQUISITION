import json
import struct
import zlib
from pathlib import Path

import pytest

from tests.agent_fakes import settings
from webcquisition_agent import capture, firefox, hotkey, interfaces, screenshot, watcher
from webcquisition_agent.settings import AgentConfigError, AgentSettings
from webcquisition_common.events import EventLog, read_events

DUMPCAP_D = r"""1. \Device\NPF_{11111111-2222-3333-4444-555555555555} (Ethernet)
2. \Device\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} (Ethernet 2)
3. \Device\NPF_Loopback (Adapter for loopback traffic capture)
4. etwdump (Event Tracing for Windows (ETW) reader)
"""
ADAPTERS = json.dumps([
    {"Name": "Ethernet", "Guid": "{11111111-2222-3333-4444-555555555555}", "IPv4": ["10.0.2.15"], "Gateway": True},
    {"Name": "Ethernet 2", "Guid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", "IPv4": "192.168.150.10",
     "Gateway": False},
])


def test_parse_and_merge_interfaces():
    d = interfaces.parse_dumpcap_list(DUMPCAP_D)
    assert len(d) == 4 and d[0]["guid"] == "11111111-2222-3333-4444-555555555555"
    merged = interfaces.merge_interfaces(d, interfaces.parse_adapters_json(ADAPTERS), "192.168.150.10")
    eth, ctl = merged[0], merged[1]
    assert eth["friendly_name"] == "Ethernet" and eth["has_default_gateway"] and not eth["is_control"]
    assert ctl["is_control"] and ctl["ipv4"] == ["192.168.150.10"]
    assert merged[2]["friendly_name"].startswith("Adapter for loopback")


def test_parse_single_adapter_object():
    one = json.dumps({"Name": "Ethernet", "Guid": "{11111111-2222-3333-4444-555555555555}", "IPv4": None})
    assert interfaces.parse_adapters_json(one)[0]["ipv4"] == []


def test_agent_settings_validation():
    base = {"listen_host": "192.168.150.10", "token": "x" * 40, "agent_id": "a"}
    AgentSettings.from_dict(base)
    for bad in ({**base, "listen_host": "0.0.0.0"}, {**base, "token": "short"}, {**base, "extra": 1},
                {k: v for k, v in base.items() if k != "agent_id"}):
        with pytest.raises(AgentConfigError):
            AgentSettings.from_dict(bad)


def test_capture_command(tmp_path):
    cmd = capture.build_command(settings(), {"interface": "IF", "engine": "dumpcap", "ring_filesize_mb": 100,
                                             "capture_filter": "not arp"}, tmp_path)
    assert cmd[1:5] == ["-i", "IF", "-w", str(tmp_path / "capture.pcapng")]
    assert "filesize:102400" in cmd and "-f" in cmd
    assert not any(a.startswith("files:") for a in cmd)  # nessuna cancellazione di file ruotati
    t = capture.build_command(settings(), {"interface": "IF", "engine": "tshark"}, tmp_path)
    assert t[0].endswith("tshark.exe") and "pcapng" in t
    with pytest.raises(capture.CaptureError):
        capture.build_command(settings(), {"interface": "IF", "engine": "tcpdump"}, tmp_path)


def test_firefox_prefs_and_env(tmp_path):
    prefs = firefox.effective_prefs({"extra_prefs": {"browser.cache.disk.enable": False}})
    assert prefs["network.trr.mode"] == 5 and prefs["network.http.http3.enable"] is False
    assert prefs["network.dns.echconfig.enabled"] is False and prefs["browser.cache.disk.enable"] is False
    js = firefox.build_user_js(prefs)
    assert 'user_pref("network.trr.mode", 5);' in js
    assert "network.trr.mode" not in firefox.effective_prefs({"disable_doh": False})
    with pytest.raises(firefox.FirefoxError):
        firefox.effective_prefs({"extra_prefs": {"x": [1]}})
    env = firefox.build_env({"SSLKEYLOGFILE": "C:\\altrove.log", "PATH": "p"}, tmp_path / "k.log")
    assert env["SSLKEYLOGFILE"] == str(tmp_path / "k.log") and env["PATH"] == "p"
    assert "SSLKEYLOGFILE" not in firefox.build_env({"SSLKEYLOGFILE": "x"}, None)
    cmd = firefox.build_command("firefox.exe", tmp_path, "about:blank")
    assert "-no-remote" in cmd and "-profile" in cmd and "-wait-for-browser" in cmd


def _png_size_and_pixels(png: bytes):
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, w, h = 8, b"", None, None
    while pos < len(png):
        n = struct.unpack(">I", png[pos:pos + 4])[0]
        tag, data = png[pos + 4:pos + 8], png[pos + 8:pos + 8 + n]
        crc = struct.unpack(">I", png[pos + 8 + n:pos + 12 + n])[0]
        assert crc == zlib.crc32(tag + data) & 0xFFFFFFFF
        if tag == b"IHDR":
            w, h = struct.unpack(">II", data[:8])
        if tag == b"IDAT":
            idat += data
        pos += 12 + n
    return w, h, zlib.decompress(idat)


def test_png_encoder():
    rgb = bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 10, 20, 30])
    w, h, raw = _png_size_and_pixels(screenshot.encode_png_rgb(2, 2, rgb, {"Software": "WEBCQUISITION"}))
    assert (w, h) == (2, 2)
    assert raw == b"\x00" + rgb[:6] + b"\x00" + rgb[6:]
    assert screenshot.bgra_to_rgb(bytes([1, 2, 3, 255])) == bytes([3, 2, 1])


def test_screenshot_service(tmp_path):
    (tmp_path / "screenshots").mkdir()
    with EventLog(tmp_path / "e.jsonl", "C", "guest", durable=False) as log:
        svc = screenshot.ScreenshotService(tmp_path, log, grabber=lambda: (1, 1, b"\x00\x00\x00", {}),
                                           title_fn=lambda: "Firefox")
        m1, m2 = svc.take("hotkey"), svc.take("panel")
    assert (m1["file"], m2["file"]) == ("screenshot-0001.png", "screenshot-0002.png")
    meta = json.loads((tmp_path / "screenshots" / "screenshot-0002.json").read_text())
    assert meta["trigger"] == "panel" and meta["foreground_window_title"] == "Firefox" and len(meta["sha256"]) == 64
    assert svc.count() == 2
    assert [e["event"] for e in read_events(tmp_path / "e.jsonl")] == ["SCREENSHOT_CREATED"] * 2


@pytest.mark.parametrize("spec,expected", [("ctrl+alt+s", (0x4003, ord("S"))), ("win+shift+f9", (0x400C, 0x78)),
                                           ("ctrl+printscreen", (0x4002, 0x2C))])
def test_parse_hotkey(spec, expected):
    assert hotkey.parse_hotkey(spec) == expected


@pytest.mark.parametrize("spec", ["s", "ctrl+", "hyper+s", "ctrl+tastoinesistente"])
def test_parse_hotkey_invalid(spec):
    with pytest.raises(ValueError):
        hotkey.parse_hotkey(spec)


def test_watcher(tmp_path):
    (tmp_path / "operator").mkdir()
    (tmp_path / "README.txt").write_text("agent")
    with EventLog(tmp_path / "logs" / "e.jsonl", "C", "guest", durable=False) as log:
        w = watcher.OperatorFileWatcher(tmp_path, log)
        (tmp_path / "nota.txt").write_text("uno")
        (tmp_path / "operator" / "download.pdf").write_bytes(b"%PDF")
        w.scan()
        assert w.count() == 0  # attende stabilità
        w.scan()
        assert w.count() == 2
        (tmp_path / "nota.txt").write_text("due, modificata")
        w.scan(final=True)
    evs = read_events(tmp_path / "logs" / "e.jsonl")
    assert [e["event"] for e in evs].count("OPERATOR_FILE_DETECTED") == 2
    assert evs[-1]["event"] == "OPERATOR_FILE_MODIFIED" and evs[-1]["data"]["path"] == "nota.txt"
    assert not any(e["data"]["path"] == "README.txt" for e in evs)


def test_bundle_script(tmp_path):
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "bundle"
    subprocess.run([sys.executable, str(root / "scripts" / "build-agent-bundle.py"), "--out", str(out)], check=True)
    assert (out / "lib" / "webcquisition_agent" / "session.py").is_file()
    assert (out / "run_agent.pyw").is_file() and (out / "BUNDLE-SHA256SUMS.txt").is_file()
    # il bundle agent non dipende dal pacchetto host
    for p in (out / "lib").rglob("*.py"):
        assert "import webcquisition." not in p.read_text() and "from webcquisition." not in p.read_text()
