import json

import pytest

from tests.agent_fakes import CAP, CTL, make_session
from webcquisition_agent.session import AgentAPIError
from webcquisition_common import protocol as P
from webcquisition_common.events import verify_chain
from webcquisition_common.hashing import sha256_file


def full(s, case_id="CASE-1"):
    s.prepare({"case_id": case_id, "tls": {"enabled": True}})
    s.capture_start({"interface": CAP, "engine": "dumpcap", "mode": "headless"})
    s.firefox_start({})
    s.ui_start({"hotkey_enabled": False, "control_panel": False})
    s.status()
    s.stop({"order": "browser_first"})
    return s.seal()


def test_prepare_creates_structure(tmp_path):
    s = make_session(tmp_path)
    r = s.prepare({"case_id": "CASE-1"})
    d = tmp_path / "Desktop" / "CASE-1"
    assert r["guest_case_dir"] == str(d)
    for sub in P.GUEST_SUBDIRS:
        assert (d / sub).is_dir()
    assert (d / "tls" / "sslkeylog.log").is_file()
    assert json.loads((d / "metadata" / "sysinfo.json").read_text())["windows"]["ProductName"] == "test"


def test_existing_case_dir_rejected(tmp_path):
    (tmp_path / "Desktop" / "CASE-1").mkdir(parents=True)
    with pytest.raises(AgentAPIError) as e:
        make_session(tmp_path).prepare({"case_id": "CASE-1"})
    assert e.value.code == "CASE_DIR_EXISTS"


def test_one_session_only(tmp_path):
    s = make_session(tmp_path)
    s.prepare({"case_id": "CASE-1"})
    with pytest.raises(AgentAPIError) as e:
        s.prepare({"case_id": "CASE-2"})
    assert e.value.code == "SESSION_ACTIVE"


@pytest.mark.parametrize("bad", ["../x", "..\\x", "C:\\Windows", "CON"])
def test_invalid_case_id(tmp_path, bad):
    with pytest.raises(AgentAPIError):
        make_session(tmp_path).prepare({"case_id": bad})


def test_control_interface_refused(tmp_path):
    s = make_session(tmp_path)
    s.prepare({"case_id": "CASE-1"})
    with pytest.raises(AgentAPIError) as e:
        s.capture_start({"interface": CTL})
    assert e.value.code == "INTERFACE_IS_CONTROL"
    with pytest.raises(AgentAPIError) as e:
        s.capture_start({"interface": r"\Device\NPF_{nope}"})
    assert e.value.code == "INTERFACE_NOT_FOUND"


def test_firefox_requires_capture(tmp_path):
    s = make_session(tmp_path)
    s.prepare({"case_id": "CASE-1"})
    with pytest.raises(AgentAPIError) as e:
        s.firefox_start({})
    assert e.value.code == "CAPTURE_NOT_RUNNING"


def test_seal_requires_stop(tmp_path):
    s = make_session(tmp_path)
    s.prepare({"case_id": "CASE-1"})
    with pytest.raises(AgentAPIError) as e:
        s.seal()
    assert e.value.code == "SESSION_NOT_STOPPED"


def test_full_session_and_manifest(tmp_path):
    s = make_session(tmp_path)
    seal = full(s)
    d = tmp_path / "Desktop" / "CASE-1"
    assert sha256_file(d / P.GUEST_MANIFEST_REL)[0] == seal["manifest_sha256"]
    paths = {f["path"] for f in s.list_files()["files"]}
    assert {"logs/guest-events.jsonl", "tls/sslkeylog.log", P.GUEST_MANIFEST_REL, P.GUEST_SUMS_REL} <= paths
    assert any(p.startswith("network/") for p in paths)
    assert verify_chain(d / "logs" / "guest-events.jsonl")["valid"]
    # il log è chiuso: il suo hash nel manifest resta valido
    entry = next(f for f in seal["manifest"]["files"] if f["path"] == "logs/guest-events.jsonl")
    assert sha256_file(d / "logs" / "guest-events.jsonl")[0] == entry["sha256"]
    with pytest.raises(AgentAPIError):
        s.seal()


def test_download_whitelist(tmp_path):
    s = make_session(tmp_path)
    with pytest.raises(AgentAPIError):
        s.open_file("tls/sslkeylog.log")  # non sigillata
    full(s)
    path, size = s.open_file("tls/sslkeylog.log")
    assert size == path.stat().st_size
    for bad in ("../../etc/passwd", "..\\..\\x", "C:/Windows/win.ini", "/etc/passwd", "metadata/../../x"):
        with pytest.raises(AgentAPIError) as e:
            s.open_file(bad)
        assert e.value.code == "PATH_UNSAFE"
    (tmp_path / "Desktop" / "CASE-1" / "operator" / "late.txt").write_text("dopo il sigillo")
    with pytest.raises(AgentAPIError) as e:
        s.open_file("operator/late.txt")
    assert e.value.code == "FILE_NOT_IN_MANIFEST"


def test_panel_stop_request_visible_in_status(tmp_path):
    s = make_session(tmp_path)
    s.prepare({"case_id": "CASE-1"})
    s.request_stop("panel")
    st = s.status()
    assert st["stop_requested"] and st["stop_source"] == "panel"


def test_stop_order_validated(tmp_path):
    s = make_session(tmp_path)
    s.prepare({"case_id": "CASE-1"})
    with pytest.raises(AgentAPIError):
        s.stop({"order": "whatever"})


def test_health(tmp_path):
    h = make_session(tmp_path).health()
    assert h["agent_id"] == "agent-test" and h["protocol"] == 1 and h["session_active"] is False
