import json

import pytest

from webcquisition_common.events import EventChainError, EventLog, EventType, Severity, read_events, verify_chain


def _log(tmp_path, n=3):
    p = tmp_path / "events.jsonl"
    with EventLog(p, "CASE-1", "host", durable=False) as log:
        for i in range(n):
            log.emit(EventType.USER_ACTION, data={"i": i})
    return p


def test_event_fields(tmp_path):
    p = _log(tmp_path, 1)
    ev = read_events(p)[0]
    for key in ("schema_version", "seq", "timestamp", "event", "severity", "case_id", "source", "prev_hash", "hash"):
        assert key in ev
    assert ev["timestamp"].endswith("Z")
    assert ev["seq"] == 1 and ev["prev_hash"] == "0" * 64


def test_chain_valid(tmp_path):
    p = _log(tmp_path, 5)
    r = verify_chain(p)
    assert r["valid"] and r["count"] == 5


def test_chain_detects_modification(tmp_path):
    p = _log(tmp_path, 3)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["data"]["i"] = 99
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    assert not verify_chain(p)["valid"]


def test_chain_detects_deletion(tmp_path):
    p = _log(tmp_path, 3)
    lines = p.read_text().splitlines()
    p.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not verify_chain(p)["valid"]


def test_reopen_continues_chain(tmp_path):
    p = _log(tmp_path, 2)
    with EventLog(p, "CASE-1", "host", durable=False) as log:
        rec = log.emit(EventType.WARNING, severity=Severity.WARNING)
    assert rec["seq"] == 3
    assert verify_chain(p)["valid"]


def test_refuses_to_append_to_tampered_log(tmp_path):
    p = _log(tmp_path, 2)
    p.write_text(p.read_text().replace('"i": 0', '"i": 7'))
    with pytest.raises(EventChainError):
        EventLog(p, "CASE-1", "host")


def test_unknown_event_rejected(tmp_path):
    with EventLog(tmp_path / "e.jsonl", "C", "host", durable=False) as log:
        with pytest.raises(ValueError):
            log.emit("NON_ESISTE")


def test_required_events_exist():
    for name in ("CASE_CREATED", "VM_START_REQUESTED", "VM_STARTED", "VM_READY", "CASE_DIRECTORY_CREATED",
                 "TLS_KEYLOG_INITIALIZED", "WIRESHARK_START_REQUESTED", "WIRESHARK_STARTED", "CAPTURE_STARTED",
                 "FIREFOX_STARTED", "SCREENSHOT_CREATED", "USER_ACTION", "CAPTURE_STOP_REQUESTED",
                 "CAPTURE_STOPPED", "FIREFOX_STOPPED", "VM_SHUTDOWN_REQUESTED", "VM_SHUTDOWN", "EXPORT_STARTED",
                 "EXPORT_COMPLETED", "HASH_CALCULATED", "CASE_COMPLETED", "ERROR"):
        EventType(name)
