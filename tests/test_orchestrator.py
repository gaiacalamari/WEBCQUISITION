"""Workflow completo e gestione degli errori con hypervisor e agent simulati."""

import json

import pytest

from tests.conftest import base_config
from webcquisition.orchestrator import AcquisitionFailed, InterfaceSelectionError, select_interface
from webcquisition.providers import VMState
from webcquisition.state import AcquisitionState as S
from webcquisition_common.events import read_events, verify_chain
from webcquisition_common.hashing import parse_sha256sums, verify_entries


def codes(acq):
    return {i["code"] for i in acq.issues}


def events(acq):
    return [e["event"] for e in read_events(acq.case.events_path)]


def run_ok(acq, polls=3):
    acq.prepare_and_start()
    for _ in range(polls):
        acq.monitor_once()
    return acq.finalize(reason="operator_stop")


# ------------------------------------------------------------------ successo
def test_full_workflow_completed(make_acq):
    acq, provider, guest = make_acq()
    final = run_ok(acq)
    assert final == S.COMPLETED, acq.issues
    case = acq.case.dir
    manifest = json.loads((case / "acquisition.json").read_text())
    assert manifest["acquisition"]["state"] == "COMPLETED"
    assert manifest["case"]["case_id"] == "CASE-2026-001" and manifest["case"]["operator"]
    for k in ("started_at_utc", "finished_at_utc", "host_timezone", "guest_timezone"):
        assert k in manifest["acquisition"]
    for section in ("host", "hypervisor", "guest", "network", "tls", "browser", "integrity", "files", "issues"):
        assert section in manifest
    sums = parse_sha256sums((case / "hashes" / "SHA256SUMS.txt").read_text())
    assert verify_entries(case / "acquired", [{"path": p, "sha256": h} for p, h in sums.items()]) == []
    assert (case / "acquired" / "network").glob("*.pcapng")
    assert (case / "report" / "acquisition-report.html").is_file()
    assert (case / "hashes" / "package-seal.json").is_file()
    assert verify_chain(case / "logs" / "host-events.jsonl")["valid"]
    ev = events(acq)
    order = ["VM_START_REQUESTED", "VM_STARTED", "VM_READY", "CASE_DIRECTORY_CREATED", "TLS_KEYLOG_INITIALIZED",
             "WIRESHARK_START_REQUESTED", "CAPTURE_STARTED", "FIREFOX_STARTED", "CAPTURE_TRAFFIC_VERIFIED",
             "FIREFOX_STOPPED", "CAPTURE_STOPPED", "GUEST_SEALED", "EXPORT_COMPLETED", "INTEGRITY_VERIFIED",
             "VM_SHUTDOWN", "CASE_COMPLETED"]
    idx = [ev.index(e) for e in order]
    assert idx == sorted(idx), list(zip(order, idx, strict=True))
    assert ("restore_snapshot", "clean") in provider.calls
    assert provider.state == VMState.POWERED_OFF


def test_case_acquired_only_once(make_acq):
    acq, _, _ = make_acq()
    run_ok(acq)
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()


def test_browser_first_is_default(make_acq):
    acq, _, _ = make_acq()
    run_ok(acq)
    assert acq.session["stop_result"]["order"] == "browser_first"


def test_exported_files_read_only(make_acq):
    import os
    acq, _, _ = make_acq()
    run_ok(acq)
    pcap = next((acq.case.dir / "acquired" / "network").glob("*.pcapng"))
    assert not os.access(pcap, os.W_OK) or os.name == "nt" or os.geteuid() == 0


# ------------------------------------------------------------------ errori VM
def test_vm_does_not_start(make_acq):
    acq, _, _ = make_acq(provider_kwargs={"failures": {"start_fails"}})
    with pytest.raises(AcquisitionFailed) as e:
        acq.prepare_and_start()
    assert e.value.final_state == S.FAILED
    assert "VM_START_FAILED" in codes(acq)
    assert json.loads((acq.case.dir / "acquisition.json").read_text())["acquisition"]["state"] == "FAILED"


def test_vm_not_ready(make_acq):
    acq, provider, _ = make_acq(guest_options={"never_ready": True})
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert "VM_NOT_READY" in codes(acq)
    assert provider.state == VMState.POWERED_OFF  # la VM avviata viene spenta


def test_agent_unreachable(make_acq):
    acq, _, _ = make_acq(guest_options={"unreachable": True})
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert "VM_NOT_READY" in codes(acq)


def test_vm_uuid_mismatch_blocks_before_start(make_acq):
    acq, provider, _ = make_acq(provider_kwargs={"uuid": "99999999-0000-0000-0000-000000000000"})
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert "VM_IDENTITY_MISMATCH" in codes(acq)
    assert not any(c[0] == "start" for c in provider.calls)


def test_network_mismatch_blocks_before_start(make_acq):
    acq, provider, _ = make_acq(provider_kwargs={"nics": [{"index": 1, "attachment": "bridged"},
                                                          {"index": 2, "attachment": "hostonly"}]})
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert "NETWORK_CONFIG_MISMATCH" in codes(acq)
    assert not any(c[0] == "start" for c in provider.calls)


def test_snapshot_missing(make_acq):
    acq, _, _ = make_acq(provider_kwargs={"snapshots": ["other"]})
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert "SNAPSHOT_NOT_FOUND" in codes(acq)


def test_vm_already_running_rejected(make_acq):
    acq, _, _ = make_acq(provider_kwargs={"state": VMState.RUNNING})
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()


def test_shutdown_hangs_forced_poweroff(make_acq):
    acq, provider, _ = make_acq(provider_kwargs={"failures": {"shutdown_hangs"}})
    final = run_ok(acq)
    assert "VM_FORCED_POWEROFF" in codes(acq)
    assert final == S.COMPLETED or final == S.INCOMPLETE
    assert ("force_poweroff",) in provider.calls


# ------------------------------------------------------------------ errori guest
def test_prepare_error(make_acq):
    acq, _, _ = make_acq(guest_options={"prepare_error": True})
    with pytest.raises(AcquisitionFailed) as e:
        acq.prepare_and_start()
    assert e.value.final_state == S.FAILED


def test_capture_start_error_recovers_material(make_acq):
    acq, _, _ = make_acq(guest_options={"capture_start_error": True})
    with pytest.raises(AcquisitionFailed) as e:
        acq.prepare_and_start()
    assert e.value.final_state == S.FAILED
    assert "NO_VALID_CAPTURE" in codes(acq)
    assert (acq.case.dir / "acquired" / "metadata" / "sysinfo.json").is_file()  # materiale recuperato


def test_capture_interface_mismatch(make_acq):
    acq, _, _ = make_acq(guest_options={"capture_wrong_iface": True})
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert "CAPTURE_INTERFACE_MISMATCH" in codes(acq)


def test_capture_dies_during_acquisition(make_acq):
    acq, _, _ = make_acq(guest_options={"capture_dies": True})
    final = run_ok(acq)
    assert "CAPTURE_PROCESS_DIED" in codes(acq)
    assert final == S.INCOMPLETE


def test_no_traffic(make_acq):
    acq, _, _ = make_acq(guest_options={"no_traffic": True})
    final = run_ok(acq)
    assert "CAPTURE_NO_TRAFFIC" in codes(acq)
    assert final == S.FAILED  # nessun pacchetto nel PCAPNG


def test_firefox_fail(make_acq):
    acq, _, _ = make_acq(guest_options={"firefox_fail": True})
    with pytest.raises(AcquisitionFailed) as e:
        acq.prepare_and_start()
    assert "FIREFOX_START_FAILED" in codes(acq)
    assert e.value.final_state in (S.INCOMPLETE, S.FAILED)


def test_keylog_empty_required(make_acq):
    acq, _, _ = make_acq(guest_options={"keylog_empty": True})
    assert run_ok(acq) == S.INCOMPLETE
    assert "TLS_KEYLOG_EMPTY" in codes(acq)


def test_keylog_empty_not_required(make_acq):
    acq, _, _ = make_acq(guest_options={"keylog_empty": True}, config=base_config(tls={"required": False}))
    assert run_ok(acq) == S.COMPLETED


def test_corrupt_download_retried(make_acq):
    acq, _, _ = make_acq(guest_options={"corrupt_download": {"tls/sslkeylog.log": 1}})
    assert run_ok(acq) == S.COMPLETED
    assert "EXPORT_HASH_MISMATCH" in events(acq)


def test_corrupt_download_persistent(make_acq):
    acq, _, _ = make_acq(guest_options={"corrupt_download": {"tls/sslkeylog.log": 99}})
    assert run_ok(acq) == S.FAILED
    assert "EXPORT_FILE_FAILED" in codes(acq)
    assert not (acq.case.dir / "acquired" / "tls" / "sslkeylog.log").exists()
    assert not list((acq.case.dir / "acquired").rglob("*.partial"))


def test_vm_lost_during_acquisition(make_acq):
    acq, provider, _ = make_acq(guest_options={"unreachable_after_status": 2})
    acq.prepare_and_start()
    provider.crash()
    results = [acq.monitor_once() for _ in range(6)]
    assert "lost" in results
    final = acq.finalize(reason="vm_lost")
    assert final == S.FAILED
    assert {"VM_LOST", "GUEST_FINALIZATION_FAILED"} <= codes(acq)


def test_agent_temporarily_unreachable_is_warning(make_acq):
    acq, _, guest = make_acq()
    acq.prepare_and_start()
    guest.options["unreachable"] = True
    assert acq.monitor_once() is None
    guest.options.pop("unreachable")
    acq.monitor_once()
    assert "AGENT_RECONNECTED" in events(acq)


def test_stop_from_guest_panel(make_acq):
    acq, _, _ = make_acq(guest_options={"stop_after_status_calls": 3})
    final = acq.run_interactive(input_fn=lambda: (_ for _ in ()).throw(EOFError()))
    assert final == S.COMPLETED
    assert acq.session["stop_reason"] == "guest_panel_stop"


def test_post_snapshot_on_failure(make_acq):
    acq, provider, _ = make_acq(guest_options={"no_traffic": True})
    run_ok(acq)
    assert any(c[0] == "take_snapshot" for c in provider.calls)


# ------------------------------------------------------------------ interfacce
IFACES = [
    {"name": "N1", "friendly_name": "Ethernet", "guid": "G1", "has_default_gateway": True, "is_control": False},
    {"name": "N2", "friendly_name": "Ethernet 2", "guid": "G2", "has_default_gateway": False, "is_control": True},
]


def test_select_interface_auto():
    assert select_interface("auto", IFACES)["name"] == "N1"


def test_select_interface_never_control():
    with pytest.raises(InterfaceSelectionError) as e:
        select_interface("Ethernet 2", IFACES)
    assert e.value.code == "INTERFACE_IS_CONTROL"


def test_select_interface_not_found_and_ambiguous():
    with pytest.raises(InterfaceSelectionError):
        select_interface("Wi-Fi", IFACES)
    two = IFACES + [{"name": "N3", "friendly_name": "Ethernet 3", "has_default_gateway": True, "is_control": False}]
    with pytest.raises(InterfaceSelectionError) as e:
        select_interface("auto", two)
    assert e.value.code == "INTERFACE_AMBIGUOUS"
