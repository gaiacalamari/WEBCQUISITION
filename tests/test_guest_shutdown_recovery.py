"""Spegnimento di Windows come fine acquisizione, recupero dopo VM spenta, avvio bloccato di vmrun."""

import pytest

from tests.agent_fakes import make_session
from tests.conftest import VirtualClock, base_config
from tests.vmware_fakes import FakeVmrun, power_off_hard, suspend
from webcquisition.case import Case
from webcquisition.config import config_from_dict
from webcquisition.fake_guest import FakeGuestClient
from webcquisition.orchestrator import Acquisition
from webcquisition.providers import ProviderError, VMwareProvider
from webcquisition.state import AcquisitionState as S
from webcquisition_agent.session import AgentAPIError
from webcquisition_common import protocol as P
from webcquisition_common.events import read_events, verify_chain


def _acq(tmp_path, options=None):
    fake = FakeVmrun(tmp_path / "vmware", snapshots=["webcq-clean"])
    cfg = config_from_dict(base_config(hypervisor={
        "provider": "vmware", "vm_name": str(fake.vmx), "snapshot": "webcq-clean", "vm_uuid": "564d3c5e2a1b9f078c44a1b2c3d4e5f6",
        "expected_nics": {"1": "nat", "2": "hostonly"}}))
    case = Case.create(tmp_path / "Cases" / "CASE001", "CASE001", config_dict=cfg.to_dict())
    guest = FakeGuestClient(tmp_path / "guest", options=options)
    guest.link = fake
    clock = VirtualClock()
    out = []
    acq = Acquisition(case, cfg, VMwareProvider(runner=fake, executable="vmrun"), guest,
                      sleep=clock.sleep, monotonic=clock.monotonic, out=out.append)
    return acq, fake, guest, case, out


def _cmds(fake):
    return [c[3] for c in fake.calls if len(c) > 3]


def _run_until(acq, wanted, limit=20):
    for _ in range(limit):
        r = acq.monitor_once()
        if r == wanted:
            return r
    raise AssertionError(f"'{wanted}' non raggiunto")


# ------------------------------------------------------------ orchestratore
def test_default_start_page_is_time_is(tmp_path):
    acq, fake, guest, case, _ = _acq(tmp_path)
    acq.prepare_and_start()
    assert acq.cfg.browser.start_url == "https://time.is"
    acq.close()


def test_windows_shutdown_ends_acquisition_and_copies_folder(tmp_path):
    acq, fake, guest, case, _ = _acq(tmp_path, {"guest_shutdown_after_status_calls": 2})
    acq.prepare_and_start()
    _run_until(acq, "stop")
    assert acq.session["stop_source"] == "guest_shutdown"
    assert acq.finalize(reason="guest_shutdown") == S.COMPLETED, acq.issues
    assert guest.released and not fake.running
    assert "stop" not in _cmds(fake)  # spenta da Windows, non dall'host
    assert list((case.acquired_dir / "network").glob("*.pcapng"))
    names = [e["event"] for e in read_events(case.events_path)]
    assert names.index("EXPORT_COMPLETED") < names.index("GUEST_SHUTDOWN_RELEASED") < names.index("VM_SHUTDOWN")
    acq.close()


def test_hard_power_off_recovers_folder_without_snapshot(tmp_path):
    acq, fake, guest, case, out = _acq(tmp_path)
    acq.prepare_and_start()
    acq.monitor_once()
    power_off_hard(fake)
    _run_until(acq, "lost")
    final = acq.finalize(reason="vm_lost")
    assert final == S.INCOMPLETE, acq.issues
    codes = {i["code"] for i in acq.issues}
    assert {"VM_LOST", "RECOVERED_AFTER_POWER_LOSS"} <= codes
    cmds = _cmds(fake)
    assert cmds.count("start") == 2 and cmds.count("revertToSnapshot") == 1
    assert cmds.index("revertToSnapshot") < cmds.index("start")  # il ripristino solo PRIMA del primo avvio
    assert list((case.acquired_dir / "network").glob("*.pcapng"))
    assert (case.acquired_dir / P.GUEST_RECOVERY_EVENTS_REL).is_file()
    assert not fake.running
    assert any("SENZA ripristinare lo snapshot" in line for line in out)
    assert verify_chain(case.events_path)["valid"]
    acq.close()


def test_suspended_vm_is_resumed_and_closed_normally(tmp_path):
    acq, fake, guest, case, _ = _acq(tmp_path)
    acq.prepare_and_start()
    acq.monitor_once()
    suspend(fake)
    _run_until(acq, "lost")
    assert acq.finalize(reason="vm_lost") == S.INCOMPLETE, acq.issues
    ev = [e["event"] for e in read_events(case.events_path)]
    assert "RECOVERY_COMPLETED" in ev and "CAPTURE_STOPPED" in ev  # sessione intatta: chiusura ordinata
    assert not (case.acquired_dir / P.GUEST_RECOVERY_EVENTS_REL).exists()
    acq.close()


def test_recovery_disabled(tmp_path):
    acq, fake, guest, case, _ = _acq(tmp_path)
    acq.cfg.finalize.recover_on_vm_loss = False
    acq.prepare_and_start()
    acq.monitor_once()
    power_off_hard(fake)
    _run_until(acq, "lost")
    assert acq.finalize(reason="vm_lost") == S.FAILED
    assert _cmds(fake).count("start") == 1
    acq.close()


# ------------------------------------------------------------ vmrun start bloccato
def test_vmrun_start_hang_but_vm_running(tmp_path):
    fake = FakeVmrun(tmp_path / "vm")
    fake.start_hangs = True
    p = VMwareProvider(runner=fake, executable="vmrun")
    p.start(str(fake.vmx))
    assert fake.running and "non ha risposto" in p.last_start_warning


def test_vmrun_start_hang_vm_off_gives_hint(tmp_path):
    fake = FakeVmrun(tmp_path / "vm")
    fake.start_hangs_vm_off = True
    with pytest.raises(ProviderError) as e:
        VMwareProvider(runner=fake, executable="vmrun").start(str(fake.vmx))
    assert "I Moved It" in str(e.value)


# ------------------------------------------------------------ agent
class FakeGuard:
    def __init__(self, should_block, on_request):
        self.should_block, self.on_request = should_block, on_request
        self.released = False

    def start(self):
        return {"enabled": True, "error": None}

    def release(self):
        self.released = True

    def stop(self):
        self.release()


def _agent(tmp_path):
    clock = VirtualClock()
    s = make_session(tmp_path, guard_factory=FakeGuard, monotonic=clock.monotonic)
    return s, clock


def test_agent_blocks_windows_shutdown_until_release(tmp_path):
    s, clock = _agent(tmp_path)
    s.prepare({"case_id": "CASE001"})
    s.ui_start({"hotkey_enabled": False, "control_panel": False, "block_guest_shutdown": True})
    g = s.guard
    assert not g.should_block()  # l'host non si è ancora fatto sentire
    s.touch_host()
    assert g.should_block()
    g.on_request()  # WM_QUERYENDSESSION
    st = s.status()
    assert st["stop_requested"] and st["stop_source"] == "guest_shutdown"
    clock.sleep(300)  # host scomparso: non si blocca Windows all'infinito
    assert not g.should_block()
    s.touch_host()
    assert s.release()["shutdown_was_requested"] is True
    assert g.released and not g.should_block()


def test_agent_guard_can_be_disabled(tmp_path):
    s, _ = _agent(tmp_path)
    s.prepare({"case_id": "CASE001"})
    out = s.ui_start({"hotkey_enabled": False, "control_panel": False, "block_guest_shutdown": False})
    assert s.guard is None and out["shutdown_guard"]["enabled"] is False


def test_agent_recover_after_reboot(tmp_path):
    s, _ = _agent(tmp_path)
    s.prepare({"case_id": "CASE001"})
    (tmp_path / "Desktop" / "CASE001" / "network" / "cap.pcapng").write_bytes(b"x" * 10)
    s2, _ = _agent(tmp_path)  # nuovo processo agent dopo il riavvio
    r = s2.recover({"case_id": "CASE001"})
    assert r["already_sealed"] is False and s2.stopped
    seal = s2.seal()
    paths = {f["path"] for f in seal["manifest"]["files"]}
    assert "network/cap.pcapng" in paths and P.GUEST_RECOVERY_EVENTS_REL in paths
    with pytest.raises(AgentAPIError):
        s2.recover({"case_id": "CASE001"})


def test_agent_recover_reuses_existing_seal(tmp_path):
    s, _ = _agent(tmp_path)
    s.prepare({"case_id": "CASE001"})
    s.stop({})
    first = s.seal()
    s2, _ = _agent(tmp_path)
    r = s2.recover({"case_id": "CASE001"})
    assert r["already_sealed"] and r["manifest_sha256"] == first["manifest_sha256"]
    assert {f["path"] for f in s2.list_files()["files"]} >= {P.GUEST_MANIFEST_REL, P.GUEST_SUMS_REL}


def test_agent_recover_missing_folder(tmp_path):
    s, _ = _agent(tmp_path)
    with pytest.raises(AgentAPIError) as e:
        s.recover({"case_id": "CASE001"})
    assert e.value.code == "CASE_DIR_NOT_FOUND"


def test_server_records_host_contact(tmp_path):
    import json
    import threading
    import urllib.request

    from tests.agent_fakes import TOKEN, settings
    from webcquisition_agent.server import build_server
    s, _ = _agent(tmp_path)
    srv = build_server(settings(), s, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}{P.HEALTH}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
        json.loads(urllib.request.urlopen(req, timeout=5).read())
        assert s.host_present()
    finally:
        srv.shutdown()
