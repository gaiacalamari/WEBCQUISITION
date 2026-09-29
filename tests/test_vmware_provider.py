import pytest

from tests.conftest import VirtualClock, base_config
from tests.vmware_fakes import VMX_TEMPLATE, FakeVmrun
from webcquisition.case import Case
from webcquisition.config import ConfigError, config_from_dict
from webcquisition.fake_guest import FakeGuestClient
from webcquisition.orchestrator import Acquisition, AcquisitionFailed
from webcquisition.providers import ProviderError, VMState, VMwareProvider, normalize_uuid
from webcquisition.providers.vmware import (
    parse_count_list,
    parse_vmx,
    read_vmx_text,
    set_vmx_values,
    vmx_nics,
)
from webcquisition.state import AcquisitionState as S


@pytest.fixture
def vm(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", snapshots=["webcq-clean"])
    return fake, VMwareProvider(runner=fake, executable="vmrun")


def test_vmx_parsing_and_nics():
    kv = parse_vmx(VMX_TEMPLATE + 'ethernet2.present = "TRUE"\nethernet2.connectionType = "custom"\n'
                   'ethernet2.vnet = "VMnet3"\nethernet2.startConnected = "FALSE"\nethernet3.present = "TRUE"\n')
    nics = vmx_nics(kv)
    assert [(n.index, n.attachment) for n in nics] == [(1, "nat"), (2, "hostonly"), (3, "custom:vmnet3"), (4, "bridged")]
    assert nics[2].connected is False and nics[0].connected is True


def test_vmx_encodings(tmp_path):
    p = tmp_path / "x.vmx"
    p.write_bytes('.encoding = "windows-1252"\ndisplayName = "Città"\n'.encode("cp1252"))
    assert parse_vmx(read_vmx_text(p))["displayname"] == "Città"


def test_set_vmx_values_preserves_other_lines():
    text = 'a = "1"\n# commento\nB.x = "2"\n'
    out = set_vmx_values(text, {"b.X": "3", "c": "4", "a": None})
    assert "# commento" in out and 'B.x = "3"' in out and 'c = "4"' in out and 'a = "1"' not in out


def test_parse_count_list():
    assert parse_count_list("Total snapshots: 2\nuno\ndue\n", "Total snapshots") == ["uno", "due"]
    assert parse_count_list("Total running VMs: 0\n", "Total running VMs") == []


def test_normalize_uuid():
    assert normalize_uuid("56 4d 3c 5e 2a 1b 9f 07-8c 44 a1 b2 c3 d4 e5 f6") == "564d3c5e2a1b9f078c44a1b2c3d4e5f6"


def test_get_info(vm):
    fake, p = vm
    info = p.get_info(str(fake.vmx))
    assert info.name == "Forensic Windows" and info.state == VMState.POWERED_OFF
    assert info.uuid == "564d3c5e2a1b9f078c44a1b2c3d4e5f6"
    assert info.snapshots == ["webcq-clean"]
    p.start(str(fake.vmx))
    assert p.get_info(str(fake.vmx)).state == VMState.RUNNING
    assert p.get_info(str(fake.vmx)).nics[1].mac == "00:0c:29:aa:bb:02"
    assert p.version() == "1.17.0 build-24995812" and p.is_available()


def test_suspended_and_encrypted(tmp_path):
    fake = FakeVmrun(tmp_path / "a", VMX_TEMPLATE + 'checkpoint.vmState = "x.vmss"\n')
    assert VMwareProvider(runner=fake).get_info(str(fake.vmx)).state == VMState.SAVED
    fake2 = FakeVmrun(tmp_path / "b", VMX_TEMPLATE + 'encryption.keySafe = "vmware:key/..."\n')
    with pytest.raises(ProviderError):
        VMwareProvider(runner=fake2).get_info(str(fake2.vmx))


def test_vm_name_must_be_vmx(vm):
    _, p = vm
    with pytest.raises(ProviderError):
        p.get_info("Forensic Windows")


def test_snapshot_rules(vm):
    fake, p = vm
    with pytest.raises(ProviderError):
        p.restore_snapshot(str(fake.vmx), "non-esiste")
    with pytest.raises(ProviderError):
        p.take_snapshot(str(fake.vmx), "webcq-clean")
    fake.snapshots.append("webcq-clean")
    with pytest.raises(ProviderError) as e:
        p.restore_snapshot(str(fake.vmx), "webcq-clean")
    assert "ambiguo" in str(e.value)


def test_tools_wait(vm):
    fake, p = vm
    clock = VirtualClock()
    with pytest.raises(ProviderError):
        p.wait_tools_running(str(fake.vmx), 30, sleep=clock.sleep, monotonic=clock.monotonic)
    p.start(str(fake.vmx))
    p.wait_tools_running(str(fake.vmx), 30, sleep=clock.sleep, monotonic=clock.monotonic)
    assert p.tools_state(str(fake.vmx)) == "running"


def test_player_rejected():
    with pytest.raises(ProviderError):
        VMwareProvider(host_type="player")
    with pytest.raises(ConfigError):
        config_from_dict(base_config(hypervisor={"provider": "vmware", "vm_name": "a.vmx", "vmrun_host_type": "player"}))


def test_config_requires_vmx_path():
    with pytest.raises(ConfigError):
        config_from_dict(base_config(hypervisor={"provider": "vmware", "vm_name": "Forensic Windows"}))


def test_guest_program_exit_code(vm):
    fake, p = vm
    from webcquisition.providers import GuestAuth
    p.start(str(fake.vmx))
    auth = GuestAuth("admin", "segreta")
    p.mkdir_in_guest(str(fake.vmx), auth, r"C:\Windows\Temp\webcq-setup")
    fake.guest_mode = "fail"
    for f in ("setup-params.json", "agent.json", "agent-bundle.zip", "guest-setup.ps1"):
        (fake._gpath(r"C:\Windows\Temp\webcq-setup") / f).write_text("{}")
    assert p.run_in_guest(str(fake.vmx), auth, "powershell.exe", ["-File", "guest-setup.ps1"]) == 1
    assert "segreta" not in repr(auth)


# ---------------------------------------------------------------- orchestratore con provider VMware reale
def _vmware_acq(tmp_path, fake, **hyp):
    h = {"provider": "vmware", "vm_name": str(fake.vmx), "snapshot": "webcq-clean",
         "vm_uuid": "564d3c5e-2a1b-9f07-8c44-a1b2c3d4e5f6", "expected_nics": {"1": "nat", "2": "hostonly"}, **hyp}
    cfg = config_from_dict(base_config(hypervisor=h))
    case = Case.create(tmp_path / "cases" / "CASE-VM-1", "CASE-VM-1", config_dict=cfg.to_dict())
    clock = VirtualClock()
    return Acquisition(case, cfg, VMwareProvider(runner=fake), FakeGuestClient(tmp_path / "guest"),
                       sleep=clock.sleep, monotonic=clock.monotonic, out=lambda s: None)


def test_full_acquisition_with_vmware_provider(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", snapshots=["webcq-clean"])
    acq = _vmware_acq(tmp_path, fake)
    acq.prepare_and_start()
    for _ in range(3):
        acq.monitor_once()
    assert acq.finalize() == S.COMPLETED, acq.issues
    cmds = [c[3] if c[3] != "-gu" else c[7] for c in fake.calls if len(c) > 3]
    assert cmds.index("revertToSnapshot") < cmds.index("start") < cmds.index("stop")
    assert not fake.running
    assert any(i["code"] == "PROVIDER_EXPERIMENTAL" for i in acq.issues)
    acq.close()


def test_vmware_uuid_mismatch(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", snapshots=["webcq-clean"])
    acq = _vmware_acq(tmp_path, fake, vm_uuid="00000000000000000000000000000000")
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert not any("start" in c for c in fake.calls)
    acq.close()


def test_vmware_nic_not_connected(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", VMX_TEMPLATE + 'ethernet0.startConnected = "FALSE"\n', snapshots=["webcq-clean"])
    acq = _vmware_acq(tmp_path, fake)
    with pytest.raises(AcquisitionFailed):
        acq.prepare_and_start()
    assert any(i["code"] == "NETWORK_CONFIG_MISMATCH" for i in acq.issues)
    acq.close()


def test_vmware_soft_stop_fails_then_hard(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", snapshots=["webcq-clean"])
    fake.stop_soft_works = False
    acq = _vmware_acq(tmp_path, fake)
    acq.prepare_and_start()
    acq.monitor_once()
    acq.monitor_once()
    acq.finalize()
    assert not fake.running and any(i["code"] == "VM_FORCED_POWEROFF" for i in acq.issues)
    acq.close()


# ---------------------------------------------------------------- CommandRunner reale
@pytest.mark.skipif(__import__("os").name == "nt", reason="usa sh")
def test_runner_does_not_wait_for_grandchildren():
    """vmrun start gui lascia in vita Workstation, che eredita l'output: non si deve attendere."""
    import time

    from webcquisition.providers import CommandRunner
    t = time.monotonic()
    r = CommandRunner().run(["sh", "-c", "sleep 8 & echo avviata"], timeout=30)
    assert time.monotonic() - t < 4
    assert r.returncode == 0 and "avviata" in r.stdout


@pytest.mark.skipif(__import__("os").name == "nt", reason="usa sh")
def test_runner_timeout_with_grandchildren():
    import time

    from webcquisition.providers import CommandRunner
    t = time.monotonic()
    with pytest.raises(ProviderError):
        CommandRunner().run(["sh", "-c", "sleep 8 & sleep 8"], timeout=1)
    assert time.monotonic() - t < 4


def test_runner_missing_executable():
    from webcquisition.providers import CommandRunner
    with pytest.raises(ProviderError):
        CommandRunner().run(["eseguibile-che-non-esiste-webcq"])
