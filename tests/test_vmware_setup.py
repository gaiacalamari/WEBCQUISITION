import ipaddress
import json

import pytest

from tests.conftest import VirtualClock
from tests.vmware_fakes import VMX_TEMPLATE, WIN_DHCP_CONF, FakeAgentClient, FakeVmrun
from webcquisition.config import load_config
from webcquisition.providers import VMwareProvider
from webcquisition.providers.vmware import parse_vmx, vmx_nics
from webcquisition.vmware_setup import (
    SetupError,
    SetupOptions,
    VmwareSetup,
    network_fix_updates,
    network_problems,
    parse_vmnet_dhcp,
    plan_addresses,
)
from webcquisition_common.events import read_events, verify_chain

PASSWORD = "Password-Guest-123!"


def test_parse_windows_dhcp_conf():
    host, nets = parse_vmnet_dhcp(WIN_DHCP_CONF, "vmnet1")
    assert host == "192.168.150.1" and ipaddress.IPv4Network("192.168.150.0/24") in nets
    assert parse_vmnet_dhcp(WIN_DHCP_CONF, "vmnet8")[0] == "192.168.44.1"


def test_plan_addresses():
    net = ipaddress.IPv4Network("192.168.150.0/24")
    assert plan_addresses("192.168.150.1", net, None) == ("192.168.150.10", 24)
    assert plan_addresses("192.168.150.10", net, None)[0] == "192.168.150.11"
    for bad in ("192.168.151.5", "192.168.150.1", "192.168.150.255"):
        with pytest.raises(SetupError):
            plan_addresses("192.168.150.1", net, bad)


def test_network_problems_and_fix():
    text = VMX_TEMPLATE.replace('ethernet1.connectionType = "hostonly"', 'ethernet1.connectionType = "bridged"')
    text += 'ethernet2.present = "TRUE"\n'
    kv = parse_vmx(text)
    probs = network_problems(vmx_nics(kv))
    assert len(probs) == 2
    fixed = {**kv, **{k.lower(): v for k, v in network_fix_updates(kv).items() if v is not None}}
    assert network_problems(vmx_nics(fixed)) == []


def _setup(tmp_path, fake, **kw):
    dhcp = tmp_path / "vmnetdhcp.conf"
    dhcp.write_text(WIN_DHCP_CONF)
    opts = SetupOptions(vmx=str(fake.vmx), guest_user="admin", guest_password=PASSWORD, operator_user="forensic",
                        config_out=tmp_path / "conf" / "webcquisition.yaml", token_file=tmp_path / "conf" / "agent.token",
                        cases_dir=str(tmp_path / "Cases"), **kw)
    clock = VirtualClock()
    client = FakeAgentClient(fake, interactive_after=2)
    out = []
    s = VmwareSetup(opts, VMwareProvider(runner=fake, executable="vmrun"), client_factory=lambda url, tok: client,
                    out=out.append, sleep=clock.sleep, monotonic=clock.monotonic, dhcp_paths=[str(dhcp)])
    return s, opts, out


def test_setup_end_to_end(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware")
    s, opts, out = _setup(tmp_path, fake)
    report = s.run()
    assert report["ok"] and "webcq-clean" in fake.snapshots and not fake.running
    cfg = load_config(opts.config_out)
    assert cfg.hypervisor.provider == "vmware" and cfg.hypervisor.vm_name == str(fake.vmx)
    assert cfg.hypervisor.vm_uuid == "564d3c5e2a1b9f078c44a1b2c3d4e5f6"
    assert cfg.agent.url == "http://192.168.150.10:8765" and cfg.agent.expected_agent_id == fake.agent_id
    assert cfg.capture.interface == "WEBCQ-Acquisizione"
    assert fake.params["control_ip"] == "192.168.150.10" and fake.params["host_ip"] == "192.168.150.1"
    token = opts.token_file.read_text().strip()
    assert len(token) >= 32
    # nessun segreto nei documenti prodotti
    rep_text = s.report_path.read_text()
    ev_path = s.events_path
    assert s.report_path.name.startswith("webcquisition.yaml.setup-")
    for secret in (PASSWORD, token):
        assert secret not in rep_text and secret not in ev_path.read_text()
        assert secret not in "\n".join(out)
    assert verify_chain(ev_path)["valid"]
    assert read_events(ev_path)[-1]["event"] == "VM_SETUP_COMPLETED"
    # i file sensibili non restano nel guest
    work = fake._gpath(r"C:\Windows\Temp\webcq-setup")
    assert not (work / "agent.json").exists() and not (work / "operator.pw").exists()
    # ordine: snapshot solo dopo lo spegnimento finale
    cmds = [c[7] if "-gu" in c else c[3] for c in fake.calls if len(c) > 3]
    assert cmds.index("snapshot") > max(i for i, c in enumerate(cmds) if c == "stop")


def test_setup_refuses_existing_config(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware")
    s, opts, _ = _setup(tmp_path, fake)
    opts.config_out.parent.mkdir(parents=True)
    opts.config_out.write_text("x")
    with pytest.raises(SetupError) as e:
        s.run()
    assert e.value.code == "CONFIG_EXISTS" and not fake.running


def test_setup_refuses_running_vm(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware")
    fake.running = True
    s, _, _ = _setup(tmp_path, fake)
    with pytest.raises(SetupError) as e:
        s.run()
    assert e.value.code == "VM_NOT_OFF"


def test_setup_network_layout_requires_fix(tmp_path):
    bad = VMX_TEMPLATE.replace('ethernet1.present = "TRUE"', 'ethernet1.present = "FALSE"')
    fake = FakeVmrun(tmp_path / "vmware", bad)
    s, _, _ = _setup(tmp_path, fake)
    with pytest.raises(SetupError) as e:
        s.run()
    assert e.value.code == "NETWORK_LAYOUT"


def test_setup_fix_network(tmp_path):
    bad = VMX_TEMPLATE.replace('ethernet1.connectionType = "hostonly"', 'ethernet1.connectionType = "bridged"')
    fake = FakeVmrun(tmp_path / "vmware", bad)
    s, _, _ = _setup(tmp_path, fake, fix_network=True)
    assert s.run()["ok"]
    assert list(fake.vmx.parent.glob("*.webcq-backup-*"))
    assert 'ethernet1.connectionType = "hostonly"' in fake.vmx.read_text()


def test_setup_guest_failure_no_snapshot(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", guest_mode="fail")
    s, opts, _ = _setup(tmp_path, fake)
    with pytest.raises(SetupError) as e:
        s.run()
    assert e.value.code == "PYTHON_NOT_FOUND"
    assert fake.snapshots == [] and not opts.config_out.exists()
    rep = json.loads(s.report_path.read_text())
    assert rep["ok"] is False and "PYTHON_NOT_FOUND" in rep["error"]


def test_setup_not_elevated_then_manual(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", guest_mode="not_elevated")
    fake.manual_run_after_fetches = 3  # l'operatore esegue lo script a mano dopo qualche secondo
    s, _, out = _setup(tmp_path, fake)
    assert s.run()["ok"]
    assert any("Esegui come amministratore" in line for line in out)


def test_setup_without_tools(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware", guest_mode="no_tools")
    s, _, _ = _setup(tmp_path, fake)
    with pytest.raises(Exception) as e:
        s.run()
    assert "VMware Tools" in str(e.value)


def test_setup_autologon_requires_password(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware")
    s, _, _ = _setup(tmp_path, fake, autologon=True)
    with pytest.raises(SetupError) as e:
        s.run()
    assert e.value.code == "AUTOLOGON_PASSWORD_MISSING"


def test_config_from_setup_drives_acquisition(tmp_path):
    """La configurazione prodotta dal setup è direttamente utilizzabile per un'acquisizione."""
    from webcquisition.case import Case
    from webcquisition.fake_guest import FakeGuestClient
    from webcquisition.orchestrator import Acquisition
    from webcquisition.state import AcquisitionState as S

    fake = FakeVmrun(tmp_path / "vmware")
    s, opts, _ = _setup(tmp_path, fake)
    s.run()
    cfg = load_config(opts.config_out)
    cfg.capture.interface = "auto"  # il FakeGuestClient usa nomi di interfaccia propri
    cfg.agent.expected_agent_id = "fake-agent"
    case = Case.create(tmp_path / "Cases" / "CASE-1", "CASE-1", config_dict=cfg.to_dict())
    clock = VirtualClock()
    acq = Acquisition(case, cfg, VMwareProvider(runner=fake, executable="vmrun"), FakeGuestClient(tmp_path / "g"),
                      sleep=clock.sleep, monotonic=clock.monotonic, out=lambda x: None)
    acq.prepare_and_start()
    acq.monitor_once()
    acq.monitor_once()
    assert acq.finalize() == S.COMPLETED, acq.issues
    acq.close()


def test_setup_runs_guest_script_without_waiting_and_shows_progress(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware")
    s, _, out = _setup(tmp_path, fake)
    s.run()
    assert fake.no_wait
    assert any("guest" in line and "avvio dello script" in line for line in out)
    assert any(d.endswith("setup-result.json") for d in fake.deleted)  # niente risultati di tentativi precedenti


def test_setup_ignores_stale_result_from_previous_run(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware")
    work = fake._gpath(r"C:\Windows\Temp\webcq-setup")
    work.mkdir(parents=True)
    (work / "setup-result.json").write_text(json.dumps({"ok": False, "code": "PYTHON_NOT_FOUND", "run_id": "vecchio"}))
    s, _, _ = _setup(tmp_path, fake)
    assert s.run()["ok"]


def test_setup_guest_timeout(tmp_path):
    fake = FakeVmrun(tmp_path / "vmware")
    fake._simulate_guest_setup = lambda: 0  # lo script non termina mai
    s, opts, _ = _setup(tmp_path, fake)
    opts.guest_setup_timeout_s = 60
    with pytest.raises(SetupError) as e:
        s.run()
    assert e.value.code == "GUEST_SETUP_TIMEOUT"
