"""CLI end-to-end in --dry-run e verifica offline del pacchetto."""

import json
import os
import stat

import pytest

from webcquisition import cli


@pytest.fixture(autouse=True)
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_sandbox", lambda case_id: tmp_path / "sandbox" / case_id)


def _acquire(tmp_path, case_id="CASE-CLI-1", extra=()):
    out = tmp_path / "cases" / case_id
    rc = cli.main(["acquire", case_id, "--output", str(out), "--dry-run", "--auto-stop", "0.3",
                   "--operator", "Test", *extra])
    return rc, out


def test_dry_run_end_to_end_and_verify(tmp_path, capsys):
    rc, out = _acquire(tmp_path)
    assert rc == cli.EXIT_OK
    data = json.loads((out / "acquisition.json").read_text())
    assert data["dry_run"] is True and data["acquisition"]["state"] == "COMPLETED"
    capsys.readouterr()
    assert cli.main(["verify", "--output", str(out)]) == cli.EXIT_OK
    assert "[KO]" not in capsys.readouterr().out


def test_verify_detects_tampering(tmp_path, capsys):
    rc, out = _acquire(tmp_path, "CASE-CLI-2")
    pcap = next((out / "acquired" / "network").glob("*.pcapng"))
    os.chmod(pcap, stat.S_IWRITE | stat.S_IREAD)
    with open(pcap, "ab") as fh:
        fh.write(b"manomissione")
    assert cli.main(["verify", "--output", str(out)]) == cli.EXIT_FAILED
    assert "hash_mismatch" in capsys.readouterr().out


def test_verify_detects_report_change(tmp_path):
    rc, out = _acquire(tmp_path, "CASE-CLI-3")
    rep = out / "report" / "acquisition-report.html"
    os.chmod(rep, stat.S_IWRITE | stat.S_IREAD)
    rep.write_text(rep.read_text() + "<!-- x -->")
    assert cli.main(["verify", "--output", str(out)]) == cli.EXIT_FAILED


def test_create_case_twice_refused(tmp_path):
    args = ["create-case", "CASE-CLI-4", "--output", str(tmp_path / "CASE-CLI-4"), "--dry-run"]
    assert cli.main(args) == cli.EXIT_OK
    assert cli.main(args) == cli.EXIT_USAGE


def test_vm_confirmation_mismatch(tmp_path):
    rc, _ = _acquire(tmp_path, "CASE-CLI-5", extra=("--vm", "un-altra-vm"))
    assert rc == cli.EXIT_USAGE


def test_start_status_stop(tmp_path, capsys):
    out = tmp_path / "CASE-CLI-6"
    assert cli.main(["create-case", "CASE-CLI-6", "--output", str(out), "--dry-run"]) == 0
    assert cli.main(["start", "--output", str(out), "--dry-run"]) == 0
    capsys.readouterr()
    assert cli.main(["status", "--output", str(out), "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "ACQUIRING"
    assert cli.main(["stop", "--output", str(out), "--dry-run"]) == 0
    assert cli.main(["start", "--output", str(out), "--dry-run"]) != 0  # un caso si acquisisce una volta sola


def test_real_case_cannot_run_as_dry(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("hypervisor: {provider: vmware, vm_name: v.vmx, snapshot: s}\n", encoding="utf-8")
    out = tmp_path / "CASE-CLI-7"
    assert cli.main(["-c", str(cfg), "create-case", "CASE-CLI-7", "--output", str(out)]) == 0
    assert cli.main(["-c", str(cfg), "run", "--output", str(out), "--dry-run"]) == cli.EXIT_USAGE


def test_gen_token_no_overwrite(tmp_path):
    p = tmp_path / "tok"
    assert cli.main(["gen-token", "--out", str(p)]) == 0
    assert len(p.read_text().strip()) >= 32
    first = p.read_text()
    assert cli.main(["gen-token", "--out", str(p)]) == cli.EXIT_USAGE
    assert p.read_text() == first


def test_example_dry_run_config(tmp_path):
    from pathlib import Path
    cfg = Path(__file__).resolve().parents[1] / "examples" / "dry-run.yaml"
    out = tmp_path / "CASE-DEMO-001"
    rc = cli.main(["-c", str(cfg), "acquire", "CASE-DEMO-001", "--output", str(out), "--dry-run", "--auto-stop", "0.3"])
    assert rc == cli.EXIT_OK


def _vmware_cfg(tmp_path, fake):
    tok = tmp_path / "agent.token"
    tok.write_text("t" * 48)
    cfg = tmp_path / "vmware.yaml"
    cfg.write_text(
        "hypervisor:\n"
        f"  provider: vmware\n  vm_name: '{fake.vmx}'\n  snapshot: webcq-clean\n"
        "  vm_uuid: '56 4d 3c 5e 2a 1b 9f 07-8c 44 a1 b2 c3 d4 e5 f6'\n"
        "  expected_nics: {'1': nat, '2': hostonly}\n  tools_timeout_s: 5\n  shutdown_timeout_s: 5\n"
        f"agent: {{token_file: '{tok}', expected_agent_id: agent-x, ready_timeout_s: 5}}\n"
        "capture: {interface: WEBCQ-Acquisizione}\n", encoding="utf-8")
    return cfg


def test_check_env_vmware(tmp_path, monkeypatch, capsys):
    from tests.vmware_fakes import FakeAgentClient, FakeVmrun
    from webcquisition.providers import VMwareProvider
    fake = FakeVmrun(tmp_path / "vm", snapshots=["webcq-clean"])
    fake.agent_id = "agent-x"
    monkeypatch.setattr(cli, "provider_from_config", lambda h: VMwareProvider(runner=fake, executable="vmrun"))
    cfg = _vmware_cfg(tmp_path, fake)
    assert cli.main(["-c", str(cfg), "check-env"]) == cli.EXIT_OK
    assert "[KO]" not in capsys.readouterr().out
    monkeypatch.setattr(cli, "HttpGuestClient", lambda url, token, timeout=10: FakeAgentClient(fake))
    assert cli.main(["-c", str(cfg), "check-env", "--live"]) == cli.EXIT_OK
    text = capsys.readouterr().out
    assert "[KO]" not in text and "WEBCQ-Acquisizione" in text and not fake.running


def test_check_env_detects_wrong_snapshot(tmp_path, monkeypatch, capsys):
    from tests.vmware_fakes import FakeVmrun
    from webcquisition.providers import VMwareProvider
    fake = FakeVmrun(tmp_path / "vm", snapshots=["altro"])
    monkeypatch.setattr(cli, "provider_from_config", lambda h: VMwareProvider(runner=fake, executable="vmrun"))
    assert cli.main(["-c", str(_vmware_cfg(tmp_path, fake)), "check-env", "--live"]) == cli.EXIT_FAILED
    assert not fake.running


def test_default_config_path(tmp_path, monkeypatch):
    from tests.vmware_fakes import FakeVmrun
    fake = FakeVmrun(tmp_path / "vm", snapshots=["webcq-clean"])
    cfg = _vmware_cfg(tmp_path, fake)
    monkeypatch.setenv("WEBCQUISITION_CONFIG", str(cfg))
    out = tmp_path / "CASE-DEF-1"
    assert cli.main(["create-case", "CASE-DEF-1", "--output", str(out)]) == cli.EXIT_OK
    assert "vmware" in (out / "metadata" / "config-snapshot.yaml").read_text()


def test_wizard_validates_and_can_cancel(tmp_path, monkeypatch, capsys):
    from tests.vmware_fakes import FakeVmrun
    fake = FakeVmrun(tmp_path / "vm", snapshots=["webcq-clean"])
    cfg = _vmware_cfg(tmp_path, fake)
    cfg.write_text(cfg.read_text() + f"case: {{output_directory: '{tmp_path / 'Cases'}'}}\n")
    answers = iter(["../x", "CASE-W-1", "Mario Rossi", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert cli.main(["-c", str(cfg), "wizard"]) == cli.EXIT_USAGE
    out = capsys.readouterr().out
    assert "Annullato" in out and not (tmp_path / "Cases" / "CASE-W-1").exists()
