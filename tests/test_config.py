import pytest

from tests.conftest import base_config
from webcquisition.config import ConfigError, config_from_dict, load_config, read_token


def test_valid_config():
    c = config_from_dict(base_config())
    assert c.hypervisor.provider == "fake"
    assert c.finalize.order == "browser_first"
    assert c.capture.engine == "dumpcap"


def test_unknown_key_is_error():
    cfg = base_config()
    cfg["hypervisor"]["snaphsot"] = "typo"
    with pytest.raises(ConfigError) as e:
        config_from_dict(cfg)
    assert "snaphsot" in str(e.value)


def test_unknown_section_is_error():
    cfg = base_config()
    cfg["extra"] = {}
    with pytest.raises(ConfigError):
        config_from_dict(cfg)


@pytest.mark.parametrize("section,key,value", [
    ("hypervisor", "provider", "qemu"),
    ("hypervisor", "vm_name", ""),
    ("capture", "engine", "wireshark"),
    ("capture", "mode", "gui"),
    ("capture", "ring_filesize_mb", 0),
    ("finalize", "order", "random"),
    ("browser", "dedicated_profile", False),
    ("agent", "url", "ftp://x"),
    ("hypervisor", "post_acquisition_snapshot", "sometimes"),
])
def test_invalid_values(section, key, value):
    cfg = base_config()
    cfg.setdefault(section, {})[key] = value
    with pytest.raises(ConfigError):
        config_from_dict(cfg)


def test_type_checked():
    cfg = base_config()
    cfg["capture"]["verify_timeout_s"] = "trenta"
    with pytest.raises(ConfigError):
        config_from_dict(cfg)


def test_snapshot_required_for_real_provider():
    cfg = base_config()
    cfg["hypervisor"].update(provider="vmware", vm_name="v.vmx", snapshot=None)
    with pytest.raises(ConfigError):
        config_from_dict(cfg)


def test_tls_required_needs_enabled():
    cfg = base_config(tls={"enabled": False, "required": True})
    with pytest.raises(ConfigError):
        config_from_dict(cfg)


def test_load_yaml_records_sha256(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("hypervisor:\n  provider: fake\n  vm_name: v\n", encoding="utf-8")
    c = load_config(p)
    assert len(c.source_sha256) == 64
    assert c.source_path


def test_example_config_is_valid():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    load_config(root / "config" / "webcquisition.example.yaml")
    load_config(root / "examples" / "dry-run.yaml")


def test_read_token(tmp_path):
    t = tmp_path / "tok"
    t.write_text("x" * 40)
    cfg = config_from_dict(base_config(agent={"token_file": str(t)}))
    assert read_token(cfg) == "x" * 40
    t.write_text("short")
    with pytest.raises(ConfigError):
        read_token(cfg)
