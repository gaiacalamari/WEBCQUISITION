"""Configurazione YAML di WEBCQUISITION.

Principi:
* nessun percorso o nome VM hardcodato: tutto arriva dalla configurazione;
* chiavi sconosciute => ERRORE (un refuso come ``snaphsot`` non deve passare
  inosservato e far partire una VM non ripristinata);
* la configurazione effettiva e il suo SHA-256 vengono registrati nel caso.
"""

from __future__ import annotations

import dataclasses
import typing
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path

import yaml

from webcquisition_common.hashing import sha256_bytes

PROVIDERS = ("vmware", "fake")


class ConfigError(ValueError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("Configurazione non valida:\n  - " + "\n  - ".join(problems))


@dataclass
class HypervisorConfig:
    provider: str = "vmware"
    vm_name: str = ""
    vm_uuid: str | None = None
    snapshot: str | None = None
    require_snapshot: bool = True
    start_mode: str = "gui"
    boot_timeout_s: int = 300
    shutdown_timeout_s: int = 180
    expected_nics: dict = field(default_factory=dict)
    post_acquisition_snapshot: str = "on_failure"
    executable: str | None = None
    vmrun_host_type: str = "ws"
    tools_timeout_s: int = 300


@dataclass
class AgentConfig:
    url: str = "http://192.168.150.10:8765"
    token_file: str = ""
    expected_agent_id: str | None = None
    request_timeout_s: int = 30
    ready_timeout_s: int = 300
    poll_interval_s: float = 5.0
    unreachable_threshold: int = 3
    max_clock_offset_s: float = 2.0


@dataclass
class CaptureConfig:
    engine: str = "dumpcap"
    mode: str = "dual"
    interface: str = "auto"
    ring_filesize_mb: int = 512
    capture_filter: str = ""
    snaplen: int = 0
    verify_timeout_s: int = 30
    require_traffic: bool = True
    stall_warning_s: int = 300
    min_free_disk_mb: int = 2048


@dataclass
class TlsConfig:
    enabled: bool = True
    required: bool = True


@dataclass
class BrowserConfig:
    browser: str = "firefox"
    dedicated_profile: bool = True
    start_url: str = "https://time.is"
    disable_doh: bool = True
    disable_http3: bool = True
    disable_ech: bool = True
    extra_prefs: dict = field(default_factory=dict)


@dataclass
class ScreenshotConfig:
    hotkey_enabled: bool = True
    hotkey: str = "ctrl+alt+s"
    control_panel: bool = True


@dataclass
class CaseConfig:
    output_directory: str = ""
    operator: str | None = None
    organization: str | None = None


@dataclass
class FinalizeConfig:
    order: str = "browser_first"
    graceful_timeout_s: int = 30
    #: spegnere Windows dall'interno della VM = fine acquisizione (lo spegnimento attende la copia)
    block_guest_shutdown: bool = True
    #: se la VM viene spenta prima della copia, riavviarla (senza snapshot) e recuperare la cartella
    recover_on_vm_loss: bool = True


@dataclass
class ExportConfig:
    retries: int = 3
    make_readonly: bool = True


@dataclass
class Config:
    hypervisor: HypervisorConfig = field(default_factory=HypervisorConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    tls: TlsConfig = field(default_factory=TlsConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    screenshot: ScreenshotConfig = field(default_factory=ScreenshotConfig)
    case: CaseConfig = field(default_factory=CaseConfig)
    finalize: FinalizeConfig = field(default_factory=FinalizeConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    # metadati di caricamento (non provengono dal YAML)
    source_path: str | None = field(default=None, metadata={"internal": True})
    source_sha256: str | None = field(default=None, metadata={"internal": True})

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d.pop("source_path", None)
        d.pop("source_sha256", None)
        return d


def _type_ok(value, hint) -> bool:
    origin = typing.get_origin(hint)
    args = typing.get_args(hint)
    if origin in (typing.Union, getattr(__import__("types"), "UnionType", None)):
        return any(_type_ok(value, a) for a in args)
    if hint is type(None):
        return value is None
    if hint is bool:
        return isinstance(value, bool)
    if hint is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if hint is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if hint is str:
        return isinstance(value, str)
    if hint is dict:
        return isinstance(value, dict)
    return True


def _build(cls, data, prefix: str, problems: list[str]):
    if data is None:
        data = {}
    if not isinstance(data, dict):
        problems.append(f"'{prefix or 'radice'}' deve essere una mappa")
        return cls()
    hints = typing.get_type_hints(cls)
    known = {f.name: f for f in fields(cls) if not f.metadata.get("internal")}
    for key in sorted(set(data) - set(known)):
        problems.append(f"chiave sconosciuta: '{prefix}{key}'")
    kwargs = {}
    for name in known:
        if name not in data:
            continue
        hint = hints[name]
        value = data[name]
        if is_dataclass(hint):
            kwargs[name] = _build(hint, value, f"{prefix}{name}.", problems)
        elif not _type_ok(value, hint):
            problems.append(f"'{prefix}{name}': tipo non valido ({type(value).__name__})")
        else:
            kwargs[name] = float(value) if hint is float else value
    return cls(**kwargs)


def validate(cfg: Config) -> list[str]:
    p: list[str] = []
    h = cfg.hypervisor
    if h.provider not in PROVIDERS:
        p.append(f"hypervisor.provider deve essere uno tra {PROVIDERS}")
    if not h.vm_name:
        p.append("hypervisor.vm_name è obbligatorio")
    if h.provider == "vmware":
        if h.vmrun_host_type not in ("ws", "fusion"):
            p.append("hypervisor.vmrun_host_type deve essere 'ws' (Workstation Pro) o 'fusion'; "
                     "VMware Player non è supportato (niente snapshot)")
        if h.vm_name and not h.vm_name.lower().endswith(".vmx"):
            p.append("hypervisor.vm_name deve essere il percorso completo del file .vmx della VM")
    if h.start_mode not in ("gui", "headless"):
        p.append("hypervisor.start_mode deve essere 'gui' o 'headless'")
    if h.post_acquisition_snapshot not in ("never", "on_failure", "always"):
        p.append("hypervisor.post_acquisition_snapshot: never | on_failure | always")
    if h.require_snapshot and not h.snapshot and h.provider != "fake":
        p.append("hypervisor.snapshot è obbligatorio quando require_snapshot è true")
    for k, v in h.expected_nics.items():
        if not str(k).isdigit() or not isinstance(v, str):
            p.append(f"hypervisor.expected_nics: voce non valida {k!r}: {v!r}")
    for name in ("boot_timeout_s", "shutdown_timeout_s"):
        if getattr(h, name) <= 0:
            p.append(f"hypervisor.{name} deve essere > 0")
    a = cfg.agent
    if not a.url.startswith(("http://", "https://")):
        p.append("agent.url deve iniziare con http:// o https://")
    if a.poll_interval_s <= 0:
        p.append("agent.poll_interval_s deve essere > 0")
    c = cfg.capture
    if c.engine not in ("dumpcap", "tshark"):
        p.append("capture.engine deve essere 'dumpcap' o 'tshark'")
    if c.mode not in ("dual", "headless"):
        p.append("capture.mode deve essere 'dual' (dumpcap + GUI Wireshark) o 'headless'")
    if c.ring_filesize_mb < 1:
        p.append("capture.ring_filesize_mb deve essere >= 1")
    if not cfg.tls.enabled and cfg.tls.required:
        p.append("tls.required richiede tls.enabled")
    b = cfg.browser
    if b.browser != "firefox":
        p.append("browser.browser: nel MVP è supportato solo 'firefox'")
    if not b.dedicated_profile:
        p.append("browser.dedicated_profile deve essere true (profilo per-caso obbligatorio nel MVP)")
    if cfg.finalize.order not in ("browser_first", "capture_first"):
        p.append("finalize.order deve essere 'browser_first' o 'capture_first'")
    if cfg.export.retries < 1:
        p.append("export.retries deve essere >= 1")
    return p


def config_from_dict(data: dict) -> Config:
    problems: list[str] = []
    cfg = _build(Config, data, "", problems)
    if not problems:
        problems = validate(cfg)
    if problems:
        raise ConfigError(problems)
    return cfg


def load_config(path: Path) -> Config:
    path = Path(path)
    raw = path.read_bytes()
    try:
        data = yaml.safe_load(raw.decode("utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError([f"YAML non valido: {exc}"]) from exc
    cfg = config_from_dict(data)
    cfg.source_path = str(path.resolve())
    cfg.source_sha256 = sha256_bytes(raw)
    return cfg


def default_config_path() -> Path:
    """Percorso predefinito della configurazione (scritto da ``vmware-setup``).

    Ordine: variabile d'ambiente ``WEBCQUISITION_CONFIG``; su Windows
    ``%ProgramData%\\WEBCQUISITION\\webcquisition.yaml``; altrove
    ``~/.config/webcquisition/webcquisition.yaml``.
    """
    import os
    import sys
    env = os.environ.get("WEBCQUISITION_CONFIG")
    if env:
        return Path(env)
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "WEBCQUISITION" / "webcquisition.yaml"
    return Path.home() / ".config" / "webcquisition" / "webcquisition.yaml"


def read_token(cfg: Config) -> str:
    if not cfg.agent.token_file:
        raise ConfigError(["agent.token_file non configurato"])
    token = Path(cfg.agent.token_file).read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise ConfigError(["il token dell'agent deve essere lungo almeno 32 caratteri"])
    return token
