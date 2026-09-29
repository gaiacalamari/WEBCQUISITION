"""Configurazione dell'agent (agent.json, installata nella VM prima dello snapshot)."""

from __future__ import annotations

import json
from dataclasses import dataclass, fields
from pathlib import Path

DEFAULT_CONFIG_PATH = r"C:\ProgramData\WEBCQUISITION\agent.json"


class AgentConfigError(ValueError):
    pass


@dataclass
class AgentSettings:
    listen_host: str
    token: str
    agent_id: str
    listen_port: int = 8765
    dumpcap_path: str = r"C:\Program Files\Wireshark\dumpcap.exe"
    tshark_path: str = r"C:\Program Files\Wireshark\tshark.exe"
    wireshark_path: str = r"C:\Program Files\Wireshark\Wireshark.exe"
    firefox_path: str = r"C:\Program Files\Mozilla Firefox\firefox.exe"
    control_ip: str | None = None
    log_dir: str = r"C:\ProgramData\WEBCQUISITION\logs"
    allow_any_listen: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "AgentSettings":
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise AgentConfigError(f"chiavi sconosciute in agent.json: {sorted(unknown)}")
        try:
            s = cls(**data)
        except TypeError as exc:
            raise AgentConfigError(f"agent.json incompleto: {exc}") from exc
        if len(s.token) < 32:
            raise AgentConfigError("token troppo corto (minimo 32 caratteri)")
        if s.listen_host in ("0.0.0.0", "::", "") and not s.allow_any_listen:
            raise AgentConfigError(
                "listen_host deve essere l'IP della scheda host-only di controllo, non tutte le interfacce "
                "(altrimenti l'agent sarebbe esposto anche sulla rete di acquisizione)"
            )
        if not s.agent_id:
            raise AgentConfigError("agent_id obbligatorio")
        if s.control_ip is None:
            s.control_ip = s.listen_host
        return s

    @classmethod
    def load(cls, path: str | Path = DEFAULT_CONFIG_PATH) -> "AgentSettings":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
