"""Avvio del guest agent:  python -m webcquisition_agent [--config PATH] [--check]

Deve essere eseguito nella SESSIONE INTERATTIVA dell'utente della VM (Scheduled Task
"At logon", vedi scripts/install-agent.ps1), altrimenti Wireshark, Firefox e il
pannello non sarebbero visibili all'operatore.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from webcquisition_common import __version__

from .settings import DEFAULT_CONFIG_PATH, AgentConfigError, AgentSettings
from .winutil import IS_WINDOWS, interactive_session


def _dpi_aware():
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # coordinate e screenshot a risoluzione reale
        except Exception:  # noqa: BLE001
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:  # noqa: BLE001
                pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="webcquisition-agent", description="WEBCQUISITION guest agent")
    ap.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    ap.add_argument("--check", action="store_true", help="verifica configurazione e prerequisiti ed esce")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        settings = AgentSettings.load(args.config)
    except (OSError, ValueError, AgentConfigError) as exc:
        print(f"configurazione agent non valida ({args.config}): {exc}", file=sys.stderr)
        return 64
    Path(settings.log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=str(Path(settings.log_dir) / "agent.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("webcquisition.agent")
    _dpi_aware()

    if args.check:
        from . import sysinfo
        from .interfaces import enumerate_interfaces
        report = {"settings_ok": True, "interactive_session": interactive_session(),
                  "tools_present": {k: Path(v).is_file() for k, v in (
                      ("dumpcap", settings.dumpcap_path), ("wireshark", settings.wireshark_path),
                      ("firefox", settings.firefox_path))},
                  "sysinfo": sysinfo.collect(settings),
                  "interfaces": enumerate_interfaces(settings.dumpcap_path, settings.control_ip)}
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        return 0

    from .server import build_server
    from .session import Session

    if not interactive_session():
        log.warning("agent NON in sessione interattiva: GUI non visibili all'operatore")
    session = Session(settings)
    server = build_server(settings, session)
    log.info("agent %s in ascolto su %s:%s", __version__, settings.listen_host, settings.listen_port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
