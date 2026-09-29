"""Costruzione di ``acquisition.json`` (manifest del caso).

Contiene SOLO le informazioni necessarie a ricostruire e verificare
l'acquisizione. Non vengono registrati: contenuto del token, variabili
d'ambiente complete, nome utente di Windows, dati del browser.
"""

from __future__ import annotations

import platform
import sys

from webcquisition_common import PROTOCOL_VERSION, __version__
from webcquisition_common.timeutil import local_timezone_description

from .state import AcquisitionState

TLS_NOTE = (
    "Il file tls/sslkeylog.log contiene segreti di sessione TLS (formato NSS Key Log). "
    "Insieme al PCAPNG consente di decifrare il traffico HTTPS acquisito, incluse eventuali "
    "credenziali: trattarlo come materiale altamente sensibile. Non tutte le connessioni sono "
    "necessariamente decifrabili: vedere docs/TLS-KEYLOG.md."
)

STATE_MEANING = {
    "COMPLETED": "Tutte le verifiche automatiche superate e nessun errore registrato.",
    "INCOMPLETE": "Pacchetto esportato e verificato, ma con errori documentati in 'issues'.",
    "FAILED": "Il pacchetto NON costituisce un'acquisizione verificata: vedere 'issues'.",
}


def build_acquisition_manifest(*, case, config, session, final_state: AcquisitionState, files, stop_reason,
                               dry_run: bool) -> dict:
    guest = session.get("guest", {})
    sysinfo = guest.get("sysinfo", {}) or {}
    capture = session.get("capture", {})
    iface = session.get("interface", {})
    pcaps = session.get("pcap_summaries", [])
    keylog_files = [f for f in files if f["path"].startswith("tls/")]
    return {
        "schema_version": 1,
        "dry_run": dry_run,
        "dry_run_notice": "SIMULAZIONE: nessuna VM reale, dati sintetici. NON è un reperto." if dry_run else None,
        "tool": {"name": "WEBCQUISITION", "version": __version__, "protocol_version": PROTOCOL_VERSION},
        "case": {
            "case_id": case.case_id,
            "operator": case.data.get("operator"),
            "organization": case.data.get("organization"),
            "created_at_utc": case.data.get("created_at_utc"),
        },
        "acquisition": {
            "state": final_state.value,
            "state_meaning": STATE_MEANING.get(final_state.value),
            "started_at_utc": session.get("started_at_utc"),
            "acquisition_active_at_utc": session.get("acquisition_active_at_utc"),
            "finished_at_utc": session.get("finished_at_utc"),
            "stop_reason": stop_reason,
            "timestamps": "UTC, ISO-8601, millisecondi",
            "host_timezone": local_timezone_description(),
            "guest_timezone": sysinfo.get("timezone"),
            "clock_offset_guest_minus_host": session.get("clock", {}),
            "state_history": case.data.get("state_history"),
        },
        "host": {
            "hostname": platform.node(),
            "os": platform.platform(),
            "python": sys.version.split()[0],
        },
        "hypervisor": {
            "provider": session.get("vm", {}).get("provider"),
            "provider_version": session.get("vm", {}).get("provider_version"),
            "vm_name": session.get("vm", {}).get("name"),
            "vm_uuid": session.get("vm", {}).get("uuid"),
            "vm_uuid_pinned": bool(config.hypervisor.vm_uuid),
            "nics": session.get("vm", {}).get("nics"),
            "expected_nics": config.hypervisor.expected_nics,
            "snapshot_restored": session.get("snapshot_restored"),
            "post_acquisition_snapshot": session.get("post_snapshot"),
        },
        "guest": {
            "agent": session.get("agent"),
            "case_dir": guest.get("case_dir"),
            "windows": sysinfo.get("windows"),
            "firefox_version": session.get("browser", {}).get("version") or sysinfo.get("firefox_version"),
            "wireshark_version": sysinfo.get("wireshark_version"),
            "time_sync": sysinfo.get("time_sync"),
        },
        "network": {
            "capture_engine": capture.get("engine"),
            "capture_mode": capture.get("mode"),
            "capture_command": capture.get("command"),
            "capture_filter": config.capture.capture_filter or None,
            "interface": {k: iface.get(k) for k in ("name", "friendly_name", "guid", "ipv4")} if iface else None,
            "interface_selection": config.capture.interface,
            "pcap_files": [
                {k: p.get(k) for k in ("path", "packets", "valid", "first_ts_utc", "last_ts_utc", "truncated_tail",
                                       "interfaces")} for p in pcaps
            ],
            "packets_total": sum(p.get("packets", 0) for p in pcaps),
        },
        "tls": {
            "enabled": config.tls.enabled,
            "method": "SSLKEYLOGFILE per-processo (solo il processo Firefox avviato da WEBCQUISITION)",
            "keylog_files": [{"path": f["path"], "size": f["size"], "sha256": f["sha256"]} for f in keylog_files],
            "sensitive": True,
            "note": TLS_NOTE,
        },
        "browser": {
            "browser": config.browser.browser,
            "dedicated_profile": True,
            "profile_dir_guest": session.get("browser", {}).get("profile_dir"),
            "prefs_applied": session.get("browser", {}).get("prefs"),
        },
        "integrity": {
            "algorithm": "SHA-256",
            "guest_manifest_sha256": session.get("guest_manifest_sha256"),
            "verified_on_host": session.get("integrity", {}).get("verified_files"),
            "problems": session.get("integrity", {}).get("problems", []),
            "unexpected_files": session.get("integrity", {}).get("unexpected", []),
            "sha256sums": "hashes/SHA256SUMS.txt",
            "package_seal": "hashes/package-seal.json",
        },
        "files": files,
        "issues": session.get("issues", []),
        "config": {"path": config.source_path, "sha256": config.source_sha256,
                   "snapshot": "metadata/config-snapshot.yaml"},
    }
