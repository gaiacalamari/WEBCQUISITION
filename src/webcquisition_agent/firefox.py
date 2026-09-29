"""Firefox con profilo dedicato al caso e TLS key log per-processo.

* Il profilo è creato in ``browser/firefox-profile`` della cartella del caso (nessuna
  cronologia, cookie, cache, estensioni o credenziali preesistenti).
* ``SSLKEYLOGFILE`` è impostata SOLO nell'ambiente del processo Firefox avviato
  dall'agent, puntando a ``tls/sslkeylog.log`` del caso corrente.
* ``user.js`` riduce il traffico "di fondo" non generato dall'operatore e disattiva
  meccanismi che impedirebbero la decifratura o l'analisi (DoH, HTTP/3, ECH).
  Ogni preferenza applicata è registrata in ``metadata/firefox-prefs.json``.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from webcquisition_common.events import EventLog, EventType, Severity
from webcquisition_common.timeutil import iso_utc

from . import winutil
from .sysinfo import firefox_version

BASE_PREFS: dict = {
    # prima esecuzione / avvisi
    "browser.shell.checkDefaultBrowser": False,
    "browser.startup.homepage_override.mstone": "ignore",
    "startup.homepage_welcome_url": "",
    "startup.homepage_welcome_url.additional": "",
    "browser.aboutwelcome.enabled": False,
    "datareporting.policy.firstRunURL": "",
    "browser.tabs.warnOnClose": False,
    "browser.warnOnQuit": False,
    "browser.sessionstore.resume_from_crash": False,
    # telemetria e studi (traffico non generato dall'operatore)
    "toolkit.telemetry.enabled": False,
    "toolkit.telemetry.unified": False,
    "toolkit.telemetry.archive.enabled": False,
    "datareporting.healthreport.uploadEnabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "app.shield.optoutstudies.enabled": False,
    "app.normandy.enabled": False,
    "browser.discovery.enabled": False,
    "browser.newtabpage.activity-stream.feeds.telemetry": False,
    "browser.newtabpage.activity-stream.telemetry": False,
    "browser.newtabpage.activity-stream.showSponsored": False,
    "browser.newtabpage.activity-stream.showSponsoredTopSites": False,
    "extensions.pocket.enabled": False,
    # aggiornamenti: la versione deve restare quella documentata
    "app.update.auto": False,
    "app.update.disabledForTesting": True,
    "extensions.update.enabled": False,
    "extensions.autoDisableScopes": 15,
    # credenziali
    "signon.rememberSignons": False,
    "browser.formfill.enable": False,
    # rilevamento connettività (riduce rumore nel PCAP)
    "network.captive-portal-service.enabled": False,
    "network.connectivity-service.enabled": False,
}

DOH_OFF = {"network.trr.mode": 5}
HTTP3_OFF = {"network.http.http3.enable": False}
ECH_OFF = {"network.dns.echconfig.enabled": False, "network.dns.http3_echconfig.enabled": False}


class FirefoxError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def effective_prefs(request: dict) -> dict:
    prefs = dict(BASE_PREFS)
    if request.get("disable_doh", True):
        prefs.update(DOH_OFF)
    if request.get("disable_http3", True):
        prefs.update(HTTP3_OFF)
    if request.get("disable_ech", True):
        prefs.update(ECH_OFF)
    extra = request.get("extra_prefs") or {}
    for k, v in extra.items():
        if not isinstance(k, str) or not isinstance(v, (bool, int, str)):
            raise FirefoxError("FIREFOX_PREF_INVALID", f"preferenza non valida: {k!r}={v!r}")
    prefs.update(extra)
    return prefs


def build_user_js(prefs: dict) -> str:
    lines = ["// Generato da WEBCQUISITION. Non modificare durante l'acquisizione."]
    for k in sorted(prefs):
        lines.append(f"user_pref({json.dumps(k)}, {json.dumps(prefs[k])});")
    return "\n".join(lines) + "\n"


def build_command(firefox_path: str, profile_dir: Path, start_url: str) -> list[str]:
    return [firefox_path, "-profile", str(profile_dir), "-no-remote", "-new-instance", "-wait-for-browser",
            start_url or "about:blank"]


def build_env(base: dict, keylog: Path | None) -> dict:
    env = dict(base)
    env.pop("SSLKEYLOGFILE", None)
    if keylog is not None:
        env["SSLKEYLOGFILE"] = str(keylog)
    env["MOZ_CRASHREPORTER_DISABLE"] = "1"
    return env


class FirefoxManager:
    def __init__(self, settings, case_dir: Path, events: EventLog, popen=subprocess.Popen,
                 startup_check_s: float = 3.0, sleep=time.sleep):
        self.settings = settings
        self.case_dir = Path(case_dir)
        self.events = events
        self._popen = popen
        self._check = startup_check_s
        self._sleep = sleep
        self.proc = None

    @property
    def profile_dir(self) -> Path:
        return self.case_dir / "browser" / "firefox-profile"

    def start(self, request: dict) -> dict:
        if self.proc is not None:
            raise FirefoxError("FIREFOX_ALREADY_STARTED", "Firefox è già stato avviato in questa sessione")
        exe = Path(self.settings.firefox_path)
        if winutil.IS_WINDOWS and not exe.is_file():
            raise FirefoxError("FIREFOX_NOT_FOUND", f"firefox.exe non trovato: {exe}")
        if self.profile_dir.exists() and any(self.profile_dir.iterdir()):
            raise FirefoxError("FIREFOX_PROFILE_EXISTS", "il profilo del caso esiste già e non è vuoto")
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        prefs = effective_prefs(request)
        (self.profile_dir / "user.js").write_text(build_user_js(prefs), encoding="utf-8")
        keylog = self.case_dir / "tls" / "sslkeylog.log" if request.get("tls_enabled", True) else None
        cmd = build_command(str(exe), self.profile_dir, request.get("start_url", "about:blank"))
        meta = {"generated_at_utc": iso_utc(), "prefs": prefs, "command": cmd,
                "sslkeylogfile": str(keylog) if keylog else None,
                "sslkeylogfile_scope": "variabile d'ambiente del solo processo Firefox avviato dall'agent"}
        (self.case_dir / "metadata" / "firefox-prefs.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.events.emit(EventType.FIREFOX_PROFILE_CREATED, component="firefox",
                         data={"profile_dir": str(self.profile_dir), "prefs_count": len(prefs)})
        try:
            self.proc = self._popen(cmd, env=build_env(os.environ, keylog), stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        except OSError as exc:
            raise FirefoxError("FIREFOX_START_FAILED", f"avvio di Firefox fallito: {exc}") from exc
        self._sleep(self._check)
        if self.proc.poll() is not None:
            raise FirefoxError("FIREFOX_START_FAILED",
                               f"Firefox è terminato subito dopo l'avvio (rc={self.proc.returncode})")
        version = firefox_version(str(exe))
        self.events.emit(EventType.FIREFOX_STARTED, component="firefox",
                         data={"pid": self.proc.pid, "version": version, "command": cmd})
        return {"pid": self.proc.pid, "version": version, "profile_dir": str(self.profile_dir), "command": cmd,
                "prefs": prefs}

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, timeout: float) -> dict:
        if self.proc is None:
            return {"stopped": True, "graceful": True, "returncode": None, "note": "Firefox mai avviato"}
        if self.proc.poll() is not None:
            return {"stopped": True, "graceful": True, "returncode": self.proc.returncode,
                    "note": "Firefox era già stato chiuso"}
        winutil.kill_tree(self.proc.pid, force=False)  # WM_CLOSE: Firefox salva il profilo
        try:
            self.proc.wait(timeout=timeout)
            return {"stopped": True, "graceful": True, "returncode": self.proc.returncode}
        except subprocess.TimeoutExpired:
            self.events.emit(EventType.WARNING, severity=Severity.WARNING, component="firefox",
                             message="Firefox non si è chiuso entro il timeout: chiusura forzata")
            winutil.kill_tree(self.proc.pid, force=True)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                pass
            return {"stopped": self.proc.poll() is not None, "graceful": False, "returncode": self.proc.poll()}
