"""Orchestrazione del ciclo di acquisizione.

Regole forensi incorporate nel flusso (vedi docs/ARCHITECTURE.md):

1. La VM viene identificata per nome E (se configurato) per UUID; deve essere
   spenta e viene ripristinata allo snapshot "pulito" configurato.
2. La configurazione di rete della VM viene confrontata con quella attesa.
3. La cattura è considerata avviata solo dopo verifica programmatica:
   processo vivo + file PCAPNG presente + IDB con l'interfaccia selezionata;
   la presenza di traffico viene verificata dalla crescita del contatore pacchetti.
4. In caso di errore il materiale già prodotto NON viene scartato: si tenta
   sempre sigillo guest -> export -> verifica, e lo stato finale è
   INCOMPLETE/FAILED, mai COMPLETED.
5. Lo snapshot NON viene mai ripristinato dopo l'inizio dell'acquisizione
   (distruggerebbe il materiale nel disco della VM). Su errore si può invece
   creare uno snapshot "post-acquisizione" che preserva il disco.
6. L'export avviene PRIMA dello spegnimento della VM perché il canale di
   trasferimento è l'agent; lo spegnimento avviene comunque dopo.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable

from webcquisition_common import PROTOCOL_VERSION, __version__
from webcquisition_common import protocol as P
from webcquisition_common.events import EventLog, EventType, Severity
from webcquisition_common.hashing import (
    find_unexpected,
    format_sha256sums,
    sha256_file,
    verify_entries,
)
from webcquisition_common.paths import UnsafePathError, safe_join
from webcquisition_common.pcapng import summarize
from webcquisition_common.timeutil import iso_utc, parse_iso, utc_now

from .case import Case
from .config import Config
from .guest_client import AgentError, AgentUnreachable, GuestClient
from .manifest import build_acquisition_manifest
from .providers import HypervisorProvider, ProviderError, VMState, normalize_uuid
from .report import generate_report
from .state import TERMINAL
from .state import AcquisitionState as S
from .util import atomic_write_json, atomic_write_text, make_readonly, make_tree_readonly

log = logging.getLogger("webcquisition")


class StepFailed(RuntimeError):
    def __init__(self, code: str, message: str, **data):
        self.code = code
        self.data = data
        super().__init__(message)


class AcquisitionFailed(RuntimeError):
    def __init__(self, final_state: S, message: str):
        self.final_state = final_state
        super().__init__(message)


class InterfaceSelectionError(StepFailed):
    pass


def select_interface(spec: str, interfaces: list[dict]) -> dict:
    """Seleziona l'interfaccia di cattura. Mai l'interfaccia di controllo."""
    if spec == "auto":
        candidates = [i for i in interfaces if not i.get("is_control") and i.get("has_default_gateway")]
        if len(candidates) == 1:
            return candidates[0]
        raise InterfaceSelectionError(
            "INTERFACE_AMBIGUOUS" if candidates else "INTERFACE_NOT_FOUND",
            f"selezione automatica impossibile: {len(candidates)} interfacce candidate "
            "(non di controllo, con default gateway). Specificare capture.interface.",
            candidates=[c.get("friendly_name") for c in candidates],
        )
    matches = [
        i for i in interfaces
        if spec in (i.get("name"), i.get("friendly_name"), i.get("guid"), i.get("display"))
    ]
    if not matches:
        raise InterfaceSelectionError("INTERFACE_NOT_FOUND", f"interfaccia '{spec}' non trovata nella VM")
    if len(matches) > 1:
        raise InterfaceSelectionError("INTERFACE_AMBIGUOUS", f"'{spec}' corrisponde a più interfacce")
    if matches[0].get("is_control"):
        raise InterfaceSelectionError(
            "INTERFACE_IS_CONTROL",
            f"'{spec}' è l'interfaccia del canale di controllo host<->guest: non può essere catturata "
            "come interfaccia di acquisizione",
        )
    return matches[0]


class Acquisition:
    def __init__(
        self,
        case: Case,
        config: Config,
        provider: HypervisorProvider,
        client: GuestClient,
        *,
        dry_run: bool = False,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        out: Callable[[str], None] = print,
    ):
        self.case = case
        self.cfg = config
        self.provider = provider
        self.client = client
        self.dry_run = dry_run
        self.sleep = sleep
        self.monotonic = monotonic
        self.out = out
        self.events = EventLog(case.events_path, case.case_id, "host")
        self.session = case.load_session()
        self.session.setdefault("issues", [])
        self.session.setdefault("monitor", {})
        self._agent_failures = 0
        self._lock = threading.RLock()
        self.vm = config.hypervisor.vm_name
        self.events.emit(
            EventType.CASE_LOADED, component="orchestrator",
            data={"state": case.state.value, "dry_run": dry_run, "pid": os.getpid()},
        )

    # ================================================================ helpers
    @property
    def issues(self) -> list[dict]:
        return self.session["issues"]

    def emit(self, event, message="", severity=Severity.INFO, component="orchestrator", **data):
        rec = self.events.emit(event, severity=severity, component=component, message=message, data=data)
        log.log(logging.WARNING if severity in (Severity.WARNING,) else
                logging.ERROR if severity in (Severity.ERROR, Severity.CRITICAL) else logging.INFO,
                "%s %s", rec["event"], message)
        return rec

    def issue(self, severity: Severity, code: str, message: str, **data):
        with self._lock:
            self.issues.append({"severity": severity.value, "code": code, "message": message,
                                "at_utc": iso_utc(), "data": data})
            ev = EventType.ERROR if severity in (Severity.ERROR, Severity.CRITICAL) else EventType.WARNING
            self.emit(ev, message, severity=severity, code=code, **data)
            self.save()

    def has_issue(self, code: str) -> bool:
        return any(i["code"] == code for i in self.issues)

    def save(self):
        self.case.save_session(self.session)

    def transition(self, new: S, reason: str = ""):
        old = self.case.set_state(new, reason)
        self.emit(EventType.STATE_CHANGED, f"{old.value} -> {new.value}", old=old.value, new=new.value, reason=reason)
        self.out(f"[{new.value}] {reason}")

    def _wait(self, timeout_s: float, poll_s: float, fn: Callable[[], object]):
        """Chiama ``fn`` finché restituisce un valore truthy o scade il timeout."""
        deadline = self.monotonic() + timeout_s
        while True:
            result = fn()
            if result:
                return result
            if self.monotonic() >= deadline:
                return None
            self.sleep(poll_s)

    # ================================================================ start
    def prepare_and_start(self) -> None:
        if self.case.state != S.CREATED:
            raise AcquisitionFailed(self.case.state, f"il caso è nello stato {self.case.state.value}: "
                                    "un caso può essere acquisito una sola volta")
        self.emit(EventType.ACQUISITION_START_REQUESTED, dry_run=self.dry_run,
                  operator=self.case.data.get("operator"))
        self.emit(EventType.CONFIG_LOADED, config_path=self.cfg.source_path,
                  config_sha256=self.cfg.source_sha256)
        self.session.update(started_at_utc=iso_utc(), dry_run=self.dry_run,
                            config_sha256=self.cfg.source_sha256, config_path=self.cfg.source_path)
        self.transition(S.PREPARING, "preparazione acquisizione")
        guest_prepared = False
        try:
            self._preflight_vm()
            self._boot_vm()
            self._wait_ready()
            self._measure_clock("start")
            self._prepare_guest()
            guest_prepared = True
            self._select_interface()
            self._start_capture()
            self._start_firefox()
            self._start_ui()
        except (StepFailed, ProviderError, AgentError, AgentUnreachable) as exc:
            code = getattr(exc, "code", type(exc).__name__.upper())
            self.issue(Severity.ERROR, code, f"preparazione fallita: {exc}", **getattr(exc, "data", {}))
            if guest_prepared:
                # Il guest ha già prodotto materiale: lo si recupera comunque.
                final = self.finalize(reason="preparation_failed")
            else:
                final = self._abort_before_guest()
            raise AcquisitionFailed(final, str(exc)) from exc
        self.session["acquisition_active_at_utc"] = iso_utc()
        self.transition(S.ACQUIRING, "acquisizione in corso: l'operatore utilizza Firefox")
        self.emit(EventType.ACQUISITION_ACTIVE, interface=self.session.get("interface", {}).get("name"))
        self.save()

    def _preflight_vm(self):
        h = self.cfg.hypervisor
        if not self.provider.is_available():
            raise StepFailed("HYPERVISOR_UNAVAILABLE", f"hypervisor '{self.provider.name}' non disponibile")
        version = self.provider.version()
        self.emit(EventType.HYPERVISOR_DETECTED, provider=self.provider.name, version=version,
                  stable=getattr(self.provider, "stable", False))
        if not getattr(self.provider, "stable", False):
            self.issue(Severity.WARNING, "PROVIDER_EXPERIMENTAL",
                       f"il provider '{self.provider.name}' è sperimentale")
        try:
            info = self.provider.get_info(self.vm)
        except ProviderError as exc:
            raise StepFailed("VM_NOT_FOUND", f"VM '{self.vm}' non trovata: {exc}") from exc
        self.session["vm"] = {"provider": self.provider.name, "provider_version": version, **info.to_dict()}
        if h.vm_uuid:
            if normalize_uuid(info.uuid) != normalize_uuid(h.vm_uuid):
                raise StepFailed("VM_IDENTITY_MISMATCH",
                                 f"UUID della VM ({info.uuid}) diverso da quello configurato ({h.vm_uuid})")
        else:
            self.issue(Severity.WARNING, "VM_UUID_NOT_PINNED",
                       "hypervisor.vm_uuid non configurato: l'identità della VM è verificata solo per nome")
        self.emit(EventType.VM_IDENTITY_VERIFIED, vm=info.name, uuid=info.uuid, pinned=bool(h.vm_uuid))
        if info.state in (VMState.RUNNING, VMState.PAUSED, VMState.STARTING, VMState.STOPPING):
            raise StepFailed("VM_ALREADY_RUNNING",
                             f"la VM è nello stato '{info.state.value}': deve essere spenta prima dell'acquisizione")
        # Configurazione di rete
        nics = {str(n.index): n for n in info.nics}
        if h.expected_nics:
            for idx, expected in h.expected_nics.items():
                nic = nics.get(str(idx))
                if nic is None or nic.attachment.lower() != str(expected).lower():
                    raise StepFailed("NETWORK_CONFIG_MISMATCH",
                                     f"NIC {idx}: attesa '{expected}', trovata "
                                     f"'{nic.attachment if nic else 'assente'}'")
                if nic.connected is False:
                    raise StepFailed("NETWORK_CONFIG_MISMATCH",
                                     f"NIC {idx} ({expected}) non è collegata all'accensione (startConnected)")
            extra = sorted(set(nics) - {str(k) for k in h.expected_nics})
            if extra:
                raise StepFailed("NETWORK_CONFIG_MISMATCH", f"NIC non previste attive nella VM: {extra}")
            self.emit(EventType.NETWORK_CONFIG_VERIFIED, nics=[n.__dict__ for n in info.nics])
        else:
            self.issue(Severity.WARNING, "NETWORK_CONFIG_NOT_PINNED",
                       "hypervisor.expected_nics non configurato: configurazione di rete solo registrata, non verificata",
                       nics=[n.__dict__ for n in info.nics])
        # Snapshot
        if h.snapshot:
            if info.snapshots and h.snapshot not in info.snapshots:
                raise StepFailed("SNAPSHOT_NOT_FOUND", f"snapshot '{h.snapshot}' non presente nella VM")
            self.provider.restore_snapshot(self.vm, h.snapshot)
            self.session["snapshot_restored"] = h.snapshot
            self.emit(EventType.SNAPSHOT_RESTORED, snapshot=h.snapshot)
        elif h.require_snapshot:
            raise StepFailed("SNAPSHOT_REQUIRED", "nessuno snapshot configurato")
        else:
            self.issue(Severity.WARNING, "NO_SNAPSHOT",
                       "nessuno snapshot ripristinato: lo stato iniziale della VM non è garantito")
        self.save()

    def _boot_vm(self):
        gui = self.cfg.hypervisor.start_mode == "gui"
        self.emit(EventType.VM_START_REQUESTED, vm=self.vm, gui=gui)
        try:
            self.provider.start(self.vm, gui=gui)
            self.session["vm_started_by_webcquisition"] = True
            self.provider.wait_for_state(self.vm, [VMState.RUNNING], self.cfg.hypervisor.boot_timeout_s,
                                         sleep=self.sleep, monotonic=self.monotonic)
        except ProviderError as exc:
            raise StepFailed("VM_START_FAILED", f"avvio VM fallito: {exc}") from exc
        self.emit(EventType.VM_STARTED, vm=self.vm)
        self.save()

    def _wait_ready(self):
        a = self.cfg.agent
        self.emit(EventType.AGENT_WAITING, url=a.url, timeout_s=a.ready_timeout_s)
        last_error = {"msg": ""}

        def probe():
            try:
                h = self.client.health()
            except AgentUnreachable as exc:
                tools = self.provider.tools_state(self.vm)
                last_error["msg"] = str(exc) + (f" [VMware Tools: {tools}]" if tools else "")
                if tools == "running" and not self.session.get("guest_tools_running"):
                    self.session["guest_tools_running"] = True
                    self.emit(EventType.GUEST_TOOLS_RUNNING, tools_state=tools)
                state = self.provider.get_info(self.vm).state
                if state not in (VMState.RUNNING, VMState.STARTING):
                    raise StepFailed("VM_STOPPED_DURING_BOOT", f"la VM è passata allo stato {state.value}")
                return None
            if not h.get("interactive_session"):
                last_error["msg"] = "agent attivo ma sessione desktop interattiva non ancora pronta"
                return None
            return h

        health = self._wait(a.ready_timeout_s, min(a.poll_interval_s, 5.0), probe)
        if not health:
            raise StepFailed("VM_NOT_READY", f"la VM non è diventata operativa entro {a.ready_timeout_s}s: "
                             f"{last_error['msg']}")
        if health.get("protocol") != PROTOCOL_VERSION:
            raise StepFailed("PROTOCOL_MISMATCH", f"protocollo agent {health.get('protocol')} != {PROTOCOL_VERSION}")
        if a.expected_agent_id:
            if health.get("agent_id") != a.expected_agent_id:
                raise StepFailed("AGENT_IDENTITY_MISMATCH",
                                 f"agent_id '{health.get('agent_id')}' diverso da '{a.expected_agent_id}': "
                                 "possibile VM diversa da quella prevista")
        else:
            self.issue(Severity.WARNING, "AGENT_ID_NOT_PINNED", "agent.expected_agent_id non configurato")
        if health.get("session_active"):
            raise StepFailed("GUEST_NOT_CLEAN",
                             f"l'agent ha già una sessione attiva (caso {health.get('case_id')}): VM non pulita")
        self.session["agent"] = {"agent_id": health.get("agent_id"), "agent_version": health.get("agent_version"),
                                 "url": a.url, "simulated": health.get("simulated", False)}
        self.emit(EventType.VM_READY, agent_id=health.get("agent_id"), agent_version=health.get("agent_version"))
        self.save()

    def _measure_clock(self, label: str):
        try:
            t0 = utc_now()
            h = self.client.health()
            t1 = utc_now()
        except (AgentUnreachable, AgentError) as exc:
            self.issue(Severity.WARNING, "CLOCK_OFFSET_UNAVAILABLE", f"misura offset orologio ({label}) fallita: {exc}")
            return
        guest = parse_iso(h["utc"])
        midpoint = t0 + (t1 - t0) / 2
        offset = (guest - midpoint).total_seconds()
        rtt = (t1 - t0).total_seconds()
        self.session.setdefault("clock", {})[label] = {
            "host_utc": iso_utc(midpoint), "guest_utc": h["utc"], "offset_s": round(offset, 3),
            "round_trip_s": round(rtt, 3),
        }
        self.emit(EventType.CLOCK_OFFSET_MEASURED, label=label, offset_s=round(offset, 3), round_trip_s=round(rtt, 3))
        if abs(offset) > self.cfg.agent.max_clock_offset_s:
            self.issue(Severity.WARNING, "CLOCK_OFFSET_HIGH",
                       f"differenza orologio guest-host {offset:.3f}s oltre la soglia "
                       f"{self.cfg.agent.max_clock_offset_s}s ({label})")
        self.save()

    def _prepare_guest(self):
        req = {
            "case_id": self.case.case_id,
            "operator": self.case.data.get("operator"),
            "tls": {"enabled": self.cfg.tls.enabled},
        }
        resp = self.client.prepare(req)
        self.session["guest"] = {"case_dir": resp.get("guest_case_dir"), "desktop_dir": resp.get("desktop_dir"),
                                 "keylog_path": resp.get("keylog_path"), "sysinfo": resp.get("sysinfo", {})}
        self.emit(EventType.CASE_DIRECTORY_CREATED, guest_case_dir=resp.get("guest_case_dir"))
        self.emit(EventType.GUEST_SYSINFO_COLLECTED,
                  windows=resp.get("sysinfo", {}).get("windows"),
                  firefox_version=resp.get("sysinfo", {}).get("firefox_version"),
                  wireshark_version=resp.get("sysinfo", {}).get("wireshark_version"))
        glob_kl = resp.get("sysinfo", {}).get("global_sslkeylogfile")
        if glob_kl:
            self.issue(Severity.WARNING, "GLOBAL_SSLKEYLOGFILE_SET",
                       f"nella VM è impostata una variabile SSLKEYLOGFILE globale ({glob_kl}): altri programmi "
                       "potrebbero scrivere segreti TLS altrove. WEBCQUISITION usa una variabile per-processo.")
        if self.cfg.tls.enabled:
            self.emit(EventType.TLS_KEYLOG_INITIALIZED, keylog_path=resp.get("keylog_path"))
        self.save()

    def _select_interface(self):
        ifaces = self.client.interfaces().get("interfaces", [])
        self.session["guest_interfaces"] = ifaces
        chosen = select_interface(self.cfg.capture.interface, ifaces)
        self.session["interface"] = chosen
        self.emit(EventType.INTERFACE_SELECTED, name=chosen.get("name"), friendly_name=chosen.get("friendly_name"),
                  ipv4=chosen.get("ipv4"), spec=self.cfg.capture.interface)
        self.save()

    def _start_capture(self):
        c = self.cfg.capture
        iface = self.session["interface"]["name"]
        self.emit(EventType.WIRESHARK_START_REQUESTED, engine=c.engine, mode=c.mode, interface=iface)
        resp = self.client.capture_start({
            "interface": iface, "engine": c.engine, "mode": c.mode, "ring_filesize_mb": c.ring_filesize_mb,
            "capture_filter": c.capture_filter, "snaplen": c.snaplen,
        })
        self.session["capture"] = {"engine": c.engine, "mode": c.mode, "command": resp.get("command"),
                                   "engine_pid": resp.get("engine_pid"), "gui_pid": resp.get("gui_pid")}
        self.emit(EventType.WIRESHARK_STARTED, pid=resp.get("engine_pid"), command=resp.get("command"))
        if resp.get("gui_pid"):
            self.emit(EventType.WIRESHARK_GUI_STARTED, pid=resp.get("gui_pid"),
                      note="la GUI è una vista di controllo per l'operatore; il reperto è il file di dumpcap")

        def verified():
            st = self.client.capture_status()
            if not st.get("running"):
                raise StepFailed("CAPTURE_PROCESS_DIED", "il processo di cattura è terminato subito dopo l'avvio",
                                 returncode=st.get("returncode"), stderr_tail=st.get("stderr_tail"))
            if not st.get("files"):
                return None
            names = st.get("interfaces") or []
            if not names:
                return None
            if iface not in names:
                raise StepFailed("CAPTURE_INTERFACE_MISMATCH",
                                 f"il PCAPNG riporta le interfacce {names}, attesa {iface}")
            return st

        st = self._wait(c.verify_timeout_s, 1.0, verified)
        if not st:
            raise StepFailed("CAPTURE_NOT_VERIFIED",
                             f"impossibile verificare la cattura entro {c.verify_timeout_s}s (file o IDB assenti)")
        mon = self.session["monitor"]
        mon.update(baseline_packets=st["packets"], last_packets=st["packets"], last_growth=self.monotonic(),
                   files=len(st["files"]), traffic_verified=False)
        self.emit(EventType.CAPTURE_STARTED, interface=iface, files=[f["path"] for f in st["files"]],
                  packets=st["packets"], verification="process_alive+pcapng_present+idb_interface_match")
        self.save()

    def _start_firefox(self):
        b = self.cfg.browser
        resp = self.client.firefox_start({
            "start_url": b.start_url, "disable_doh": b.disable_doh, "disable_http3": b.disable_http3,
            "disable_ech": b.disable_ech, "extra_prefs": b.extra_prefs, "tls_enabled": self.cfg.tls.enabled,
        })
        self.session["browser"] = {"pid": resp.get("pid"), "version": resp.get("version"),
                                   "profile_dir": resp.get("profile_dir"), "command": resp.get("command"),
                                   "prefs": resp.get("prefs")}
        self.emit(EventType.FIREFOX_PROFILE_CREATED, profile_dir=resp.get("profile_dir"))
        self.emit(EventType.FIREFOX_STARTED, pid=resp.get("pid"), version=resp.get("version"))
        self.save()

    def _start_ui(self):
        s = self.cfg.screenshot
        try:
            resp = self.client.ui_start({"hotkey_enabled": s.hotkey_enabled, "hotkey": s.hotkey,
                                         "control_panel": s.control_panel,
                                         "block_guest_shutdown": self.cfg.finalize.block_guest_shutdown})
        except AgentError as exc:
            self.issue(Severity.WARNING, "UI_START_FAILED", f"utility screenshot/pannello non avviati: {exc}")
            return
        self.session["ui"] = resp
        self.emit(EventType.SCREENSHOT_SERVICE_STARTED, **resp)
        for part in ("hotkey", "panel"):
            info = resp.get(part) or {}
            if info.get("error") and not resp.get("simulated"):
                self.issue(Severity.WARNING, f"{part.upper()}_UNAVAILABLE", f"{part}: {info.get('error')}")
        self.save()

    def _abort_before_guest(self) -> S:
        """Errore prima che il guest abbia prodotto materiale: si documenta e si spegne la VM se avviata."""
        if self.session.get("vm_started_by_webcquisition"):
            self._shutdown_vm()
        self._write_outputs(S.FAILED, stop_reason="preparation_failed")
        return S.FAILED

    # ================================================================ monitor
    def monitor_once(self) -> str | None:
        """Un ciclo di controllo. Restituisce 'stop' (richiesta dal pannello guest), 'lost' o None."""
        a = self.cfg.agent
        mon = self.session["monitor"]
        try:
            st = self.client.status()
        except AgentUnreachable as exc:
            self._agent_failures += 1
            if self._agent_failures == 1:
                self.emit(EventType.AGENT_UNREACHABLE, str(exc), severity=Severity.WARNING)
            if self._agent_failures >= a.unreachable_threshold:
                try:
                    state = self.provider.get_info(self.vm).state
                except ProviderError:
                    state = VMState.UNKNOWN
                if state != VMState.RUNNING:
                    self.issue(Severity.ERROR, "VM_LOST", f"agent irraggiungibile e VM nello stato {state.value}")
                    return "lost"
                if self._agent_failures == a.unreachable_threshold:
                    self.issue(Severity.WARNING, "AGENT_UNREACHABLE_PERSISTENT",
                               "VM in esecuzione ma agent irraggiungibile (VM bloccata o rete di controllo interrotta?)")
            return None
        if self._agent_failures:
            self.emit(EventType.AGENT_RECONNECTED, after_failures=self._agent_failures)
            self._agent_failures = 0
        cap = st.get("capture") or {}
        packets = cap.get("packets", 0)
        if not cap.get("running") and not mon.get("capture_died"):
            mon["capture_died"] = True
            self.emit(EventType.CAPTURE_PROCESS_DIED, severity=Severity.ERROR, returncode=cap.get("returncode"),
                      stderr_tail=cap.get("stderr_tail"))
            self.issue(Severity.ERROR, "CAPTURE_PROCESS_DIED",
                       "il processo di cattura è terminato durante l'acquisizione (disco pieno? interfaccia rimossa?)")
        if packets > mon.get("last_packets", 0):
            mon["last_packets"] = packets
            mon["last_growth"] = self.monotonic()
            mon.pop("stall_reported", None)
            if not mon.get("traffic_verified") and packets > mon.get("baseline_packets", 0):
                mon["traffic_verified"] = True
                self.emit(EventType.CAPTURE_TRAFFIC_VERIFIED, packets=packets)
        elif (self.monotonic() - mon.get("last_growth", self.monotonic()) > self.cfg.capture.stall_warning_s
              and not mon.get("stall_reported")):
            mon["stall_reported"] = True
            self.emit(EventType.CAPTURE_STALLED, severity=Severity.WARNING, packets=packets,
                      seconds=self.cfg.capture.stall_warning_s)
        nfiles = len(cap.get("files", []))
        if nfiles > mon.get("files", 0):
            self.emit(EventType.CAPTURE_FILE_ROTATED, files=[f["path"] for f in cap.get("files", [])])
            mon["files"] = nfiles
        kl = st.get("keylog") or {}
        if kl.get("size", 0) > 0 and not mon.get("keylog_active"):
            mon["keylog_active"] = True
            self.emit(EventType.TLS_KEYLOG_ACTIVE, size=kl.get("size"))
        if st.get("screenshots", 0) > mon.get("screenshots", 0):
            self.emit(EventType.SCREENSHOT_CREATED, count=st["screenshots"], source="guest")
            mon["screenshots"] = st["screenshots"]
        if st.get("operator_files", 0) > mon.get("operator_files", 0):
            self.emit(EventType.OPERATOR_FILE_DETECTED, count=st["operator_files"])
            mon["operator_files"] = st["operator_files"]
        ff = st.get("firefox") or {}
        if not ff.get("running") and not mon.get("firefox_exited"):
            mon["firefox_exited"] = True
            self.emit(EventType.FIREFOX_EXITED_UNEXPECTEDLY, severity=Severity.WARNING,
                      message="Firefox non è più in esecuzione (chiuso dall'operatore o crash)")
        free = st.get("disk_free_bytes")
        if free is not None and free < self.cfg.capture.min_free_disk_mb * 1024 * 1024 and not mon.get("disk_low"):
            mon["disk_low"] = True
            self.emit(EventType.DISK_SPACE_LOW, severity=Severity.WARNING, free_bytes=free)
            self.issue(Severity.WARNING, "DISK_SPACE_LOW", f"spazio libero nel guest: {free // (1024*1024)} MB")
        mon["last_status_utc"] = iso_utc()
        mon["last_status"] = {"packets": packets, "capture_running": cap.get("running"),
                              "firefox_running": ff.get("running"), "keylog_size": kl.get("size"),
                              "screenshots": st.get("screenshots")}
        self.save()
        if st.get("stop_requested"):
            self.session["stop_source"] = st.get("stop_source")
            return "stop"
        return None

    def status_summary(self) -> dict:
        return {"case_id": self.case.case_id, "state": self.case.state.value,
                "monitor": self.session.get("monitor", {}).get("last_status"),
                "issues": [f"{i['severity']} {i['code']}" for i in self.issues]}

    # ================================================================ interactive
    def run_interactive(self, input_fn: Callable[[], str] = input, auto_stop_s: float | None = None) -> S:
        self.prepare_and_start()
        self.out("\n=== ACQUISIZIONE IN CORSO ===")
        self.out("Usare Firefox nella VM. Screenshot: hotkey/pannello WEBCQUISITION nella VM.")
        self.out("Per terminare: digitare FINE e premere INVIO (oppure 'Fine acquisizione' nel pannello della VM).\n")
        stop = threading.Event()
        reason = {"value": "operator_stop"}

        if auto_stop_s is None:
            def reader():
                while not stop.is_set():
                    try:
                        line = input_fn()
                    except EOFError:
                        return
                    if line.strip().upper() in ("FINE", "STOP", "END"):
                        self.emit(EventType.USER_ACTION, action="stop_from_host_console")
                        stop.set()
                        return
                    self.out("Digitare FINE per terminare l'acquisizione.")
            threading.Thread(target=reader, daemon=True).start()
        deadline = self.monotonic() + auto_stop_s if auto_stop_s is not None else None
        try:
            while not stop.is_set():
                r = self.monitor_once()
                if r == "stop":
                    if self.session.get("stop_source") == "guest_shutdown":
                        self.emit(EventType.USER_ACTION, action="stop_from_guest_shutdown")
                        self.out("Spegnimento richiesto dall'interno della VM: chiusura dell'acquisizione e copia "
                                 "del materiale (la VM si spegnerà al termine).")
                        reason["value"] = "guest_shutdown"
                    else:
                        self.emit(EventType.USER_ACTION, action="stop_from_guest_panel")
                        reason["value"] = "guest_panel_stop"
                    break
                if r == "lost":
                    reason["value"] = "vm_lost"
                    break
                if deadline is not None and self.monotonic() >= deadline:
                    reason["value"] = "auto_stop"
                    break
                stop.wait(self.cfg.agent.poll_interval_s)
        except KeyboardInterrupt:
            reason["value"] = "interrupted"
            self.issue(Severity.ERROR, "ACQUISITION_INTERRUPTED",
                       "acquisizione interrotta (Ctrl+C): chiusura ordinata e recupero del materiale")
        stop.set()
        return self.finalize(reason=reason["value"])

    # ================================================================ finalize
    def finalize(self, reason: str = "operator_stop") -> S:
        if self.case.state in TERMINAL:
            raise AcquisitionFailed(self.case.state, "acquisizione già conclusa")
        if self.case.state not in (S.ACQUIRING, S.PREPARING):
            raise AcquisitionFailed(self.case.state, f"impossibile concludere dallo stato {self.case.state.value}")
        self.emit(EventType.STOP_REQUESTED, reason=reason)
        self.session["stop_reason"] = reason
        self.transition(S.FINALIZING, f"chiusura acquisizione ({reason})")
        seal = None
        if reason == "vm_lost":
            seal = self._recover()
        else:
            try:
                try:
                    self.monitor_once()
                except Exception as exc:  # il monitor finale è best-effort
                    log.debug("monitor finale: %s", exc)
                self._stop_guest()
                self._measure_clock("end")
                self._final_checks()
                self.emit(EventType.GUEST_SEAL_STARTED)
                seal = self.client.seal()
                self._record_seal(seal)
            except (AgentUnreachable, AgentError) as exc:
                if self._vm_state() in (VMState.POWERED_OFF, VMState.SAVED):
                    self.issue(Severity.ERROR, "VM_LOST", f"VM spenta durante la chiusura dell'acquisizione ({exc})")
                    seal = self._recover()
                else:
                    self.issue(Severity.ERROR, "GUEST_FINALIZATION_FAILED",
                               f"impossibile chiudere/sigillare la sessione nel guest: {exc}. Il materiale resta nel "
                               "disco della VM: NON ripristinare lo snapshot.")
        exported = verified = False
        pcaps: list[dict] = []
        if seal is not None:
            self.transition(S.EXPORTING, "trasferimento VM -> host")
            exported = self._export(seal)
            self.transition(S.VERIFYING, "verifica integrità sull'host")
            verified, pcaps = self._verify(seal)
        self.session["pcap_summaries"] = pcaps
        self._release_guest()
        self._shutdown_vm(guest_shutdown_pending=reason == "guest_shutdown")
        capture_ok = any(p.get("valid") and p.get("packets", 0) > 0 for p in pcaps)
        errors = [i for i in self.issues if i["severity"] in ("ERROR", "CRITICAL")]
        if not (exported and verified and capture_ok):
            final = S.FAILED
            if seal is not None and not capture_ok:
                self.issue(Severity.ERROR, "NO_VALID_CAPTURE", "nessun file PCAPNG valido con pacchetti nel pacchetto")
        elif errors:
            final = S.INCOMPLETE
        else:
            final = S.COMPLETED
        self._post_snapshot(final)
        self._write_outputs(final, stop_reason=reason)
        return final

    def _record_seal(self, seal: dict):
        self.session["guest_manifest_sha256"] = seal.get("manifest_sha256")
        self.emit(EventType.GUEST_SEALED, manifest_sha256=seal.get("manifest_sha256"),
                  file_count=seal.get("file_count"))

    def _vm_state(self) -> VMState:
        try:
            return self.provider.get_info(self.vm).state
        except ProviderError:
            return VMState.UNKNOWN

    def _release_guest(self):
        """Dopo la copia: lo spegnimento di Windows non è più bloccato dall'agent."""
        try:
            r = self.client.release()
            self.emit(EventType.GUEST_SHUTDOWN_RELEASED, shutdown_was_requested=r.get("shutdown_was_requested"))
        except (AgentUnreachable, AgentError, NotImplementedError) as exc:
            log.debug("release: %s", exc)

    def _recover(self) -> dict | None:
        """VM spenta (o sospesa) prima della copia: riavvio SENZA snapshot e recupero della cartella del caso."""
        state = self._vm_state()
        if not self.cfg.finalize.recover_on_vm_loss or state not in (VMState.POWERED_OFF, VMState.SAVED):
            self.issue(Severity.ERROR, "GUEST_FINALIZATION_FAILED",
                       f"VM nello stato {state.value}: materiale non recuperato automaticamente. Resta nel disco "
                       "della VM: NON ripristinare lo snapshot.")
            return None
        h = self.cfg.hypervisor
        self.emit(EventType.RECOVERY_STARTED, vm_state=state.value,
                  message="riavvio della VM senza ripristino dello snapshot per recuperare il materiale")
        self.out("\nLa VM è stata spenta prima della copia del materiale.")
        self.out("La riavvio SENZA ripristinare lo snapshot per recuperare la cartella del caso "
                 "(se richiesto, accedere alla VM come operatore)...")
        try:
            self.provider.start(self.vm, gui=h.start_mode == "gui")
            self.provider.wait_for_state(self.vm, [VMState.RUNNING], h.boot_timeout_s,
                                         sleep=self.sleep, monotonic=self.monotonic)

            def probe():
                try:
                    hh = self.client.health()
                except AgentUnreachable:
                    return None
                return hh if hh.get("interactive_session") else None

            health = self._wait(self.cfg.agent.ready_timeout_s, min(self.cfg.agent.poll_interval_s, 5.0), probe)
            if not health:
                raise StepFailed("VM_NOT_READY", "agent non raggiungibile dopo il riavvio")
            if self.cfg.agent.expected_agent_id and health.get("agent_id") != self.cfg.agent.expected_agent_id:
                raise StepFailed("AGENT_IDENTITY_MISMATCH", f"agent_id '{health.get('agent_id')}' inatteso")
            if health.get("session_active"):
                if health.get("case_id") != self.case.case_id:
                    raise StepFailed("GUEST_NOT_CLEAN", f"sessione attiva per un altro caso ({health.get('case_id')})")
                # ripresa da sospensione: la sessione è intatta, chiusura normale
                self._stop_guest()
                self._final_checks()
                seal = self.client.seal()
            else:
                r = self.client.recover({"case_id": self.case.case_id})
                seal = r if r.get("already_sealed") else self.client.seal()
            self._record_seal(seal)
            self.emit(EventType.RECOVERY_COMPLETED, manifest_sha256=seal.get("manifest_sha256"))
            self.issue(Severity.WARNING, "RECOVERED_AFTER_POWER_LOSS",
                       "materiale recuperato dopo uno spegnimento non controllato della VM: cattura e browser sono "
                       "stati interrotti bruscamente (ultimo blocco PCAPNG ed eventi guest possono essere troncati)")
            return seal
        except (ProviderError, AgentUnreachable, AgentError, StepFailed) as exc:
            self.emit(EventType.RECOVERY_FAILED, severity=Severity.ERROR, message=str(exc))
            self.issue(Severity.ERROR, "GUEST_FINALIZATION_FAILED",
                       f"recupero dopo lo spegnimento non riuscito: {exc}. Il materiale resta nel disco della VM: "
                       "NON ripristinare lo snapshot.")
            return None

    def _stop_guest(self):
        f = self.cfg.finalize
        self.emit(EventType.FIREFOX_STOP_REQUESTED, order=f.order)
        self.emit(EventType.CAPTURE_STOP_REQUESTED, order=f.order)
        r = self.client.stop({"order": f.order, "graceful_timeout_s": f.graceful_timeout_s})
        self.session["stop_result"] = r
        ff = r.get("firefox") or {}
        cap = r.get("capture") or {}
        self.emit(EventType.FIREFOX_STOPPED, graceful=ff.get("graceful"), returncode=ff.get("returncode"))
        if ff.get("stopped") and not ff.get("graceful"):
            self.issue(Severity.WARNING, "FIREFOX_FORCED_CLOSE",
                       "Firefox chiuso forzatamente: il profilo potrebbe non essere stato scritto completamente")
        self.emit(EventType.CAPTURE_STOPPED, graceful=cap.get("graceful"), returncode=cap.get("returncode"))
        if not cap.get("stopped"):
            self.issue(Severity.ERROR, "CAPTURE_STOP_FAILED", "impossibile arrestare la cattura")
        elif not cap.get("graceful"):
            self.issue(Severity.WARNING, "CAPTURE_FORCED_STOP",
                       "cattura terminata forzatamente: l'ultimo blocco PCAPNG potrebbe essere troncato")
        self.save()

    def _final_checks(self):
        st = self.client.status()
        cap = st.get("capture") or {}
        kl = st.get("keylog") or {}
        mon = self.session["monitor"]
        self.session["final_guest_status"] = {"packets": cap.get("packets"), "files": cap.get("files"),
                                              "keylog": kl, "screenshots": st.get("screenshots"),
                                              "operator_files": st.get("operator_files")}
        if cap.get("packets", 0) > mon.get("baseline_packets", 0) and not mon.get("traffic_verified"):
            mon["traffic_verified"] = True
            self.emit(EventType.CAPTURE_TRAFFIC_VERIFIED, packets=cap.get("packets"))
        if self.cfg.capture.require_traffic and not mon.get("traffic_verified") and "capture" in self.session:
            self.issue(Severity.ERROR, "CAPTURE_NO_TRAFFIC",
                       "il contatore dei pacchetti non è mai cresciuto dopo l'avvio della cattura")
        if self.cfg.tls.enabled and self.session.get("browser"):
            if not kl.get("exists") or kl.get("size", 0) == 0:
                sev = Severity.ERROR if self.cfg.tls.required else Severity.WARNING
                self.emit(EventType.TLS_KEYLOG_EMPTY, severity=sev)
                self.issue(sev, "TLS_KEYLOG_EMPTY",
                           "il TLS key log è vuoto: il traffico HTTPS non sarà decifrabile "
                           "(build Firefox senza supporto SSLKEYLOGFILE? nessuna connessione TLS?)")
        self.save()

    # ================================================================ export
    def _export(self, seal: dict) -> bool:
        dest_root = self.case.acquired_dir
        dest_root.mkdir(exist_ok=True)
        if any(dest_root.iterdir()):
            self.issue(Severity.ERROR, "EXPORT_DESTINATION_NOT_EMPTY", f"{dest_root} non è vuota: export annullato")
            self.emit(EventType.EXPORT_FAILED)
            return False
        try:
            files = self.client.list_files()["files"]
        except (AgentUnreachable, AgentError) as exc:
            self.issue(Severity.ERROR, "EXPORT_LIST_FAILED", f"elenco file non ottenibile: {exc}")
            self.emit(EventType.EXPORT_FAILED)
            return False
        total = sum(f.get("size") or 0 for f in files)
        self.emit(EventType.EXPORT_STARTED, files=len(files), bytes=total)
        self.out(f"Export di {len(files)} file ({total} byte)...")
        failed = []
        for entry in files:
            rel = entry["path"]
            try:
                final_path = safe_join(dest_root, rel)
            except UnsafePathError as exc:
                self.issue(Severity.ERROR, "EXPORT_UNSAFE_PATH", str(exc), path=rel)
                failed.append(rel)
                continue
            final_path.parent.mkdir(parents=True, exist_ok=True)
            part = final_path.with_name(final_path.name + ".partial")
            ok = False
            for attempt in range(1, self.cfg.export.retries + 1):
                if part.exists():
                    part.unlink()
                try:
                    digest, size = self.client.download(rel, part)
                except (AgentUnreachable, AgentError, OSError) as exc:
                    self.emit(EventType.EXPORT_FAILED, severity=Severity.WARNING, path=rel, attempt=attempt,
                              error=str(exc))
                    self.sleep(1.0)
                    continue
                if digest == entry.get("sha256") and size == entry.get("size"):
                    os.replace(part, final_path)
                    self.emit(EventType.FILE_EXPORTED, path=rel, size=size, sha256=digest, attempt=attempt)
                    ok = True
                    break
                self.emit(EventType.EXPORT_HASH_MISMATCH, severity=Severity.WARNING, path=rel, attempt=attempt,
                          expected=entry.get("sha256"), actual=digest, expected_size=entry.get("size"),
                          actual_size=size)
            if not ok:
                if part.exists():
                    part.unlink()
                failed.append(rel)
                self.issue(Severity.ERROR, "EXPORT_FILE_FAILED",
                           f"file non trasferito correttamente dopo {self.cfg.export.retries} tentativi: {rel}", path=rel)
        atomic_write_json(self.case.dir / "hashes" / "guest-manifest.json",
                          {"manifest_sha256": seal.get("manifest_sha256"), "files": files})
        self.session["export"] = {"files": len(files), "bytes": total, "failed": failed}
        if failed:
            self.emit(EventType.EXPORT_FAILED, severity=Severity.ERROR, failed=failed)
            return False
        self.emit(EventType.EXPORT_COMPLETED, files=len(files), bytes=total)
        self.save()
        return True

    def _verify(self, seal: dict) -> tuple[bool, list[dict]]:
        """Seconda verifica indipendente: rilegge da disco ogni file esportato."""
        root = self.case.acquired_dir
        guest_manifest = self.case.dir / "hashes" / "guest-manifest.json"
        import json as _json
        files = _json.loads(guest_manifest.read_text(encoding="utf-8"))["files"] if guest_manifest.exists() else []
        problems = verify_entries(root, files)
        unexpected = find_unexpected(root, files)
        # Il manifest guest esportato deve avere l'hash dichiarato dall'agent al momento del sigillo.
        mf = root / P.GUEST_MANIFEST_REL
        if mf.exists():
            mdigest, _ = sha256_file(mf)
            if mdigest != seal.get("manifest_sha256"):
                problems.append({"path": P.GUEST_MANIFEST_REL, "issue": "seal_hash_mismatch"})
        else:
            problems.append({"path": P.GUEST_MANIFEST_REL, "issue": "missing"})
        for e in files:
            if e.get("sha256"):
                self.emit(EventType.HASH_CALCULATED, path=e["path"], sha256=e["sha256"], size=e.get("size"))
        self.session["integrity"] = {"verified_files": len(files) - len(problems), "problems": problems,
                                     "unexpected": unexpected}
        if problems or unexpected:
            self.emit(EventType.INTEGRITY_FAILED, severity=Severity.ERROR, problems=problems, unexpected=unexpected)
            self.issue(Severity.ERROR, "INTEGRITY_FAILED", f"{len(problems)} problemi, {len(unexpected)} file inattesi")
            ok = False
        else:
            self.emit(EventType.INTEGRITY_VERIFIED, files=len(files))
            ok = True
        pcaps = []
        for pcap in sorted((root / "network").glob("*.pcapng")) if (root / "network").exists() else []:
            summ = summarize(pcap).to_dict()
            summ["path"] = pcap.relative_to(root).as_posix()
            pcaps.append(summ)
            self.emit(EventType.PCAP_SUMMARY, path=summ["path"], packets=summ["packets"], valid=summ["valid"],
                      interfaces=[i.get("name") for i in summ["interfaces"]],
                      first_ts_utc=summ["first_ts_utc"], last_ts_utc=summ["last_ts_utc"],
                      truncated_tail=summ["truncated_tail"])
            if not summ["valid"]:
                self.issue(Severity.ERROR, "PCAP_INVALID", f"{summ['path']}: {summ['error']}")
            elif summ["truncated_tail"]:
                self.issue(Severity.WARNING, "PCAP_TRUNCATED_TAIL", f"{summ['path']}: ultimo blocco incompleto")
        if self.cfg.export.make_readonly and root.exists():
            make_tree_readonly(root)
        self.save()
        return ok, pcaps

    # ================================================================ VM shutdown
    def _shutdown_vm(self, guest_shutdown_pending: bool = False):
        if guest_shutdown_pending:
            # l'operatore ha avviato lo spegnimento da Windows: sbloccato, Windows lo completa da solo
            try:
                self.provider.wait_for_state(self.vm, [VMState.POWERED_OFF], min(60, self.cfg.hypervisor.shutdown_timeout_s),
                                             sleep=self.sleep, monotonic=self.monotonic)
                self.emit(EventType.VM_SHUTDOWN, method="guest_initiated")
                return
            except ProviderError:
                pass  # spegnimento annullato dall'operatore: arresto controllato dall'host
        try:
            state = self.provider.get_info(self.vm).state
        except ProviderError as exc:
            self.issue(Severity.WARNING, "VM_STATE_UNKNOWN", f"stato VM non determinabile: {exc}")
            return
        if state == VMState.POWERED_OFF:
            self.emit(EventType.VM_SHUTDOWN, already_off=True)
            return
        if state != VMState.RUNNING:
            self.issue(Severity.WARNING, "VM_NOT_RUNNING_AT_SHUTDOWN", f"VM nello stato {state.value}")
            return
        self.emit(EventType.VM_SHUTDOWN_REQUESTED, method="graceful")
        try:
            self.provider.request_shutdown(self.vm)
            self.provider.wait_for_state(self.vm, [VMState.POWERED_OFF], self.cfg.hypervisor.shutdown_timeout_s,
                                         sleep=self.sleep, monotonic=self.monotonic)
            self.emit(EventType.VM_SHUTDOWN, method="graceful")
        except ProviderError as exc:
            self.issue(Severity.WARNING, "VM_FORCED_POWEROFF", f"arresto controllato non riuscito ({exc}): spegnimento forzato")
            try:
                self.provider.force_poweroff(self.vm)
                self.emit(EventType.VM_FORCED_POWEROFF)
            except ProviderError as exc2:
                self.issue(Severity.ERROR, "VM_POWEROFF_FAILED", f"impossibile spegnere la VM: {exc2}")

    def _post_snapshot(self, final: S):
        policy = self.cfg.hypervisor.post_acquisition_snapshot
        if policy == "never" or (policy == "on_failure" and final == S.COMPLETED):
            return
        name = f"WEBCQ-{self.case.case_id}-post-{utc_now().strftime('%Y%m%dT%H%M%SZ')}"
        try:
            self.provider.take_snapshot(self.vm, name, f"Stato post-acquisizione {self.case.case_id} ({final.value})")
            self.session["post_snapshot"] = name
            self.emit(EventType.SNAPSHOT_TAKEN, name=name, reason=final.value)
        except ProviderError as exc:
            self.issue(Severity.WARNING, "POST_SNAPSHOT_FAILED", f"snapshot post-acquisizione non creato: {exc}")

    # ================================================================ outputs
    def _write_outputs(self, final: S, stop_reason: str):
        self.session["finished_at_utc"] = iso_utc()
        self.session["final_state"] = final.value
        self.save()
        self.transition(final, "esito dell'acquisizione")
        root = self.case.acquired_dir
        host_files = []
        guest_list = []
        gm = self.case.dir / "hashes" / "guest-manifest.json"
        if gm.exists():
            import json as _json
            guest_list = _json.loads(gm.read_text(encoding="utf-8"))["files"]
        bad = {p["path"] for p in self.session.get("integrity", {}).get("problems", [])}
        for e in guest_list:
            if e.get("sha256") and (root / e["path"]).exists() and e["path"] not in bad:
                host_files.append({**e, "category": P.classify(e["path"])})
        atomic_write_text(self.case.dir / "hashes" / "SHA256SUMS.txt",
                          "# SHA-256 dei file in acquired/ (verificare con: cd acquired && sha256sum -c ../hashes/SHA256SUMS.txt)\n"
                          + format_sha256sums(host_files))
        atomic_write_json(self.case.dir / "hashes" / "manifest.json",
                          {"algorithm": "SHA-256", "root": "acquired/", "generated_at_utc": iso_utc(),
                           "files": host_files})
        manifest = build_acquisition_manifest(
            case=self.case, config=self.cfg, session=self.session, final_state=final,
            files=host_files, stop_reason=stop_reason, dry_run=self.dry_run,
        )
        acq_path = self.case.dir / "acquisition.json"
        atomic_write_json(acq_path, manifest)
        acq_sha, _ = sha256_file(acq_path)
        self.emit(EventType.MANIFEST_WRITTEN, path="acquisition.json", sha256=acq_sha)
        report_path = self.case.dir / "report" / "acquisition-report.html"
        from webcquisition_common.events import read_events
        generate_report(report_path, manifest, read_events(self.case.events_path))
        rep_sha, _ = sha256_file(report_path)
        self.emit(EventType.REPORT_GENERATED, path="report/acquisition-report.html", sha256=rep_sha)
        sums_sha, _ = sha256_file(self.case.dir / "hashes" / "SHA256SUMS.txt")
        final_event = {S.COMPLETED: EventType.CASE_COMPLETED, S.INCOMPLETE: EventType.CASE_INCOMPLETE,
                       S.FAILED: EventType.CASE_FAILED}[final]
        sev = Severity.INFO if final == S.COMPLETED else Severity.WARNING if final == S.INCOMPLETE else Severity.ERROR
        self.emit(final_event, severity=sev, acquisition_json_sha256=acq_sha, report_sha256=rep_sha,
                  sha256sums_sha256=sums_sha, errors=sum(1 for i in self.issues if i["severity"] == "ERROR"))
        head = self.events.head_hash
        count = self.events.count
        self.events.close()
        ev_sha, _ = sha256_file(self.case.events_path)
        seal = {
            "case_id": self.case.case_id, "final_state": final.value, "sealed_at_utc": iso_utc(),
            "webcquisition_version": __version__, "dry_run": self.dry_run,
            "acquisition_json_sha256": acq_sha, "report_sha256": rep_sha, "sha256sums_sha256": sums_sha,
            "host_events_sha256": ev_sha, "host_events_count": count, "host_events_head_hash": head,
            "guest_manifest_sha256": self.session.get("guest_manifest_sha256"),
        }
        seal_path = self.case.dir / "hashes" / "package-seal.json"
        atomic_write_json(seal_path, seal)
        seal_sha, _ = sha256_file(seal_path)
        if self.cfg.export.make_readonly:
            for p in (acq_path, report_path, self.case.dir / "hashes" / "SHA256SUMS.txt",
                      self.case.dir / "hashes" / "manifest.json", self.case.events_path, seal_path):
                if p.exists():
                    make_readonly(p)
        self.out("")
        self.out(f"Esito: {final.value}")
        for i in self.issues:
            if i["severity"] in ("ERROR", "WARNING"):
                self.out(f"  {i['severity']:<7} {i['code']}: {i['message']}")
        self.out(f"Pacchetto: {self.case.dir}")
        self.out(f"SHA-256 package-seal.json: {seal_sha}")
        self.out(f"Hash di testa del log eventi host: {head}")
        self.out("Annotare questi valori nel verbale di acquisizione.")

    def close(self):
        if not self.events.closed:
            self.events.close()
