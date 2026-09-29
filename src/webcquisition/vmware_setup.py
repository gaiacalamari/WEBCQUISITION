"""Preparazione automatica della VM di acquisizione su VMware Workstation Pro.

``webcquisition vmware-setup`` porta una VM Windows con Python, Wireshark/Npcap,
Firefox e VMware Tools già installati fino allo stato "pronta per le acquisizioni":

 1. verifica la VM (spenta, non cifrata) e le schede di rete (NIC1 NAT, NIC2 host-only;
    con ``--fix-network`` corregge il .vmx, dopo averne fatto una copia);
 2. individua la rete host-only (configurazione DHCP di VMware) e sceglie gli indirizzi;
 3. genera token e ``agent.json``, crea il bundle dell'agent;
 4. avvia la VM, attende VMware Tools, copia i file e lancia ``guest-setup.ps1`` con le
    guest operations (IP statico sulla scheda di controllo senza gateway/DNS, nomi
    espliciti delle schede, installazione agent, Scheduled Task, firewall, rimozione di
    SSLKEYLOGFILE globale, opzioni: accesso automatico, Windows Update);
 5. riavvia la VM e verifica l'agent end-to-end (identità, sessione interattiva,
    interfacce, orologio);
 6. spegne la VM, crea lo snapshot pulito, scrive la configurazione dell'host e un
    rapporto di preparazione con catena di hash (documentazione della baseline).

Le credenziali del guest servono solo qui e non vengono mai scritte su disco o nei log.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import yaml

from webcquisition_common import PROTOCOL_VERSION, __version__
from webcquisition_common.events import EventLog, EventType, Severity
from webcquisition_common.hashing import sha256_file
from webcquisition_common.timeutil import iso_utc, parse_iso, utc_now

from .bundle import asset_text, build_bundle_zip
from .config import config_from_dict
from .guest_client import AgentError, AgentUnreachable, HttpGuestClient
from .orchestrator import InterfaceSelectionError, select_interface
from .providers import GuestAuth, ProviderError, VMState, VMwareProvider
from .providers.vmware import parse_vmx, read_vmx_text, set_vmx_values

GUEST_WORKDIR = r"C:\Windows\Temp\webcq-setup"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CONTROL_NIC_NAME = "WEBCQ-Controllo"
CAPTURE_NIC_NAME = "WEBCQ-Acquisizione"

DHCP_CONF_CANDIDATES = {
    "win32": [r"C:\ProgramData\VMware\vmnetdhcp.conf"],
    "linux": ["/etc/vmware/{vnet}/dhcpd/dhcpd.conf"],
    "darwin": ["/Library/Preferences/VMware Fusion/{vnet}/dhcpd.conf"],
}


class SetupError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass
class SetupOptions:
    vmx: str
    guest_user: str
    guest_password: str
    operator_user: str
    config_out: Path
    token_file: Path
    cases_dir: str
    snapshot: str = "webcq-clean"
    agent_id: str | None = None
    host_ip: str | None = None
    control_ip: str | None = None
    prefix_length: int | None = None
    agent_port: int = 8765
    fix_network: bool = False
    autologon: bool = False
    operator_password: str | None = None
    disable_windows_update: bool = False
    organization: str | None = None
    start_url: str = "https://time.is"
    tools_timeout_s: int = 600
    agent_timeout_s: int = 900
    manual_elevation_timeout_s: int = 1800
    guest_setup_timeout_s: int = 1800
    shutdown_timeout_s: int = 300
    vmrun: str | None = None
    host_type: str = "ws"
    dumpcap_path: str = r"C:\Program Files\Wireshark\dumpcap.exe"
    wireshark_path: str = r"C:\Program Files\Wireshark\Wireshark.exe"
    firefox_path: str = r"C:\Program Files\Mozilla Firefox\firefox.exe"


# ------------------------------------------------------------------ rete host-only
def parse_vmnet_dhcp(text: str, vnet: str = "vmnet1") -> tuple[str | None, list[ipaddress.IPv4Network]]:
    """Restituisce (IP dell'host sulla vnet, sottoreti dichiarate) da vmnetdhcp.conf / dhcpd.conf."""
    host_ip = None
    m = re.search(r"host\s+" + re.escape(vnet) + r"\s*\{[^}]*?fixed-address\s+([0-9.]+)\s*;", text, re.IGNORECASE)
    if m:
        host_ip = m.group(1)
    nets = [ipaddress.IPv4Network(f"{a}/{b}", strict=False)
            for a, b in re.findall(r"subnet\s+([0-9.]+)\s+netmask\s+([0-9.]+)", text, re.IGNORECASE)]
    return host_ip, nets


def detect_hostonly_network(vnet: str = "vmnet1", paths: list[str] | None = None) -> tuple[str, ipaddress.IPv4Network]:
    plat = sys.platform if sys.platform in DHCP_CONF_CANDIDATES else "linux"
    for p in paths or [c.format(vnet=vnet) for c in DHCP_CONF_CANDIDATES[plat]]:
        path = Path(p)
        if not path.is_file():
            continue
        host_ip, nets = parse_vmnet_dhcp(path.read_text(encoding="utf-8", errors="replace"), vnet)
        if host_ip:
            net = next((n for n in nets if ipaddress.IPv4Address(host_ip) in n), None)
            if net:
                return host_ip, net
        if len(nets) == 1:  # file per-vnet (Linux/macOS): host = primo indirizzo
            return str(nets[0].network_address + 1), nets[0]
    raise SetupError("HOSTONLY_NETWORK_UNKNOWN",
                     f"rete host-only '{vnet}' non individuata automaticamente: indicare --host-ip e --control-ip "
                     "(vedere Edit > Virtual Network Editor in VMware)")


def plan_addresses(host_ip: str, net: ipaddress.IPv4Network, control_ip: str | None) -> tuple[str, int]:
    host = ipaddress.IPv4Address(host_ip)
    if control_ip:
        ctl = ipaddress.IPv4Address(control_ip)
    else:
        ctl = net.network_address + 10
        if ctl == host:
            ctl = net.network_address + 11
    if ctl not in net or ctl in (net.network_address, net.broadcast_address):
        raise SetupError("CONTROL_IP_INVALID", f"{ctl} non è un indirizzo utilizzabile della rete {net}")
    if ctl == host:
        raise SetupError("CONTROL_IP_INVALID", "l'IP di controllo coincide con quello dell'host")
    return str(ctl), net.prefixlen


# ------------------------------------------------------------------ .vmx
def network_problems(nics) -> list[str]:
    problems = []
    by_idx = {n.index: n for n in nics}
    if by_idx.get(1) is None or by_idx[1].attachment != "nat":
        problems.append(f"NIC1 (ethernet0) deve essere NAT, trovata {by_idx[1].attachment if 1 in by_idx else 'assente'}")
    if by_idx.get(2) is None or by_idx[2].attachment != "hostonly":
        problems.append(f"NIC2 (ethernet1) deve essere Host-only, trovata "
                        f"{by_idx[2].attachment if 2 in by_idx else 'assente'}")
    for n in nics:
        if n.index in (1, 2) and n.connected is False:
            problems.append(f"NIC{n.index} non è collegata all'accensione")
        if n.index > 2:
            problems.append(f"NIC{n.index} (ethernet{n.index - 1}) non prevista")
    return problems


def network_fix_updates(kv: dict) -> dict[str, str | None]:
    dev = kv.get("ethernet0.virtualdev", "e1000e")
    upd: dict[str, str | None] = {
        "ethernet0.present": "TRUE", "ethernet0.connectionType": "nat", "ethernet0.startConnected": "TRUE",
        "ethernet0.vnet": None,
        "ethernet1.present": "TRUE", "ethernet1.connectionType": "hostonly", "ethernet1.startConnected": "TRUE",
        "ethernet1.vnet": None, "ethernet1.virtualDev": kv.get("ethernet1.virtualdev", dev),
    }
    for i in (0, 1):
        if not kv.get(f"ethernet{i}.addresstype"):
            upd[f"ethernet{i}.addressType"] = "generated"
    if "ethernet0.virtualdev" not in kv:
        upd["ethernet0.virtualDev"] = dev
    for i in range(2, 10):
        if kv.get(f"ethernet{i}.present", "FALSE").upper() == "TRUE":
            upd[f"ethernet{i}.present"] = "FALSE"
    return upd


def slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9-]+", "-", text).strip("-").lower()
    return (s or "vm")[:40]


# ------------------------------------------------------------------ setup
class VmwareSetup:
    def __init__(self, opts: SetupOptions, provider: VMwareProvider | None = None, *,
                 client_factory: Callable[[str, str], object] | None = None,
                 out: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic, dhcp_paths: list[str] | None = None,
                 workdir: Path | None = None):
        self.o = opts
        self.p = provider or VMwareProvider(executable=opts.vmrun, host_type=opts.host_type)
        self.auth = GuestAuth(opts.guest_user, opts.guest_password)
        self.client_factory = client_factory or (lambda url, token: HttpGuestClient(url, token, timeout=15))
        self.out, self.sleep, self.monotonic = out, sleep, monotonic
        self.dhcp_paths = dhcp_paths
        self.vmx = str(Path(opts.vmx))
        self.report: dict = {"webcquisition_version": __version__, "vmx": self.vmx, "started_at_utc": iso_utc(),
                             "steps": [], "warnings": []}
        self._tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="webcq-setup-"))
        self._own_tmp = workdir is None
        self.log: EventLog | None = None

    # -------------------------------------------------------- utilità
    def step(self, name: str, message: str, **data):
        self.out(f"[{len(self.report['steps']) + 1:02d}] {message}")
        self.report["steps"].append({"name": name, "at_utc": iso_utc(), "message": message, **data})
        if self.log:
            self.log.emit(EventType.VM_SETUP_STEP, component="vmware-setup", message=message, data={"step": name, **data})

    def warn(self, message: str):
        self.out(f"     ATTENZIONE: {message}")
        self.report["warnings"].append(message)
        if self.log:
            self.log.emit(EventType.WARNING, severity=Severity.WARNING, component="vmware-setup", message=message)

    def _info(self):
        return self.p.get_info(self.vmx)

    def _wait_off(self):
        deadline = self.monotonic() + self.o.shutdown_timeout_s
        while self.monotonic() < deadline:
            if self._info().state == VMState.POWERED_OFF:
                return True
            self.sleep(3)
        return False

    def _shutdown(self):
        try:
            self.p.request_shutdown(self.vmx)
        except ProviderError as exc:
            self.warn(f"arresto controllato non riuscito: {exc}")
        if not self._wait_off():
            self.warn("la VM non si è spenta entro il timeout: spegnimento forzato")
            self.p.force_poweroff(self.vmx)
            if not self._wait_off():
                raise SetupError("VM_SHUTDOWN_FAILED", "impossibile spegnere la VM")

    # -------------------------------------------------------- fasi
    def _preflight(self):
        o = self.o
        if Path(o.config_out).exists():
            raise SetupError("CONFIG_EXISTS", f"{o.config_out} esiste già: non viene sovrascritto (usare --config-out)")
        if not self.p.is_available():
            raise SetupError("VMRUN_NOT_FOUND", f"vmrun non trovato ({self.p.executable}): installare VMware "
                             "Workstation Pro o indicare --vmrun")
        info = self._info()
        if info.state != VMState.POWERED_OFF:
            raise SetupError("VM_NOT_OFF", f"la VM è nello stato '{info.state.value}': spegnerla (non sospenderla) "
                             "e chiudere la sua scheda in VMware prima del setup")
        if o.snapshot in info.snapshots:
            raise SetupError("SNAPSHOT_EXISTS", f"esiste già uno snapshot '{o.snapshot}': scegliere --snapshot diverso")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", o.snapshot):
            raise SetupError("SNAPSHOT_NAME_INVALID", "nome snapshot: solo lettere, cifre, . _ -")
        if o.autologon and not o.operator_password:
            raise SetupError("AUTOLOGON_PASSWORD_MISSING", "--autologon richiede la password dell'operatore")
        self.report["vm"] = {"name": info.name, "uuid": info.uuid, "provider_version": self.p.version(),
                             "host_type": self.p.host_type}
        self.step("preflight", f"VM '{info.name}' spenta, uuid {info.uuid}, vmrun {self.report['vm']['provider_version']}")
        return info

    def _network(self, info):
        problems = network_problems(info.nics)
        if problems:
            if not self.o.fix_network:
                raise SetupError("NETWORK_LAYOUT", "configurazione di rete non conforme: " + "; ".join(problems) +
                                 ". Correggere in VM > Settings oppure rilanciare con --fix-network")
            vmx = Path(self.vmx)
            text = read_vmx_text(vmx)
            backup = vmx.with_name(vmx.name + f".webcq-backup-{utc_now().strftime('%Y%m%dT%H%M%SZ')}")
            shutil.copy2(vmx, backup)
            vmx.write_text(set_vmx_values(text, network_fix_updates(parse_vmx(text))), encoding="utf-8")
            self.step("fix_network", f"schede di rete corrette nel .vmx (copia: {backup.name})", problems=problems)
            info = self._info()
            remaining = network_problems(info.nics)
            if remaining:
                raise SetupError("NETWORK_LAYOUT", "correzione non riuscita: " + "; ".join(remaining))
        vnet = (info.nics[1].network or "vmnet1").lower()
        if self.o.host_ip:
            if not self.o.control_ip or not self.o.prefix_length:
                raise SetupError("ADDRESSING_INCOMPLETE", "con --host-ip indicare anche --control-ip e --prefix-length")
            host_ip = self.o.host_ip
            net = ipaddress.IPv4Network(f"{host_ip}/{self.o.prefix_length}", strict=False)
        else:
            host_ip, net = detect_hostonly_network(vnet, self.dhcp_paths)
        control_ip, prefix = plan_addresses(host_ip, net, self.o.control_ip)
        self.addr = {"host_ip": host_ip, "control_ip": control_ip, "prefix_length": prefix, "network": str(net)}
        self.report["network"] = {**self.addr, "capture_nic": CAPTURE_NIC_NAME, "control_nic": CONTROL_NIC_NAME}
        self.step("addressing", f"rete host-only {net}: host {host_ip}, VM {control_ip}")

    def _secrets(self):
        tf = Path(self.o.token_file)
        if tf.exists():
            self.token = tf.read_text(encoding="utf-8").strip()
            if len(self.token) < 32:
                raise SetupError("TOKEN_INVALID", f"{tf}: token troppo corto")
            self.step("token", f"token esistente riutilizzato ({tf})")
        else:
            tf.parent.mkdir(parents=True, exist_ok=True)
            self.token = secrets.token_urlsafe(48)
            with open(tf, "x", encoding="utf-8") as fh:
                fh.write(self.token + "\n")
            try:
                tf.chmod(0o600)
            except OSError:
                pass
            self.step("token", f"nuovo token generato in {tf} (proteggerne l'accesso)")
        self.agent_id = self.o.agent_id or f"{slug(Path(self.vmx).stem)}-{secrets.token_hex(3)}"

    def _prepare_files(self, info):
        zip_path = self._tmp / "agent-bundle.zip"
        zip_sha, lines = build_bundle_zip(zip_path, self._tmp)
        self.report["agent_bundle"] = {"zip_sha256": zip_sha, "files": lines}
        agent = {"listen_host": self.addr["control_ip"], "listen_port": self.o.agent_port, "token": self.token,
                 "agent_id": self.agent_id, "control_ip": self.addr["control_ip"],
                 "dumpcap_path": self.o.dumpcap_path, "tshark_path": str(Path(self.o.dumpcap_path).parent / "tshark.exe"),
                 "wireshark_path": self.o.wireshark_path, "firefox_path": self.o.firefox_path,
                 "log_dir": r"C:\ProgramData\WEBCQUISITION\logs"}
        (self._tmp / "agent.json").write_text(json.dumps(agent, indent=2), encoding="utf-8")
        nics = {n.index: n for n in info.nics}
        if not nics[1].mac or not nics[2].mac:
            raise SetupError("MAC_UNKNOWN", "indirizzi MAC delle schede non ancora assegnati da VMware nel .vmx")
        self.run_id = secrets.token_hex(8)
        params = {"run_id": self.run_id, "operator_user": self.o.operator_user, "host_ip": self.addr["host_ip"],
                  "control_ip": self.addr["control_ip"], "prefix_length": self.addr["prefix_length"],
                  "control_mac": nics[2].mac, "capture_mac": nics[1].mac, "control_nic_name": CONTROL_NIC_NAME,
                  "capture_nic_name": CAPTURE_NIC_NAME, "autologon": self.o.autologon,
                  "disable_windows_update": self.o.disable_windows_update}
        (self._tmp / "setup-params.json").write_text(json.dumps(params, indent=2), encoding="utf-8")
        (self._tmp / "guest-setup.ps1").write_text(asset_text("guest-setup.ps1"), encoding="utf-8-sig", newline="\r\n")
        files = ["agent-bundle.zip", "agent.json", "setup-params.json", "guest-setup.ps1"]
        if self.o.autologon:
            (self._tmp / "operator.pw").write_text(self.o.operator_password, encoding="utf-8")
            files.append("operator.pw")
        self.report["nics"] = [{"index": n.index, "attachment": n.attachment, "mac": n.mac} for n in info.nics]
        return files

    def _boot(self, message: str):
        self.out("     avvio della VM in corso (se non procede entro 2 minuti: controllare le finestre di "
                 "dialogo di VMware Workstation)...")
        self.p.start(self.vmx, gui=True)
        if self.p.last_start_warning:
            self.warn(self.p.last_start_warning)
        self.step("boot", message)
        self.p.wait_tools_running(self.vmx, self.o.tools_timeout_s, sleep=self.sleep, monotonic=self.monotonic)
        self.step("tools", "VMware Tools attivi nel guest")

    def _run_guest_setup(self, files: list[str]) -> dict:
        self.p.mkdir_in_guest(self.vmx, self.auth, GUEST_WORKDIR)
        for stale in ("setup-result.json", "setup-progress.log"):  # residui di tentativi precedenti
            self.p.delete_in_guest(self.vmx, self.auth, f"{GUEST_WORKDIR}\\{stale}")
        for f in files:
            self.p.copy_to_guest(self.vmx, self.auth, self._tmp / f, f"{GUEST_WORKDIR}\\{f}")
        self.step("copy", f"{len(files)} file copiati in {GUEST_WORKDIR}")
        script = f"{GUEST_WORKDIR}\\guest-setup.ps1"
        self.out("     esecuzione dello script di preparazione nel guest (di solito 1-3 minuti):")
        self.p.run_in_guest(self.vmx, self.auth, POWERSHELL,
                            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
                             "-WorkDir", GUEST_WORKDIR], no_wait=True)
        result = self._wait_guest_result(self.o.guest_setup_timeout_s)
        if result.get("code") == "NOT_ELEVATED":
            self.out("\n" + "=" * 78)
            self.out("Le guest operations non hanno privilegi di amministratore (UAC).")
            self.out("Nella VM, aprire PowerShell con 'Esegui come amministratore' ed eseguire:")
            self.out(f'    powershell -NoProfile -ExecutionPolicy Bypass -File "{script}"')
            self.out("Il setup prosegue da solo appena lo script termina (in alternativa usare")
            self.out("l'account Administrator integrato come --guest-user).")
            self.out("=" * 78 + "\n")
            result = self._wait_guest_result(self.o.manual_elevation_timeout_s,
                                             previous=result.get("finished_at_utc"))
            if result.get("code") == "NOT_ELEVATED":
                raise SetupError("NOT_ELEVATED", "script di preparazione non eseguito come amministratore entro il timeout")
        self.report["guest_setup"] = result
        for w in result.get("warnings") or []:
            self.warn(f"guest: {w}")
        # doppia sicurezza: i file con segreti non devono finire nello snapshot
        for f in ("agent.json", "operator.pw"):
            self.p.delete_in_guest(self.vmx, self.auth, f"{GUEST_WORKDIR}\\{f}")
        if not result.get("ok"):
            raise SetupError(result.get("code") or "GUEST_SETUP_FAILED",
                             f"preparazione nel guest fallita: {result.get('message')}")
        for s in result.get("steps", []):
            self.step(f"guest.{s.get('name')}", f"guest: {s.get('name')} ok")
        return result

    def _wait_guest_result(self, timeout_s: float, previous: str | None = None) -> dict:
        """Attende setup-result.json di QUESTA esecuzione, mostrando l'avanzamento scritto dal guest."""
        deadline = self.monotonic() + timeout_s
        shown = 0
        while True:
            lines = self._fetch_progress()
            for line in lines[shown:]:
                self.out(f"       guest {line}")
            shown = max(shown, len(lines))
            try:
                result = self._fetch_result()
            except SetupError:
                result = None
            if (result and result.get("run_id") in (None, self.run_id)
                    and (previous is None or result.get("finished_at_utc") != previous)):
                return result
            if any(line.endswith("script terminato") for line in lines[-2:]) and result is None:
                terminated = getattr(self, "_terminated_polls", 0) + 1
                self._terminated_polls = terminated
                if terminated >= 3:
                    raise SetupError("GUEST_RESULT_MISSING", "lo script nel guest è terminato senza scrivere il "
                                     f"risultato: vedere {GUEST_WORKDIR}\\setup-progress.log nella VM")
            if self.monotonic() >= deadline:
                last = lines[-1] if lines else "nessun avanzamento registrato"
                raise SetupError("GUEST_SETUP_TIMEOUT", f"lo script nel guest non è terminato entro {timeout_s:.0f}s "
                                 f"(ultimo passo: {last}). Nella VM: {GUEST_WORKDIR}\\setup-progress.log")
            self.sleep(5)

    def _fetch_progress(self) -> list[str]:
        dst = self._tmp / f"progress-{secrets.token_hex(4)}.log"
        try:
            self.p.copy_from_guest(self.vmx, self.auth, f"{GUEST_WORKDIR}\\setup-progress.log", dst)
            return [ln.strip() for ln in dst.read_text(encoding="utf-8-sig", errors="replace").splitlines() if ln.strip()]
        except (ProviderError, OSError):
            return []

    def _fetch_result(self) -> dict:
        dst = self._tmp / f"setup-result-{secrets.token_hex(4)}.json"
        try:
            self.p.copy_from_guest(self.vmx, self.auth, f"{GUEST_WORKDIR}\\setup-result.json", dst)
            return json.loads(dst.read_text(encoding="utf-8-sig"))
        except (ProviderError, OSError, ValueError) as exc:
            raise SetupError("GUEST_RESULT_MISSING", f"risultato della preparazione non leggibile: {exc}") from exc

    def _verify_agent(self):
        url = f"http://{self.addr['control_ip']}:{self.o.agent_port}"
        client = self.client_factory(url, self.token)
        if not self.o.autologon:
            self.out(f"\n>>> Accedere ora nella VM con l'utente '{self.o.operator_user}': l'agent parte al logon.\n")
        deadline = self.monotonic() + self.o.agent_timeout_s
        health, last = None, ""
        while self.monotonic() < deadline:
            try:
                h = client.health()
                if h.get("interactive_session"):
                    health = h
                    break
                last = "sessione desktop non ancora interattiva"
            except (AgentUnreachable, AgentError) as exc:
                last = str(exc)
            self.sleep(5)
        if not health:
            raise SetupError("AGENT_NOT_REACHABLE", f"agent non raggiungibile su {url} entro {self.o.agent_timeout_s}s: "
                             f"{last}. Verificare che l'host abbia l'IP {self.addr['host_ip']} sulla rete host-only.")
        if health.get("agent_id") != self.agent_id:
            raise SetupError("AGENT_IDENTITY_MISMATCH", f"agent_id '{health.get('agent_id')}' atteso '{self.agent_id}'")
        if health.get("protocol") != PROTOCOL_VERSION:
            raise SetupError("PROTOCOL_MISMATCH", f"protocollo {health.get('protocol')} != {PROTOCOL_VERSION}")
        if health.get("session_active"):
            raise SetupError("GUEST_NOT_CLEAN", "l'agent ha già una sessione attiva")
        offset = (parse_iso(health["utc"]) - datetime.now(timezone.utc)).total_seconds()
        if abs(offset) > 2:
            self.warn(f"orologio del guest sfasato di {offset:.1f}s: attivare la sincronizzazione oraria di VMware Tools")
        ifaces = client.interfaces().get("interfaces", [])
        try:
            chosen = select_interface(CAPTURE_NIC_NAME, ifaces)
        except InterfaceSelectionError as exc:
            raise SetupError(exc.code, str(exc)) from exc
        if not any(i.get("is_control") for i in ifaces):
            raise SetupError("CONTROL_NOT_DETECTED", "l'agent non riconosce la propria scheda di controllo")
        self.report["agent"] = {"url": url, "agent_id": self.agent_id, "agent_version": health.get("agent_version"),
                                "clock_offset_s": round(offset, 3), "capture_interface": chosen, "interfaces": ifaces}
        self.step("agent", f"agent {self.agent_id} raggiungibile, sessione interattiva, cattura su "
                           f"'{CAPTURE_NIC_NAME}' ({chosen.get('name')})")

    def _write_config(self, info):
        o = self.o
        cfg = {
            "hypervisor": {"provider": "vmware", "vm_name": self.vmx, "vm_uuid": info.uuid, "snapshot": o.snapshot,
                           "require_snapshot": True, "start_mode": "gui",
                           "expected_nics": {"1": "nat", "2": "hostonly"}, "post_acquisition_snapshot": "on_failure",
                           "executable": self.p.executable, "vmrun_host_type": self.p.host_type},
            "agent": {"url": f"http://{self.addr['control_ip']}:{o.agent_port}", "token_file": str(Path(o.token_file).resolve()),
                      "expected_agent_id": self.agent_id},
            "capture": {"engine": "dumpcap", "mode": "dual", "interface": CAPTURE_NIC_NAME},
            "browser": {"start_url": o.start_url},
            "finalize": {"block_guest_shutdown": True, "recover_on_vm_loss": True},
            "case": {"output_directory": o.cases_dir, "organization": o.organization},
        }
        config_from_dict(cfg)  # validazione prima della scrittura
        header = (f"# Generato da 'webcquisition vmware-setup' {__version__} il {iso_utc()}\n"
                  f"# VM: {self.vmx}\n# Snapshot pulito: {o.snapshot}\n"
                  "# Opzioni complete: config/webcquisition.example.yaml e docs/CONFIGURATION.md\n")
        Path(o.config_out).parent.mkdir(parents=True, exist_ok=True)
        with open(o.config_out, "x", encoding="utf-8") as fh:
            fh.write(header + yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
        self.report["config"] = {"path": str(o.config_out), "sha256": sha256_file(Path(o.config_out))[0]}

    # -------------------------------------------------------- esecuzione
    def run(self) -> dict:
        stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
        report_path = self.report_path = Path(f"{self.o.config_out}.setup-{stamp}.json")
        log_path = self.events_path = Path(f"{self.o.config_out}.setup-{stamp}.events.jsonl")
        Path(self.o.config_out).parent.mkdir(parents=True, exist_ok=True)
        self.log = EventLog(log_path, "VM-SETUP", "host")
        self.report["events_file"] = log_path.name
        self.log.emit(EventType.VM_SETUP_STARTED, component="vmware-setup",
                      data={"vmx": self.vmx, "guest_user": self.o.guest_user, "operator_user": self.o.operator_user,
                            "snapshot": self.o.snapshot})
        vm_started = False
        try:
            info = self._preflight()
            self._network(info)
            self._secrets()
            self._boot("VM avviata per la preparazione")
            vm_started = True
            info = self._info()  # MAC generati da VMware all'accensione
            files = self._prepare_files(info)
            self._run_guest_setup(files)
            self._shutdown()
            self.step("reboot", "VM spenta; riavvio per verificare l'avvio automatico dell'agent")
            self._boot("VM riavviata")
            self._verify_agent()
            self._shutdown()
            vm_started = False
            self.step("shutdown", "VM spenta in modo controllato")
            self.p.take_snapshot(self.vmx, self.o.snapshot)
            info = self._info()
            if self.o.snapshot not in info.snapshots:
                raise SetupError("SNAPSHOT_FAILED", "snapshot non presente dopo la creazione")
            self.step("snapshot", f"snapshot pulito '{self.o.snapshot}' creato")
            self._write_config(info)
            self.step("config", f"configurazione scritta in {self.o.config_out}")
            self.report.update(ok=True, finished_at_utc=iso_utc())
            self.log.emit(EventType.VM_SETUP_COMPLETED, component="vmware-setup",
                          data={"snapshot": self.o.snapshot, "config": self.report["config"],
                                "bundle_zip_sha256": self.report["agent_bundle"]["zip_sha256"]})
            return self.report
        except (SetupError, ProviderError) as exc:
            self.report.update(ok=False, error=str(exc), finished_at_utc=iso_utc())
            self.log.emit(EventType.VM_SETUP_FAILED, severity=Severity.ERROR, component="vmware-setup", message=str(exc))
            if vm_started:
                self.warn("la VM è rimasta accesa per l'analisi del problema; nessuno snapshot è stato creato")
            raise
        finally:
            self.report["events_head_hash"] = self.log.head_hash
            self.log.close()
            with open(report_path, "x", encoding="utf-8") as fh:
                json.dump(self.report, fh, indent=2, ensure_ascii=False, default=str)
            if self._own_tmp:
                shutil.rmtree(self._tmp, ignore_errors=True)
