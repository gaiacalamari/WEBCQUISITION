"""Interfaccia a riga di comando.

    webcquisition -c config.yaml check-env
    webcquisition -c config.yaml create-case CASE-2026-001 --output D:\\Cases\\CASE-2026-001 --operator "Mario Rossi"
    webcquisition -c config.yaml run   --output D:\\Cases\\CASE-2026-001        (interattivo, consigliato)
    webcquisition -c config.yaml start --output D:\\Cases\\CASE-2026-001        (avvia e ritorna)
    webcquisition -c config.yaml status --output D:\\Cases\\CASE-2026-001
    webcquisition -c config.yaml stop  --output D:\\Cases\\CASE-2026-001
    webcquisition verify --output D:\\Cases\\CASE-2026-001
    webcquisition -c config.yaml acquire CASE-2026-001 --output ... --dry-run  (crea + run)
    webcquisition gen-token --out token.txt
"""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

from webcquisition_common import __version__
from webcquisition_common.events import EventType, verify_chain
from webcquisition_common.hashing import parse_sha256sums, verify_entries

from .case import Case, CaseError, CaseLockedError, resolve_case_dir
from .config import Config, ConfigError, config_from_dict, default_config_path, load_config, read_token
from .fake_guest import FakeGuestClient
from .guest_client import AgentError, AgentUnreachable, HttpGuestClient
from .orchestrator import Acquisition, AcquisitionFailed
from .providers import FakeProvider, ProviderError, VMState, normalize_uuid, provider_from_config
from .state import AcquisitionState as S

EXIT_OK, EXIT_INCOMPLETE, EXIT_FAILED, EXIT_USAGE = 0, 2, 3, 64


def _setup_logging(case_dir: Path | None, verbose: bool):
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    handlers[0].setLevel(logging.DEBUG if verbose else logging.WARNING)
    if case_dir and (case_dir / "logs").is_dir():
        fh = logging.FileHandler(case_dir / "logs" / "host.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        handlers.append(fh)
    logging.basicConfig(level=logging.DEBUG, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", force=True)


def _load_cfg(args) -> Config:
    if args.config:
        return load_config(Path(args.config))
    default = default_config_path()
    if default.is_file() and not getattr(args, "dry_run", False):
        return load_config(default)
    if getattr(args, "dry_run", False):
        return config_from_dict({"hypervisor": {"provider": "fake", "vm_name": "fake-vm", "snapshot": "clean"},
                                 "agent": {"expected_agent_id": "fake-agent", "poll_interval_s": 0.2},
                                 "capture": {"verify_timeout_s": 5}})
    raise ConfigError([f"nessuna configurazione: eseguire 'webcquisition vmware-setup' (crea {default}) "
                       "oppure indicare -c/--config"])


def _dryrun_cfg(cfg: Config) -> Config:
    """In dry-run si forzano provider e agent simulati mantenendo il resto della configurazione."""
    cfg.hypervisor.provider = "fake"
    cfg.hypervisor.executable = None
    cfg.agent.poll_interval_s = min(cfg.agent.poll_interval_s, 0.2)
    cfg.agent.expected_agent_id = "fake-agent"
    cfg.agent.ready_timeout_s = min(cfg.agent.ready_timeout_s, 10)
    cfg.capture.verify_timeout_s = min(cfg.capture.verify_timeout_s, 5)
    return cfg


def _sandbox(case_id: str) -> Path:
    return Path(tempfile.gettempdir()) / "webcquisition-dryrun" / case_id


def _build(cfg: Config, case: Case, dry_run: bool):
    if dry_run:
        sb = _sandbox(case.case_id)
        provider = FakeProvider(vm_name=cfg.hypervisor.vm_name, uuid=cfg.hypervisor.vm_uuid or
                                "00000000-0000-0000-0000-00000000f00d",
                                snapshots=[cfg.hypervisor.snapshot] if cfg.hypervisor.snapshot else [],
                                nics=[{"index": int(k), "attachment": v} for k, v in cfg.hypervisor.expected_nics.items()]
                                or None, state_file=sb / "vm.json")
        client = FakeGuestClient(sb / "guest", agent_id="fake-agent")
    else:
        provider = provider_from_config(cfg.hypervisor)
        client = HttpGuestClient(cfg.agent.url, read_token(cfg), timeout=cfg.agent.request_timeout_s)
    return provider, client


def _case_dir(args, cfg: Config | None) -> Path:
    return resolve_case_dir(getattr(args, "output", None), getattr(args, "case", None),
                            cfg.case.output_directory if cfg else None)


def _exit_for(state: S) -> int:
    return {S.COMPLETED: EXIT_OK, S.INCOMPLETE: EXIT_INCOMPLETE}.get(state, EXIT_FAILED)


# ---------------------------------------------------------------- commands
def cmd_gen_token(args) -> int:
    out = Path(args.out)
    if out.exists():
        print(f"{out} esiste già: non viene sovrascritto", file=sys.stderr)
        return EXIT_USAGE
    out.write_text(secrets.token_urlsafe(48) + "\n", encoding="utf-8")
    print(f"Token scritto in {out}. Copiarlo in agent.json nella VM (campo 'token').")
    return EXIT_OK


def cmd_check_env(args) -> int:
    cfg = _load_cfg(args)
    ok = True
    h = cfg.hypervisor

    def res(good: bool, text: str) -> bool:
        print(f"[{'OK' if good else 'KO'}] {text}")
        return good

    print(f"Configurazione: {cfg.source_path} (SHA-256 {cfg.source_sha256})")
    provider = provider_from_config(h)
    info = None
    try:
        ok &= res(provider.is_available(), f"hypervisor {provider.name} ({provider.executable}) versione {provider.version()}")
        info = provider.get_info(h.vm_name)
        print(f"[OK] VM {info.name} uuid={info.uuid} stato={info.state.value}")
        if h.vm_uuid:
            ok &= res(normalize_uuid(info.uuid) == normalize_uuid(h.vm_uuid), "UUID uguale a quello configurato")
        if h.snapshot:
            ok &= res(info.snapshots.count(h.snapshot) == 1,
                      f"snapshot '{h.snapshot}' presente una sola volta (disponibili: {info.snapshots})")
        for idx, exp in h.expected_nics.items():
            nic = next((n for n in info.nics if str(n.index) == str(idx)), None)
            good = nic is not None and nic.attachment.lower() == exp.lower() and nic.connected is not False
            ok &= res(good, f"NIC {idx}: atteso {exp}, trovato {nic.attachment if nic else 'assente'}"
                            + (" (non collegata all'accensione)" if nic and nic.connected is False else ""))
        extra = sorted({n.index for n in info.nics} - {int(k) for k in h.expected_nics})
        if h.expected_nics:
            ok &= res(not extra, f"nessuna NIC non prevista {extra if extra else ''}".strip())
    except ProviderError as exc:
        ok = res(False, str(exc))
    try:
        token = read_token(cfg)
        res(True, "token agent leggibile")
    except (ConfigError, OSError) as exc:
        token = None
        ok = res(False, f"token: {exc}")
    if cfg.case.output_directory:
        out = Path(cfg.case.output_directory)
        ok &= res(out.is_dir() or not out.exists(), f"cartella dei casi {out}")
    if not getattr(args, "live", False):
        print("Suggerimento: 'check-env --live' avvia la VM dallo snapshot e verifica anche l'agent.")
        return EXIT_OK if ok else EXIT_FAILED
    if not ok or info is None or token is None:
        print("Verifica live non eseguita: correggere prima gli errori sopra.")
        return EXIT_FAILED
    return EXIT_OK if _live_check(cfg, provider, info, token) else EXIT_FAILED


def _live_check(cfg: Config, provider, info, token: str) -> bool:
    """Avvia la VM dallo snapshot pulito, verifica agent e interfacce, spegne. Nessun caso creato."""
    import time as _time

    from .orchestrator import InterfaceSelectionError, select_interface
    h = cfg.hypervisor
    if info.state != VMState.POWERED_OFF:
        print(f"[KO] la VM è nello stato {info.state.value}: deve essere spenta")
        return False
    ok = True
    try:
        provider.restore_snapshot(h.vm_name, h.snapshot)
        provider.start(h.vm_name, gui=h.start_mode == "gui")
        print("[OK] VM ripristinata dallo snapshot e avviata")
        if hasattr(provider, "wait_tools_running"):
            provider.wait_tools_running(h.vm_name, h.tools_timeout_s)
            print("[OK] VMware Tools attivi")
        client = HttpGuestClient(cfg.agent.url, token, timeout=10)
        deadline = _time.monotonic() + cfg.agent.ready_timeout_s
        health = None
        while _time.monotonic() < deadline:
            try:
                hh = client.health()
                if hh.get("interactive_session"):
                    health = hh
                    break
            except (AgentUnreachable, AgentError):
                pass
            _time.sleep(3)
        if not health:
            print(f"[KO] agent non pronto entro {cfg.agent.ready_timeout_s}s su {cfg.agent.url}")
            return False
        ok &= health.get("agent_id") == cfg.agent.expected_agent_id or not cfg.agent.expected_agent_id
        print(f"[{'OK' if ok else 'KO'}] agent {health.get('agent_id')} versione {health.get('agent_version')}")
        try:
            chosen = select_interface(cfg.capture.interface, client.interfaces().get("interfaces", []))
            print(f"[OK] interfaccia di cattura: {chosen.get('friendly_name')} {chosen.get('name')}")
        except InterfaceSelectionError as exc:
            print(f"[KO] {exc}")
            ok = False
    except ProviderError as exc:
        print(f"[KO] {exc}")
        ok = False
    finally:
        try:
            if provider.get_info(h.vm_name).state == VMState.RUNNING:
                provider.request_shutdown(h.vm_name)
                provider.wait_for_state(h.vm_name, [VMState.POWERED_OFF], h.shutdown_timeout_s)
                print("[OK] VM spenta")
        except ProviderError as exc:
            print(f"[KO] arresto: {exc}; spegnimento forzato")
            provider.force_poweroff(h.vm_name)
    return ok

def _read_secret(path: str | None, prompt: str, env: str) -> str:
    import getpass
    import os
    if path:
        return Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    if os.environ.get(env):
        return os.environ[env]
    return getpass.getpass(prompt)


def cmd_vmware_setup(args) -> int:
    from .vmware_setup import SetupError, SetupOptions, VmwareSetup
    config_out = Path(args.config_out) if args.config_out else default_config_path()
    opts = SetupOptions(
        vmx=args.vmx, guest_user=args.guest_user,
        guest_password=_read_secret(args.guest_password_file, f"Password di '{args.guest_user}' nella VM: ",
                                    "WEBCQ_GUEST_PASSWORD"),
        operator_user=args.operator_user or args.guest_user, config_out=config_out,
        token_file=Path(args.token_file) if args.token_file else config_out.with_name("agent.token"),
        cases_dir=args.cases_dir, snapshot=args.snapshot, agent_id=args.agent_id, host_ip=args.host_ip,
        control_ip=args.control_ip, prefix_length=args.prefix_length, agent_port=args.agent_port,
        fix_network=args.fix_network, autologon=args.autologon, disable_windows_update=args.disable_windows_update,
        organization=args.organization, start_url=args.start_url, vmrun=args.vmrun, host_type="fusion" if args.fusion else "ws",
        operator_password=(_read_secret(args.operator_password_file, f"Password di '{args.operator_user or args.guest_user}'"
                                        " per l'accesso automatico: ", "WEBCQ_OPERATOR_PASSWORD")
                           if args.autologon else None),
    )
    print(f"WEBCQUISITION {__version__} - preparazione automatica della VM {opts.vmx}\n")
    setup = VmwareSetup(opts)
    try:
        report = setup.run()
    except (SetupError, ProviderError) as exc:
        print(f"\nPREPARAZIONE NON COMPLETATA: {exc}", file=sys.stderr)
        if getattr(setup, "report_path", None):
            print(f"Dettagli: {setup.report_path}", file=sys.stderr)
        return EXIT_FAILED
    print(f"\nVM pronta. Snapshot pulito: {opts.snapshot}")
    print(f"Configurazione: {config_out}")
    print(f"Rapporto di preparazione: {setup.report_path} (conservarlo con la documentazione del laboratorio)")
    if report.get("warnings"):
        print(f"{len(report['warnings'])} avvisi: vedere il rapporto.")
    print("\nProva completa:  webcquisition check-env --live")
    print("Acquisizione:    webcquisition acquire CASE-AAAA-NNN --operator \"Nome Cognome\"")
    return EXIT_OK


def cmd_create_case(args) -> int:
    cfg = _load_cfg(args)
    case_dir = resolve_case_dir(args.output, args.case_id, cfg.case.output_directory)
    case = Case.create(case_dir, args.case_id, operator=args.operator or cfg.case.operator,
                       organization=cfg.case.organization, dry_run=args.dry_run, config_dict=cfg.to_dict())
    from webcquisition_common.events import EventLog
    with EventLog(case.events_path, case.case_id, "host") as ev:
        ev.emit(EventType.CASE_CREATED, component="cli",
                data={"case_dir": str(case.dir.resolve()), "operator": case.data.get("operator"),
                      "config_sha256": cfg.source_sha256, "dry_run": args.dry_run})
    if args.dry_run:
        # la sandbox simulata (VM + guest finti) riparte sempre pulita, come uno snapshot ripristinato
        shutil.rmtree(_sandbox(case.case_id), ignore_errors=True)
    print(f"Caso {case.case_id} creato in {case.dir}")
    return EXIT_OK


def _open(args, need_cfg=True):
    cfg = _load_cfg(args)
    case_dir = _case_dir(args, cfg)
    case = Case(case_dir)
    dry = bool(args.dry_run or case.data.get("dry_run"))
    if dry != bool(case.data.get("dry_run")):
        raise CaseError("un caso reale non può essere eseguito in --dry-run e viceversa")
    if dry:
        cfg = _dryrun_cfg(cfg)
    _apply_overrides(args, cfg)
    _setup_logging(case_dir, args.verbose)
    return cfg, case, dry


def _apply_overrides(args, cfg: Config) -> None:
    """--vm è una CONFERMA (deve coincidere con la configurazione), --interface una scelta esplicita."""
    vm = getattr(args, "vm", None)
    if vm and vm != cfg.hypervisor.vm_name:
        raise ConfigError([f"--vm '{vm}' non corrisponde a hypervisor.vm_name '{cfg.hypervisor.vm_name}' "
                           "della configurazione: per sicurezza non si usa una VM non documentata"])
    iface = getattr(args, "interface", None)
    if iface:
        cfg.capture.interface = iface


def cmd_run(args) -> int:
    cfg, case, dry = _open(args)
    if case.state != S.CREATED:
        print(f"ERRORE: il caso è nello stato {case.state.value}: un caso si acquisisce una sola volta. "
              "Creare un nuovo caso.", file=sys.stderr)
        return EXIT_USAGE
    provider, client = _build(cfg, case, dry)
    with case.lock():
        acq = Acquisition(case, cfg, provider, client, dry_run=dry)
        try:
            final = acq.run_interactive(auto_stop_s=args.auto_stop)
        except AcquisitionFailed as exc:
            print(f"Acquisizione terminata con esito {exc.final_state.value}: {exc}", file=sys.stderr)
            return _exit_for(exc.final_state)
        finally:
            acq.close()
    return _exit_for(final)


def cmd_start(args) -> int:
    cfg, case, dry = _open(args)
    if case.state != S.CREATED:
        print(f"ERRORE: il caso è nello stato {case.state.value}: un caso si acquisisce una sola volta. "
              "Creare un nuovo caso.", file=sys.stderr)
        return EXIT_USAGE
    provider, client = _build(cfg, case, dry)
    with case.lock():
        acq = Acquisition(case, cfg, provider, client, dry_run=dry)
        try:
            acq.prepare_and_start()
        except AcquisitionFailed as exc:
            print(f"Avvio fallito, esito {exc.final_state.value}: {exc}", file=sys.stderr)
            return _exit_for(exc.final_state)
        finally:
            acq.close()
    print("Acquisizione avviata. Usare 'status' per il monitoraggio e 'stop' per terminare.")
    return EXIT_OK


def cmd_status(args) -> int:
    cfg, case, dry = _open(args)
    if case.state != S.ACQUIRING:
        print(json.dumps({"case_id": case.case_id, "state": case.state.value}, indent=2))
        return EXIT_OK
    provider, client = _build(cfg, case, dry)
    with case.lock():
        acq = Acquisition(case, cfg, provider, client, dry_run=dry)
        try:
            r = acq.monitor_once()
            summary = acq.status_summary()
            summary["stop_requested_from_guest"] = r == "stop"
            print(json.dumps(summary, indent=2, ensure_ascii=False))
        finally:
            acq.close()
    return EXIT_OK


def cmd_stop(args) -> int:
    cfg, case, dry = _open(args)
    provider, client = _build(cfg, case, dry)
    with case.lock():
        acq = Acquisition(case, cfg, provider, client, dry_run=dry)
        try:
            acq.emit(EventType.USER_ACTION,
                     action="stop_command", reason=args.reason)
            final = acq.finalize(reason=args.reason)
        except AcquisitionFailed as exc:
            print(str(exc), file=sys.stderr)
            return _exit_for(exc.final_state)
        finally:
            acq.close()
    return _exit_for(final)


def cmd_acquire(args) -> int:
    rc = cmd_create_case(args)
    if rc != EXIT_OK:
        return rc
    if not args.output:
        cfg = _load_cfg(args)
        args.output = str(resolve_case_dir(None, args.case_id, cfg.case.output_directory))
    return cmd_run(args)


def cmd_wizard(args) -> int:
    """Procedura guidata: chiede ID caso e operatore, mostra il riepilogo e avvia l'acquisizione."""
    from webcquisition_common.paths import validate_case_id
    cfg = _load_cfg(args)
    if not cfg.case.output_directory:
        raise ConfigError(["case.output_directory non configurata"])
    print(f"WEBCQUISITION {__version__} - nuova acquisizione")
    print(f"  VM:       {cfg.hypervisor.vm_name}")
    print(f"  Snapshot: {cfg.hypervisor.snapshot}")
    print(f"  Casi in:  {cfg.case.output_directory}\n")
    while True:
        case_id = input("ID del caso (es. CASE-2026-001): ").strip()
        try:
            validate_case_id(case_id)
        except ValueError as exc:
            print(f"  {exc}")
            continue
        if resolve_case_dir(None, case_id, cfg.case.output_directory).exists():
            print("  esiste già un caso con questo ID")
            continue
        break
    operator = input(f"Operatore [{cfg.case.operator or ''}]: ").strip() or cfg.case.operator
    if not operator:
        print("L'operatore è obbligatorio.")
        return EXIT_USAGE
    out = resolve_case_dir(None, case_id, cfg.case.output_directory)
    print(f"\nLa VM verrà ripristinata dallo snapshot '{cfg.hypervisor.snapshot}' e avviata.")
    print(f"Il pacchetto sarà creato in {out}")
    if input("Confermi? [s/N] ").strip().lower() not in ("s", "si", "sì", "y", "yes"):
        print("Annullato.")
        return EXIT_USAGE
    args.case_id, args.output, args.operator, args.dry_run, args.auto_stop = case_id, str(out), operator, False, None
    args.case, args.vm, args.interface = None, None, None
    return cmd_acquire(args)


def cmd_verify(args) -> int:
    """Verifica offline di un pacchetto: nessuna scrittura."""
    case_dir = Path(args.output)
    ok = True
    sums = case_dir / "hashes" / "SHA256SUMS.txt"
    entries = [{"path": p, "sha256": h} for p, h in parse_sha256sums(sums.read_text(encoding="utf-8")).items()]
    problems = verify_entries(case_dir / "acquired", entries)
    print(f"[{'OK' if not problems else 'KO'}] {len(entries)} file verificati rispetto a SHA256SUMS.txt")
    for p in problems:
        print(f"      {p}")
        ok = False
    seal_path = case_dir / "hashes" / "package-seal.json"
    if seal_path.exists():
        from webcquisition_common.hashing import sha256_file
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        for key, rel in (("acquisition_json_sha256", "acquisition.json"),
                         ("report_sha256", "report/acquisition-report.html"),
                         ("sha256sums_sha256", "hashes/SHA256SUMS.txt"),
                         ("host_events_sha256", "logs/host-events.jsonl")):
            actual, _ = sha256_file(case_dir / rel)
            good = actual == seal.get(key)
            ok &= good
            print(f"[{'OK' if good else 'KO'}] {rel}")
        print(f"      SHA-256 package-seal.json: {sha256_file(seal_path)[0]}  (confrontare con il verbale)")
    else:
        print("[KO] hashes/package-seal.json mancante")
        ok = False
    for log_rel in ("logs/host-events.jsonl", "acquired/logs/guest-events.jsonl"):
        p = case_dir / log_rel
        if p.exists():
            r = verify_chain(p)
            ok &= r["valid"]
            print(f"[{'OK' if r['valid'] else 'KO'}] catena eventi {log_rel}: {r['count']} eventi"
                  + (f" – {r['error']}" if r["error"] else ""))
    return EXIT_OK if ok else EXIT_FAILED


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="webcquisition", description="Acquisizione forense di attività web in VM Windows")
    ap.add_argument("--version", action="version", version=f"WEBCQUISITION {__version__}")
    ap.add_argument("-c", "--config", help="file di configurazione YAML")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="command", required=True)

    def case_args(p, allow_dry=True):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--output", help="cartella del caso (es. D:\\Cases\\CASE-2026-001)")
        g.add_argument("--case", help="ID caso (cartella = case.output_directory/ID)")
        if allow_dry:
            p.add_argument("--dry-run", action="store_true", help="simulazione senza VM reale")

    def vm_args(p):
        p.add_argument("--vm", help="nome VM atteso (conferma: deve coincidere con hypervisor.vm_name)")
        p.add_argument("--interface", help="interfaccia di cattura nel guest (sovrascrive capture.interface)")

    p = sub.add_parser("gen-token", help="genera il token condiviso host/agent")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_gen_token)

    p = sub.add_parser("check-env", help="verifica VMware, VM, snapshot, NIC e token")
    p.add_argument("--live", action="store_true",
                   help="avvia la VM dallo snapshot, verifica agent e interfacce, la spegne (nessun caso creato)")
    p.set_defaults(fn=cmd_check_env)

    p = sub.add_parser("vmware-setup", help="prepara automaticamente la VM (agent, rete, snapshot, configurazione)")
    p.add_argument("--vmx", required=True, help="percorso del file .vmx della VM (spenta)")
    p.add_argument("--guest-user", required=True, help="account amministratore del guest per le guest operations")
    p.add_argument("--guest-password-file", help="file con la password (default: richiesta a terminale "
                   "o variabile WEBCQ_GUEST_PASSWORD)")
    p.add_argument("--operator-user", help="utente Windows con cui l'operatore usa la VM (default: --guest-user)")
    p.add_argument("--cases-dir", required=True, help="cartella dei casi sull'host (es. D:\\Cases)")
    p.add_argument("--config-out", help=f"configurazione da creare (default: {default_config_path()})")
    p.add_argument("--token-file", help="file del token (default: agent.token accanto alla configurazione)")
    p.add_argument("--snapshot", default="webcq-clean", help="nome dello snapshot pulito da creare")
    p.add_argument("--agent-id")
    p.add_argument("--host-ip", help="IP dell'host sulla rete host-only (default: rilevato da VMware)")
    p.add_argument("--control-ip", help="IP da assegnare alla VM sulla rete host-only (default: .10)")
    p.add_argument("--prefix-length", type=int)
    p.add_argument("--agent-port", type=int, default=8765)
    p.add_argument("--fix-network", action="store_true",
                   help="corregge le schede nel .vmx (NIC1 NAT, NIC2 host-only), dopo averne fatto una copia")
    p.add_argument("--autologon", action="store_true",
                   help="accesso automatico dell'operatore all'avvio (password in chiaro nel registro della VM)")
    p.add_argument("--operator-password-file")
    p.add_argument("--disable-windows-update", action="store_true")
    p.add_argument("--organization")
    p.add_argument("--start-url", default="https://time.is", help="pagina iniziale di Firefox (default: time.is)")
    p.add_argument("--vmrun", help="percorso di vmrun")
    p.add_argument("--fusion", action="store_true", help="VMware Fusion (macOS) invece di Workstation Pro")
    p.set_defaults(fn=cmd_vmware_setup)

    for name, fn in (("create-case", cmd_create_case), ("acquire", cmd_acquire)):
        p = sub.add_parser(name, help="crea un nuovo caso" if name == "create-case" else "crea il caso ed esegue run")
        p.add_argument("case_id")
        p.add_argument("--output", help="cartella del caso (default: case.output_directory/ID)")
        p.add_argument("--operator")
        p.add_argument("--dry-run", action="store_true")
        if name == "acquire":
            vm_args(p)
            p.add_argument("--auto-stop", type=float, default=None, help="(test) termina dopo N secondi")
        p.set_defaults(fn=fn, case=None)

    p = sub.add_parser("run", help="acquisizione interattiva completa (consigliato)")
    case_args(p)
    vm_args(p)
    p.add_argument("--auto-stop", type=float, default=None, help="(test) termina dopo N secondi")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("start", help="prepara e avvia l'acquisizione, poi ritorna")
    case_args(p)
    vm_args(p)
    p.set_defaults(fn=cmd_start)

    p = sub.add_parser("status", help="stato dell'acquisizione in corso")
    case_args(p)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("stop", help="'Fine acquisizione': chiusura, export, verifica, report")
    case_args(p)
    p.add_argument("--reason", default="operator_stop")
    p.set_defaults(fn=cmd_stop)

    p = sub.add_parser("wizard", help="procedura guidata per una nuova acquisizione")
    p.set_defaults(fn=cmd_wizard)

    p = sub.add_parser("verify", help="verifica offline dell'integrità di un pacchetto")
    p.add_argument("--output", required=True)
    p.set_defaults(fn=cmd_verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ConfigError, CaseError, CaseLockedError, ValueError, FileNotFoundError, AgentError,
            AgentUnreachable, ProviderError) as exc:
        print(f"ERRORE: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
