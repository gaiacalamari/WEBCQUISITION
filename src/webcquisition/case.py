"""Gestione del caso sul computer host.

Struttura della cartella caso sull'host (vedi docs/CASE-STRUCTURE.md):

    <CASE>/
      acquisition.json        manifest finale dell'acquisizione (scritto alla fine)
      README.txt              guida al contenuto del pacchetto
      acquired/               COPIA VERIFICATA della cartella Desktop\\<CASE> della VM
      logs/host-events.jsonl  log eventi host (catena di hash)
      logs/host.log           log leggibile
      hashes/                 SHA256SUMS.txt, manifest.json, guest-manifest.json, package-seal.json
      report/                 acquisition-report.html
      metadata/               case.json, session.json, config-snapshot.yaml (metadati applicativi)
"""

from __future__ import annotations

import json
import os
import platform
from contextlib import contextmanager
from pathlib import Path

import yaml

from webcquisition_common import __version__
from webcquisition_common.paths import validate_case_id
from webcquisition_common.timeutil import iso_utc

from .state import AcquisitionState, check_transition
from .util import atomic_write_json, write_new_text

HOST_SUBDIRS = ("acquired", "logs", "hashes", "report", "metadata")
CASE_FILE = "metadata/case.json"
SESSION_FILE = "metadata/session.json"
LOCK_FILE = "metadata/.lock"
EVENTS_FILE = "logs/host-events.jsonl"

README_TEXT = """WEBCQUISITION - pacchetto di acquisizione forense web
====================================================

Caso: {case_id}
Creato (UTC): {created}
Versione WEBCQUISITION: {version}

Contenuto
---------
acquisition.json   Manifest dell'acquisizione (stato finale, ambiente, hash, anomalie).
acquired/          Copia verificata (SHA-256) della cartella del caso creata sul Desktop della VM:
  network/         Traffico di rete catturato (PCAPNG, dumpcap). DATO ORIGINALE.
  tls/             TLS key log (SSLKEYLOGFILE) prodotto da Firefox. DATO ORIGINALE.
  browser/         Profilo Firefox dedicato al caso (cronologia, cookie, cache...). DATO ORIGINALE.
  screenshots/     Screenshot generati dall'utility WEBCQUISITION su richiesta dell'operatore (+ .json).
  operator/        File salvati manualmente dall'operatore.
  metadata/        Metadati raccolti nel guest (sistema, comandi, manifest guest).
  logs/            Log eventi del guest agent.
logs/              Log dell'host controller (host-events.jsonl con catena di hash).
hashes/            SHA256SUMS.txt (verificabile con `sha256sum -c`), manifest.json, sigillo finale.
report/            Report HTML dell'acquisizione.
metadata/          Metadati applicativi (stato del caso, sessione, snapshot della configurazione).

ATTENZIONE - MATERIALE SENSIBILE
--------------------------------
Il file acquired/tls/sslkeylog.log contiene i segreti delle sessioni TLS:
chiunque lo possieda insieme al PCAPNG può decifrare il traffico HTTPS acquisito,
incluse eventuali credenziali o dati personali. Trattarlo con lo stesso livello di
riservatezza dell'intero reperto.

Verifica dell'integrità
-----------------------
    webcquisition verify --output <questa cartella>
oppure, nella cartella acquired/:
    sha256sum -c ../hashes/SHA256SUMS.txt
"""


class CaseError(RuntimeError):
    pass


class CaseLockedError(CaseError):
    pass


class Case:
    def __init__(self, case_dir: Path):
        self.dir = Path(case_dir)
        path = self.dir / CASE_FILE
        if not path.is_file():
            raise CaseError(f"{self.dir} non è una cartella caso WEBCQUISITION (manca {CASE_FILE})")
        self._data = json.loads(path.read_text(encoding="utf-8"))
        validate_case_id(self._data["case_id"])

    # ------------------------------------------------------------------ creazione
    @classmethod
    def create(
        cls,
        case_dir: Path,
        case_id: str,
        *,
        operator: str | None = None,
        organization: str | None = None,
        dry_run: bool = False,
        config_dict: dict | None = None,
    ) -> "Case":
        validate_case_id(case_id)
        case_dir = Path(case_dir)
        if case_dir.exists():
            # Mai riutilizzare/sovrascrivere una cartella esistente, nemmeno se vuota:
            # una cartella vuota con quel nome potrebbe essere un residuo non documentato.
            raise CaseError(f"la cartella {case_dir} esiste già: scegliere un'altra destinazione")
        if case_dir.name != case_id:
            raise CaseError(
                f"il nome della cartella ({case_dir.name}) deve coincidere con l'ID del caso ({case_id}) "
                "per evitare confusione tra casi"
            )
        case_dir.parent.mkdir(parents=True, exist_ok=True)
        case_dir.mkdir()
        for sub in HOST_SUBDIRS:
            (case_dir / sub).mkdir()
        created = iso_utc()
        data = {
            "schema_version": 1,
            "case_id": case_id,
            "created_at_utc": created,
            "operator": operator,
            "organization": organization,
            "dry_run": dry_run,
            "webcquisition_version": __version__,
            "created_on_host": platform.node(),
            "state": AcquisitionState.CREATED.value,
            "state_history": [{"state": "CREATED", "at_utc": created, "reason": "case created"}],
        }
        atomic_write_json(case_dir / CASE_FILE, data)
        write_new_text(
            case_dir / "README.txt",
            README_TEXT.format(case_id=case_id, created=created, version=__version__),
        )
        if config_dict is not None:
            write_new_text(
                case_dir / "metadata" / "config-snapshot.yaml",
                "# Configurazione effettiva al momento della creazione del caso\n"
                + yaml.safe_dump(config_dict, sort_keys=False, allow_unicode=True),
            )
        return cls(case_dir)

    # ------------------------------------------------------------------ proprietà
    @property
    def case_id(self) -> str:
        return self._data["case_id"]

    @property
    def state(self) -> AcquisitionState:
        return AcquisitionState(self._data["state"])

    @property
    def data(self) -> dict:
        return dict(self._data)

    @property
    def events_path(self) -> Path:
        return self.dir / EVENTS_FILE

    @property
    def acquired_dir(self) -> Path:
        return self.dir / "acquired"

    def set_state(self, new: AcquisitionState, reason: str = "") -> AcquisitionState:
        old = self.state
        check_transition(old, new)
        self._data["state"] = new.value
        self._data.setdefault("state_history", []).append(
            {"state": new.value, "at_utc": iso_utc(), "reason": reason}
        )
        atomic_write_json(self.dir / CASE_FILE, self._data)
        return old

    # ------------------------------------------------------------------ sessione
    def load_session(self) -> dict:
        path = self.dir / SESSION_FILE
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def save_session(self, session: dict) -> None:
        atomic_write_json(self.dir / SESSION_FILE, session)

    # ------------------------------------------------------------------ lock
    @contextmanager
    def lock(self):
        """Impedisce due processi WEBCQUISITION concorrenti sullo stesso caso."""
        path = self.dir / LOCK_FILE
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            info = path.read_text(encoding="utf-8", errors="replace")
            raise CaseLockedError(
                f"il caso è in uso da un altro processo ({info.strip()}). Se il processo non esiste più, "
                f"verificare la situazione e rimuovere manualmente {path}"
            ) from exc
        with os.fdopen(fd, "w") as fh:
            fh.write(f"pid={os.getpid()} host={platform.node()} since={iso_utc()}\n")
        try:
            yield self
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def resolve_case_dir(output: str | None, case_id: str | None, output_root: str | None) -> Path:
    """--output ha priorità; altrimenti <case.output_directory>/<case_id>."""
    if output:
        return Path(output)
    if case_id and output_root:
        validate_case_id(case_id)
        return Path(output_root) / case_id
    raise CaseError("specificare --output <cartella caso> oppure --case <ID> con case.output_directory in configurazione")
