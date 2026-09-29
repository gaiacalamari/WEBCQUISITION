"""Validazione degli identificativi di caso e join sicuri dei percorsi.

Queste funzioni sono una difesa contro:
* sovrascritture accidentali o confusione tra casi (ID non validi / ambigui);
* path traversal nelle API del guest agent e durante l'export.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {
    f"LPT{i}" for i in range(1, 10)
}


class UnsafePathError(ValueError):
    """Percorso relativo non ammesso (assoluto, con '..', con drive, ecc.)."""


def validate_case_id(case_id: str) -> str:
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise ValueError(
            f"ID caso non valido: {case_id!r}. Ammessi lettere, cifre, '.', '_', '-' "
            "(max 64 caratteri, deve iniziare con lettera o cifra)."
        )
    if case_id.endswith(".") or case_id.split(".")[0].upper() in _WINDOWS_RESERVED:
        raise ValueError(f"ID caso non valido su Windows: {case_id!r}")
    return case_id


def normalize_relpath(rel: str) -> str:
    """Normalizza un percorso relativo in forma POSIX e rifiuta forme pericolose."""
    if not isinstance(rel, str) or not rel:
        raise UnsafePathError("percorso vuoto")
    if "\x00" in rel or ":" in rel or rel.startswith(("/", "\\")):
        raise UnsafePathError(f"percorso non ammesso: {rel!r}")
    p = PurePosixPath(rel.replace("\\", "/"))
    if any(part in ("..", ".", "") for part in p.parts):
        raise UnsafePathError(f"percorso non ammesso: {rel!r}")
    return p.as_posix()


def safe_join(root: Path, rel: str) -> Path:
    """Unisce ``root`` e ``rel`` garantendo che il risultato resti dentro ``root``."""
    norm = normalize_relpath(rel)
    root_resolved = Path(root).resolve()
    full = (root_resolved / Path(*PurePosixPath(norm).parts)).resolve()
    if full != root_resolved and root_resolved not in full.parents:
        raise UnsafePathError(f"percorso fuori dalla radice: {rel!r}")
    return full


def to_posix_rel(root: Path, path: Path) -> str:
    return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
