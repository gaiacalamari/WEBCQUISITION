"""Utility host: scritture atomiche e protezione in sola lettura."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, text: str) -> None:
    """Scrive su file temporaneo nella stessa cartella e poi rinomina (os.replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, obj) -> None:
    atomic_write_text(path, json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n")


def write_new_text(path: Path, text: str) -> None:
    """Crea un file NUOVO: fallisce se esiste già (nessuna sovrascrittura)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())


def make_readonly(path: Path) -> None:
    """Rimuove i permessi di scrittura (su Windows imposta l'attributo Read-only).

    È una protezione contro modifiche ACCIDENTALI, non contro un utente che
    intenzionalmente rimuove l'attributo. L'integrità è garantita dagli hash.
    """
    mode = os.stat(path).st_mode
    os.chmod(path, mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def make_tree_readonly(root: Path) -> int:
    count = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            make_readonly(Path(dirpath) / name)
            count += 1
    return count
