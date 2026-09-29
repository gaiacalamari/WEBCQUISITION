"""Hashing SHA-256 e manifest di integrità."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .paths import normalize_relpath, safe_join
from .timeutil import iso_utc

ALGORITHM = "SHA-256"
CHUNK_SIZE = 1024 * 1024


class StreamingHasher:
    """Calcola SHA-256 e dimensione di un flusso di byte (usato durante l'export)."""

    def __init__(self) -> None:
        self._h = hashlib.sha256()
        self.size = 0

    def update(self, data: bytes) -> None:
        self._h.update(data)
        self.size += len(data)

    def hexdigest(self) -> str:
        return self._h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    """Restituisce (sha256 esadecimale, dimensione in byte). Apertura in sola lettura."""
    h = StreamingHasher()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest(), h.size


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _mtime_utc(path: Path) -> str:
    return iso_utc(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc))


def inventory(root: Path, exclude: Iterable[str] = ()) -> list[dict]:
    """Elenca ricorsivamente i file sotto ``root`` con dimensione, hash e mtime.

    ``exclude`` contiene percorsi relativi POSIX da escludere (es. il manifest stesso).
    I symlink non vengono seguiti e sono segnalati come tali.
    """
    root = Path(root)
    excluded = {normalize_relpath(e) for e in exclude}
    entries: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if rel in excluded:
                continue
            if full.is_symlink():
                entries.append({"path": rel, "size": None, "sha256": None, "symlink": True})
                continue
            digest, size = sha256_file(full)
            entries.append(
                {"path": rel, "size": size, "sha256": digest, "mtime_utc": _mtime_utc(full)}
            )
    entries.sort(key=lambda e: e["path"])
    return entries


def build_manifest(root: Path, exclude: Iterable[str] = (), extra: dict | None = None) -> dict:
    manifest = {
        "algorithm": ALGORITHM,
        "generated_at_utc": iso_utc(),
        "files": inventory(root, exclude),
    }
    if extra:
        manifest.update(extra)
    return manifest


def format_sha256sums(entries: Iterable[dict]) -> str:
    """Formato compatibile con ``sha256sum -c`` (GNU coreutils)."""
    lines = [f"{e['sha256']}  {e['path']}" for e in entries if e.get("sha256")]
    return "\n".join(lines) + ("\n" if lines else "")


def parse_sha256sums(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, path = line.partition("  ")
        if len(digest) != 64 or not path:
            raise ValueError(f"riga SHA256SUMS non valida: {line!r}")
        result[path.lstrip("*")] = digest.lower()
    return result


def verify_entries(root: Path, entries: Iterable[dict]) -> list[dict]:
    """Verifica i file sotto ``root`` rispetto alle voci attese.

    Restituisce la lista dei problemi (vuota se tutto corrisponde).
    """
    problems: list[dict] = []
    for e in entries:
        rel = e["path"]
        try:
            full = safe_join(Path(root), rel)
        except ValueError as exc:
            problems.append({"path": rel, "issue": "unsafe_path", "detail": str(exc)})
            continue
        if not full.is_file():
            problems.append({"path": rel, "issue": "missing"})
            continue
        digest, size = sha256_file(full)
        if e.get("size") is not None and size != e["size"]:
            problems.append(
                {"path": rel, "issue": "size_mismatch", "expected": e["size"], "actual": size}
            )
        if digest != e.get("sha256"):
            problems.append(
                {"path": rel, "issue": "hash_mismatch", "expected": e.get("sha256"), "actual": digest}
            )
    return problems


def find_unexpected(root: Path, entries: Iterable[dict]) -> list[str]:
    """File presenti sotto ``root`` ma non elencati nel manifest."""
    expected = {e["path"] for e in entries}
    return sorted(p for p in list_relative_files(root) if p not in expected)


def list_relative_files(root: Path) -> list[str]:
    root = Path(root)
    out = []
    for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            out.append((Path(dirpath) / name).relative_to(root).as_posix())
    return sorted(out)
