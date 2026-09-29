"""Costruzione del bundle dell'agent da installare nella VM.

Il bundle contiene solo codice a libreria standard (``webcquisition_agent`` e
``webcquisition_common``), il bootstrap ``run_agent.pyw``, ``install-agent.ps1`` e
``BUNDLE-SHA256SUMS.txt``, che documenta esattamente cosa è stato installato.
"""

from __future__ import annotations

import hashlib
import shutil
import zipfile
from importlib import resources
from pathlib import Path

import webcquisition_agent
import webcquisition_common

BOOTSTRAP = '''"""Bootstrap WEBCQUISITION agent (avviato dallo Scheduled Task "At logon")."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from webcquisition_agent.__main__ import main
sys.exit(main(sys.argv[1:]))
'''

AGENT_EXAMPLE = {
    "listen_host": "192.168.150.10", "listen_port": 8765, "token": "INCOLLARE-QUI-IL-TOKEN",
    "agent_id": "forensic-windows-01", "control_ip": "192.168.150.10",
}


def asset_text(name: str) -> str:
    return resources.files("webcquisition").joinpath("assets", name).read_text(encoding="utf-8")


def build_bundle(out: Path) -> list[str]:
    """Crea il bundle in ``out`` (che non deve esistere). Restituisce le righe di BUNDLE-SHA256SUMS."""
    out = Path(out)
    if out.exists():
        raise FileExistsError(f"{out} esiste già")
    lib = out / "lib"
    for pkg in (webcquisition_agent, webcquisition_common):
        src = Path(pkg.__file__).resolve().parent
        shutil.copytree(src, lib / src.name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (out / "run_agent.pyw").write_text(BOOTSTRAP, encoding="utf-8")
    (out / "install-agent.ps1").write_text(asset_text("install-agent.ps1"), encoding="utf-8-sig", newline="\r\n")
    import json
    (out / "agent.example.json").write_text(json.dumps(AGENT_EXAMPLE, indent=2), encoding="utf-8")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}"
             for p in sorted(x for x in out.rglob("*") if x.is_file())]
    (out / "BUNDLE-SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lines


def build_bundle_zip(zip_path: Path, workdir: Path) -> tuple[str, list[str]]:
    """Crea bundle + zip. Restituisce (sha256 dello zip, righe BUNDLE-SHA256SUMS)."""
    staging = Path(workdir) / "bundle"
    lines = build_bundle(staging)
    with zipfile.ZipFile(zip_path, "x", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(x for x in staging.rglob("*") if x.is_file()):
            z.write(p, p.relative_to(staging).as_posix())
    return hashlib.sha256(Path(zip_path).read_bytes()).hexdigest(), lines
