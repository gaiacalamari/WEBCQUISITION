#!/usr/bin/env python3
"""Crea il bundle dell'agent per l'installazione MANUALE nella VM.

Normalmente non serve: ``webcquisition vmware-setup`` crea e installa il bundle da solo.

    python scripts/build-agent-bundle.py --out dist/webcquisition-agent
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webcquisition.bundle import build_bundle  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    try:
        lines = build_bundle(Path(args.out))
    except FileExistsError as exc:
        print(f"{exc}: rimuoverla o scegliere un'altra destinazione", file=sys.stderr)
        return 1
    print(f"Bundle creato in {args.out} ({len(lines)} file)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
