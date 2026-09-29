"""Gestione del tempo. Tutti i timestamp registrati da WEBCQUISITION sono UTC ISO-8601
con precisione al millisecondo e suffisso ``Z``."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime | None = None) -> str:
    dt = dt or utc_now()
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def local_timezone_description() -> dict:
    """Descrive il fuso orario locale del sistema su cui gira il codice."""
    now = datetime.now().astimezone()
    offset = now.utcoffset()
    return {
        "name": now.tzname(),
        "utc_offset_seconds": int(offset.total_seconds()) if offset else 0,
    }
