"""Parser PCAPNG minimale e incrementale (solo standard library).

Scopo: permettere a guest agent e host di VERIFICARE programmaticamente che una
cattura sia reale e attiva, senza dipendere da tshark/capinfos:

* il file inizia con un Section Header Block valido;
* l'Interface Description Block riporta l'interfaccia effettivamente catturata
  (opzione ``if_name``, per dumpcap su Windows ``\\Device\\NPF_{GUID}``);
* il numero di pacchetti (EPB/SPB/PB) cresce nel tempo;
* primo e ultimo timestamp.

Il parser è tollerante a un blocco finale incompleto (file ancora in scrittura):
in quel caso si ferma all'ultimo blocco completo e riprende dalla stessa
posizione alla chiamata successiva. Non modifica MAI il file (apertura "rb").
"""

from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
PB_TYPE = 0x00000002
SPB_TYPE = 0x00000003
ISB_TYPE = 0x00000005
EPB_TYPE = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D

OPT_ENDOFOPT = 0
OPT_IF_NAME = 2
OPT_IF_DESCRIPTION = 3
OPT_IF_TSRESOL = 9


@dataclass
class PcapngSummary:
    path: str
    valid: bool = True
    error: str | None = None
    sections: int = 0
    packets: int = 0
    interfaces: list = field(default_factory=list)
    first_ts: float | None = None
    last_ts: float | None = None
    bytes_parsed: int = 0
    truncated_tail: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        for key in ("first_ts", "last_ts"):
            v = d[key]
            d[key + "_utc"] = (
                datetime.fromtimestamp(v, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
                if v is not None
                else None
            )
        return d

    @property
    def interface_names(self) -> list[str]:
        return [i.get("name") for i in self.interfaces if i.get("name")]


def _parse_options(buf: bytes, e: str) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(buf):
        code, length = struct.unpack(e + "HH", buf[i : i + 4])
        if code == OPT_ENDOFOPT:
            break
        value = buf[i + 4 : i + 4 + length]
        opts.setdefault(code, value)
        i += 4 + length + ((4 - length % 4) % 4)
    return opts


def _decode(value: bytes | None) -> str | None:
    if value is None:
        return None
    return value.rstrip(b"\x00").decode("utf-8", errors="replace")


class IncrementalPcapngReader:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.offset = 0
        self.endian: str | None = None
        self.summary = PcapngSummary(path=str(path))
        self._section_ifaces: list[dict] = []

    def _invalid(self, msg: str) -> None:
        self.summary.valid = False
        self.summary.error = msg

    def update(self) -> PcapngSummary:
        s = self.summary
        if not s.valid or not self.path.exists():
            return s
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            while True:
                pos = self.offset
                hdr = f.read(8)
                if len(hdr) < 8:
                    s.truncated_tail = len(hdr) > 0
                    break
                if struct.unpack("<I", hdr[:4])[0] == SHB_TYPE:
                    bom_raw = f.read(4)
                    if len(bom_raw) < 4:
                        s.truncated_tail = True
                        break
                    if struct.unpack("<I", bom_raw)[0] == BYTE_ORDER_MAGIC:
                        self.endian = "<"
                    elif struct.unpack(">I", bom_raw)[0] == BYTE_ORDER_MAGIC:
                        self.endian = ">"
                    else:
                        self._invalid(f"byte-order magic non valido all'offset {pos}")
                        break
                    f.seek(pos + 8)
                elif self.endian is None:
                    self._invalid("il file non inizia con un Section Header Block (non è PCAPNG)")
                    break
                e = self.endian
                btype, blen = struct.unpack(e + "II", hdr)
                if blen < 12 or blen % 4:
                    self._invalid(f"lunghezza blocco non valida ({blen}) all'offset {pos}")
                    break
                body = f.read(blen - 8)
                if len(body) < blen - 8:
                    s.truncated_tail = True
                    break
                if struct.unpack(e + "I", body[-4:])[0] != blen:
                    self._invalid(f"trailer del blocco non coerente all'offset {pos}")
                    break
                try:
                    self._handle(btype, body[:-4], e)
                except struct.error as exc:
                    self._invalid(f"blocco malformato all'offset {pos}: {exc}")
                    break
                self.offset = pos + blen
                s.bytes_parsed = self.offset
                s.truncated_tail = False
        return s

    def _handle(self, btype: int, body: bytes, e: str) -> None:
        s = self.summary
        if btype == SHB_TYPE:
            s.sections += 1
            self._section_ifaces = []
        elif btype == IDB_TYPE:
            link_type, _reserved, snaplen = struct.unpack(e + "HHI", body[:8])
            opts = _parse_options(body[8:], e)
            tsresol = 1e-6
            if OPT_IF_TSRESOL in opts and opts[OPT_IF_TSRESOL]:
                v = opts[OPT_IF_TSRESOL][0]
                tsresol = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
            iface = {
                "name": _decode(opts.get(OPT_IF_NAME)),
                "description": _decode(opts.get(OPT_IF_DESCRIPTION)),
                "link_type": link_type,
                "snaplen": snaplen,
            }
            self._section_ifaces.append({**iface, "tsresol": tsresol})
            s.interfaces.append(iface)
        elif btype == EPB_TYPE:
            iid, hi, lo = struct.unpack(e + "III", body[:12])
            s.packets += 1
            self._ts(iid, hi, lo)
        elif btype == SPB_TYPE:
            s.packets += 1
        elif btype == PB_TYPE:
            iid, _drops, hi, lo = struct.unpack(e + "HHII", body[:12])
            s.packets += 1
            self._ts(iid, hi, lo)

    def _ts(self, iid: int, hi: int, lo: int) -> None:
        res = self._section_ifaces[iid]["tsresol"] if iid < len(self._section_ifaces) else 1e-6
        ts = ((hi << 32) | lo) * res
        s = self.summary
        if s.first_ts is None or ts < s.first_ts:
            s.first_ts = ts
        if s.last_ts is None or ts > s.last_ts:
            s.last_ts = ts


def summarize(path: Path) -> PcapngSummary:
    return IncrementalPcapngReader(path).update()


# --------------------------------------------------------------------------
# Scrittura di PCAPNG SINTETICI: usata solo da test e modalità --dry-run.
# --------------------------------------------------------------------------

def _block(btype: int, body: bytes) -> bytes:
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * ((4 - len(value) % 4) % 4)


def synthetic_header(if_name: str, link_type: int = 1) -> bytes:
    shb = _block(SHB_TYPE, struct.pack("<IHHq", BYTE_ORDER_MAGIC, 1, 0, -1))
    idb_body = struct.pack("<HHI", link_type, 0, 0) + _option(OPT_IF_NAME, if_name.encode()) + _option(0, b"")
    return shb + _block(IDB_TYPE, idb_body)


def synthetic_packet(ts: float, payload: bytes = b"\x00" * 60) -> bytes:
    t = int(ts * 1_000_000)
    body = struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(payload), len(payload)) + payload
    return _block(EPB_TYPE, body)


def synthetic_pcapng(if_name: str, packets: int, start_ts: float) -> bytes:
    return synthetic_header(if_name) + b"".join(
        synthetic_packet(start_ts + i * 0.01) for i in range(packets)
    )
