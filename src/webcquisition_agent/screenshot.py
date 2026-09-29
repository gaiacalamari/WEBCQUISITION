"""Utility screenshot WEBCQUISITION.

* Cattura dell'intero desktop virtuale (tutti i monitor) via GDI (BitBlt), senza
  dipendenze esterne; encoder PNG in Python puro (zlib).
* Nomi prevedibili e mai sovrascritti: ``screenshots/screenshot-NNNN.png``, con
  sidecar ``screenshot-NNNN.json`` (timestamp UTC e locale, SHA-256, dimensioni,
  titolo della finestra in primo piano, origine: hotkey/pannello).
* Non sostituisce gli strumenti nativi: l'operatore può comunque usare Win+Shift+S
  o altro e salvare nella cartella del caso; quei file sono rilevati dal watcher
  come file dell'operatore.
"""

from __future__ import annotations

import json
import re
import struct
import threading
import zlib
from datetime import datetime
from pathlib import Path

from webcquisition_common.events import EventLog, EventType
from webcquisition_common.hashing import sha256_bytes
from webcquisition_common.timeutil import iso_utc

from .winutil import IS_WINDOWS

_NAME = re.compile(r"^screenshot-(\d{4,})\.png$")


def _chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def encode_png_rgb(width: int, height: int, rgb: bytes, text: dict | None = None) -> bytes:
    if len(rgb) != width * height * 3:
        raise ValueError("dimensione del buffer RGB non coerente")
    stride = width * 3
    raw = b"".join(b"\x00" + rgb[y * stride:(y + 1) * stride] for y in range(height))
    out = [b"\x89PNG\r\n\x1a\n", _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))]
    for k, v in (text or {}).items():
        out.append(_chunk(b"tEXt", k.encode("latin-1", "replace")[:79] + b"\x00" + str(v).encode("latin-1", "replace")))
    out += [_chunk(b"IDAT", zlib.compress(raw, 6)), _chunk(b"IEND", b"")]
    return b"".join(out)


def bgra_to_rgb(bgra: bytes) -> bytes:
    n = len(bgra) // 4
    rgb = bytearray(n * 3)
    rgb[0::3] = bgra[2::4]
    rgb[1::3] = bgra[1::4]
    rgb[2::3] = bgra[0::4]
    return bytes(rgb)


def grab_virtual_screen() -> tuple[int, int, bytes, dict]:
    """Restituisce (width, height, rgb, info) del desktop virtuale. Solo Windows."""
    if not IS_WINDOWS:
        raise OSError("cattura schermo disponibile solo su Windows")
    import ctypes
    from ctypes import wintypes

    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    x, y = user32.GetSystemMetrics(76), user32.GetSystemMetrics(77)
    w, h = user32.GetSystemMetrics(78), user32.GetSystemMetrics(79)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                    ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]

    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    user32.GetDC.restype = wintypes.HDC
    screen = user32.GetDC(None)
    mem = gdi32.CreateCompatibleDC(screen)
    bmp = gdi32.CreateCompatibleBitmap(screen, w, h)
    old = gdi32.SelectObject(mem, bmp)
    try:
        if not gdi32.BitBlt(mem, 0, 0, w, h, screen, x, y, 0x00CC0020 | 0x40000000):  # SRCCOPY|CAPTUREBLT
            raise OSError("BitBlt fallita")
        bih = BITMAPINFOHEADER()
        bih.biSize, bih.biWidth, bih.biHeight = ctypes.sizeof(BITMAPINFOHEADER), w, -h  # top-down
        bih.biPlanes, bih.biBitCount, bih.biCompression = 1, 32, 0
        buf = ctypes.create_string_buffer(w * h * 4)
        if gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bih), 0) != h:
            raise OSError("GetDIBits fallita")
        data = buf.raw
    finally:
        gdi32.SelectObject(mem, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem)
        user32.ReleaseDC(None, screen)
    return w, h, bgra_to_rgb(data), {"virtual_screen": {"x": x, "y": y, "width": w, "height": h}}


def foreground_window_title() -> str | None:
    if not IS_WINDOWS:
        return None
    import ctypes
    user32 = ctypes.windll.user32
    hwnd = user32.GetForegroundWindow()
    n = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


class ScreenshotService:
    def __init__(self, case_dir: Path, events: EventLog, grabber=grab_virtual_screen,
                 title_fn=foreground_window_title, case_id: str = ""):
        self.dir = Path(case_dir) / "screenshots"
        self.events = events
        self._grab = grabber
        self._title = title_fn
        self._case_id = case_id
        self._lock = threading.Lock()

    def _next_index(self) -> int:
        nums = [int(m.group(1)) for p in self.dir.glob("screenshot-*.png") if (m := _NAME.match(p.name))]
        return max(nums, default=0) + 1

    def count(self) -> int:
        return sum(1 for p in self.dir.glob("screenshot-*.png") if _NAME.match(p.name))

    def take(self, trigger: str) -> dict:
        with self._lock:
            title = self._title()
            taken = iso_utc()
            w, h, rgb, info = self._grab()
            png = encode_png_rgb(w, h, rgb, {"Software": "WEBCQUISITION", "Creation Time": taken,
                                             "Comment": f"case {self._case_id}"})
            idx = self._next_index()
            name = f"screenshot-{idx:04d}.png"
            path = self.dir / name
            with open(path, "xb") as fh:  # mai sovrascrivere
                fh.write(png)
            digest = sha256_bytes(png)
            meta = {"file": name, "sha256": digest, "size": len(png), "taken_at_utc": taken,
                    "taken_at_local": datetime.now().astimezone().isoformat(timespec="milliseconds"),
                    "trigger": trigger, "foreground_window_title": title, "width": w, "height": h, **info}
            with open(self.dir / f"screenshot-{idx:04d}.json", "x", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2, ensure_ascii=False)
            self.events.emit(EventType.SCREENSHOT_CREATED, component="screenshot",
                             data={"file": name, "sha256": digest, "trigger": trigger, "window_title": title})
            return meta
