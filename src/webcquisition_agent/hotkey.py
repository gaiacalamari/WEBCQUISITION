"""Hotkey globale (RegisterHotKey) per lo screenshot WEBCQUISITION."""

from __future__ import annotations

import threading

from .winutil import IS_WINDOWS

MODS = {"alt": 0x0001, "ctrl": 0x0002, "control": 0x0002, "shift": 0x0004, "win": 0x0008}
MOD_NOREPEAT = 0x4000
NAMED_KEYS = {"printscreen": 0x2C, "prtsc": 0x2C, "space": 0x20, "pause": 0x13, "insert": 0x2D, "home": 0x24,
              "end": 0x23}
WM_HOTKEY, WM_QUIT = 0x0312, 0x0012


def parse_hotkey(spec: str) -> tuple[int, int]:
    parts = [p.strip().lower() for p in spec.split("+") if p.strip()]
    if not parts:
        raise ValueError("hotkey vuoto")
    mods, key = 0, parts[-1]
    for m in parts[:-1]:
        if m not in MODS:
            raise ValueError(f"modificatore sconosciuto: {m}")
        mods |= MODS[m]
    if len(key) == 1 and key.isalnum():
        vk = ord(key.upper())
    elif key in NAMED_KEYS:
        vk = NAMED_KEYS[key]
    elif key.startswith("f") and key[1:].isdigit() and 1 <= int(key[1:]) <= 24:
        vk = 0x6F + int(key[1:])
    else:
        raise ValueError(f"tasto sconosciuto: {key}")
    if mods == 0:
        raise ValueError("serve almeno un modificatore (ctrl/alt/shift/win)")
    return mods | MOD_NOREPEAT, vk


class HotkeyListener:
    def __init__(self, spec: str, callback):
        self.spec = spec
        self.callback = callback
        self._thread: threading.Thread | None = None
        self._tid = None
        self._ready = threading.Event()
        self.error: str | None = None

    def start(self, timeout: float = 5) -> dict:
        try:
            mods, vk = parse_hotkey(self.spec)
        except ValueError as exc:
            self.error = str(exc)
            return {"enabled": False, "hotkey": self.spec, "error": self.error}
        if not IS_WINDOWS:
            self.error = "hotkey disponibile solo su Windows"
            return {"enabled": False, "hotkey": self.spec, "error": self.error}
        self._thread = threading.Thread(target=self._loop, args=(mods, vk), daemon=True, name="hotkey")
        self._thread.start()
        self._ready.wait(timeout)
        return {"enabled": self.error is None, "hotkey": self.spec, "error": self.error}

    def _loop(self, mods: int, vk: int):
        import ctypes
        from ctypes import wintypes
        user32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
        self._tid = k32.GetCurrentThreadId()
        if not user32.RegisterHotKey(None, 1, mods, vk):
            self.error = f"RegisterHotKey fallita (hotkey già in uso?) err={k32.GetLastError()}"
            self._ready.set()
            return
        self._ready.set()
        msg = wintypes.MSG()
        try:
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                if msg.message == WM_HOTKEY:
                    try:
                        self.callback()
                    except Exception:  # noqa: BLE001 - l'errore è registrato dal callback
                        pass
        finally:
            user32.UnregisterHotKey(None, 1)

    def stop(self):
        if self._thread and self._tid and IS_WINDOWS:
            import ctypes
            ctypes.windll.user32.PostThreadMessageW(self._tid, WM_QUIT, 0, 0)
            self._thread.join(5)
