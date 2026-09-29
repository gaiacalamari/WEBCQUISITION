"""Helper Windows (import sicuro anche su altri OS, per i test)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008


def run(args: list[str], timeout: float = 60) -> tuple[int, str, str]:
    try:
        kwargs = {"creationflags": CREATE_NO_WINDOW} if IS_WINDOWS else {}
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace", **kwargs)
        return p.returncode, p.stdout or "", p.stderr or ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, "", str(exc)


def hidden_startupinfo():
    if not IS_WINDOWS:
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return si


def resolve_desktop() -> Path:
    """Percorso reale del Desktop (gestisce Desktop reindirizzati, es. OneDrive)."""
    if IS_WINDOWS:
        try:
            import ctypes
            import uuid
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                            ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

            u = uuid.UUID("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")  # FOLDERID_Desktop
            g = GUID(u.fields[0], u.fields[1], u.fields[2], (ctypes.c_ubyte * 8)(*u.bytes[8:]))
            p = ctypes.c_wchar_p()
            shell32 = ctypes.windll.shell32
            if shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p)) == 0:
                path = Path(p.value)
                ctypes.windll.ole32.CoTaskMemFree(p)
                return path
        except Exception:
            pass
    return Path(os.path.expanduser("~")) / "Desktop"


def interactive_session() -> bool:
    """True se l'agent gira in una sessione utente interattiva (non Session 0)."""
    if not IS_WINDOWS:
        return True
    import ctypes
    sid = ctypes.c_ulong()
    if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid)):
        return False
    return sid.value != 0


def kill_tree(pid: int, force: bool) -> int:
    """taskkill: senza /F invia WM_CLOSE (chiusura gentile) alle finestre del processo."""
    if not IS_WINDOWS:
        import signal
        try:
            os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
            return 0
        except OSError:
            return 1
    args = ["taskkill", "/PID", str(pid), "/T"] + (["/F"] if force else [])
    return run(args, timeout=30)[0]
