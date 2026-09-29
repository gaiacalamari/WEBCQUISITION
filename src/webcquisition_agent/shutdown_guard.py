"""Spegnimento di Windows = fine acquisizione.

Quando l'operatore spegne o riavvia Windows dal menu Start durante un'acquisizione,
Windows invia ``WM_QUERYENDSESSION`` a tutte le finestre top-level. Questo modulo crea
una finestra nascosta (in un thread con il proprio ciclo di messaggi) che:

  1. chiede di essere avvisata per prima (``SetProcessShutdownParameters``);
  2. alla richiesta di spegnimento, se l'acquisizione è in corso, **blocca** lo
     spegnimento (``ShutdownBlockReasonCreate`` + risposta FALSE) e segnala la
     richiesta di fine acquisizione all'host;
  3. quando l'host ha copiato e verificato il materiale chiama ``release()``: la
     finestra viene distrutta e Windows completa lo spegnimento avviato dall'operatore.

Windows mostra la schermata "WEBCQUISITION impedisce l'arresto" con il motivo. Se
l'operatore sceglie comunque "Arresta comunque", l'host recupera il materiale
riavviando la VM (vedi orchestratore, recupero dopo VM spenta).

Se l'host non contatta l'agent da più di ``host_timeout_s`` secondi, lo spegnimento
non viene bloccato (host assente: nessuno completerebbe la copia).
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Callable

log = logging.getLogger("webcquisition.agent.shutdown")

WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
REASON = "WEBCQUISITION sta chiudendo l'acquisizione e copiando il materiale sull'host. Attendere: " \
         "la VM si spegnerà da sola."


class ShutdownGuard:
    def __init__(self, should_block: Callable[[], bool], on_shutdown_requested: Callable[[], None]):
        self.should_block = should_block
        self.on_shutdown_requested = on_shutdown_requested
        self._thread: threading.Thread | None = None
        self._hwnd = None
        self._ready = threading.Event()
        self._error: str | None = None
        self.blocked_count = 0

    # ------------------------------------------------------------ API
    def start(self) -> dict:
        if sys.platform != "win32":
            return {"enabled": False, "error": "disponibile solo su Windows"}
        self._thread = threading.Thread(target=self._run, name="webcq-shutdown-guard", daemon=True)
        self._thread.start()
        self._ready.wait(10)
        return {"enabled": self._error is None and self._hwnd is not None, "error": self._error}

    def release(self) -> None:
        """Rimuove il blocco: uno spegnimento in attesa viene completato da Windows."""
        if sys.platform != "win32" or not self._hwnd:
            return
        import ctypes
        user32 = ctypes.windll.user32
        try:
            user32.ShutdownBlockReasonDestroy(self._hwnd)
        except Exception:  # noqa: BLE001
            pass
        user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)

    stop = release

    # ------------------------------------------------------------ Win32
    def _run(self):  # pragma: no cover - richiede Windows
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        LRESULT = ctypes.c_ssize_t
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.ShutdownBlockReasonCreate.argtypes = [wintypes.HWND, wintypes.LPCWSTR]

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                        ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                        ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

        def wndproc(hwnd, msg, wparam, lparam):
            if msg == WM_QUERYENDSESSION:
                try:
                    block = bool(self.should_block())
                except Exception:  # noqa: BLE001 - nel dubbio non si blocca Windows
                    block = False
                if block:
                    self.blocked_count += 1
                    user32.ShutdownBlockReasonCreate(hwnd, REASON)
                    try:
                        self.on_shutdown_requested()
                    except Exception:  # noqa: BLE001
                        log.exception("segnalazione della richiesta di spegnimento fallita")
                    return 0  # FALSE: spegnimento rimandato
                return 1
            if msg == WM_ENDSESSION:
                return 0
            if msg == WM_CLOSE:
                user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        try:
            self._proc = WNDPROC(wndproc)  # riferimento conservato: evita la garbage collection
            kernel32.SetProcessShutdownParameters(0x3FF, 0)  # avvisati per primi
            hinst = kernel32.GetModuleHandleW(None)
            wc = WNDCLASSW()
            wc.lpfnWndProc = self._proc
            wc.hInstance = hinst
            wc.lpszClassName = "WEBCQUISITIONShutdownGuard"
            user32.RegisterClassW(ctypes.byref(wc))
            # finestra top-level NASCOSTA (le message-only window non ricevono WM_QUERYENDSESSION)
            self._hwnd = user32.CreateWindowExW(0, wc.lpszClassName, "WEBCQUISITION", 0, 0, 0, 0, 0,
                                                None, None, hinst, None)
            if not self._hwnd:
                self._error = f"CreateWindowEx fallita ({kernel32.GetLastError()})"
        except Exception as exc:  # noqa: BLE001
            self._error = str(exc)
        finally:
            self._ready.set()
        if not self._hwnd:
            return
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        self._hwnd = None
