"""Pannello di controllo WEBCQUISITION nel guest (tkinter, sempre in primo piano).

Mostra caso, stato della cattura e contatori; offre i pulsanti "Screenshot" e
"Fine acquisizione" (con conferma). Non può essere chiuso dall'operatore: la
chiusura avviene solo a fine sessione. Tutte le chiamate tkinter avvengono nel
thread del pannello.
"""

from __future__ import annotations

import threading


class ControlPanel:
    def __init__(self, case_id: str, status_fn, on_screenshot, on_stop):
        self.case_id = case_id
        self._status = status_fn
        self._on_screenshot = on_screenshot
        self._on_stop = on_stop
        self._thread: threading.Thread | None = None
        self._closing = threading.Event()
        self._ready = threading.Event()
        self.error: str | None = None

    def start(self, timeout: float = 10) -> dict:
        self._thread = threading.Thread(target=self._run, daemon=True, name="panel")
        self._thread.start()
        self._ready.wait(timeout)
        return {"enabled": self.error is None, "error": self.error}

    def _run(self):
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
        except Exception as exc:  # noqa: BLE001 - tkinter assente o nessun display
            self.error = f"pannello non disponibile: {exc}"
            self._ready.set()
            return
        root.title(f"WEBCQUISITION - {self.case_id}")
        root.attributes("-topmost", True)
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", lambda: None)
        frame = tk.Frame(root, padx=10, pady=8)
        frame.pack()
        tk.Label(frame, text=f"Caso {self.case_id}", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        status = tk.StringVar(value="…")
        tk.Label(frame, textvariable=status, font=("Consolas", 9), justify="left").pack(anchor="w", pady=4)
        buttons = tk.Frame(frame)
        buttons.pack(fill="x")

        def shot():
            root.withdraw()  # il pannello non deve comparire nello screenshot
            def do():
                try:
                    self._on_screenshot("panel")
                finally:
                    root.deiconify()
                    root.attributes("-topmost", True)
            root.after(350, do)

        def stop():
            if messagebox.askyesno("WEBCQUISITION", "Terminare l'acquisizione?\n\nFirefox e la cattura verranno "
                                   "chiusi, i dati copiati sull'host e la VM spenta.", parent=root):
                self._on_stop("panel")
                status.set("Fine acquisizione richiesta.\nAttendere la chiusura…")

        tk.Button(buttons, text="Screenshot", width=14, command=shot).pack(side="left", padx=(0, 6))
        tk.Button(buttons, text="Fine acquisizione", width=16, fg="white", bg="#a4262c",
                  command=stop).pack(side="left")
        tk.Label(frame, text="Per terminare si può anche spegnere Windows (Start > Arresta):\n"
                             "lo spegnimento attende la copia del materiale sull'host.",
                 font=("Segoe UI", 8), fg="#555555", justify="left").pack(anchor="w", pady=(6, 0))

        def refresh():
            if self._closing.is_set():
                root.destroy()
                return
            try:
                s = self._status()
                cap = s.get("capture") or {}
                status.set(f"Cattura: {'ATTIVA' if cap.get('running') else 'NON ATTIVA'}  "
                           f"pacchetti: {cap.get('packets', 0)}\n"
                           f"Key log TLS: {(s.get('keylog') or {}).get('size', 0)} byte\n"
                           f"Screenshot: {s.get('screenshots', 0)}  file operatore: {s.get('operator_files', 0)}")
            except Exception as exc:  # noqa: BLE001
                status.set(f"stato non disponibile: {exc}")
            root.after(2000, refresh)

        root.geometry("+20+20")
        root.after(200, refresh)
        self._ready.set()
        root.mainloop()

    def stop(self):
        self._closing.set()
        if self._thread:
            self._thread.join(5)
