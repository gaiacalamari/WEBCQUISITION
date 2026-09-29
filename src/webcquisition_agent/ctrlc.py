"""Invia CTRL+C alla console di un processo (arresto *pulito* di dumpcap/tshark su Windows).

Uso interno:  python -m webcquisition_agent.ctrlc <pid>

dumpcap viene avviato con una propria console nascosta (CREATE_NEW_CONSOLE):
questo helper si stacca dalla propria console, si aggancia a quella di dumpcap,
disattiva la gestione di CTRL+C per sé stesso e genera l'evento. dumpcap
intercetta CTRL+C, chiude correttamente il file PCAPNG (scrivendo anche gli
Interface Statistics Block) e termina. È eseguito in un processo separato per
non alterare la console/handler dell'agent.
"""

import sys


def send_ctrl_c(pid: int) -> int:
    import ctypes

    k32 = ctypes.windll.kernel32
    k32.FreeConsole()
    if not k32.AttachConsole(pid):
        return 2
    k32.SetConsoleCtrlHandler(None, True)
    ok = k32.GenerateConsoleCtrlEvent(0, 0)  # CTRL_C_EVENT a tutti i processi della console
    k32.FreeConsole()
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(send_ctrl_c(int(sys.argv[1])))
