# Installazione

## Host

Requisiti:
- Windows 10/11 (consigliato) o Linux, con Python 3.10+.
- **VMware Workstation Pro** 17.x. Su macOS c'è VMware Fusion, meno provato (`--fusion`).
- **VMware Workstation Player non è supportato**: `vmrun` non gestisce gli snapshot con Player.
- Orologio sincronizzato (NTP). L'ora dell'host è il riferimento del caso: verificarla e annotarla
  nel verbale.
- Spazio su disco adeguato: i PCAPNG possono essere grandi.

```powershell
git clone https://github.com/webcquisition/WEBCQUISITION.git
cd WEBCQUISITION
py -m venv C:\WEBCQUISITION\venv
C:\WEBCQUISITION\venv\Scripts\activate
pip install .
webcquisition --version
```

Per avere il comando sempre disponibile, aggiungere `C:\WEBCQUISITION\venv\Scripts` al PATH
dell'utente. Poi copiare `scripts\WEBCQUISITION.cmd` sul Desktop dell'operatore.

`vmrun` viene cercato nel PATH e in `C:\Program Files (x86)\VMware\VMware Workstation\`.
Altrimenti indicarlo con `--vmrun` (setup) o `hypervisor.executable` (configurazione).

## VM Windows: cosa installare prima del setup

Installare nella VM:

1. **Windows 10/11** aggiornato.
2. **VMware Tools** (VM → Install VMware Tools), con la sincronizzazione oraria attiva.
3. **Python 3.10+** con l'**installer classico** di python.org ("Windows installer (64-bit)").
   Scegliere "Customize installation", lasciare "tcl/tk and IDLE" (serve al pannello) e spuntare
   "Install Python for all users": il percorso deve diventare `C:\Program Files\Python3xx`.
   Non usare la versione Microsoft Store né il "Python install manager", che installa per singolo
   utente.
4. **Wireshark** con **Npcap**. Nell'installer di Npcap **non** selezionare "Restrict Npcap driver's
   access to Administrators only".
5. **Firefox** dall'installer ufficiale Mozilla, non dalla versione Store.

Servono anche due account:
- un **account operatore** locale (es. `forensic`), con cui si userà la VM;
- per il setup, un **account amministratore** del guest. È consigliato l'account `Administrator`
  integrato, per evitare le limitazioni UAC delle guest operations; abilitarlo con
  `net user Administrator /active:yes` e impostarne la password.

Tutto il resto (agent, rete di controllo, snapshot, configurazione) lo fa `vmware-setup`: vedi
[VM-PREPARATION.md](VM-PREPARATION.md).
