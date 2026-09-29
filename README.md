# WEBCQUISITION

**Acquisizione forense automatizzata di attività web, in una VM Windows su VMware Workstation Pro.**

WEBCQUISITION automatizza tutte le operazioni *meccaniche* di un'acquisizione web e lascia all'operatore
solo quelle *investigative*: la navigazione e la scelta di cosa documentare.

Per ogni acquisizione, WEBCQUISITION:

- riparte da uno **snapshot pulito** della VM, verificandone identità, schede di rete e snapshot;
- avvia e **verifica** la cattura del traffico (PCAPNG) sulla scheda di rete corretta, con Wireshark
  visibile all'operatore;
- registra i **segreti TLS** (SSLKEYLOGFILE) per decifrare il traffico HTTPS in analisi;
- apre **Firefox** su [time.is](https://time.is), con un profilo dedicato al caso;
- fornisce **screenshot** con hash e metadati (`Ctrl+Alt+S` o pannello), ma lascia ovviamente la possibilità di effettuare screenshot da browser manualmente;
- una volta terminata l'attività un bottone consente di terminare l'acquisizione e il tool **copia la cartella del caso sull'host** con doppia verifica SHA-256;
  - alla fine (anche solo spegnendo Windows) chiude tutto;
- produce `acquisition.json`, un **report HTML** e un **log eventi con catena di hash**.

---

## Indice

1. [Come funziona](#come-funziona)
2. [Requisiti](#requisiti)
3. [Passo 1 – Preparare la VM Windows](#passo-1--preparare-la-vm-windows)
4. [Passo 2 – Installare WEBCQUISITION sull'host](#passo-2--installare-webcquisition-sullhost)
5. [Passo 3 – Preparazione automatica della VM](#passo-3--preparazione-automatica-della-vm-vmware-setup)
6. [Passo 4 – Prova completa](#passo-4--prova-completa-check-env---live)
7. [Passo 5 – Acquisizione](#passo-5--acquisizione)
8. [Passo 6 – Risultato, verifica e analisi](#passo-6--risultato-verifica-e-analisi)
9. [Problemi frequenti](#problemi-frequenti)
10. [Aggiornamenti](#aggiornare-webcquisition-o-la-vm)
11. [Riferimenti](#riferimenti)

---

## Come funziona

```
HOST (Windows)                               VM Windows (VMware Workstation Pro)
┌──────────────────────────┐  VMnet1 host-only ┌──────────────────────────────────────────┐
│ webcquisition            │ ◄──────────────► │ agent (sessione dell'operatore)           │
│  • vmrun: snapshot, VM   │  HTTP + token     │  • Desktop\<CASO>\                        │
│  • orchestrazione, stati │  (mai catturata)  │  • dumpcap ─► network\*.pcapng (REPERTO)  │
│  • copia + SHA-256       │                   │  • Wireshark (vista per l'operatore)      │
│  • report, verify        │                   │  • Firefox su time.is + SSLKEYLOGFILE     │
└──────────────────────────┘                   │  • pannello e hotkey per gli screenshot   │
                                   VMnet8 NAT ─►│  NIC di acquisizione (catturata)          │
                                               └──────────────────────────────────────────┘
```

- La VM ha **due schede di rete**. **NIC1 (NAT)** serve alla navigazione ed è l'unica catturata.
  **NIC2 (Host-only)** è il canale di controllo tra host e agent, non è mai catturata e non ha
  gateway.
- L'**agent** gira nella VM, nella sessione dell'operatore, e avvia gli strumenti in modo visibile.
- L'**host** comanda tutto: VMware tramite `vmrun`, l'agent tramite HTTP con token.

**L'acquisizione si avvia sempre dall'host**, non aprendo la VM da VMware Workstation. È l'host che
ripristina lo snapshot pulito prima di avviare la VM.

---

## Requisiti

### Host
- Windows 10/11 con **Python 3.10+** (da python.org).
- **VMware Workstation Pro** 17.x. **Workstation Player non è supportato**: `vmrun` non gestisce
  gli snapshot con Player.
- Orologio sincronizzato (NTP): l'ora dell'host è il riferimento del caso.
- Spazio disco adeguato: i PCAPNG possono essere grandi.

### VM
- Windows 10/11 con **VMware Tools**.
- **Python 3.10+** installato **per tutti gli utenti** con **tcl/tk**.
- **Wireshark** con **Npcap**.
- **Firefox** dall'installer Mozilla.
- Un account **operatore** e l'account **Administrator** attivo (solo per la preparazione).

Nel passo 1 trovi il dettaglio di ciascuno.

### Ambiente validato

| Componente | Versione |
|---|---|
| Host | Windows 11, Python 3.x in virtualenv |
| VMware | Workstation Pro 17 (`vmrun 1.17.0 build-24832109`) |
| Guest | Windows 11, Python 3.13 (per tutti gli utenti), Wireshark + Npcap, Firefox |

---

## Passo 1 – Preparare la VM Windows

Da fare una sola volta, dentro la VM.

1. **VMware Tools**: VM → *Install VMware Tools*, poi riavvia. Attiva la sincronizzazione oraria in
   VM → *Settings* → *Options* → *VMware Tools* → *Synchronize guest time with host*.
2. **Python** con l'**installer classico** di python.org ("Windows installer (64-bit)"):
   1. spunta *Add python.exe to PATH*;
   2. scegli **Customize installation** e lascia spuntati **tcl/tk and IDLE** e **py launcher**;
   3. in *Advanced Options* spunta **Install Python for all users**. Il percorso deve essere
      `C:\Program Files\Python3xx`.

   Non usare la versione Microsoft Store né il "Python install manager": entrambi installano per
   singolo utente.
3. **Wireshark** con **Npcap**. Nell'installer di Npcap **non** spuntare *Restrict Npcap driver's
   access to Administrators only*: l'agent gira con privilegi limitati.
4. **Firefox** dall'installer di **mozilla.org**, non dallo Store.
5. **Account operatore**: un account locale, per esempio `User`. Verifica il nome esatto con
   `whoami` in un prompt: è la parte dopo la `\`.
6. **Account Administrator**, usato solo per la preparazione automatica. In un prompt
   *Esegui come amministratore*:
   ```
   net user Administrator /active:yes
   net user Administrator <password>
   ```
7. Riduci il rumore di fondo: OneDrive, app in background, sincronizzazioni. Quello che resta attivo
   comparirà nel PCAP.
8. **Spegni** la VM (non sospenderla).

> **Consiglio.** Se la VM ha una lunga storia di snapshot, cloni collegati o esperimenti, crea un
> **clone completo** pulito: VM → *Manage* → *Clone* → *Create a full clone*. 

---

## Passo 2 – Installare WEBCQUISITION sull'host

In un **Prompt dei comandi normale**, **non** *Esegui come amministratore*:

```
git clone https://github.com/webcquisition/WEBCQUISITION.git
cd WEBCQUISITION
py -m venv venv
venv\Scripts\activate
pip install .
webcquisition --version
```

In alternativa a `git clone`, puoi scaricare lo ZIP da GitHub (*Code* → *Download ZIP*).

`vmrun` viene cercato automaticamente in `C:\Program Files (x86)\VMware\VMware Workstation\`. Se non
viene trovato, indica il percorso con `--vmrun`.

> **Importante.** Esegui WEBCQUISITION con gli **stessi privilegi di VMware Workstation**,
> normalmente senza privilegi elevati.

---

## Passo 3 – Preparazione automatica della VM (`vmware-setup`)

Da fare una volta, e di nuovo dopo ogni modifica della VM. Con la VM **spenta** e la sua scheda
**chiusa** in Workstation:

```
webcquisition vmware-setup --vmx "D:\VM\WIN11_WEBCQ\WIN11_WEBCQ.vmx" ^
    --guest-user Administrator --operator-user User ^
    --cases-dir D:\Casi --fix-network
```

| Parametro | Significato |
|---|---|
| `--vmx` | percorso completo del file `.vmx` della VM |
| `--guest-user` | account amministratore del guest (consigliato `Administrator`) |
| `--operator-user` | account con cui l'operatore userà la VM |
| `--cases-dir` | cartella dell'host in cui verranno creati i casi. **Tenerla fuori dalla cartella del programma** |
| `--fix-network` | imposta nel `.vmx` NIC1 = NAT e NIC2 = Host-only (prima fa una copia del file) |
| `--autologon` + `--operator-password-file` | *(opzionale)* accesso automatico dell'operatore; la password resta in chiaro nel registro della VM |
| `--disable-windows-update` | *(opzionale)* evita che gli aggiornamenti cambino l'ambiente tra un caso e l'altro |
| `--start-url` | *(opzionale)* pagina iniziale di Firefox (default `https://time.is`) |

La password di Administrator viene chiesta a terminale e non viene mai scritta su disco né nei log.

**Cosa succede** (5–10 minuti):

1. Controlli preliminari, correzione delle schede di rete, rilevamento della rete host-only.
2. Avvio della VM e attesa di VMware Tools.
3. Esecuzione nella VM dello script di preparazione, con l'avanzamento in console (`guest …`).
   Lo script:
   - controlla Python, Wireshark/Npcap e Firefox;
   - configura la rete di controllo (IP statico, senza gateway né DNS);
   - rinomina le schede in `WEBCQ-Acquisizione` / `WEBCQ-Controllo`;
   - installa l'agent (avvio automatico all'accesso dell'operatore, firewall limitato all'host);
   - rimuove un eventuale SSLKEYLOGFILE globale.
4. Riavvio della VM. **Quando compare `>>> Accedere ora nella VM con l'utente '…'`, fai il logon
   nella VM** con l'account operatore. Nella VM non si apre nulla: è normale.
5. Verifica dell'agent, spegnimento, creazione dello snapshot **`webcq-clean`**.
6. Messaggio **"VM pronta"**.

**File prodotti** in `C:\ProgramData\WEBCQUISITION\`:

| File | Contenuto |
|---|---|
| `webcquisition.yaml` | configurazione dell'host, letta automaticamente da tutti i comandi |
| `agent.token` | segreto condiviso con l'agent: **proteggerlo** |
| `webcquisition.yaml.setup-<data>.json` | rapporto di preparazione: versioni, schede, MAC, indirizzi, hash del bundle installato, avvisi |
| `webcquisition.yaml.setup-<data>.events.jsonl` | log eventi della preparazione con catena di hash |

Conserva rapporto e log con la documentazione del laboratorio: descrivono la **baseline** da cui
partono tutte le acquisizioni.

---

## Passo 4 – Prova completa (`check-env --live`)

```
webcquisition check-env --live
```

1. La VM riparte dallo snapshot e si avvia. Se richiesto, fai il logon come operatore.
2. Viene verificato che l'agent risponda e che la scheda di acquisizione sia catturabile.
3. La VM si spegne.

Non viene creato alcun caso. Tutte le righe devono risultare `[OK]`.

---

## Passo 5 – Acquisizione

Doppio clic su `scripts\WEBCQUISITION.cmd`, che puoi copiare sul Desktop, oppure:

```
webcquisition wizard
```

La procedura chiede l'**ID del caso** (per esempio `CASE001` o `CASE-2026-001`) e l'**operatore**,
mostra VM, snapshot e destinazione, e chiede conferma. Senza domande:
`webcquisition acquire CASE001 --operator "Nome Cognome"`.

**Cosa succede e cosa fare:**

1. La VM riparte dallo snapshot pulito e si apre in Workstation. **Non aprirla tu**: la apre
   WEBCQUISITION.
2. Fai il logon come operatore, se non hai attivato l'accesso automatico.
3. Si aprono automaticamente:
   - **Wireshark**, con la cattura in corso su `WEBCQ-Acquisizione`. **Controlla che i pacchetti
     scorrano**;
   - **Firefox su time.is**, che mostra l'ora di riferimento, utile negli screenshot;
   - il **pannello WEBCQUISITION**, con i pulsanti *Screenshot* e *Fine acquisizione*.
4. **Naviga e documenta.** Screenshot con **`Ctrl+Alt+S`** o dal pannello. I file scaricati o
   salvati vanno messi in `Desktop\<CASO>` (o `Desktop\<CASO>\operator`).
5. **Per terminare**, in uno di questi modi:
   - **Spegni Windows** (Start → Arresta). Compare *"WEBCQUISITION impedisce l'arresto"*: è
     normale, **non** scegliere *Arresta comunque*. Attendi: la cartella viene copiata e verificata
     sull'host, poi la VM si spegne da sola.
   - *Fine acquisizione* nel pannello.
   - `FINE` nella console dell'host.
6. Nella console dell'host compare l'esito:
   - **`COMPLETED`**: tutto regolare;
   - **`INCOMPLETE`**: pacchetto integro, ma con problemi documentati;
   - **`FAILED`**.

   **Annota nel verbale** l'hash di `package-seal.json` e l'hash di testa del log eventi mostrati
   in console.

**Se la VM viene spenta di colpo** (Power Off, chiusura della finestra di Workstation, *Arresta
comunque*), l'host la riaccende **senza** ripristinare lo snapshot, recupera e verifica la cartella
del caso e la rispegne. L'esito è `INCOMPLETE`, perché cattura e browser sono stati interrotti
bruscamente, ma il materiale è sull'host. Il recupero è documentato negli eventi `RECOVERY_*`.

---

## Passo 6 – Risultato, verifica e analisi

Il caso viene creato in `<cartella casi>\<CASO>\`:

```
CASE001\
├── acquisition.json          metadati completi (stato, orari, VM, rete, TLS, file, eventi)
├── acquired\                 COPIA VERIFICATA di Desktop\CASE001 della VM
│   ├── network\*.pcapng      traffico catturato (reperto)
│   ├── tls\sslkeylog.log     segreti TLS (SENSIBILE)
│   ├── screenshots\          screenshot + metadati
│   ├── browser\              profilo Firefox del caso
│   ├── metadata\  logs\      informazioni di sistema, comandi, eventi del guest
│   └── (file dell'operatore)
├── hashes\                   SHA256SUMS.txt, manifest.json, package-seal.json
├── logs\host-events.jsonl    eventi dell'host con catena di hash
└── report\acquisition-report.html
```

**Verifica d'integrità**, anche in seguito o su un altro computer:

```
webcquisition verify --output D:\Casi\CASE001
```

Con strumenti standard: `cd acquired` e poi `sha256sum -c ..\hashes\SHA256SUMS.txt`.

**Analisi del traffico HTTPS.** Lavora su una **copia** del pacchetto. In Wireshark apri
*Modifica* → *Preferenze* → *Protocols* → *TLS* e imposta *(Pre)-Master-Secret log filename* su
`acquired\tls\sslkeylog.log`. Vedi [docs/TLS-KEYLOG.md](docs/TLS-KEYLOG.md).

**Cosa è verificato automaticamente e cosa resta all'operatore**

| Aspetto | Verifica |
|---|---|
| Identità della VM, schede di rete, ripristino dello snapshot | automatica |
| Cattura attiva sull'interfaccia giusta, pacchetti in crescita | automatica |
| Key log TLS presente e non vuoto | automatica (non dice *quali* sessioni sono decifrabili) |
| Integrità di ogni file dopo la copia (SHA-256 ×2), catene di eventi | automatica |
| Wireshark e Firefox visibili a schermo | **operatore** |
| Pertinenza e completezza di navigazione e screenshot | **operatore** |
| Decifrabilità effettiva del traffico | **operatore**, in analisi |
| Esattezza dell'ora dell'host rispetto a una fonte attendibile | **operatore** (l'offset host↔VM è misurato) |

---

## Problemi frequenti

| Sintomo / codice | Causa | Soluzione |
|---|---|---|
| La VM aperta a mano non avvia cattura né Firefox | è il comportamento previsto | avviare l'acquisizione dall'host (`wizard`) |
| Il setup resta su "avvio della VM in corso" | finestra di dialogo di Workstation in attesa; privilegi diversi tra prompt e Workstation | rispondere alla finestra ("moved or copied" → *I Moved It*); prompt **non** amministratore |
| `CONFIG_EXISTS` | esiste già `C:\ProgramData\WEBCQUISITION\webcquisition.yaml` | rinominarlo (es. `webcquisition.old.yaml`) o usare `--config-out` |
| `VM_NOT_OFF` | VM accesa o sospesa | spegnerla (non sospenderla) |
| `PYTHON_NOT_FOUND` | Python per singolo utente, Store o install manager | installer classico, *Install Python for all users* |
| `NPCAP_ADMIN_ONLY` | Npcap limitato agli amministratori | reinstallare Npcap senza quell'opzione |
| `NOT_ELEVATED` | UAC limita l'account usato | usare `Administrator`, oppure eseguire nella VM il comando mostrato |
| "The virtual disk is used multiple times" | catena di snapshot della VM incoerente | clone completo pulito della VM e nuovo setup |
| `AGENT_NOT_REACHABLE` / `VM_NOT_READY` | nessun logon dell'operatore; scheda "VMware Network Adapter VMnet1" disattivata sull'host | fare il logon; riattivare VMnet1 |
| Avviso `CLOCK_OFFSET_HIGH` | sincronizzazione oraria della VM assente | attivarla in VMware Tools e rifare il setup |

Per segnalare un problema, allega:
- per il setup: l'output della console e il file `*.setup-<data>.json` / `.events.jsonl`;
- per un'acquisizione: `logs\host-events.jsonl` del caso.

**Non allegare** mai token, key log TLS o materiale dei casi.

---

## Aggiornare WEBCQUISITION o la VM

- **Nuova versione di WEBCQUISITION**:
  1. `git pull` (o nuovo ZIP), poi `pip install .`;
  2. rinomina `webcquisition.yaml`;
  3. ripristina `webcq-clean`, spegni e rilancia `vmware-setup` con un nuovo `--snapshot`, per
     esempio `webcq-clean-2`. In questo modo l'agent nella VM viene aggiornato.
- **Modifiche alla VM** (aggiornamenti di Windows, Firefox, Wireshark):
  1. ripristina lo snapshot pulito;
  2. aggiorna e spegni;
  3. rilancia `vmware-setup` con un nuovo `--snapshot` e un nuovo `--config-out`, oppure dopo aver
     rinominato la configurazione.

Ogni caso registra lo snapshot da cui è partito.

---

## Riferimenti

### Prova senza VMware (simulazione)

```
pip install -e ".[dev]"
webcquisition -c examples\dry-run.yaml acquire CASE-DEMO-001 --output .\out\CASE-DEMO-001 --dry-run --auto-stop 3
webcquisition verify --output .\out\CASE-DEMO-001
pytest
```

### Comandi

| Comando | Scopo |
|---|---|
| `vmware-setup` | preparazione automatica della VM |
| `check-env [--live]` | verifica configurazione, VM, snapshot, schede, token; con `--live` anche l'agent |
| `wizard` | procedura guidata per una nuova acquisizione |
| `acquire ID --operator NOME` | acquisizione senza domande |
| `verify --output CASO` | verifica offline di un pacchetto (nessuna scrittura) |
| `create-case`, `run`, `start`, `status`, `stop`, `gen-token` | passi separati e installazione manuale |

Codici di uscita: `0` COMPLETED, `2` INCOMPLETE, `3` FAILED, `64` errore d'uso o di configurazione.

### Sicurezza e buone pratiche

- `agent.token` e `tls\sslkeylog.log` sono **segreti**: proteggerli come il resto del reperto.
- Tenere la cartella dei casi **fuori** dalla cartella del programma e non versionarla mai.
- Il key log permette di decifrare tutto il traffico TLS della sessione, inclusi eventuali
  accessi fatti con credenziali: valutarne la gestione caso per caso.
- Vulnerabilità: segnalarle come indicato in [SECURITY.md](SECURITY.md), non con issue pubbliche.

### Limiti principali

- Solo VMware Workstation Pro (e Fusion, meno provato); niente Player, niente VM cifrate.
- Solo Firefox come browser.
- Il recupero dopo uno spegnimento brusco riavvia la VM dallo stato corrente: il riavvio modifica il
  sistema della VM, anche se il traffico non viene catturato.

---

## Licenza e contributi

Rilasciato sotto **Apache License 2.0** ([LICENSE](LICENSE), [NOTICE](NOTICE)). Contributi benvenuti:
[CONTRIBUTING.md](CONTRIBUTING.md).
