# Changelog

Formato basato su [Keep a Changelog](https://keepachangelog.com/it/1.1.0/); versioni secondo
[Semantic Versioning](https://semver.org/lang/it/).

## [0.2.5] — 2026-09-29

### Corretto
- **Blocco nella scrittura del risultato del setup** in Windows PowerShell 5.1: una stringa letta con
  `Get-Content` (elenco hash del bundle) porta proprietà nascoste PSPath/PSDrive/PSProvider che
  `ConvertTo-Json -Depth 10` esplorava ricorsivamente senza fine. Lettura con `[IO.File]::ReadAllText`
  e conversione di tutto il risultato in tipi JSON semplici (`ConvertTo-WebcqPlain`) prima della
  serializzazione; scrittura in UTF-8 con `[IO.File]::WriteAllText`. Test di regressione.

## [0.2.4] — 2026-09-29

### Corretto
- Il setup restava in attesa dopo `ok: agent`: nel blocco finale di `guest-setup.ps1` una
  cancellazione fallita (file appena estratto bloccato dall'antivirus) interrompeva lo script prima
  della scrittura del risultato. Ora ogni cancellazione è isolata e ritentata, un fallimento diventa
  un avviso (segnalato come dato sensibile se riguarda `agent.json`/`operator.pw`) e il risultato
  viene sempre scritto. L'host cancella comunque i file con segreti e rileva uno script terminato
  senza risultato (`GUEST_RESULT_MISSING`) invece di attendere il timeout.

## [0.2.3] — 2026-09-29

### Corretto / migliorato
- Lo script di preparazione nel guest viene avviato senza attesa (`runProgramInGuest -noWait`):
  l'host mostra in console l'avanzamento scritto dal guest (`setup-progress.log`) e applica un
  timeout complessivo (`GUEST_SETUP_TIMEOUT`, con l'ultimo passo raggiunto).
- Ogni programma lanciato dallo script guest ha un timeout e lo stdin chiuso: nessuna attesa
  infinita di input (per esempio il primo avvio del "Python install manager").
- Ricerca di Python: prima `C:\Program Files\Python3*`; messaggio con le installazioni per singolo
  utente trovate; `py.exe` usato solo come ultima possibilità.
- Risultati di tentativi precedenti cancellati prima dell'esecuzione e riconosciuti tramite `run_id`.

## [0.2.2] — 2026-09-29

### Corretto
- **Blocco indefinito all'avvio della VM su Windows**: `vmrun start ... gui` avvia l'interfaccia di
  Workstation, che ereditava le pipe di output; Python attendeva la loro chiusura (anche dopo il
  timeout) finché Workstation restava aperto. L'output dei comandi esterni ora passa da file
  temporanei: si attende solo la fine del processo lanciato. Nuovi test con processi figli che
  mantengono aperto l'output.

## [0.2.1] — 2026-09-29

### Aggiunto
- **Spegnere Windows nella VM = fine acquisizione**: l'agent trattiene lo spegnimento
  (`ShutdownBlockReasonCreate`) finché l'host non ha copiato e verificato la cartella del caso, poi
  Windows lo completa da solo (`finalize.block_guest_shutdown`). Nuovo endpoint `session/release`.
- **Recupero dopo VM spenta o sospesa** prima della copia: riavvio senza snapshot, endpoint
  `session/recover`, sigillo ed export della cartella del caso; esito INCOMPLETE documentato
  (`finalize.recover_on_vm_loss`, eventi `RECOVERY_*`, `GUEST_SHUTDOWN_*`).
- Pagina iniziale di Firefox predefinita **https://time.is** (`--start-url` in `vmware-setup`).

### Corretto
- `vmrun start` bloccato (finestra di dialogo di Workstation, privilegi diversi): dopo 120 s, se la
  VM risulta accesa si prosegue; altrimenti errore con indicazioni. Il setup avvisa prima dell'avvio.

## [0.2.0] — 2026-09-28

Edizione dedicata a VMware Workstation Pro.

### Aggiunto
- `vmware-setup`: preparazione automatica della VM tramite VMware Tools (verifica/correzione delle
  schede nel `.vmx`, rilevamento della rete host-only, token, installazione e verifica dell'agent,
  IP statico e nomi espliciti delle schede, rimozione di SSLKEYLOGFILE globale, accesso automatico e
  disattivazione di Windows Update opzionali, riavvio con verifica end-to-end, snapshot pulito,
  configurazione dell'host, rapporto di preparazione e log eventi con catena di hash). Gestione di
  UAC con esecuzione manuale guidata.
- `check-env --live`: avvio dallo snapshot e verifica di agent e interfacce senza creare casi.
- `wizard` e `scripts/WEBCQUISITION.cmd`: procedura guidata per l'operatore.
- Configurazione predefinita (`%ProgramData%\WEBCQUISITION\webcquisition.yaml`,
  `WEBCQUISITION_CONFIG`).
- Provider VMware riscritto: stato sospeso, VM cifrate rifiutate, codifica del `.vmx`, reti
  `custom:vmnetN`, schede non collegate all'accensione, snapshot duplicati, VMware Tools, guest
  operations. Evento `GUEST_TOOLS_RUNNING`, eventi `VM_SETUP_*`.
- Test: simulatore di `vmrun` con stato, acquisizione completa con il provider reale, setup
  end-to-end, esecuzione di `guest-setup.ps1` in PowerShell 7 con cmdlet simulati.

### Modificato
- L'agent gira con privilegi **limitati** (prima: elevati); il setup verifica che Npcap non sia
  limitato agli amministratori.
- `install-agent.ps1` usa i SID invece dei nomi localizzati dei gruppi.
- Confronto degli UUID indipendente da spazi e trattini.

### Rimosso
- Provider VirtualBox e Hyper-V.

## [0.1.0] — 2026-09-28

Prima versione pubblica (alpha).

### Aggiunto
- Host controller: CLI (`gen-token`, `check-env`, `create-case`, `acquire`, `run`, `start`,
  `status`, `stop`, `verify`), configurazione YAML con validazione stretta, macchina a stati del
  caso, lock, `--dry-run`.
- Provider hypervisor: VirtualBox (MVP), VMware Workstation e Hyper-V (sperimentali), Fake.
- Verifiche preliminari: identità VM (UUID), NIC attese, snapshot, VM spenta, `agent_id`.
- Guest agent (solo stdlib): API HTTP autenticata su NIC host-only, cartella del caso sul
  Desktop, metadati di sistema, cattura dumpcap/tshark con GUI Wireshark e verifica programmatica,
  arresto pulito tramite CTRL+C, Firefox con profilo dedicato e `SSLKEYLOGFILE` per-processo,
  screenshot integrati (hotkey e pannello), watcher dei file dell'operatore, sigillo SHA-256.
- Export verificato con retry, seconda verifica da disco, riepilogo PCAPNG, file in sola lettura.
- Log eventi JSONL con catena di hash su host e guest.
- `acquisition.json`, report HTML autocontenuto, `package-seal.json`, `SHA256SUMS.txt`.
- Script di bundle e installazione dell'agent, documentazione completa, CI.
