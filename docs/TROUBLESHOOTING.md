# Risoluzione dei problemi

Il punto di partenza è sempre il caso stesso: `acquisition.json` (sezione `issues`), il report,
`logs/host.log`, `logs/host-events.jsonl` e, se esportato, `acquired/logs/`. Con `-v` la console
mostra anche i messaggi di debug.

## Preparazione (`vmware-setup`)

| Codice | Causa | Cosa fare |
|---|---|---|
| `VM_NOT_OFF` | VM accesa o sospesa | spegnerla e chiudere la scheda in Workstation |
| `NETWORK_LAYOUT` | schede diverse da NIC1 NAT / NIC2 Host-only | correggere in VM → Settings o usare `--fix-network` |
| `HOSTONLY_NETWORK_UNKNOWN` | `vmnetdhcp.conf` assente o diverso | indicare `--host-ip`, `--control-ip`, `--prefix-length` (Virtual Network Editor) |
| `VMware Tools non attivi` | Tools non installati o non avviati | installarli, riavviare la VM |
| `Invalid user name or password` | credenziali del guest errate | verificare `--guest-user` e password |
| `NOT_ELEVATED` | UAC limita le guest operations | eseguire lo script nella VM come indicato (il setup prosegue da solo) o usare `Administrator` |
| `PYTHON_NOT_FOUND` / `PYTHON_TOO_OLD` | Python assente, per singolo utente, Store o install manager | installer classico di python.org, "Install Python for all users" (`C:\Program Files\Python3xx`) |
| `GUEST_SETUP_TIMEOUT` | un passo dello script nel guest non termina | leggere l'ultimo passo in console o in `C:\Windows\Temp\webcq-setup\setup-progress.log` nella VM |
| `WIRESHARK_NOT_FOUND` / `NPCAP_NOT_FOUND` / `NPCAP_ADMIN_ONLY` | Wireshark/Npcap assenti o Npcap limitato agli amministratori | (re)installare; deselezionare "Restrict … to Administrators only" |
| `FIREFOX_NOT_FOUND` / `FIREFOX_STORE` | Firefox assente o versione Store | installer Mozilla |
| `OPERATOR_NOT_FOUND` | utente operatore inesistente | crearlo nella VM o correggere `--operator-user` |
| `CONTROL_NIC_NOT_FOUND` / `CAPTURE_NIC_NOT_FOUND` | driver di rete non installato, scheda disattivata nel guest | verificare in Gestione dispositivi |
| `AGENT_NOT_REACHABLE` | nessun logon dell'operatore, firewall dell'host, VMnet1 disattivata | accedere come operatore; verificare VMnet1 |
| `SNAPSHOT_EXISTS` / `CONFIG_EXISTS` | nomi già usati | scegliere `--snapshot` / `--config-out` nuovi |

In caso di errore la VM resta accesa e non viene creato alcuno snapshot: spegnerla prima di
rilanciare. Il rapporto `*.setup-<data>.json` riporta il passo fallito e l'esito di ogni controllo
nel guest.

## Acquisizione

| Codice / sintomo | Causa probabile | Cosa fare |
|---|---|---|
| `ConfigError ... chiave sconosciuta` | refuso nel YAML | correggere; le chiavi sconosciute sono volutamente un errore |
| `HYPERVISOR_UNAVAILABLE` / `VMRUN_NOT_FOUND` | vmrun non trovato | installare Workstation Pro; impostare `hypervisor.executable` o `--vmrun` |
| `VM_NOT_FOUND` | percorso del `.vmx` errato, VM spostata, VM cifrata | `hypervisor.vm_name` deve essere il percorso completo del `.vmx` |
| `VM_IDENTITY_MISMATCH` | VM clonata/reimportata | verificare che sia la VM giusta, poi aggiornare `vm_uuid` |
| `NETWORK_CONFIG_MISMATCH` | NIC cambiate o aggiunte | ripristinare la configurazione documentata o aggiornare `expected_nics` e lo snapshot |
| `SNAPSHOT_NOT_FOUND` / snapshot ambiguo | nome diverso o duplicato | `vmrun -T ws listSnapshots "<vmx>"`; rinominare i duplicati in Snapshot Manager |
| VM "già in esecuzione" / sospesa | VM lasciata accesa o sospesa | spegnerla (non riprenderla): WEBCQUISITION parte solo da VM spenta |
| `VM_NOT_READY` con `[VMware Tools: installed/unknown]` | Windows non ancora avviato o Tools non aggiornati | attendere, aggiornare VMware Tools, rifare il setup |
| agent irraggiungibile ma VM e Tools ok | scheda "VMware Network Adapter VMnet1" disattivata sull'host, subnet VMnet1 cambiata | riattivarla; se la subnet è cambiata rifare `vmware-setup` |
| `VM_NOT_READY` con agent irraggiungibile | agent non avviato, firewall, IP host-only diverso | accedere alla VM, controllare lo Scheduled Task, `run_agent.pyw --check`, `ping` dall'host all'IP host-only |
| `VM_NOT_READY` con "sessione desktop non pronta" | logon non avvenuto | effettuare il logon dell'utente operatore (o accesso automatico) |
| `AGENT_IDENTITY_MISMATCH` | `agent_id` diverso: forse un'altra VM | verificare; non forzare |
| `GUEST_NOT_CLEAN` | la VM non è ripartita dallo snapshot | verificare snapshot e `require_snapshot` |
| `PROTOCOL_MISMATCH` | versioni host/agent diverse | ricreare il bundle agent dalla stessa versione e un nuovo snapshot |
| HTTP 401 `UNAUTHORIZED` | token diverso tra host e `agent.json` | allineare il token |
| `INTERFACE_AMBIGUOUS` / `INTERFACE_NOT_FOUND` | più NIC con gateway o nessuna | impostare `capture.interface` o `--interface`; controllare che la NIC2 non abbia gateway |
| `INTERFACE_IS_CONTROL` | scelta la NIC host-only | scegliere la NIC di acquisizione |
| `CAPTURE_ENGINE_NOT_FOUND` / `CAPTURE_START_FAILED` | Wireshark/Npcap non installati, percorso diverso | correggere `dumpcap_path`; reinstallare Npcap |
| `CAPTURE_NOT_VERIFIED` | Npcap non avviato, permessi | `dumpcap -D` e `dumpcap -i <if> -a duration:5 -w test.pcapng` nella VM; vedere `logs/dumpcap-stderr.log` |
| `CAPTURE_NO_TRAFFIC` | nessuna navigazione, NIC senza connettività | verificare la rete NAT; navigare almeno una pagina |
| `CAPTURE_PROCESS_DIED` | disco pieno, interfaccia disattivata | vedere `stderr_tail` nell'evento e lo spazio libero |
| `CAPTURE_FORCED_STOP` | dumpcap non ha risposto a CTRL+C | segnalare come bug con `logs/` allegati; il file è comunque verificato |
| `FIREFOX_NOT_FOUND` / `FIREFOX_START_FAILED` | percorso errato, Firefox aperto con un altro profilo bloccato | correggere `firefox_path`; non usare la versione Store |
| `TLS_KEYLOG_EMPTY` | build senza key log, nessuna connessione HTTPS, `SSLKEYLOGFILE` ignorata | vedi TLS-KEYLOG; provare `about:support` → versione e distribuzione |
| `GLOBAL_SSLKEYLOGFILE_SET` | variabile impostata nella VM | rimuoverla e ricreare lo snapshot |
| `HOTKEY_UNAVAILABLE` | combinazione già registrata da un altro programma | cambiare `screenshot.hotkey` |
| `PANEL_UNAVAILABLE` | tkinter non installato con Python | reinstallare Python con "tcl/tk and IDLE" |
| `CLOCK_OFFSET_HIGH` | sincronizzazione oraria della VM assente | VM → Settings → Options → VMware Tools → sincronizzazione ora; rifare il setup |
| `AGENT_UNREACHABLE_PERSISTENT` | VM bloccata o rete di controllo caduta | controllare la finestra della VM; se la VM è bloccata scrivere FINE: il materiale resta nella VM e nello snapshot post-acquisizione |
| `VM_LOST` | crash/spegnimento della VM | esito FAILED; esaminare lo snapshot `WEBCQ-<caso>-post-…` se creato; **non** ripristinare lo snapshot pulito prima di aver deciso |
| `EXPORT_HASH_MISMATCH` ripetuto → `EXPORT_FILE_FAILED` | disco host, antivirus, rete instabile | escludere la cartella dei casi dall'antivirus in tempo reale; verificare il disco |
| `CaseLockedError` | un altro processo sul caso, o processo terminato male | verificare che nessun processo sia attivo, poi rimuovere `metadata/.lock` annotandolo nel verbale |
| `verify` segnala `[KO]` | file modificati dopo l'acquisizione | lavorare sempre su copie; confrontare con gli hash del verbale |

Se l'host si interrompe durante `ACQUIRING`, la VM e il materiale restano: rieseguire
`webcquisition stop --output <caso>` per chiudere, esportare e verificare.
