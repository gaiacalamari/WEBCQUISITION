# Preparazione della VM (`vmware-setup`)

Lo **snapshot pulito** è il punto di partenza di ogni acquisizione e fa parte dell'ambiente
documentato. `vmware-setup` lo crea in modo ripetibile e ne produce la documentazione.

## Prima del setup

- Installare nella VM i prerequisiti (vedi [INSTALLATION.md](INSTALLATION.md)).
- Ridurre il rumore di fondo, perché ciò che resta attivo comparirà nel PCAP: OneDrive, app in
  background, sincronizzazioni. Annotare le scelte fatte.
- **Spegnere** la VM (non sospenderla) e chiudere la sua scheda in VMware Workstation. Workstation
  potrebbe riscrivere il `.vmx` se la scheda è aperta.

## Esecuzione

```powershell
webcquisition vmware-setup `
    --vmx "D:\VMs\Forensic Windows\Forensic Windows.vmx" `
    --guest-user Administrator `
    --operator-user forensic `
    --cases-dir D:\Cases `
    --fix-network
```

La password dell'account del guest viene chiesta a terminale. In alternativa si può usare
`--guest-password-file` oppure la variabile `WEBCQ_GUEST_PASSWORD`. La password non viene mai
scritta su disco né nei log.

Opzioni utili:

| Opzione | Effetto |
|---|---|
| `--fix-network` | imposta nel `.vmx` NIC1 = NAT e NIC2 = Host-only, disattiva altre schede. Prima fa una copia `.webcq-backup-<data>` del file |
| `--autologon --operator-password-file F` | accesso automatico dell'operatore all'avvio, così l'acquisizione non richiede il logon manuale. **La password resta in chiaro nel registro della VM** |
| `--disable-windows-update` | evita che aggiornamenti e relativo traffico cambino l'ambiente tra un caso e l'altro |
| `--snapshot NOME` | nome dello snapshot pulito (default `webcq-clean`, non deve esistere) |
| `--config-out F` | dove scrivere la configurazione. Default `%ProgramData%\WEBCQUISITION\webcquisition.yaml`, letta automaticamente dagli altri comandi |
| `--host-ip`, `--control-ip`, `--prefix-length` | indirizzi manuali, se la rete host-only non è quella predefinita |
| `--fusion`, `--vmrun` | VMware Fusion, percorso di `vmrun` |

## Cosa succede, passo per passo

1. **Verifiche preliminari**:
   - `vmrun` presente;
   - VM spenta e non cifrata;
   - snapshot e configurazione di destinazione non ancora esistenti.
2. **Rete**:
   - `ethernet0` deve essere NAT e `ethernet1` Host-only, entrambe collegate all'accensione;
   - la subnet host-only e l'IP dell'host sono letti dalla configurazione DHCP di VMware
     (`C:\ProgramData\VMware\vmnetdhcp.conf`);
   - la VM riceve l'indirizzo `.10` della subnet, fuori dall'intervallo DHCP di VMware.
3. **Segreti**: nuovo token in `agent.token`, accanto alla configurazione (va protetto); nuovo `agent_id`.
4. **Primo avvio**: attesa di VMware Tools, copia dei file in `C:\Windows\Temp\webcq-setup`,
   esecuzione di `guest-setup.ps1`. Lo script:
   - controlla privilegi, utente operatore, Python, tkinter, dumpcap, Npcap (anche l'opzione
     "solo amministratori"), Wireshark e Firefox (non la versione Store);
   - individua le schede **dal MAC del `.vmx`**. Quella di controllo riceve IP statico, senza
     gateway, senza DNS, senza registrazione DNS e con DHCP disattivato;
   - rinomina le schede `WEBCQ-Controllo` e `WEBCQ-Acquisizione`;
   - rimuove un eventuale `SSLKEYLOGFILE` globale;
   - installa l'agent: Scheduled Task all'accesso dell'operatore **con privilegi limitati**,
     `agent.json` con ACL restrittiva, regola firewall che accetta solo l'IP dell'host;
   - verifica l'agent con `--check`;
   - applica le opzioni scelte;
   - **cancella** dalla cartella temporanea `agent.json` e la password.
5. **Riavvio e verifica**:
   - senza `--autologon` il setup chiede di accedere nella VM come operatore;
   - l'host contatta l'agent sulla rete host-only e verifica identità, protocollo, sessione
     interattiva, orologio, scheda di controllo riconosciuta e scheda di acquisizione catturabile.
6. **Snapshot**: spegnimento controllato, creazione dello snapshot pulito e verifica che esista.
7. **Documentazione**. Accanto alla configurazione vengono creati:
   - `webcquisition.yaml`: configurazione dell'host già completa di `vm_uuid`, NIC attese,
     snapshot, `agent_id`, interfaccia `WEBCQ-Acquisizione`;
   - `webcquisition.yaml.setup-<data>.json`: esito di ogni passo, versioni degli strumenti, schede
     e MAC, indirizzi, hash dello zip e di ogni file del bundle installato, avvisi;
   - `webcquisition.yaml.setup-<data>.events.jsonl`: log eventi con catena di hash.

   Conservarli con la documentazione del laboratorio: descrivono la baseline da cui partono tutte
   le acquisizioni.

## Se le guest operations non hanno privilegi di amministratore

Con UAC attivo, un account amministratore diverso da `Administrator` può ricevere un token non
elevato. Il setup lo rileva (`NOT_ELEVATED`), stampa il comando da eseguire nella VM in un
PowerShell "Esegui come amministratore" e **prosegue da solo** appena lo script termina (timeout
30 minuti). In alternativa: rilanciare con `--guest-user Administrator`.

## In caso di errore

Il setup si ferma al primo errore:
- non crea lo snapshot né la configurazione;
- lascia la VM accesa per l'analisi;
- scrive comunque il rapporto con il codice di errore (vedi [TROUBLESHOOTING.md](TROUBLESHOOTING.md)).

Spegnere la VM, correggere e rilanciare. Il token già generato viene riutilizzato; ogni esecuzione
produce un proprio rapporto con data e ora, e nessun rapporto precedente viene sovrascritto.

## Aggiornare la VM

Ogni modifica della VM (aggiornamenti di Windows, Firefox o Wireshark, nuova versione di
WEBCQUISITION) richiede:
1. ripristinare lo snapshot pulito;
2. applicare le modifiche e spegnere;
3. rilanciare `vmware-setup` con un `--snapshot` e un `--config-out` **nuovi**.

Il nome dello snapshot usato è registrato in ogni caso, quindi resta sempre chiaro da quale
baseline parte ciascuna acquisizione.

## Installazione manuale (senza guest operations)

`python scripts/build-agent-bundle.py --out dist\agent` crea il bundle. Poi:
1. copiarlo nella VM;
2. creare `agent.json` da `agent.example.json`;
3. eseguire da amministratore:
   `.\install-agent.ps1 -AgentJson .\agent.json -OperatorUser forensic -HostIp <IP host VMnet1>`;
4. configurare a mano l'IP statico della scheda host-only, creare lo snapshot e scrivere la
   configurazione partendo da `config/webcquisition.example.yaml`.
